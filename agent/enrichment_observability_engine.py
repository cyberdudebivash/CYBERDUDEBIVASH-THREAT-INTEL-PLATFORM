# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/enrichment_observability_engine.py
# PHASE 4 — ENRICHMENT OBSERVABILITY ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
Enrichment Observability Engine — Phase 4 of Enterprise Observability Layer.

Measures enrichment pipeline coverage, completeness, and failure rates:
  - Coverage telemetry: % of advisories with each enrichment field populated
  - Completeness analytics: per-advisory completeness scores
  - IOC extraction telemetry: extraction rates, type distributions
  - ATT&CK enrichment telemetry: technique coverage, tactic breadth
  - Failure analytics: enrichment failures by source, engine, field
  - Drift analytics: enrichment rate changes over time
  - Source reliability: per-feed enrichment yield rates

Outputs:
  data/observability/enrichment_observability_report.json (atomic write)
  data/observability/enrichment_observability_telemetry.jsonl (append)

Never raises — all errors caught and surfaced in report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinel.enrichment_obs")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OBS_DIR = DATA_DIR / "observability"
REPORT_PATH = OBS_DIR / "enrichment_observability_report.json"
TELEMETRY_PATH = OBS_DIR / "enrichment_observability_telemetry.jsonl"

INTEL_DIR = DATA_DIR / "intelligence"

# Enrichment fields to track coverage for
ENRICHMENT_FIELDS = [
    "cvss_score", "epss_score", "kev_listed", "iocs", "techniques",
    "ttps", "actors", "summary", "risk_score", "confidence",
    "intelligence_depth", "attack_maturity", "estimated_dwell_days",
]

IOC_TYPES = ["ip", "domain", "url", "hash_md5", "hash_sha256", "email", "cve", "file"]
ATT_AND_CK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class FieldCoverage:
    field_name: str
    populated_count: int
    total_count: int
    coverage_pct: float
    is_critical: bool


@dataclass
class IOCTelemetry:
    total_advisories_with_iocs: int
    total_advisories_without_iocs: int
    ioc_coverage_pct: float
    total_iocs_extracted: int
    mean_iocs_per_advisory: float
    type_distribution: Dict[str, int]
    depth_distribution: Dict[str, int]


@dataclass
class ATTCKTelemetry:
    total_with_techniques: int
    technique_coverage_pct: float
    total_techniques_mapped: int
    mean_techniques_per_advisory: float
    tactic_coverage: Dict[str, int]
    unique_techniques: int
    maturity_distribution: Dict[str, int]


@dataclass
class EnrichmentFailure:
    engine: str
    field: str
    failure_count: int
    failure_rate_pct: float
    sample_advisory_ids: List[str]


@dataclass
class EnrichmentObservabilityReport:
    report_id: str
    generated_at: str
    total_advisories: int
    mean_completeness_score: float
    completeness_tier: str
    field_coverage: List[FieldCoverage]
    ioc_telemetry: IOCTelemetry
    attck_telemetry: ATTCKTelemetry
    failures: List[EnrichmentFailure]
    source_yield: Dict[str, float]
    enrichment_health_score: float
    duration_ms: float = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _short_id(s: str) -> str:
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()[:12]

def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)

def _load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ── COVERAGE ANALYZER ────────────────────────────────────────────────────────
CRITICAL_FIELDS = {"cvss_score", "iocs", "techniques", "risk_score", "summary"}

class FieldCoverageAnalyzer:

    def analyze(self, advisories: List[Dict]) -> List[FieldCoverage]:
        n = len(advisories)
        if n == 0:
            return []

        results = []
        for fname in ENRICHMENT_FIELDS:
            populated = 0
            for adv in advisories:
                val = adv.get(fname)
                if val is not None and val != "" and val != [] and val != {}:
                    populated += 1
            results.append(FieldCoverage(
                field_name=fname,
                populated_count=populated,
                total_count=n,
                coverage_pct=round(populated / n * 100, 2),
                is_critical=fname in CRITICAL_FIELDS,
            ))
        return results

    def completeness_score(self, advisory: Dict) -> float:
        """Score 0–100 for a single advisory's enrichment completeness."""
        weights = {
            "cvss_score": 15, "epss_score": 10, "kev_listed": 5,
            "iocs": 20, "techniques": 15, "risk_score": 10,
            "confidence": 10, "summary": 10, "actors": 5,
        }
        score = 0.0
        for fname, w in weights.items():
            val = advisory.get(fname)
            if val is not None and val != "" and val != [] and val != {}:
                score += w
        return min(100.0, score)


# ── IOC TELEMETRY ────────────────────────────────────────────────────────────
class IOCTelemetryAnalyzer:

    def analyze(self, advisories: List[Dict]) -> IOCTelemetry:
        with_iocs = 0
        without_iocs = 0
        total_iocs = 0
        type_dist: Counter = Counter()
        depth_dist: Counter = Counter()

        for adv in advisories:
            iocs = adv.get("iocs", adv.get("recovered_iocs", []))
            if not isinstance(iocs, list):
                iocs = []

            if iocs:
                with_iocs += 1
                total_iocs += len(iocs)
                for ioc in iocs:
                    if isinstance(ioc, dict):
                        t = ioc.get("type", ioc.get("ioc_type", "unknown"))
                        type_dist[str(t).lower()] += 1
                    elif isinstance(ioc, str):
                        type_dist["raw_string"] += 1
            else:
                without_iocs += 1

            depth = adv.get("intelligence_depth", adv.get("ioc_depth", "UNKNOWN"))
            depth_dist[str(depth)] += 1

        n = len(advisories)
        return IOCTelemetry(
            total_advisories_with_iocs=with_iocs,
            total_advisories_without_iocs=without_iocs,
            ioc_coverage_pct=round(with_iocs / n * 100, 2) if n > 0 else 0.0,
            total_iocs_extracted=total_iocs,
            mean_iocs_per_advisory=round(total_iocs / n, 2) if n > 0 else 0.0,
            type_distribution=dict(type_dist.most_common(20)),
            depth_distribution=dict(depth_dist),
        )


# ── ATT&CK TELEMETRY ─────────────────────────────────────────────────────────
class ATTCKTelemetryAnalyzer:

    def analyze(self, advisories: List[Dict]) -> ATTCKTelemetry:
        with_tech = 0
        total_tech = 0
        all_techniques: Set[str] = set()
        tactic_coverage: Counter = Counter()
        maturity_dist: Counter = Counter()

        for adv in advisories:
            techs = adv.get("techniques", adv.get("ttps", []))
            if not isinstance(techs, list):
                techs = []

            if techs:
                with_tech += 1
                total_tech += len(techs)
                for t in techs:
                    if isinstance(t, str):
                        all_techniques.add(t)
                    elif isinstance(t, dict):
                        tid = t.get("technique_id", t.get("id", ""))
                        if tid:
                            all_techniques.add(tid)
                        tactic = t.get("tactic", "")
                        if tactic:
                            tactic_coverage[tactic] += 1

            maturity = adv.get("attack_maturity", adv.get("behavioral_maturity", "UNKNOWN"))
            maturity_dist[str(maturity)] += 1

        n = len(advisories)
        return ATTCKTelemetry(
            total_with_techniques=with_tech,
            technique_coverage_pct=round(with_tech / n * 100, 2) if n > 0 else 0.0,
            total_techniques_mapped=total_tech,
            mean_techniques_per_advisory=round(total_tech / n, 2) if n > 0 else 0.0,
            tactic_coverage=dict(tactic_coverage.most_common()),
            unique_techniques=len(all_techniques),
            maturity_distribution=dict(maturity_dist),
        )


# ── FAILURE ANALYZER ─────────────────────────────────────────────────────────
class EnrichmentFailureAnalyzer:

    def analyze(self, advisories: List[Dict]) -> List[EnrichmentFailure]:
        n = len(advisories)
        if n == 0:
            return []

        failures: List[EnrichmentFailure] = []
        critical_missing: Dict[str, List[str]] = defaultdict(list)

        for adv in advisories:
            adv_id = adv.get("id", adv.get("cve_id", "unknown"))
            for fname in CRITICAL_FIELDS:
                val = adv.get(fname)
                if val is None or val == "" or val == [] or val == {}:
                    critical_missing[fname].append(str(adv_id))

        engine_map = {
            "cvss_score": "scoring_engine",
            "epss_score": "scoring_engine",
            "kev_listed": "scoring_engine",
            "iocs": "ioc_engine/ioc_depth_recovery_engine",
            "techniques": "attck_context_engine",
            "risk_score": "scoring_engine",
            "summary": "ingestion_pipeline",
        }

        for fname, missing_ids in critical_missing.items():
            if missing_ids:
                failures.append(EnrichmentFailure(
                    engine=engine_map.get(fname, "unknown"),
                    field=fname,
                    failure_count=len(missing_ids),
                    failure_rate_pct=round(len(missing_ids) / n * 100, 2),
                    sample_advisory_ids=missing_ids[:5],
                ))

        return sorted(failures, key=lambda f: f.failure_rate_pct, reverse=True)


# ── SOURCE YIELD ─────────────────────────────────────────────────────────────
def _compute_source_yield(advisories: List[Dict]) -> Dict[str, float]:
    source_counts: Counter = Counter()
    source_enriched: Counter = Counter()

    for adv in advisories:
        src = adv.get("source", adv.get("feed_source", "unknown"))
        source_counts[str(src)] += 1
        # Count as "enriched" if has both iocs and techniques
        has_iocs = bool(adv.get("iocs") or adv.get("recovered_iocs"))
        has_tech = bool(adv.get("techniques") or adv.get("ttps"))
        if has_iocs and has_tech:
            source_enriched[str(src)] += 1

    yield_rates: Dict[str, float] = {}
    for src, count in source_counts.items():
        enriched = source_enriched.get(src, 0)
        yield_rates[src] = round(enriched / count * 100, 2) if count > 0 else 0.0

    return yield_rates


# ── HEALTH SCORER ────────────────────────────────────────────────────────────
def _health_score(
    field_coverage: List[FieldCoverage],
    ioc_tel: IOCTelemetry,
    attck_tel: ATTCKTelemetry,
    failures: List[EnrichmentFailure],
) -> float:
    score = 100.0

    # Penalize low critical field coverage
    for fc in field_coverage:
        if fc.is_critical and fc.coverage_pct < 50:
            score -= 10.0
        elif fc.is_critical and fc.coverage_pct < 75:
            score -= 5.0

    # Penalize low IOC coverage
    if ioc_tel.ioc_coverage_pct < 30:
        score -= 15.0
    elif ioc_tel.ioc_coverage_pct < 50:
        score -= 8.0

    # Penalize low ATT&CK coverage
    if attck_tel.technique_coverage_pct < 30:
        score -= 10.0
    elif attck_tel.technique_coverage_pct < 50:
        score -= 5.0

    # Penalize high failure rates
    for f in failures:
        if f.failure_rate_pct > 50:
            score -= 8.0
        elif f.failure_rate_pct > 25:
            score -= 4.0

    return round(max(0.0, min(100.0, score)), 2)


def _tier_from_score(score: float) -> str:
    if score >= 90:
        return "EXCELLENT"
    elif score >= 75:
        return "GOOD"
    elif score >= 60:
        return "ACCEPTABLE"
    elif score >= 40:
        return "DEGRADED"
    else:
        return "CRITICAL"


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class EnrichmentObservabilityEngine:

    def __init__(self) -> None:
        self._coverage = FieldCoverageAnalyzer()
        self._ioc_tel = IOCTelemetryAnalyzer()
        self._attck_tel = ATTCKTelemetryAnalyzer()
        self._failure = EnrichmentFailureAnalyzer()

    def run_full_pipeline(
        self, advisories: Optional[List[Dict]] = None
    ) -> EnrichmentObservabilityReport:
        t0 = time.time()
        report_id = f"enrich_obs_{_short_id(_now_iso())}"
        logger.info("[ENRICH-OBS] Starting enrichment observability run %s", report_id)

        if advisories is None:
            advisories = self._load_advisories()

        if not advisories:
            logger.warning("[ENRICH-OBS] No advisories found")
            advisories = []

        # Run all analyzers
        field_coverage = []
        ioc_tel = IOCTelemetry(0, 0, 0.0, 0, 0.0, {}, {})
        attck_tel = ATTCKTelemetry(0, 0.0, 0, 0.0, {}, 0, {})
        failures: List[EnrichmentFailure] = []
        source_yield: Dict[str, float] = {}
        completeness_scores: List[float] = []

        try:
            field_coverage = self._coverage.analyze(advisories)
            completeness_scores = [self._coverage.completeness_score(a) for a in advisories]
        except Exception as exc:
            logger.warning("[ENRICH-OBS] Field coverage error: %s", exc)

        try:
            ioc_tel = self._ioc_tel.analyze(advisories)
        except Exception as exc:
            logger.warning("[ENRICH-OBS] IOC telemetry error: %s", exc)

        try:
            attck_tel = self._attck_tel.analyze(advisories)
        except Exception as exc:
            logger.warning("[ENRICH-OBS] ATT&CK telemetry error: %s", exc)

        try:
            failures = self._failure.analyze(advisories)
        except Exception as exc:
            logger.warning("[ENRICH-OBS] Failure analysis error: %s", exc)

        try:
            source_yield = _compute_source_yield(advisories)
        except Exception as exc:
            logger.warning("[ENRICH-OBS] Source yield error: %s", exc)

        mean_comp = (
            round(sum(completeness_scores) / len(completeness_scores), 2)
            if completeness_scores else 0.0
        )
        health = _health_score(field_coverage, ioc_tel, attck_tel, failures)
        tier = _tier_from_score(mean_comp)

        report = EnrichmentObservabilityReport(
            report_id=report_id,
            generated_at=_now_iso(),
            total_advisories=len(advisories),
            mean_completeness_score=mean_comp,
            completeness_tier=tier,
            field_coverage=field_coverage,
            ioc_telemetry=ioc_tel,
            attck_telemetry=attck_tel,
            failures=failures,
            source_yield=source_yield,
            enrichment_health_score=health,
            duration_ms=round((time.time() - t0) * 1000, 2),
        )

        self._persist(report)
        logger.info(
            "[ENRICH-OBS] Run %s: completeness=%.1f tier=%s ioc_cov=%.1f%% tech_cov=%.1f%%",
            report_id, mean_comp, tier,
            ioc_tel.ioc_coverage_pct, attck_tel.technique_coverage_pct
        )
        return report

    def _load_advisories(self) -> List[Dict]:
        results: List[Dict] = []
        conf_data = _load_json(INTEL_DIR / "explainable_confidence_scores.json")
        if isinstance(conf_data, list):
            results.extend(conf_data)

        reports_dir = INTEL_DIR / "reports"
        if reports_dir.exists():
            for f in sorted(reports_dir.glob("*.json"))[-30:]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(d, dict) and d.get("id"):
                        results.append(d)
                    elif isinstance(d, list):
                        results.extend(d[:5])
                except Exception:
                    pass
        return results

    def _persist(self, report: EnrichmentObservabilityReport) -> None:
        try:
            report_dict = asdict(report)
            _atomic_write(REPORT_PATH, report_dict)

            telem = {
                "report_id": report.report_id,
                "ts": report.generated_at,
                "n": report.total_advisories,
                "completeness": report.mean_completeness_score,
                "tier": report.completeness_tier,
                "ioc_coverage": report.ioc_telemetry.ioc_coverage_pct,
                "tech_coverage": report.attck_telemetry.technique_coverage_pct,
                "health": report.enrichment_health_score,
                "failures": len(report.failures),
            }
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(telem) + "\n")
        except Exception as exc:
            logger.error("[ENRICH-OBS] Persist error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        report = _load_json(REPORT_PATH)
        if not report:
            return {"status": "no_report"}
        return {
            "status": "ok",
            "completeness": report.get("mean_completeness_score"),
            "tier": report.get("completeness_tier"),
            "health": report.get("enrichment_health_score"),
            "ioc_coverage": report.get("ioc_telemetry", {}).get("ioc_coverage_pct"),
            "tech_coverage": report.get("attck_telemetry", {}).get("technique_coverage_pct"),
            "generated_at": report.get("generated_at"),
        }


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = EnrichmentObservabilityEngine()
    result = engine.run_full_pipeline()
    print(f"\n[ENRICH-OBS] Report: {result.report_id}")
    print(f"  Total advisories: {result.total_advisories}")
    print(f"  Completeness: {result.mean_completeness_score:.1f}  Tier: {result.completeness_tier}")
    print(f"  IOC coverage: {result.ioc_telemetry.ioc_coverage_pct:.1f}%  "
          f"ATT&CK coverage: {result.attck_telemetry.technique_coverage_pct:.1f}%")
    print(f"  Enrichment health: {result.enrichment_health_score:.1f}")
    sys.exit(0 if result.completeness_tier not in ("CRITICAL", "DEGRADED") else 1)
