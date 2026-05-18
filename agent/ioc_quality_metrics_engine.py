# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/ioc_quality_metrics_engine.py
# PHASE 5 — IOC QUALITY METRICS ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
IOC Quality Metrics Engine — Phase 5 of Enterprise Observability Layer.

Measures IOC quality across all dimensions:
  - Quality analytics: per-type quality scoring (precision, richness, confidence)
  - Uniqueness scoring: deduplication rate, IOC overlap across sources
  - Contextual richness: IOCs with context (tags, actors, campaigns) vs. bare
  - Freshness telemetry: age distribution, decay curve position
  - Decay analytics: IOCs at each lifecycle stage (ACTIVE/PERSISTENT/AGING/STALE/RETIRED)
  - Trust weighting: per-source IOC quality scores
  - High-value IOC detection: IOCs corroborated by 3+ sources

Outputs:
  data/observability/ioc_quality_report.json (atomic write)
  data/observability/ioc_quality_telemetry.jsonl (append)

Never raises — all errors caught and surfaced in report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinel.ioc_quality")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OBS_DIR = DATA_DIR / "observability"
REPORT_PATH = OBS_DIR / "ioc_quality_report.json"
TELEMETRY_PATH = OBS_DIR / "ioc_quality_telemetry.jsonl"

INTEL_DIR = DATA_DIR / "intelligence"
MEMORY_DIR = DATA_DIR / "threat_memory"
IOC_MEMORY_PATH = MEMORY_DIR / "ioc_memory.json"

# IOC quality thresholds
HIGH_FIDELITY_TYPES = {"hash_sha256", "hash_md5", "hash_sha1", "ip", "domain", "cve"}
LOW_FIDELITY_TYPES = {"raw_string", "unknown"}
SOURCE_TRUST_SCORES = {
    "cisa": 0.95, "nvd": 0.90, "mitre": 0.88, "github": 0.75,
    "threatfox": 0.80, "abuse_ch": 0.82, "sans": 0.78,
    "unknown": 0.35, "default": 0.55,
}


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class IOCTypeQuality:
    ioc_type: str
    count: int
    mean_confidence: float
    mean_age_days: float
    contextual_rate_pct: float
    multi_source_rate_pct: float
    quality_score: float


@dataclass
class LifecycleDistribution:
    active: int = 0
    persistent: int = 0
    aging: int = 0
    stale: int = 0
    retired: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.active + self.persistent + self.aging + self.stale + self.retired + self.unknown

    @property
    def active_rate_pct(self) -> float:
        t = self.total
        return round((self.active + self.persistent) / t * 100, 2) if t > 0 else 0.0


@dataclass
class IOCQualityReport:
    report_id: str
    generated_at: str
    total_iocs_analyzed: int
    unique_ioc_count: int
    deduplication_rate_pct: float
    mean_confidence: float
    mean_contextual_richness_pct: float
    high_fidelity_rate_pct: float
    multi_source_rate_pct: float
    lifecycle: LifecycleDistribution
    type_quality: List[IOCTypeQuality]
    source_trust_scores: Dict[str, float]
    high_value_iocs: List[str]
    overall_quality_score: float
    quality_tier: str
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


# ── IOC EXTRACTORS ───────────────────────────────────────────────────────────
def _extract_iocs_from_advisories(advisories: List[Dict]) -> List[Dict]:
    """Flatten all IOCs from advisories list into a single list with metadata."""
    iocs: List[Dict] = []
    for adv in advisories:
        adv_id = adv.get("id", adv.get("cve_id", "unknown"))
        source = adv.get("source", adv.get("feed_source", "unknown"))
        published = adv.get("published", adv.get("date", ""))

        for ioc_list_key in ["iocs", "recovered_iocs"]:
            raw = adv.get(ioc_list_key, [])
            if not isinstance(raw, list):
                continue
            for ioc in raw:
                if isinstance(ioc, dict):
                    ioc["_advisory_id"] = adv_id
                    ioc["_source"] = source
                    ioc["_published"] = published
                    iocs.append(ioc)
                elif isinstance(ioc, str) and ioc.strip():
                    iocs.append({
                        "value": ioc, "type": "raw_string",
                        "_advisory_id": adv_id, "_source": source,
                        "_published": published,
                    })
    return iocs


def _extract_iocs_from_memory() -> List[Dict]:
    """Load IOCs from intel_memory_aging_engine's ioc_memory store."""
    raw = _load_json(IOC_MEMORY_PATH)
    if isinstance(raw, dict):
        return list(raw.values())
    elif isinstance(raw, list):
        return raw
    return []


def _age_days(date_str: Optional[str]) -> float:
    if not date_str:
        return 999.0
    try:
        now = datetime.now(timezone.utc)
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0.0, (now - dt).total_seconds() / 86400)
    except Exception:
        return 999.0


# ── ANALYZERS ────────────────────────────────────────────────────────────────
class UniquenessAnalyzer:
    """Computes deduplication rate and multi-source corroboration."""

    def analyze(self, iocs: List[Dict]) -> Tuple[int, float, float, List[str]]:
        """Returns (unique_count, dedup_rate_pct, multi_source_rate_pct, high_value_ids)"""
        seen_values: Dict[str, List[str]] = defaultdict(list)
        for ioc in iocs:
            val = ioc.get("value", ioc.get("ioc_value", "")).strip().lower()
            src = ioc.get("_source", ioc.get("source", "unknown"))
            if val:
                seen_values[val].append(src)

        total = len(iocs)
        unique = len(seen_values)
        dedup_rate = round((1 - unique / total) * 100, 2) if total > 0 else 0.0

        multi_source = sum(1 for sources in seen_values.values() if len(set(sources)) >= 2)
        multi_source_rate = round(multi_source / unique * 100, 2) if unique > 0 else 0.0

        # High-value: corroborated by 3+ sources
        high_value = [
            val for val, srcs in seen_values.items()
            if len(set(srcs)) >= 3
        ][:20]

        return unique, dedup_rate, multi_source_rate, high_value


class ContextualRichnessAnalyzer:
    """Measures what fraction of IOCs have contextual metadata."""

    CONTEXT_FIELDS = {"tags", "actor", "campaign", "malware_family", "technique",
                      "context", "provenance", "risk_score", "confidence"}

    def score_ioc(self, ioc: Dict) -> float:
        """0.0–1.0 richness score for a single IOC."""
        hit = sum(1 for f in self.CONTEXT_FIELDS if ioc.get(f))
        return round(hit / len(self.CONTEXT_FIELDS), 3)

    def analyze(self, iocs: List[Dict]) -> float:
        """Returns mean contextual richness % across all IOCs."""
        if not iocs:
            return 0.0
        scores = [self.score_ioc(ioc) for ioc in iocs]
        return round(sum(scores) / len(scores) * 100, 2)


class LifecycleAnalyzer:
    """Maps IOCs to lifecycle stages based on age."""

    # Days thresholds (from intel_memory_aging_engine)
    ACTIVE_DAYS = 30
    PERSISTENT_DAYS = 60
    AGING_DAYS = 90
    STALE_DAYS = 180

    def analyze(self, iocs: List[Dict]) -> LifecycleDistribution:
        dist = LifecycleDistribution()
        for ioc in iocs:
            # Prefer explicit lifecycle field
            lc = ioc.get("lifecycle_state", ioc.get("state", ""))
            if lc in ("ACTIVE", "PERSISTENT", "AGING", "STALE", "RETIRED"):
                setattr(dist, lc.lower(), getattr(dist, lc.lower()) + 1)
                continue

            # Derive from age
            date_str = ioc.get("last_seen", ioc.get("first_seen", ioc.get("_published", "")))
            age = _age_days(date_str)
            if age <= self.ACTIVE_DAYS:
                dist.active += 1
            elif age <= self.PERSISTENT_DAYS:
                dist.persistent += 1
            elif age <= self.AGING_DAYS:
                dist.aging += 1
            elif age <= self.STALE_DAYS:
                dist.stale += 1
            elif age < 999:
                dist.retired += 1
            else:
                dist.unknown += 1
        return dist


class TypeQualityAnalyzer:
    """Computes per-type quality scores."""

    def analyze(self, iocs: List[Dict]) -> List[IOCTypeQuality]:
        by_type: Dict[str, List[Dict]] = defaultdict(list)
        for ioc in iocs:
            t = str(ioc.get("type", ioc.get("ioc_type", "unknown"))).lower()
            by_type[t].append(ioc)

        ctx_analyzer = ContextualRichnessAnalyzer()
        results: List[IOCTypeQuality] = []

        for ioc_type, type_iocs in by_type.items():
            confidences = []
            ages = []
            multi_srcs = 0

            for ioc in type_iocs:
                c = ioc.get("confidence", ioc.get("confidence_score"))
                if c is not None:
                    try:
                        confidences.append(float(c))
                    except (TypeError, ValueError):
                        pass
                date_str = ioc.get("last_seen", ioc.get("first_seen", ioc.get("_published", "")))
                ages.append(_age_days(date_str))
                srcs = ioc.get("sources", [ioc.get("_source", "")])
                if isinstance(srcs, list) and len(set(srcs)) >= 2:
                    multi_srcs += 1

            mean_conf = sum(confidences) / len(confidences) if confidences else 0.0
            mean_age = sum(ages) / len(ages) if ages else 999.0
            ctx_rate = ctx_analyzer.analyze(type_iocs)
            multi_rate = round(multi_srcs / len(type_iocs) * 100, 2) if type_iocs else 0.0

            # Quality score: weighted combination
            fidelity_bonus = 20.0 if ioc_type in HIGH_FIDELITY_TYPES else (
                -10.0 if ioc_type in LOW_FIDELITY_TYPES else 0.0
            )
            age_penalty = min(30.0, mean_age / 10.0)  # up to -30 for old IOCs
            q_score = max(0.0, min(100.0,
                mean_conf * 0.4 + ctx_rate * 0.2 + multi_rate * 0.2 + fidelity_bonus - age_penalty + 30
            ))

            results.append(IOCTypeQuality(
                ioc_type=ioc_type,
                count=len(type_iocs),
                mean_confidence=round(mean_conf, 3),
                mean_age_days=round(mean_age, 1),
                contextual_rate_pct=ctx_rate,
                multi_source_rate_pct=multi_rate,
                quality_score=round(q_score, 2),
            ))

        return sorted(results, key=lambda x: x.count, reverse=True)


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class IOCQualityMetricsEngine:

    def __init__(self) -> None:
        self._unique = UniquenessAnalyzer()
        self._ctx = ContextualRichnessAnalyzer()
        self._lifecycle = LifecycleAnalyzer()
        self._type_qual = TypeQualityAnalyzer()

    def run_full_pipeline(
        self, advisories: Optional[List[Dict]] = None
    ) -> IOCQualityReport:
        t0 = time.time()
        report_id = f"ioc_qual_{_short_id(_now_iso())}"
        logger.info("[IOC-QUALITY] Starting IOC quality metrics run %s", report_id)

        # Load IOCs from advisories and memory
        all_iocs: List[Dict] = []
        if advisories is not None:
            all_iocs.extend(_extract_iocs_from_advisories(advisories))
        else:
            advisories = self._load_advisories()
            all_iocs.extend(_extract_iocs_from_advisories(advisories))

        memory_iocs = _extract_iocs_from_memory()
        all_iocs.extend(memory_iocs)

        if not all_iocs:
            logger.warning("[IOC-QUALITY] No IOCs found to analyze")

        # Run analyzers
        unique_count, dedup_rate, multi_src_rate, high_value = 0, 0.0, 0.0, []
        try:
            unique_count, dedup_rate, multi_src_rate, high_value = self._unique.analyze(all_iocs)
        except Exception as exc:
            logger.warning("[IOC-QUALITY] Uniqueness error: %s", exc)

        ctx_richness = 0.0
        try:
            ctx_richness = self._ctx.analyze(all_iocs)
        except Exception as exc:
            logger.warning("[IOC-QUALITY] Contextual richness error: %s", exc)

        lifecycle = LifecycleDistribution()
        try:
            lifecycle = self._lifecycle.analyze(all_iocs)
        except Exception as exc:
            logger.warning("[IOC-QUALITY] Lifecycle error: %s", exc)

        type_quality: List[IOCTypeQuality] = []
        try:
            type_quality = self._type_qual.analyze(all_iocs)
        except Exception as exc:
            logger.warning("[IOC-QUALITY] Type quality error: %s", exc)

        # Mean confidence across all IOCs
        confidences = []
        for ioc in all_iocs:
            c = ioc.get("confidence", ioc.get("confidence_score"))
            if c is not None:
                try:
                    confidences.append(float(c))
                except (TypeError, ValueError):
                    pass
        mean_conf = round(sum(confidences) / len(confidences), 3) if confidences else 0.0

        # High-fidelity rate
        hf_count = sum(
            1 for ioc in all_iocs
            if str(ioc.get("type", ioc.get("ioc_type", ""))).lower() in HIGH_FIDELITY_TYPES
        )
        hf_rate = round(hf_count / len(all_iocs) * 100, 2) if all_iocs else 0.0

        # Source trust
        source_trust = self._compute_source_trust(all_iocs)

        # Overall quality score
        q_score, q_tier = self._overall_quality(
            mean_conf, ctx_richness, hf_rate, multi_src_rate,
            dedup_rate, lifecycle.active_rate_pct
        )

        report = IOCQualityReport(
            report_id=report_id,
            generated_at=_now_iso(),
            total_iocs_analyzed=len(all_iocs),
            unique_ioc_count=unique_count,
            deduplication_rate_pct=dedup_rate,
            mean_confidence=mean_conf,
            mean_contextual_richness_pct=ctx_richness,
            high_fidelity_rate_pct=hf_rate,
            multi_source_rate_pct=multi_src_rate,
            lifecycle=lifecycle,
            type_quality=type_quality,
            source_trust_scores=source_trust,
            high_value_iocs=high_value,
            overall_quality_score=q_score,
            quality_tier=q_tier,
            duration_ms=round((time.time() - t0) * 1000, 2),
        )

        self._persist(report)
        logger.info(
            "[IOC-QUALITY] Run %s: total=%d unique=%d quality=%.1f tier=%s",
            report_id, len(all_iocs), unique_count, q_score, q_tier
        )
        return report

    def _compute_source_trust(self, iocs: List[Dict]) -> Dict[str, float]:
        source_iocs: Dict[str, List[Dict]] = defaultdict(list)
        for ioc in iocs:
            src = str(ioc.get("_source", ioc.get("source", "unknown"))).lower()
            source_iocs[src].append(ioc)

        result = {}
        for src, src_iocs in source_iocs.items():
            base_trust = SOURCE_TRUST_SCORES.get(src, SOURCE_TRUST_SCORES["default"])
            # Adjust by mean confidence of this source's IOCs
            confs = [float(i.get("confidence", 0.5)) for i in src_iocs
                    if i.get("confidence") is not None]
            if confs:
                mean_c = sum(confs) / len(confs)
                adjusted = (base_trust * 0.7 + mean_c * 0.3)
            else:
                adjusted = base_trust
            result[src] = round(adjusted, 4)
        return result

    def _overall_quality(
        self,
        mean_conf: float,
        ctx_richness: float,
        hf_rate: float,
        multi_src_rate: float,
        dedup_rate: float,
        active_rate: float,
    ) -> Tuple[float, str]:
        # mean_conf is 0-1 scale usually, normalize to 0-100
        conf_norm = mean_conf * 100 if mean_conf <= 1.0 else mean_conf
        score = (
            conf_norm * 0.25 +
            ctx_richness * 0.20 +
            hf_rate * 0.20 +
            multi_src_rate * 0.15 +
            (100 - dedup_rate) * 0.10 +  # lower dedup = more unique = better
            active_rate * 0.10
        )
        score = round(max(0.0, min(100.0, score)), 2)
        if score >= 80:
            tier = "EXCELLENT"
        elif score >= 65:
            tier = "GOOD"
        elif score >= 50:
            tier = "ACCEPTABLE"
        elif score >= 30:
            tier = "POOR"
        else:
            tier = "CRITICAL"
        return score, tier

    def _load_advisories(self) -> List[Dict]:
        conf_data = _load_json(INTEL_DIR / "explainable_confidence_scores.json")
        if isinstance(conf_data, list):
            return conf_data
        results: List[Dict] = []
        reports_dir = INTEL_DIR / "reports"
        if reports_dir.exists():
            for f in sorted(reports_dir.glob("*.json"))[-30:]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(d, dict):
                        results.append(d)
                    elif isinstance(d, list):
                        results.extend(d[:5])
                except Exception:
                    pass
        return results

    def _persist(self, report: IOCQualityReport) -> None:
        try:
            report_dict = asdict(report)
            _atomic_write(REPORT_PATH, report_dict)

            telem = {
                "report_id": report.report_id,
                "ts": report.generated_at,
                "total": report.total_iocs_analyzed,
                "unique": report.unique_ioc_count,
                "dedup_rate": report.deduplication_rate_pct,
                "mean_conf": report.mean_confidence,
                "ctx_richness": report.mean_contextual_richness_pct,
                "hf_rate": report.high_fidelity_rate_pct,
                "quality": report.overall_quality_score,
                "tier": report.quality_tier,
                "active_rate": report.lifecycle.active_rate_pct,
            }
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(telem) + "\n")
        except Exception as exc:
            logger.error("[IOC-QUALITY] Persist error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        report = _load_json(REPORT_PATH)
        if not report:
            return {"status": "no_report"}
        return {
            "status": "ok",
            "total": report.get("total_iocs_analyzed"),
            "unique": report.get("unique_ioc_count"),
            "quality": report.get("overall_quality_score"),
            "tier": report.get("quality_tier"),
            "active_rate": report.get("lifecycle", {}).get("active_rate_pct") if report.get("lifecycle") else None,
            "generated_at": report.get("generated_at"),
        }


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = IOCQualityMetricsEngine()
    result = engine.run_full_pipeline()
    print(f"\n[IOC-QUALITY] Report: {result.report_id}")
    print(f"  Total IOCs: {result.total_iocs_analyzed}  Unique: {result.unique_ioc_count}")
    print(f"  Quality: {result.overall_quality_score:.1f}  Tier: {result.quality_tier}")
    print(f"  HF Rate: {result.high_fidelity_rate_pct:.1f}%  "
          f"Multi-source: {result.multi_source_rate_pct:.1f}%")
    print(f"  Active IOCs: {result.lifecycle.active_rate_pct:.1f}%  "
          f"High-value (3+ src): {len(result.high_value_iocs)}")
    sys.exit(0 if result.quality_tier not in ("CRITICAL", "POOR") else 1)
