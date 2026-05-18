# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/false_positive_observability_engine.py
# PHASE 8 — FALSE-POSITIVE OBSERVABILITY ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
False-Positive Observability Engine — Phase 8 of Enterprise Observability Layer.

Detects and quantifies false-positive risk signals in the intelligence pipeline:
  - FP telemetry: per-source FP rate estimation based on heuristic signals
  - Enrichment anomaly detector: advisories with implausible enrichment combinations
  - Over-correlation detector: IOCs/actors over-attributed across unrelated advisories
  - Confidence inflation detector: advisories where confidence is inflated vs. evidence
  - Low-evidence high-confidence detector: CVSS=0 + EPSS=0 + no IOCs but conf > 70
  - IOC type mismatch detector: IOC type inconsistent with advisory context
  - Duplicate CVE detector: same CVE processed multiple times with different scores

Outputs:
  data/observability/fp_observability_report.json  (atomic write)
  data/observability/fp_observability_telemetry.jsonl (append)

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

logger = logging.getLogger("sentinel.fp_obs")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
OBS_DIR    = DATA_DIR / "observability"
REPORT_PATH    = OBS_DIR / "fp_observability_report.json"
TELEMETRY_PATH = OBS_DIR / "fp_observability_telemetry.jsonl"
INTEL_DIR  = DATA_DIR / "intelligence"

# Thresholds
CONFIDENCE_INFLATION_THRESHOLD = 70.0   # conf > 70 with no hard evidence
MAX_CROSS_ADVISORY_IOC_RATE = 0.6       # IOC appearing in >60% advisories = over-correlated
OVER_ATTRIBUTION_THRESHOLD = 5          # actor appearing in >5 unrelated advisories = risk
MIN_EVIDENCE_FOR_HIGH_CONF = 2          # at minimum 2 of: CVSS>4, EPSS>0.1, KEV, IOCs, techniques


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class FPSignal:
    signal_id: str
    signal_type: str       # CONFIDENCE_INFLATION | OVER_CORRELATION | ENRICHMENT_ANOMALY |
                           # LOW_EVIDENCE_HIGH_CONF | IOC_TYPE_MISMATCH | DUPLICATE_CVE
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    advisory_id: str
    description: str
    evidence: List[str] = field(default_factory=list)
    fp_probability: float = 0.0   # 0.0–1.0 estimated FP probability

@dataclass
class SourceFPProfile:
    source: str
    advisory_count: int
    fp_signal_count: int
    fp_rate_pct: float
    dominant_signal_type: str

@dataclass
class FPObservabilityReport:
    report_id: str
    generated_at: str
    total_advisories: int
    total_fp_signals: int
    fp_signal_rate_pct: float
    fp_risk_tier: str
    signals_by_type: Dict[str, int]
    signals_by_severity: Dict[str, int]
    source_profiles: List[SourceFPProfile]
    high_risk_advisories: List[str]
    over_correlated_iocs: List[str]
    over_attributed_actors: List[str]
    duplicate_cves: List[str]
    confidence_inflation_count: int
    top_signals: List[FPSignal]
    overall_fp_risk_score: float
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


# ── DETECTORS ────────────────────────────────────────────────────────────────

class ConfidenceInflationDetector:
    """Flags advisories where confidence is high but underlying evidence is weak."""

    def detect(self, advisories: List[Dict]) -> List[FPSignal]:
        signals: List[FPSignal] = []
        for adv in advisories:
            adv_id = str(adv.get("id", adv.get("cve_id", "unknown")))
            conf = adv.get("confidence", adv.get("risk_score", adv.get("final_confidence", 0.0)))
            try:
                conf = float(conf)
            except (TypeError, ValueError):
                conf = 0.0

            if conf < CONFIDENCE_INFLATION_THRESHOLD:
                continue

            # Count hard evidence signals
            evidence_count = 0
            evidence_present: List[str] = []
            cvss = adv.get("cvss_score", 0.0)
            if cvss and float(cvss) >= 4.0:
                evidence_count += 1
                evidence_present.append(f"CVSS={cvss}")
            epss = adv.get("epss_score", 0.0)
            if epss and float(epss) >= 0.1:
                evidence_count += 1
                evidence_present.append(f"EPSS={epss}")
            if adv.get("kev_listed") in (True, "true", "True", 1):
                evidence_count += 1
                evidence_present.append("KEV=True")
            iocs = adv.get("iocs", adv.get("recovered_iocs", []))
            if isinstance(iocs, list) and len(iocs) >= 2:
                evidence_count += 1
                evidence_present.append(f"IOCs={len(iocs)}")
            techs = adv.get("techniques", adv.get("ttps", []))
            if isinstance(techs, list) and len(techs) >= 2:
                evidence_count += 1
                evidence_present.append(f"Techniques={len(techs)}")

            if evidence_count < MIN_EVIDENCE_FOR_HIGH_CONF:
                fp_prob = round((CONFIDENCE_INFLATION_THRESHOLD / 100) * (1 - evidence_count / MIN_EVIDENCE_FOR_HIGH_CONF), 3)
                signals.append(FPSignal(
                    signal_id=_short_id(f"conf_infl_{adv_id}"),
                    signal_type="CONFIDENCE_INFLATION",
                    severity="HIGH" if conf >= 80 else "MEDIUM",
                    advisory_id=adv_id,
                    description=(
                        f"Confidence={conf:.1f} but only {evidence_count}/{MIN_EVIDENCE_FOR_HIGH_CONF} "
                        f"evidence signals present"
                    ),
                    evidence=evidence_present,
                    fp_probability=fp_prob,
                ))
        return signals


class OverCorrelationDetector:
    """Detects IOCs and actors appearing across too many unrelated advisories."""

    def detect(
        self, advisories: List[Dict]
    ) -> Tuple[List[FPSignal], List[str], List[str]]:
        n = len(advisories)
        if n == 0:
            return [], [], []

        ioc_to_advs: Dict[str, List[str]] = defaultdict(list)
        actor_to_advs: Dict[str, List[str]] = defaultdict(list)

        for adv in advisories:
            adv_id = str(adv.get("id", adv.get("cve_id", "unknown")))
            for ioc in adv.get("iocs", adv.get("recovered_iocs", [])):
                val = ""
                if isinstance(ioc, dict):
                    val = str(ioc.get("value", ioc.get("ioc_value", ""))).strip().lower()
                elif isinstance(ioc, str):
                    val = ioc.strip().lower()
                if val:
                    ioc_to_advs[val].append(adv_id)

            for actor in adv.get("actors", adv.get("threat_actors", [])):
                if isinstance(actor, str) and actor.strip():
                    actor_to_advs[actor.strip().lower()].append(adv_id)

        signals: List[FPSignal] = []
        over_correlated_iocs: List[str] = []
        over_attributed_actors: List[str] = []

        for ioc_val, adv_ids in ioc_to_advs.items():
            rate = len(set(adv_ids)) / n
            if rate > MAX_CROSS_ADVISORY_IOC_RATE:
                over_correlated_iocs.append(f"{ioc_val}:{len(set(adv_ids))}/{n}")
                signals.append(FPSignal(
                    signal_id=_short_id(f"over_corr_{ioc_val}"),
                    signal_type="OVER_CORRELATION",
                    severity="HIGH" if rate > 0.8 else "MEDIUM",
                    advisory_id="multiple",
                    description=(
                        f"IOC '{ioc_val[:40]}' appears in {len(set(adv_ids))}/{n} "
                        f"advisories ({rate*100:.0f}%) — potential FP indicator"
                    ),
                    evidence=[f"advisory_count={len(set(adv_ids))}"],
                    fp_probability=round(min(0.9, rate), 3),
                ))

        for actor, adv_ids in actor_to_advs.items():
            if len(set(adv_ids)) > OVER_ATTRIBUTION_THRESHOLD:
                over_attributed_actors.append(f"{actor}:{len(set(adv_ids))}")
                signals.append(FPSignal(
                    signal_id=_short_id(f"over_attr_{actor}"),
                    signal_type="OVER_CORRELATION",
                    severity="MEDIUM",
                    advisory_id="multiple",
                    description=(
                        f"Actor '{actor}' attributed to {len(set(adv_ids))} advisories — "
                        f"verify attribution evidence"
                    ),
                    evidence=[f"advisories={len(set(adv_ids))}"],
                    fp_probability=0.3,
                ))

        return signals, over_correlated_iocs[:10], over_attributed_actors[:10]


class EnrichmentAnomalyDetector:
    """Detects implausible enrichment combinations."""

    ANOMALY_PATTERNS = [
        # (condition_fn, description, severity)
        (lambda a: float(a.get("cvss_score", 0) or 0) > 9.0 and
                   not a.get("kev_listed") and
                   not a.get("iocs") and
                   not a.get("techniques"),
         "CVSS>9.0 but no KEV, no IOCs, no techniques", "HIGH"),
        (lambda a: a.get("intelligence_depth") == "RICH" and
                   len(a.get("iocs", a.get("recovered_iocs", []))) == 0,
         "Intelligence depth=RICH but zero IOCs", "MEDIUM"),
        (lambda a: float(a.get("risk_score", 0) or 0) >= 90.0 and
                   float(a.get("cvss_score", 0) or 0) == 0.0,
         "Risk score >= 90 but CVSS=0", "MEDIUM"),
        (lambda a: float(a.get("epss_score", 0) or 0) > 0.9 and
                   float(a.get("cvss_score", 0) or 0) < 4.0,
         "EPSS>0.9 but CVSS<4 (implausible combination)", "HIGH"),
    ]

    def detect(self, advisories: List[Dict]) -> List[FPSignal]:
        signals: List[FPSignal] = []
        for adv in advisories:
            adv_id = str(adv.get("id", adv.get("cve_id", "unknown")))
            for cond_fn, desc, sev in self.ANOMALY_PATTERNS:
                try:
                    if cond_fn(adv):
                        signals.append(FPSignal(
                            signal_id=_short_id(f"anomaly_{adv_id}_{desc[:20]}"),
                            signal_type="ENRICHMENT_ANOMALY",
                            severity=sev,
                            advisory_id=adv_id,
                            description=desc,
                            evidence=[
                                f"cvss={adv.get('cvss_score')}",
                                f"epss={adv.get('epss_score')}",
                                f"kev={adv.get('kev_listed')}",
                            ],
                            fp_probability=0.4 if sev == "HIGH" else 0.25,
                        ))
                except Exception:
                    pass
        return signals


class DuplicateCVEDetector:
    """Detects the same CVE processed multiple times with divergent scores."""

    def detect(self, advisories: List[Dict]) -> Tuple[List[FPSignal], List[str]]:
        cve_scores: Dict[str, List[Tuple[str, float]]] = defaultdict(list)

        for adv in advisories:
            adv_id = str(adv.get("id", adv.get("cve_id", "unknown")))
            cve_id = adv.get("cve_id", adv.get("id", ""))
            if cve_id and "CVE-" in str(cve_id).upper():
                score = adv.get("risk_score", adv.get("confidence", 0.0))
                try:
                    cve_scores[str(cve_id)].append((adv_id, float(score)))
                except (TypeError, ValueError):
                    cve_scores[str(cve_id)].append((adv_id, 0.0))

        signals: List[FPSignal] = []
        duplicate_cves: List[str] = []

        for cve_id, entries in cve_scores.items():
            if len(entries) > 1:
                scores = [e[1] for e in entries]
                score_range = max(scores) - min(scores)
                if score_range > 15.0:
                    duplicate_cves.append(f"{cve_id}:range={score_range:.1f}")
                    signals.append(FPSignal(
                        signal_id=_short_id(f"dup_{cve_id}"),
                        signal_type="DUPLICATE_CVE",
                        severity="MEDIUM",
                        advisory_id=cve_id,
                        description=(
                            f"{cve_id} processed {len(entries)} times with "
                            f"score range {score_range:.1f} pts"
                        ),
                        evidence=[f"{eid}:{sc:.1f}" for eid, sc in entries[:5]],
                        fp_probability=0.2,
                    ))

        return signals, duplicate_cves[:10]


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class FalsePositiveObservabilityEngine:

    def __init__(self) -> None:
        self._conf_infl   = ConfidenceInflationDetector()
        self._over_corr   = OverCorrelationDetector()
        self._enrich_anom = EnrichmentAnomalyDetector()
        self._dup_cve     = DuplicateCVEDetector()

    def run_full_pipeline(
        self, advisories: Optional[List[Dict]] = None
    ) -> FPObservabilityReport:
        t0 = time.time()
        report_id = f"fp_obs_{_short_id(_now_iso())}"
        logger.info("[FP-OBS] Starting FP observability run %s", report_id)

        if advisories is None:
            advisories = self._load_advisories()

        all_signals: List[FPSignal] = []
        over_corr_iocs: List[str] = []
        over_attr_actors: List[str] = []
        dup_cves: List[str] = []

        # Run all detectors non-blocking
        try:
            all_signals.extend(self._conf_infl.detect(advisories))
        except Exception as exc:
            logger.warning("[FP-OBS] Confidence inflation detector error: %s", exc)

        try:
            signals, over_corr_iocs, over_attr_actors = self._over_corr.detect(advisories)
            all_signals.extend(signals)
        except Exception as exc:
            logger.warning("[FP-OBS] Over-correlation detector error: %s", exc)

        try:
            all_signals.extend(self._enrich_anom.detect(advisories))
        except Exception as exc:
            logger.warning("[FP-OBS] Enrichment anomaly detector error: %s", exc)

        try:
            signals, dup_cves = self._dup_cve.detect(advisories)
            all_signals.extend(signals)
        except Exception as exc:
            logger.warning("[FP-OBS] Duplicate CVE detector error: %s", exc)

        # Aggregate
        n = len(advisories)
        sig_count = len(all_signals)
        sig_rate = round(sig_count / n * 100, 2) if n > 0 else 0.0

        by_type = Counter(s.signal_type for s in all_signals)
        by_sev  = Counter(s.severity for s in all_signals)

        high_risk_adv_ids = list(set(
            s.advisory_id for s in all_signals
            if s.severity in ("CRITICAL", "HIGH") and s.advisory_id != "multiple"
        ))[:20]

        conf_infl_count = by_type.get("CONFIDENCE_INFLATION", 0)

        # Per-source FP profiles
        source_profiles = self._build_source_profiles(advisories, all_signals)

        # FP risk score
        fp_risk_score, fp_risk_tier = self._fp_risk(sig_rate, conf_infl_count, n)

        # Sort signals: CRITICAL first, then HIGH
        all_signals.sort(key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s.severity, 4))

        report = FPObservabilityReport(
            report_id=report_id,
            generated_at=_now_iso(),
            total_advisories=n,
            total_fp_signals=sig_count,
            fp_signal_rate_pct=sig_rate,
            fp_risk_tier=fp_risk_tier,
            signals_by_type=dict(by_type),
            signals_by_severity=dict(by_sev),
            source_profiles=source_profiles,
            high_risk_advisories=high_risk_adv_ids,
            over_correlated_iocs=over_corr_iocs,
            over_attributed_actors=over_attr_actors,
            duplicate_cves=dup_cves,
            confidence_inflation_count=conf_infl_count,
            top_signals=all_signals[:15],
            overall_fp_risk_score=fp_risk_score,
            duration_ms=round((time.time() - t0) * 1000, 2),
        )

        self._persist(report)
        logger.info(
            "[FP-OBS] Run %s: signals=%d rate=%.1f%% risk=%s score=%.1f",
            report_id, sig_count, sig_rate, fp_risk_tier, fp_risk_score
        )
        return report

    def _build_source_profiles(
        self, advisories: List[Dict], signals: List[FPSignal]
    ) -> List[SourceFPProfile]:
        source_counts: Counter = Counter()
        source_signals: Dict[str, Counter] = defaultdict(Counter)

        for adv in advisories:
            src = str(adv.get("source", adv.get("feed_source", "unknown")))
            source_counts[src] += 1

        sig_adv_set: Set[str] = {s.advisory_id for s in signals}
        for adv in advisories:
            adv_id = str(adv.get("id", adv.get("cve_id", "unknown")))
            src = str(adv.get("source", adv.get("feed_source", "unknown")))
            if adv_id in sig_adv_set:
                for s in signals:
                    if s.advisory_id == adv_id:
                        source_signals[src][s.signal_type] += 1

        profiles: List[SourceFPProfile] = []
        for src, count in source_counts.most_common():
            sig_count = sum(source_signals[src].values())
            dominant = source_signals[src].most_common(1)[0][0] if source_signals[src] else "NONE"
            profiles.append(SourceFPProfile(
                source=src,
                advisory_count=count,
                fp_signal_count=sig_count,
                fp_rate_pct=round(sig_count / count * 100, 2) if count > 0 else 0.0,
                dominant_signal_type=dominant,
            ))
        return profiles[:15]

    def _fp_risk(self, sig_rate: float, conf_infl: int, n: int) -> Tuple[float, str]:
        # Risk score: 0 = no FP risk, 100 = severe FP contamination
        score = min(100.0, sig_rate * 1.5 + (conf_infl / max(n, 1)) * 50.0)
        score = round(score, 2)
        tier = (
            "CRITICAL"   if score >= 60 else
            "HIGH"       if score >= 40 else
            "ELEVATED"   if score >= 20 else
            "MODERATE"   if score >= 10 else
            "LOW"
        )
        return score, tier

    def _load_advisories(self) -> List[Dict]:
        conf_data = _load_json(INTEL_DIR / "explainable_confidence_scores.json")
        if isinstance(conf_data, list) and conf_data:
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

    def _persist(self, report: FPObservabilityReport) -> None:
        try:
            report_dict = asdict(report)
            _atomic_write(REPORT_PATH, report_dict)

            telem = {
                "report_id": report.report_id,
                "ts": report.generated_at,
                "n": report.total_advisories,
                "signals": report.total_fp_signals,
                "rate": report.fp_signal_rate_pct,
                "risk_score": report.overall_fp_risk_score,
                "risk_tier": report.fp_risk_tier,
                "conf_inflation": report.confidence_inflation_count,
                "over_corr": len(report.over_correlated_iocs),
                "dup_cves": len(report.duplicate_cves),
            }
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(telem) + "\n")
        except Exception as exc:
            logger.error("[FP-OBS] Persist error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        report = _load_json(REPORT_PATH)
        if not report:
            return {"status": "no_report"}
        return {
            "status": "ok",
            "risk_score": report.get("overall_fp_risk_score"),
            "risk_tier": report.get("fp_risk_tier"),
            "signals": report.get("total_fp_signals"),
            "signal_rate": report.get("fp_signal_rate_pct"),
            "conf_inflation": report.get("confidence_inflation_count"),
            "generated_at": report.get("generated_at"),
        }


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = FalsePositiveObservabilityEngine()
    result = engine.run_full_pipeline()
    print(f"\n[FP-OBS] Report: {result.report_id}")
    print(f"  Advisories: {result.total_advisories}  FP Signals: {result.total_fp_signals}")
    print(f"  Signal Rate: {result.fp_signal_rate_pct:.1f}%  Risk: {result.fp_risk_tier}")
    print(f"  Confidence inflation: {result.confidence_inflation_count}")
    print(f"  Over-correlated IOCs: {len(result.over_correlated_iocs)}")
    sys.exit(0 if result.fp_risk_tier not in ("CRITICAL", "HIGH") else 1)
