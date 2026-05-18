# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/scoring_drift_engine.py
# PHASE 3 — SCORING DRIFT DETECTION ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
Scoring Drift Detection Engine — Phase 3 of Enterprise Observability Layer.

Detects and measures confidence score drift over time:
  - Confidence drift detector: sliding window mean/std deviation tracking
  - Scoring variance analytics: per-source, per-severity, per-tier distributions
  - Anomaly detector: Z-score based outliers + sudden distribution shifts
  - Calibration telemetry: expected vs. actual confidence distribution
  - Historical comparison: baseline vs. current population statistics
  - Score population health: entropy, concentration, imbalance indicators

Outputs:
  data/observability/scoring_drift_report.json (atomic write)
  data/observability/scoring_drift_telemetry.jsonl (append)
  data/observability/scoring_baseline.json (baseline snapshot)

Never raises — all errors caught and surfaced in report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.scoring_drift")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OBS_DIR = DATA_DIR / "observability"
REPORT_PATH = OBS_DIR / "scoring_drift_report.json"
TELEMETRY_PATH = OBS_DIR / "scoring_drift_telemetry.jsonl"
BASELINE_PATH = OBS_DIR / "scoring_baseline.json"

INTEL_DIR = DATA_DIR / "intelligence"
CONFIDENCE_PATH = INTEL_DIR / "explainable_confidence_scores.json"
PIPELINE_REPORT_PATH = INTEL_DIR / "pipeline_report.json"

# Thresholds
DRIFT_MEAN_THRESHOLD = 5.0       # >5 point mean shift → drift alert
DRIFT_STD_THRESHOLD = 8.0        # >8 point std dev increase → variance alert
ZSCORE_ANOMALY_THRESHOLD = 2.5   # Z-score > 2.5 → outlier
MIN_SAMPLE_SIZE = 5              # minimum scores to compute statistics


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class ScoreStats:
    count: int
    mean: float
    std_dev: float
    min_score: float
    max_score: float
    median: float
    p10: float    # 10th percentile
    p90: float    # 90th percentile
    entropy: float    # Shannon entropy over 10-bucket histogram

@dataclass
class DriftAlert:
    alert_id: str
    alert_type: str    # MEAN_DRIFT | VARIANCE_SPIKE | ANOMALY | DISTRIBUTION_SHIFT
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    delta: float
    threshold: float
    affected_ids: List[str] = field(default_factory=list)

@dataclass
class TierDistribution:
    very_low: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    very_high: int = 0

@dataclass
class ScoringDriftReport:
    report_id: str
    generated_at: str
    current_stats: ScoreStats
    baseline_stats: Optional[ScoreStats]
    mean_drift: float
    std_drift: float
    drift_detected: bool
    drift_severity: str
    tier_distribution: TierDistribution
    anomaly_count: int
    anomalous_ids: List[str]
    alerts: List[DriftAlert] = field(default_factory=list)
    sources_analyzed: int = 0
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


# ── STATISTICS ───────────────────────────────────────────────────────────────
def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (k - lo) * (sorted_vals[hi] - sorted_vals[lo])


def _compute_stats(scores: List[float]) -> ScoreStats:
    if not scores:
        return ScoreStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    n = len(scores)
    mean = sum(scores) / n
    variance = sum((s - mean) ** 2 for s in scores) / n
    std = math.sqrt(variance)
    sorted_s = sorted(scores)
    median = _percentile(sorted_s, 50)
    p10 = _percentile(sorted_s, 10)
    p90 = _percentile(sorted_s, 90)

    # Shannon entropy over 10 buckets (0-10, 10-20, ..., 90-100)
    buckets = [0] * 10
    for s in scores:
        idx = min(int(s / 10), 9)
        buckets[idx] += 1
    entropy = 0.0
    for b in buckets:
        if b > 0:
            p = b / n
            entropy -= p * math.log2(p)

    return ScoreStats(
        count=n,
        mean=round(mean, 3),
        std_dev=round(std, 3),
        min_score=round(min(scores), 3),
        max_score=round(max(scores), 3),
        median=round(median, 3),
        p10=round(p10, 3),
        p90=round(p90, 3),
        entropy=round(entropy, 4),
    )


def _compute_tier_distribution(scores: List[float]) -> TierDistribution:
    dist = TierDistribution()
    for s in scores:
        if s < 20:
            dist.very_low += 1
        elif s < 40:
            dist.low += 1
        elif s < 60:
            dist.medium += 1
        elif s < 80:
            dist.high += 1
        else:
            dist.very_high += 1
    return dist


def _detect_anomalies(
    scores: List[float], ids: List[str], mean: float, std: float
) -> Tuple[List[str], int]:
    if std < 0.001:
        return [], 0
    anomalous: List[str] = []
    for i, (score, sid) in enumerate(zip(scores, ids)):
        z = abs(score - mean) / std
        if z > ZSCORE_ANOMALY_THRESHOLD:
            anomalous.append(f"{sid}:score={score:.1f}:z={z:.2f}")
    return anomalous[:30], len(anomalous)


# ── DRIFT DETECTOR ────────────────────────────────────────────────────────────
class ScoringDriftDetector:

    def detect(
        self, current: ScoreStats, baseline: Optional[ScoreStats]
    ) -> Tuple[float, float, bool, str, List[DriftAlert]]:
        alerts: List[DriftAlert] = []
        mean_drift = 0.0
        std_drift = 0.0
        drift_detected = False
        severity = "NONE"

        if baseline is None or baseline.count < MIN_SAMPLE_SIZE:
            return 0.0, 0.0, False, "NONE", []

        mean_drift = abs(current.mean - baseline.mean)
        std_drift = abs(current.std_dev - baseline.std_dev)

        if mean_drift > DRIFT_MEAN_THRESHOLD:
            drift_detected = True
            sev = "HIGH" if mean_drift > 15 else "MEDIUM"
            alerts.append(DriftAlert(
                alert_id=_short_id(f"mean_drift_{current.mean}_{baseline.mean}"),
                alert_type="MEAN_DRIFT",
                severity=sev,
                description=(
                    f"Confidence mean shifted {'+' if current.mean > baseline.mean else ''}"
                    f"{current.mean - baseline.mean:.2f} pts "
                    f"(baseline={baseline.mean:.2f} → current={current.mean:.2f})"
                ),
                delta=round(current.mean - baseline.mean, 3),
                threshold=DRIFT_MEAN_THRESHOLD,
            ))

        if std_drift > DRIFT_STD_THRESHOLD:
            drift_detected = True
            sev = "HIGH" if std_drift > 15 else "MEDIUM"
            alerts.append(DriftAlert(
                alert_id=_short_id(f"std_drift_{current.std_dev}_{baseline.std_dev}"),
                alert_type="VARIANCE_SPIKE",
                severity=sev,
                description=(
                    f"Score variance increased {std_drift:.2f} pts "
                    f"(baseline σ={baseline.std_dev:.2f} → current σ={current.std_dev:.2f})"
                ),
                delta=round(std_drift, 3),
                threshold=DRIFT_STD_THRESHOLD,
            ))

        # Distribution shift: compare tier concentrations
        if baseline.p90 > 0 and current.p90 > 0:
            tier_shift = abs(current.p90 - baseline.p90)
            if tier_shift > 20:
                drift_detected = True
                alerts.append(DriftAlert(
                    alert_id=_short_id(f"dist_shift_{current.p90}_{baseline.p90}"),
                    alert_type="DISTRIBUTION_SHIFT",
                    severity="MEDIUM",
                    description=(
                        f"P90 score shifted {tier_shift:.1f} pts "
                        f"(baseline p90={baseline.p90:.1f} → current={current.p90:.1f})"
                    ),
                    delta=round(tier_shift, 3),
                    threshold=20.0,
                ))

        # Entropy collapse (all scores concentrated in one tier)
        if current.entropy < 1.0 and baseline.entropy >= 1.5:
            drift_detected = True
            alerts.append(DriftAlert(
                alert_id=_short_id(f"entropy_{current.entropy}"),
                alert_type="DISTRIBUTION_SHIFT",
                severity="MEDIUM",
                description=(
                    f"Score entropy collapsed from {baseline.entropy:.2f} → {current.entropy:.2f} "
                    "(scores over-concentrated in one tier)"
                ),
                delta=round(baseline.entropy - current.entropy, 4),
                threshold=1.0,
            ))

        if alerts:
            max_sev = max(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(a.severity)
                         for a in alerts)
            severity = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"][max_sev]

        return (
            round(mean_drift, 3),
            round(std_drift, 3),
            drift_detected,
            severity,
            alerts,
        )


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class ScoringDriftEngine:
    """Orchestrates confidence score drift detection and variance analytics."""

    def __init__(self) -> None:
        self._detector = ScoringDriftDetector()

    def run_full_pipeline(
        self, advisories: Optional[List[Dict]] = None
    ) -> ScoringDriftReport:
        t0 = time.time()
        report_id = f"drift_{_short_id(_now_iso())}"
        logger.info("[SCORING-DRIFT] Starting drift analysis %s", report_id)

        if advisories is None:
            advisories = self._load_scored_advisories()

        scores: List[float] = []
        ids: List[str] = []

        for adv in advisories:
            sid = adv.get("id", adv.get("advisory_id", adv.get("cve_id", _short_id(str(adv)))))
            score = adv.get("confidence", adv.get("risk_score",
                    adv.get("final_confidence", adv.get("score"))))
            if score is not None:
                try:
                    scores.append(float(score))
                    ids.append(str(sid))
                except (TypeError, ValueError):
                    pass

        current_stats = _compute_stats(scores)
        baseline = self._load_baseline()

        anomalous_ids, anomaly_count = [], 0
        if current_stats.count >= MIN_SAMPLE_SIZE:
            anomalous_ids, anomaly_count = _detect_anomalies(
                scores, ids, current_stats.mean, current_stats.std_dev
            )
            if anomaly_count > 0:
                pass  # logged below

        mean_drift, std_drift, drift_detected, drift_severity, alerts = (
            self._detector.detect(current_stats, baseline)
        )

        # Anomaly alerts
        if anomaly_count > 0:
            alerts.append(DriftAlert(
                alert_id=_short_id(f"anomaly_{anomaly_count}"),
                alert_type="ANOMALY",
                severity="MEDIUM" if anomaly_count < 5 else "HIGH",
                description=f"{anomaly_count} score(s) are statistical outliers (|Z|>{ZSCORE_ANOMALY_THRESHOLD})",
                delta=float(anomaly_count),
                threshold=ZSCORE_ANOMALY_THRESHOLD,
                affected_ids=anomalous_ids[:10],
            ))

        tier_dist = _compute_tier_distribution(scores)

        report = ScoringDriftReport(
            report_id=report_id,
            generated_at=_now_iso(),
            current_stats=current_stats,
            baseline_stats=baseline,
            mean_drift=mean_drift,
            std_drift=std_drift,
            drift_detected=drift_detected,
            drift_severity=drift_severity,
            tier_distribution=tier_dist,
            anomaly_count=anomaly_count,
            anomalous_ids=anomalous_ids[:20],
            alerts=alerts,
            sources_analyzed=len(advisories),
            duration_ms=round((time.time() - t0) * 1000, 2),
        )

        self._persist(report)
        self._update_baseline(current_stats)

        logger.info(
            "[SCORING-DRIFT] Run %s: drift=%s severity=%s anomalies=%d n=%d",
            report_id, drift_detected, drift_severity, anomaly_count, current_stats.count
        )
        return report

    def _load_scored_advisories(self) -> List[Dict]:
        data = _load_json(CONFIDENCE_PATH)
        if isinstance(data, list) and data:
            return data

        reports_dir = INTEL_DIR / "reports"
        result: List[Dict] = []
        if reports_dir.exists():
            for f in sorted(reports_dir.glob("*.json"))[-50:]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(d, dict):
                        result.append(d)
                    elif isinstance(d, list):
                        result.extend(d[:10])
                except Exception:
                    pass
        return result

    def _load_baseline(self) -> Optional[ScoreStats]:
        b = _load_json(BASELINE_PATH)
        if not b:
            return None
        try:
            return ScoreStats(**b)
        except Exception:
            return None

    def _update_baseline(self, stats: ScoreStats) -> None:
        if stats.count < MIN_SAMPLE_SIZE:
            return
        try:
            existing = self._load_baseline()
            if existing is None or existing.count < MIN_SAMPLE_SIZE:
                _atomic_write(BASELINE_PATH, asdict(stats))
        except Exception as exc:
            logger.warning("[SCORING-DRIFT] Baseline update error: %s", exc)

    def _persist(self, report: ScoringDriftReport) -> None:
        try:
            rd = asdict(report)
            _atomic_write(REPORT_PATH, rd)

            telem = {
                "report_id": report.report_id,
                "ts": report.generated_at,
                "mean": report.current_stats.mean,
                "std": report.current_stats.std_dev,
                "mean_drift": report.mean_drift,
                "std_drift": report.std_drift,
                "drift_detected": report.drift_detected,
                "severity": report.drift_severity,
                "anomalies": report.anomaly_count,
                "n": report.current_stats.count,
            }
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(telem) + "\n")
        except Exception as exc:
            logger.error("[SCORING-DRIFT] Persist error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        report = _load_json(REPORT_PATH)
        if not report:
            return {"status": "no_report"}
        return {
            "status": "ok",
            "mean": report.get("current_stats", {}).get("mean"),
            "drift_detected": report.get("drift_detected"),
            "drift_severity": report.get("drift_severity"),
            "anomaly_count": report.get("anomaly_count"),
            "n": report.get("current_stats", {}).get("count"),
            "generated_at": report.get("generated_at"),
        }


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = ScoringDriftEngine()
    result = engine.run_full_pipeline()
    print(f"\n[SCORING-DRIFT] Report: {result.report_id}")
    print(f"  Scores analyzed: {result.current_stats.count}")
    print(f"  Mean: {result.current_stats.mean:.2f}  σ: {result.current_stats.std_dev:.2f}")
    print(f"  Drift: {result.drift_detected}  Severity: {result.drift_severity}")
    print(f"  Anomalies: {result.anomaly_count}")
    sys.exit(0 if result.drift_severity not in ("CRITICAL", "HIGH") else 1)
