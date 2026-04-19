#!/usr/bin/env python3
"""
anomaly_detector.py — CYBERDUDEBIVASH® SENTINEL APEX v123.0.0
════════════════════════════════════════════════════════════════════════════════
Unknown Threat Detection Engine

Detects anomalous/novel threats in the intel feed using Isolation Forest
and statistical outlier detection. Flags threats that don't fit known patterns.

Rule-based fallback when baseline corpus is unavailable.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import logging
import math
import statistics
import threading
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("CDB-ANOMALY-DETECTOR")

# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

ISOLATION_FOREST_CONTAMINATION = 0.08   # ~8% of baseline assumed anomalous
ISOLATION_FOREST_N_ESTIMATORS = 120
ISOLATION_FOREST_MAX_SAMPLES = "auto"

# Anomaly score threshold: sklearn IF scores < SCORE_THRESHOLD → anomaly
ANOMALY_SCORE_THRESHOLD = -0.05

# Minimum baseline items before training
MIN_BASELINE_ITEMS = 5

# Temporal spike detection sensitivity
SPIKE_ZSCORE_THRESHOLD = 2.5
SPIKE_VOLUME_MULTIPLIER = 3.0

# 0-day heuristic indicators
ZERO_DAY_NO_CVE_SEVERITY_THRESHOLD = 7.0
ZERO_DAY_RAPID_IOC_COUNT = 10
ZERO_DAY_CONF_HIGH = 0.85
ZERO_DAY_CONF_MEDIUM = 0.55

FEATURE_NAMES = [
    "cvss_score_norm",
    "epss_score",
    "kev_present",
    "ttp_count_norm",
    "ioc_count_norm",
    "exploit_maturity_score",
    "source_entropy",
    "sector_encoded",
    "has_cve",
    "actor_known",
    "severity_int_norm",
]


# ════════════════════════════════════════════════════════════════════════════════
# FEATURE ENGINEERING
# ════════════════════════════════════════════════════════════════════════════════

def _safe_float(value: Any, default: float = 0.0, lo: float = 0.0, hi: float = 1.0) -> float:
    try:
        v = float(value)
        return max(lo, min(hi, v))
    except (TypeError, ValueError):
        return default


EXPLOIT_MATURITY_MAP: Dict[str, float] = {
    "not_defined": 0.0, "unproven": 0.10, "poc": 0.35,
    "functional": 0.65, "high": 0.85, "active": 1.00,
    "weaponized": 1.00, "in_the_wild": 1.00,
}

KNOWN_ACTORS = {
    "apt28", "apt29", "apt41", "lazarus", "fin7", "conti", "lockbit",
    "blackcat", "revil", "cozy bear", "fancy bear", "carbanak", "turla",
    "sandworm", "darkside", "cl0p", "alphv", "scattered spider",
}

SECTOR_ENCODING: Dict[str, float] = {
    "healthcare": 0.90, "finance": 0.92, "energy": 0.95,
    "government": 0.93, "defense": 0.97, "critical_infrastructure": 0.98,
    "education": 0.65, "retail": 0.70, "manufacturing": 0.75,
    "technology": 0.80, "telecom": 0.82, "transportation": 0.78,
    "unknown": 0.50, "": 0.50,
}


def _exploit_maturity_score(item: dict) -> float:
    raw = str(item.get("exploit_maturity", "")).lower().replace(" ", "_").replace("-", "_")
    for key, score in EXPLOIT_MATURITY_MAP.items():
        if key and key in raw:
            return score
    if any(k in raw for k in ("wild", "active", "weapon")):
        return 1.00
    if "poc" in raw or "proof" in raw:
        return 0.35
    return 0.10


def _has_cve(item: dict) -> float:
    cve_id = str(item.get("cve_id", item.get("id", item.get("vulnerability_id", ""))))
    return 1.0 if cve_id.upper().startswith("CVE-") else 0.0


def _actor_known(item: dict) -> float:
    actor = str(item.get("actor", item.get("threat_actor", ""))).lower()
    for name in KNOWN_ACTORS:
        if name in actor:
            return 1.0
    return 0.0


def _source_entropy(item: dict) -> float:
    """Shannon entropy of the source string as a novelty proxy (normalised to [0,1])."""
    source = str(item.get("source", item.get("feed_source", "unknown")))
    if not source:
        return 0.5
    counts = Counter(source.lower())
    total = len(source)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
    return min(1.0, entropy / 5.0)  # normalise — typical entropy ~3-4 bits


def _severity_int_norm(item: dict) -> float:
    raw = str(item.get("severity", item.get("risk_level", "low"))).lower()
    m = {"critical": 1.0, "high": 0.75, "medium": 0.50, "low": 0.25,
         "informational": 0.0, "info": 0.0}
    for k, v in m.items():
        if k in raw:
            return v
    cvss = _safe_float(item.get("cvss_score", 0.0), 0.0, 0.0, 10.0)
    return cvss / 10.0


def _ttp_count_norm(item: dict) -> float:
    ttps = item.get("ttps", item.get("techniques", item.get("mitre_techniques", [])))
    if isinstance(ttps, (list, set, tuple)):
        return min(float(len(ttps)), 30.0) / 30.0
    if isinstance(ttps, str):
        return min(float(len(ttps.split(","))), 30.0) / 30.0
    return 0.0


def _ioc_count_norm(item: dict) -> float:
    iocs = item.get("iocs", item.get("indicators", []))
    if isinstance(iocs, (list, set, tuple)):
        return min(float(len(iocs)), 100.0) / 100.0
    return 0.0


def _sector_encoded(item: dict) -> float:
    sector = str(item.get("sector", item.get("industry", ""))).lower().replace(" ", "_")
    for key, val in SECTOR_ENCODING.items():
        if key and key in sector:
            return val
    return 0.50


def build_feature_vector(item: dict) -> np.ndarray:
    """Extract normalised feature vector for anomaly detection."""
    fv = np.array([
        _safe_float(item.get("cvss_score", item.get("cvss", 0.0)), 0.0, 0.0, 10.0) / 10.0,
        _safe_float(item.get("epss_score", item.get("epss", 0.0)), 0.0, 0.0, 1.0),
        1.0 if item.get("kev", item.get("in_kev", item.get("kev_present", False))) else 0.0,
        _ttp_count_norm(item),
        _ioc_count_norm(item),
        _exploit_maturity_score(item),
        _source_entropy(item),
        _sector_encoded(item),
        _has_cve(item),
        _actor_known(item),
        _severity_int_norm(item),
    ], dtype=np.float64)
    return fv


# ════════════════════════════════════════════════════════════════════════════════
# BASELINE STATISTICS
# ════════════════════════════════════════════════════════════════════════════════

class _BaselineStats:
    """Stores per-feature mean/std for statistical outlier detection."""

    def __init__(self) -> None:
        self.means: Optional[np.ndarray] = None
        self.stds: Optional[np.ndarray] = None
        self.fitted = False

    def fit(self, X: np.ndarray) -> None:
        self.means = np.mean(X, axis=0)
        self.stds = np.std(X, axis=0)
        # Avoid division by zero
        self.stds = np.where(self.stds < 1e-8, 1e-8, self.stds)
        self.fitted = True

    def z_scores(self, fv: np.ndarray) -> np.ndarray:
        if not self.fitted:
            return np.zeros(len(fv))
        return np.abs((fv - self.means) / self.stds)

    def mahalanobis_approx(self, fv: np.ndarray) -> float:
        """Simplified diagonal Mahalanobis (ignores covariance)."""
        if not self.fitted:
            return 0.0
        z = self.z_scores(fv)
        return float(np.sqrt(np.sum(z ** 2)))


# ════════════════════════════════════════════════════════════════════════════════
# MAIN CLASS
# ════════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Detects anomalous/novel threats in the intel feed using Isolation Forest
    and statistical outlier detection.

    Fully functional from first instantiation — rule-based fallback when
    baseline is not yet fitted.  Thread-safe via internal RLock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._iso_forest = None       # IsolationForest or None
        self._fitted = False
        self._baseline_stats = _BaselineStats()
        self._baseline_size = 0
        self._baseline_vectors: Optional[np.ndarray] = None  # kept for novelty scoring
        # Rolling window for temporal anomaly detection
        self._temporal_window: deque = deque(maxlen=2000)
        logger.info("AnomalyDetector initialised.")

    # ── fit ───────────────────────────────────────────────────────────────────

    def fit(self, baseline_items: List[dict]) -> None:
        """
        Train Isolation Forest on normal intel feed patterns.
        Also compute baseline statistics for statistical tests.
        Requires at least MIN_BASELINE_ITEMS items.
        """
        if len(baseline_items) < MIN_BASELINE_ITEMS:
            logger.warning(
                "Baseline has %d items (min %d). Using rule-based fallback.",
                len(baseline_items), MIN_BASELINE_ITEMS,
            )
            return

        try:
            from sklearn.ensemble import IsolationForest
        except ImportError as exc:
            logger.error("scikit-learn not available: %s", exc)
            return

        X = np.array([build_feature_vector(item) for item in baseline_items], dtype=np.float64)

        with self._lock:
            clf = IsolationForest(
                n_estimators=ISOLATION_FOREST_N_ESTIMATORS,
                contamination=ISOLATION_FOREST_CONTAMINATION,
                max_samples=ISOLATION_FOREST_MAX_SAMPLES,
                random_state=42,
                n_jobs=-1,
            )
            clf.fit(X)
            self._iso_forest = clf
            self._fitted = True
            self._baseline_size = len(baseline_items)
            self._baseline_vectors = X.copy()
            self._baseline_stats.fit(X)

        logger.info("AnomalyDetector fitted on %d baseline items.", self._baseline_size)

    # ── detect ────────────────────────────────────────────────────────────────

    def detect(self, item: dict) -> dict:
        """
        Detect whether an intel item is anomalous.

        Returns:
            is_anomaly: bool
            anomaly_score: float  (IF score; more negative = more anomalous)
            anomaly_type: str
            explanation: str
            novelty_indicators: List[str]
        """
        fv = build_feature_vector(item)
        novelty_indicators: List[str] = []
        anomaly_type = "normal"
        explanation_parts: List[str] = []

        if self._fitted and self._iso_forest is not None:
            with self._lock:
                raw_score = float(self._iso_forest.score_samples(fv.reshape(1, -1))[0])
                prediction = int(self._iso_forest.predict(fv.reshape(1, -1))[0])
            is_anomaly_if = prediction == -1 or raw_score < ANOMALY_SCORE_THRESHOLD
        else:
            # Rule-based fallback
            raw_score = self._rule_based_anomaly_score(fv)
            is_anomaly_if = raw_score < ANOMALY_SCORE_THRESHOLD

        # Statistical z-score analysis
        z_scores = self._baseline_stats.z_scores(fv)
        stat_anomalies = [
            (FEATURE_NAMES[i], float(z_scores[i]))
            for i in range(len(FEATURE_NAMES))
            if float(z_scores[i]) > 2.5
        ]

        is_anomaly = is_anomaly_if or len(stat_anomalies) >= 2

        # Classify anomaly type
        if is_anomaly:
            cvss = fv[0]
            epss = fv[1]
            exploit = fv[5]
            has_cve = fv[8]
            iocs = fv[4]

            if exploit >= 0.85 and has_cve < 0.5:
                anomaly_type = "potential_zero_day"
                explanation_parts.append("High exploit maturity with no CVE assignment.")
                novelty_indicators.append("exploit_without_cve")
            elif cvss >= 0.90 and epss >= 0.80:
                anomaly_type = "critical_velocity"
                explanation_parts.append("Extreme CVSS + EPSS combination outside baseline norms.")
                novelty_indicators.append("extreme_severity_epss_combo")
            elif iocs >= 0.40 and has_cve < 0.5:
                anomaly_type = "ioc_surge_no_advisory"
                explanation_parts.append("High IOC count with no associated CVE advisory.")
                novelty_indicators.append("ioc_surge_without_cve")
            elif len(stat_anomalies) >= 3:
                anomaly_type = "multi_feature_outlier"
                explanation_parts.append(
                    f"Statistical outlier on {len(stat_anomalies)} features: "
                    + ", ".join(f"{n}(z={z:.1f})" for n, z in stat_anomalies[:4])
                )
                novelty_indicators.extend([f"z_outlier_{n}" for n, _ in stat_anomalies[:4]])
            else:
                anomaly_type = "pattern_deviation"
                explanation_parts.append("Feature vector deviates significantly from baseline distribution.")
                novelty_indicators.append("baseline_deviation")

        for feat, z in stat_anomalies:
            if feat not in novelty_indicators:
                novelty_indicators.append(f"high_z_{feat}({z:.1f})")

        explanation = " ".join(explanation_parts) if explanation_parts else (
            "Item falls within baseline distribution norms."
        )

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(raw_score, 6),
            "anomaly_type": anomaly_type,
            "explanation": explanation,
            "novelty_indicators": novelty_indicators[:10],
            "statistical_outlier_features": [(n, round(z, 2)) for n, z in stat_anomalies],
            "model_type": "isolation_forest" if self._fitted else "rule_based_heuristic",
        }

    def _rule_based_anomaly_score(self, fv: np.ndarray) -> float:
        """
        Heuristic anomaly score when no fitted model is available.
        Returns a value in roughly the same range as sklearn IF scores.
        """
        cvss, epss, kev, ttps, iocs, exploit, _, _, has_cve, actor_known, sev = fv

        # Items with extreme combinations that are rarely seen = anomalous
        score = 0.0
        if exploit >= 0.85 and has_cve < 0.5:
            score += 0.5     # 0-day indicator
        if cvss >= 0.90 and epss >= 0.80:
            score += 0.3
        if iocs >= 0.60 and ttps >= 0.60:
            score += 0.2     # very high IOC + TTP density

        # Normalise: typical score range -0.5 to +0.1 (matching sklearn)
        return round(-score * 0.3, 6)

    # ── batch detect ──────────────────────────────────────────────────────────

    def detect_batch(self, items: List[dict]) -> List[dict]:
        """Detect anomalies across a list of items."""
        results = []
        for item in items:
            try:
                result = self.detect(item)
                result["item_id"] = item.get("id", item.get("cve_id", ""))
                results.append(result)
            except Exception as exc:
                logger.error("detect_batch error: %s", exc)
                results.append({"error": str(exc), "item_id": item.get("id", "")})
        return results

    # ── temporal anomaly ──────────────────────────────────────────────────────

    def detect_temporal_anomaly(self, items: List[dict], window_hours: int = 24) -> dict:
        """
        Detect unusual spikes in volume, severity, or actor activity within a time window.
        """
        now = datetime.now(tz=timezone.utc)

        # Parse timestamps
        timestamped = []
        for item in items:
            for key in ("disclosure_date", "published_date", "created_at", "date", "timestamp"):
                raw = item.get(key)
                if raw:
                    try:
                        if isinstance(raw, (int, float)):
                            dt = datetime.fromtimestamp(raw, tz=timezone.utc)
                        else:
                            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                        timestamped.append((dt, item))
                        break
                    except Exception:
                        pass

        if not timestamped:
            return {
                "spike_detected": False,
                "spike_type": None,
                "magnitude": 0.0,
                "likely_cause": "No timestamped items to analyse.",
            }

        # Bucket into hourly bins
        hourly_counts: Counter = Counter()
        hourly_severity: Counter = Counter()
        hourly_actors: Counter = Counter()

        for dt, item in timestamped:
            hour_key = dt.strftime("%Y-%m-%dT%H")
            hourly_counts[hour_key] += 1
            sev_raw = str(item.get("severity", "low")).lower()
            sev_score = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev_raw, 1)
            hourly_severity[hour_key] += sev_score
            actor = str(item.get("actor", "unknown"))
            if actor.lower() not in ("unknown", ""):
                hourly_actors[hour_key] += 1

        counts = list(hourly_counts.values())
        if len(counts) < 3:
            return {
                "spike_detected": False,
                "spike_type": None,
                "magnitude": 0.0,
                "likely_cause": "Insufficient temporal data (< 3 hourly buckets).",
            }

        mean_count = statistics.mean(counts)
        std_count = statistics.pstdev(counts) or 1.0
        max_count = max(counts)
        z_score = (max_count - mean_count) / std_count

        spike_detected = (
            z_score >= SPIKE_ZSCORE_THRESHOLD
            or max_count >= mean_count * SPIKE_VOLUME_MULTIPLIER
        )

        spike_type: Optional[str] = None
        likely_cause = "No significant spike detected."
        magnitude = round(float(z_score), 4)

        if spike_detected:
            # Characterise the spike
            peak_hour = max(hourly_counts, key=hourly_counts.get)
            severity_in_peak = hourly_severity.get(peak_hour, 0)
            actor_in_peak = hourly_actors.get(peak_hour, 0)

            if severity_in_peak / max(hourly_counts[peak_hour], 1) >= 3.5:
                spike_type = "severity_surge"
                likely_cause = "Unusual concentration of high/critical severity items in peak hour."
            elif actor_in_peak >= hourly_counts[peak_hour] * 0.7:
                spike_type = "actor_campaign_burst"
                likely_cause = "High proportion of attributed items suggests coordinated campaign activity."
            else:
                spike_type = "volume_spike"
                likely_cause = f"Volume spike: {max_count} items/hour vs baseline {mean_count:.1f} (z={z_score:.2f})."

        return {
            "spike_detected": spike_detected,
            "spike_type": spike_type,
            "magnitude": magnitude,
            "likely_cause": likely_cause,
            "peak_hourly_volume": max_count,
            "baseline_mean_volume": round(mean_count, 2),
            "z_score": round(float(z_score), 4),
            "hourly_buckets_analysed": len(counts),
        }

    # ── zero-day indicators ───────────────────────────────────────────────────

    def detect_zero_day_indicators(self, item: dict) -> dict:
        """
        Heuristic detection of potential 0-day indicators.
        Returns: zero_day_probability, indicators, recommended_action.
        """
        indicators: List[str] = []
        score = 0.0

        cve_id = str(item.get("cve_id", item.get("id", item.get("vulnerability_id", ""))))
        has_cve = cve_id.upper().startswith("CVE-")

        cvss = _safe_float(item.get("cvss_score", item.get("cvss", 0.0)), 0.0, 0.0, 10.0)
        epss = _safe_float(item.get("epss_score", item.get("epss", 0.0)), 0.0, 0.0, 1.0)
        exploit_maturity = str(item.get("exploit_maturity", "")).lower()
        is_in_kev = bool(item.get("kev", item.get("in_kev", item.get("kev_present", False))))

        iocs = item.get("iocs", item.get("indicators", []))
        ioc_count = len(iocs) if isinstance(iocs, (list, set, tuple)) else 0

        ttps = item.get("ttps", item.get("techniques", []))
        ttp_count = len(ttps) if isinstance(ttps, (list, set, tuple)) else 0

        # Signal 1: No CVE but high severity claimed
        if not has_cve and cvss >= ZERO_DAY_NO_CVE_SEVERITY_THRESHOLD:
            indicators.append("no_cve_high_severity")
            score += 0.35

        # Signal 2: Exploit active/weaponized but no CVE
        if not has_cve and any(k in exploit_maturity for k in ("active", "wild", "weapon", "functional")):
            indicators.append("active_exploit_no_cve")
            score += 0.40

        # Signal 3: Rapid IOC proliferation with no CVE
        if not has_cve and ioc_count >= ZERO_DAY_RAPID_IOC_COUNT:
            indicators.append("rapid_ioc_proliferation_no_cve")
            score += 0.25

        # Signal 4: High EPSS but no CVE (community exploitability without official record)
        if not has_cve and epss >= 0.70:
            indicators.append("high_epss_no_cve")
            score += 0.20

        # Signal 5: In KEV but no CVE (unusual — KEV entries almost always have CVEs)
        if is_in_kev and not has_cve:
            indicators.append("kev_flagged_no_cve")
            score += 0.45

        # Signal 6: High TTP density with no CVE (novel multi-technique attack)
        if not has_cve and ttp_count >= 5:
            indicators.append("high_ttp_density_no_cve")
            score += 0.15

        # Mild penalise if has CVE (still could be 0-day window)
        if has_cve and any(k in exploit_maturity for k in ("active", "wild", "weapon")):
            # CVE exists but exploit is already active — narrow 0-day window
            indicators.append("cve_exists_but_actively_exploited")
            score += 0.10

        zero_day_probability = round(min(1.0, score), 4)

        if zero_day_probability >= ZERO_DAY_CONF_HIGH:
            recommended_action = (
                "IMMEDIATE: Treat as probable zero-day. Activate threat hunting, "
                "isolate exposed assets, apply network-level controls, and escalate to CISO."
            )
        elif zero_day_probability >= ZERO_DAY_CONF_MEDIUM:
            recommended_action = (
                "HIGH PRIORITY: Monitor for CVE assignment. Apply IOC-based blocking. "
                "Increase logging verbosity on affected systems."
            )
        elif zero_day_probability > 0.20:
            recommended_action = (
                "WATCH: Track for CVE publication. Review vendor advisories. "
                "Apply principle of least privilege on affected surfaces."
            )
        else:
            recommended_action = "ROUTINE: Standard triage and prioritisation procedures apply."

        return {
            "zero_day_probability": zero_day_probability,
            "indicators": indicators,
            "recommended_action": recommended_action,
            "has_cve": has_cve,
            "cve_id": cve_id if has_cve else None,
            "exploit_maturity": exploit_maturity or "unknown",
            "ioc_count": ioc_count,
        }

    # ── novelty score ─────────────────────────────────────────────────────────

    def get_novelty_score(self, item: dict) -> float:
        """
        0.0 = seen before / well-understood, 1.0 = completely novel.
        Computed as normalised distance from baseline centroid.
        """
        fv = build_feature_vector(item)

        if not self._baseline_stats.fitted or self._baseline_vectors is None:
            # Fallback: use raw feature extremity as novelty proxy
            extremity = float(np.mean(np.abs(fv - 0.5)))
            return round(min(1.0, extremity * 2.0), 4)

        dist = self._baseline_stats.mahalanobis_approx(fv)
        # Typical dist for known items: 2-5; outliers: 8+
        novelty = min(1.0, dist / 10.0)
        return round(novelty, 4)

    # ── diagnostics ───────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            baseline_means = {}
            if self._baseline_stats.fitted and self._baseline_stats.means is not None:
                baseline_means = {
                    FEATURE_NAMES[i]: round(float(self._baseline_stats.means[i]), 6)
                    for i in range(len(FEATURE_NAMES))
                }
            return {
                "module": "AnomalyDetector",
                "version": "v123.0.0",
                "algorithm": "IsolationForest + StatisticalOutlier",
                "fitted": self._fitted,
                "baseline_size": self._baseline_size,
                "contamination_rate": ISOLATION_FOREST_CONTAMINATION,
                "n_estimators": ISOLATION_FOREST_N_ESTIMATORS,
                "anomaly_score_threshold": ANOMALY_SCORE_THRESHOLD,
                "feature_count": len(FEATURE_NAMES),
                "baseline_feature_means": baseline_means,
                "temporal_window_size": len(self._temporal_window),
            }


# ════════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(name)s | %(levelname)s | %(message)s")

    ad = AnomalyDetector()

    # Baseline corpus
    baseline = [
        {"id": f"CVE-2024-{i:05d}", "cvss_score": 5.0 + (i % 5) * 0.5, "epss_score": 0.05,
         "kev": False, "ttps": ["T1190"], "iocs": ["1.2.3.4"],
         "exploit_maturity": "poc", "source": "NVD", "sector": "technology",
         "severity": "medium", "actor": "unknown", "disclosure_date": "2024-06-01"}
        for i in range(50)
    ]
    ad.fit(baseline)

    # Anomalous item — 0-day indicator
    anomalous = {
        "id": "THREAT-UNKNOWN-001",
        "cvss_score": 9.8,
        "epss_score": 0.95,
        "kev": True,
        "ttps": ["T1190", "T1059", "T1486", "T1027", "T1055"],
        "iocs": [f"evil{i}.net" for i in range(15)],
        "exploit_maturity": "active",
        "source": "private_feed_X",
        "sector": "healthcare",
        "severity": "critical",
        "actor": "unknown",
        "disclosure_date": "2026-04-19",
    }

    result = ad.detect(anomalous)
    print("=== Anomaly Detection ===")
    print(json.dumps(result, indent=2))

    zd = ad.detect_zero_day_indicators(anomalous)
    print("\n=== Zero-Day Indicators ===")
    print(json.dumps(zd, indent=2))

    novelty = ad.get_novelty_score(anomalous)
    print(f"\nNovelty score: {novelty}")

    temporal_result = ad.detect_temporal_anomaly(baseline + [anomalous], window_hours=24)
    print("\n=== Temporal Anomaly ===")
    print(json.dumps(temporal_result, indent=2))

    print("\n=== Stats ===")
    print(json.dumps(ad.stats(), indent=2))
