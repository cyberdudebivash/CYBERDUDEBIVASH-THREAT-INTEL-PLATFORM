"""
CYBERDUDEBIVASH® SENTINEL APEX
BEHAVIORAL ANALYTICS ENGINE — Anomaly detection in threat patterns
Detects unusual spikes, novel TTPs, and emerging attack vectors.
"""
import logging
import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-BEHAVIORAL")


class BehavioralAnalytics:
    """
    Statistical anomaly detection for threat advisory streams.
    Uses Z-score + IQR methods for outlier detection.
    """

    def __init__(self, window_size: int = 30):
        self.window_size = window_size
        self.risk_window: deque = deque(maxlen=window_size)
        self.ioc_window: deque = deque(maxlen=window_size)
        self.severity_window: deque = deque(maxlen=window_size)
        self.anomalies_detected: int = 0

    def feed(self, advisory: Dict) -> None:
        """Feed a new advisory into the behavioral windows."""
        risk = float(advisory.get("risk_score") or advisory.get("cvss") or 5.0)
        ioc_count = len(advisory.get("iocs", []))
        severity_score = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "INFO": 1}.get(
            advisory.get("severity", "MEDIUM"), 5
        )
        self.risk_window.append(risk)
        self.ioc_window.append(ioc_count)
        self.severity_window.append(severity_score)

    def _zscore_anomaly(self, window: deque, value: float, threshold: float = 2.5) -> Tuple[bool, float]:
        """Returns (is_anomaly, zscore) using rolling Z-score."""
        if len(window) < 5:
            return False, 0.0
        mean = statistics.mean(window)
        stdev = statistics.stdev(window) if len(window) > 1 else 1.0
        if stdev == 0:
            return False, 0.0
        zscore = (value - mean) / stdev
        return abs(zscore) > threshold, round(zscore, 2)

    def detect_anomaly(self, advisory: Dict) -> Dict:
        """Detect if a new advisory represents anomalous behavior."""
        risk = float(advisory.get("risk_score") or advisory.get("cvss") or 5.0)
        ioc_count = len(advisory.get("iocs", []))
        severity_score = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "INFO": 1}.get(
            advisory.get("severity", "MEDIUM"), 5
        )

        risk_anomaly, risk_z = self._zscore_anomaly(self.risk_window, risk)
        ioc_anomaly, ioc_z = self._zscore_anomaly(self.ioc_window, float(ioc_count))
        sev_anomaly, sev_z = self._zscore_anomaly(self.severity_window, float(severity_score))

        anomaly_signals = []
        if risk_anomaly:
            anomaly_signals.append(f"RISK_SPIKE (z={risk_z})")
        if ioc_anomaly:
            anomaly_signals.append(f"IOC_SURGE (z={ioc_z})")
        if sev_anomaly:
            anomaly_signals.append(f"SEVERITY_SPIKE (z={sev_z})")

        is_anomaly = len(anomaly_signals) >= 1
        anomaly_score = min(10.0, sum([abs(risk_z), abs(ioc_z), abs(sev_z)]))

        if is_anomaly:
            self.anomalies_detected += 1

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 2),
            "anomaly_signals": anomaly_signals,
            "risk_zscore": risk_z,
            "ioc_zscore": ioc_z,
            "severity_zscore": sev_z,
            "recommendation": "IMMEDIATE REVIEW" if is_anomaly and anomaly_score > 5 else
                              "FLAG FOR REVIEW" if is_anomaly else "NORMAL",
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_baseline_stats(self) -> Dict:
        """Return current behavioral baseline statistics."""
        def safe_stats(window: deque) -> Dict:
            if len(window) < 2:
                return {"mean": 0, "stdev": 0, "min": 0, "max": 0}
            vals = list(window)
            return {
                "mean": round(statistics.mean(vals), 2),
                "stdev": round(statistics.stdev(vals), 2),
                "min": round(min(vals), 2),
                "max": round(max(vals), 2),
            }
        return {
            "window_size": self.window_size,
            "current_samples": len(self.risk_window),
            "risk_baseline": safe_stats(self.risk_window),
            "ioc_baseline": safe_stats(self.ioc_window),
            "severity_baseline": safe_stats(self.severity_window),
            "total_anomalies_detected": self.anomalies_detected,
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }
