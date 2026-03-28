"""
CYBERDUDEBIVASH® SENTINEL APEX
AI PREDICTIVE THREAT ENGINE v1.0
Behavioral analytics, attack prediction, trend forecasting.
Uses statistical models and pattern learning — no external ML deps required.
"""
import math
import logging
import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-PREDICTIVE-ENGINE")

# ── Threat velocity thresholds ─────────────────────────────────────────────
VELOCITY_THRESHOLDS = {
    "critical_surge":   5.0,   # 5x increase → critical
    "high_surge":       3.0,   # 3x increase → high
    "moderate_surge":   2.0,   # 2x → moderate
    "normal_variance":  1.5,   # 1.5x → normal variance
}

# ── Attack pattern windows ──────────────────────────────────────────────────
PATTERN_WINDOWS = {
    "24h":  timedelta(hours=24),
    "7d":   timedelta(days=7),
    "30d":  timedelta(days=30),
}


class PredictiveThreatEngine:
    """
    Statistical threat prediction engine.
    Analyzes historical advisory data to predict future threat trends.
    No heavy ML dependencies — uses regression, EMA, and statistical models.
    """

    def __init__(self):
        self.advisory_history: deque = deque(maxlen=10000)
        self.ttp_frequency: Dict[str, int] = defaultdict(int)
        self.severity_timeline: List[Dict] = []
        self.predictions_made: int = 0

    def ingest_advisories(self, advisories: List[Dict]) -> int:
        """Add historical advisories for analysis."""
        added = 0
        for adv in advisories:
            self.advisory_history.append({
                "timestamp": adv.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "severity": adv.get("severity", "MEDIUM"),
                "risk_score": float(adv.get("risk_score") or adv.get("cvss") or 5.0),
                "ttps": adv.get("mitre_techniques", []),
                "kev": adv.get("kev_confirmed", False),
                "epss": float(adv.get("epss") or 0),
            })
            for ttp in adv.get("mitre_techniques", []):
                self.ttp_frequency[ttp] += 1
            added += 1
        return added

    # ── EMA (Exponential Moving Average) ────────────────────────────────────

    def _compute_ema(self, values: List[float], period: int = 7) -> List[float]:
        """Exponential moving average for smoothed trend analysis."""
        if not values:
            return []
        alpha = 2.0 / (period + 1)
        ema = [values[0]]
        for v in values[1:]:
            ema.append(alpha * v + (1 - alpha) * ema[-1])
        return ema

    # ── Linear Regression ─────────────────────────────────────────────────

    def _linear_regression(self, x: List[float], y: List[float]) -> Tuple[float, float, float]:
        """Simple linear regression: returns (slope, intercept, r_squared)."""
        n = len(x)
        if n < 2:
            return 0.0, y[0] if y else 0.0, 0.0
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        ss_xy = sum((xi - x_mean) * (yi - y_mean) for xi, yi in zip(x, y))
        ss_xx = sum((xi - x_mean) ** 2 for xi in x)
        if ss_xx == 0:
            return 0.0, y_mean, 0.0
        slope = ss_xy / ss_xx
        intercept = y_mean - slope * x_mean
        y_pred = [slope * xi + intercept for xi in x]
        ss_res = sum((yi - yp) ** 2 for yi, yp in zip(y, y_pred))
        ss_tot = sum((yi - y_mean) ** 2 for yi in y)
        r_sq = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
        return round(slope, 4), round(intercept, 4), round(r_sq, 4)

    # ── Threat Velocity ─────────────────────────────────────────────────────

    def compute_threat_velocity(self, window_days: int = 7) -> Dict:
        """Measure rate of change in threat activity."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=window_days)
        prev_cutoff = cutoff - timedelta(days=window_days)

        current_period = [a for a in self.advisory_history
                          if a["timestamp"] >= cutoff.isoformat()]
        previous_period = [a for a in self.advisory_history
                           if prev_cutoff.isoformat() <= a["timestamp"] < cutoff.isoformat()]

        curr_count = len(current_period) or 0
        prev_count = len(previous_period) or 1

        velocity_ratio = curr_count / prev_count
        curr_avg_risk = (sum(a["risk_score"] for a in current_period) / curr_count) if curr_count else 0
        prev_avg_risk = (sum(a["risk_score"] for a in previous_period) / len(previous_period)) \
                         if previous_period else curr_avg_risk

        risk_velocity = (curr_avg_risk - prev_avg_risk) if prev_avg_risk else 0

        surge_level = "NORMAL"
        if velocity_ratio >= VELOCITY_THRESHOLDS["critical_surge"]: surge_level = "CRITICAL_SURGE"
        elif velocity_ratio >= VELOCITY_THRESHOLDS["high_surge"]: surge_level = "HIGH_SURGE"
        elif velocity_ratio >= VELOCITY_THRESHOLDS["moderate_surge"]: surge_level = "MODERATE_SURGE"

        return {
            "window_days": window_days,
            "current_period_count": curr_count,
            "previous_period_count": prev_count,
            "velocity_ratio": round(velocity_ratio, 2),
            "surge_level": surge_level,
            "avg_risk_current": round(curr_avg_risk, 2),
            "avg_risk_previous": round(prev_avg_risk, 2),
            "risk_delta": round(risk_velocity, 2),
            "trend": "ESCALATING" if risk_velocity > 0.5 else "STABLE" if abs(risk_velocity) <= 0.5 else "DECLINING",
        }

    # ── Trend Prediction ─────────────────────────────────────────────────────

    def predict_next_period(self, forecast_days: int = 7) -> Dict:
        """Predict threat levels for next N days using EMA + linear regression."""
        history = list(self.advisory_history)
        if len(history) < 7:
            return {"warning": "Insufficient historical data", "min_required": 7}

        # Build daily risk score series
        daily_risk: Dict[str, List[float]] = defaultdict(list)
        for item in history:
            day = item["timestamp"][:10]
            daily_risk[day].append(item["risk_score"])

        days_sorted = sorted(daily_risk.keys())
        daily_avg = [statistics.mean(daily_risk[d]) for d in days_sorted]

        if len(daily_avg) < 3:
            return {"warning": "Insufficient daily data points"}

        # EMA smoothing
        ema_values = self._compute_ema(daily_avg, period=7)

        # Linear regression for trend
        x = list(range(len(ema_values)))
        slope, intercept, r_sq = self._linear_regression(x, ema_values)

        # Project forward
        last_x = len(ema_values)
        forecasted = []
        for i in range(1, forecast_days + 1):
            projected = slope * (last_x + i) + intercept
            # Add EMA momentum
            projected = projected * 0.6 + ema_values[-1] * 0.4
            projected = max(0, min(10, projected))

            future_date = (datetime.now(timezone.utc) + timedelta(days=i)).strftime("%Y-%m-%d")
            forecasted.append({
                "date": future_date,
                "predicted_risk": round(projected, 2),
                "risk_level": "CRITICAL" if projected >= 8 else "HIGH" if projected >= 6
                              else "MEDIUM" if projected >= 4 else "LOW",
                "confidence": min(0.95, max(0.3, r_sq + 0.1)),
            })

        # TTP trend analysis
        top_ttps = sorted(self.ttp_frequency.items(), key=lambda x: -x[1])[:5]

        self.predictions_made += 1
        return {
            "forecast_days": forecast_days,
            "historical_days": len(daily_avg),
            "trend_direction": "ESCALATING" if slope > 0.05 else "DECLINING" if slope < -0.05 else "STABLE",
            "trend_slope": slope,
            "model_confidence": r_sq,
            "current_avg_risk": round(daily_avg[-1], 2) if daily_avg else 0,
            "ema_smoothed_risk": round(ema_values[-1], 2) if ema_values else 0,
            "forecast": forecasted,
            "trending_ttps": [{"ttp": t, "frequency": f} for t, f in top_ttps],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_attack_predictions(self) -> Dict:
        """High-level attack prediction based on velocity + TTP trends."""
        velocity = self.compute_threat_velocity()
        forecast = self.predict_next_period(forecast_days=3)

        # Assess likelihood of attack categories
        ransomware_ttps = {"T1486", "T1490", "T1078", "T1021"}
        observed_ttps = set(self.ttp_frequency.keys())
        ransomware_prob = len(ransomware_ttps & observed_ttps) / len(ransomware_ttps)

        supply_chain_ttps = {"T1195", "T1199", "T1059"}
        supply_chain_prob = len(supply_chain_ttps & observed_ttps) / len(supply_chain_ttps)

        phishing_ttps = {"T1566", "T1203", "T1071"}
        phishing_prob = len(phishing_ttps & observed_ttps) / len(phishing_ttps)

        predictions = [
            {
                "attack_type": "Ransomware Campaign",
                "probability": round(min(0.99, ransomware_prob * velocity.get("velocity_ratio", 1.0) * 0.5), 2),
                "confidence": "HIGH" if ransomware_prob > 0.6 else "MEDIUM",
                "indicators": list(ransomware_ttps & observed_ttps),
            },
            {
                "attack_type": "Supply Chain Attack",
                "probability": round(min(0.99, supply_chain_prob * 0.6), 2),
                "confidence": "MEDIUM" if supply_chain_prob > 0.5 else "LOW",
                "indicators": list(supply_chain_ttps & observed_ttps),
            },
            {
                "attack_type": "Phishing Campaign",
                "probability": round(min(0.99, phishing_prob * 0.7), 2),
                "confidence": "HIGH" if phishing_prob > 0.6 else "MEDIUM",
                "indicators": list(phishing_ttps & observed_ttps),
            },
        ]

        return {
            "velocity_analysis": velocity,
            "short_term_forecast": forecast.get("forecast", [])[:3],
            "attack_predictions": sorted(predictions, key=lambda x: -x["probability"]),
            "overall_threat_level": velocity.get("surge_level", "NORMAL"),
            "predictions_made": self.predictions_made,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
