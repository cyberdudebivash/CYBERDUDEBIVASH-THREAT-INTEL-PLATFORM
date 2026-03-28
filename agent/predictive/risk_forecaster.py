"""
CYBERDUDEBIVASH® SENTINEL APEX
RISK FORECASTER — 30/60/90 day risk projections
Combines predictive engine output with business impact scoring.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

logger = logging.getLogger("CDB-RISK-FORECASTER")

INDUSTRY_RISK_MULTIPLIERS = {
    "financial":     1.4,
    "healthcare":    1.3,
    "government":    1.5,
    "technology":    1.2,
    "retail":        1.1,
    "energy":        1.6,
    "default":       1.0,
}


class RiskForecaster:
    """30/60/90 day threat risk forecast with business impact scoring."""

    def __init__(self, industry: str = "technology"):
        self.industry = industry
        self.multiplier = INDUSTRY_RISK_MULTIPLIERS.get(industry, 1.0)

    def forecast(self, predictive_data: Dict, horizon_days: List[int] = None) -> Dict:
        if horizon_days is None:
            horizon_days = [30, 60, 90]

        forecast_points = predictive_data.get("forecast", [])
        if not forecast_points:
            return {"error": "No forecast data available"}

        avg_predicted = sum(f["predicted_risk"] for f in forecast_points) / len(forecast_points)
        trend = predictive_data.get("trend_direction", "STABLE")
        trend_slope = predictive_data.get("trend_slope", 0.0)

        horizons = []
        for days in horizon_days:
            # Project risk at horizon
            projected_risk = min(10.0, avg_predicted + (trend_slope * days * 0.1))
            adjusted_risk = min(10.0, projected_risk * self.multiplier)
            business_impact = self._compute_business_impact(adjusted_risk)

            horizons.append({
                "horizon_days": days,
                "horizon_date": (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d"),
                "projected_risk_score": round(projected_risk, 2),
                "industry_adjusted_risk": round(adjusted_risk, 2),
                "risk_level": self._risk_level(adjusted_risk),
                "business_impact": business_impact,
                "recommended_actions": self._get_recommendations(adjusted_risk, days),
            })

        return {
            "industry": self.industry,
            "industry_multiplier": self.multiplier,
            "current_trend": trend,
            "horizons": horizons,
            "overall_outlook": self._overall_outlook(horizons),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _risk_level(self, score: float) -> str:
        if score >= 8.5: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 5.0: return "MEDIUM"
        if score >= 3.0: return "LOW"
        return "INFORMATIONAL"

    def _compute_business_impact(self, risk: float) -> Dict:
        return {
            "financial_exposure": f"${int(risk * 1.2e6):,} - ${int(risk * 3.5e6):,}",
            "breach_probability": f"{min(95, int(risk * 9.5))}%",
            "recovery_time_estimate": f"{int(risk * 3.2)} - {int(risk * 7.5)} days",
            "reputational_risk": "CRITICAL" if risk >= 8 else "HIGH" if risk >= 6 else "MEDIUM",
        }

    def _get_recommendations(self, risk: float, days: int) -> List[str]:
        recs = ["Maintain threat monitoring cadence"]
        if risk >= 8:
            recs = ["URGENT: Activate incident response retainer",
                    "Conduct tabletop exercise within 2 weeks",
                    "Review and test backup recovery procedures",
                    "Brief executive team on elevated threat posture"]
        elif risk >= 6:
            recs = ["Increase security monitoring frequency",
                    "Review privileged access controls",
                    "Validate patch management completeness"]
        elif risk >= 4:
            recs = ["Schedule penetration test",
                    "Review security awareness training completeness"]
        return recs

    def _overall_outlook(self, horizons: List[Dict]) -> str:
        avg = sum(h["industry_adjusted_risk"] for h in horizons) / len(horizons)
        if avg >= 7.5: return "DETERIORATING — Elevated threat activity expected"
        if avg >= 5.5: return "CAUTIONARY — Moderate threat escalation possible"
        if avg >= 3.5: return "STABLE — Normal threat landscape"
        return "IMPROVING — Declining threat indicators"
