"""
CYBERDUDEBIVASH® SENTINEL APEX
EXPLOITABILITY & RISK SCORING ENGINE v1.0
CVE prioritization, EPSS enrichment, business impact scoring.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-SCORING-ENGINE")

CVSS_VECTORS = {
    "AV:N": 1.0, "AV:A": 0.7, "AV:L": 0.55, "AV:P": 0.2,
    "AC:L": 1.0, "AC:H": 0.5,
    "PR:N": 1.0, "PR:L": 0.68, "PR:H": 0.5,
    "UI:N": 1.0, "UI:R": 0.85,
    "S:C": 1.0,  "S:U": 0.8,
    "C:H": 1.0,  "C:L": 0.5,  "C:N": 0.0,
    "I:H": 1.0,  "I:L": 0.5,  "I:N": 0.0,
    "A:H": 1.0,  "A:L": 0.5,  "A:N": 0.0,
}

BUSINESS_IMPACT_FACTORS = {
    "pii_data":          2.5,
    "financial_data":    2.8,
    "health_records":    2.6,
    "ip_source_code":    2.2,
    "infrastructure":    3.0,
    "authentication":    2.0,
    "email_server":      1.8,
    "default":           1.0,
}


class ScoringEngine:
    """
    Multi-dimensional risk scoring: CVSS + EPSS + KEV + Business Impact.
    Produces normalized 0-10 composite risk score.
    """

    def score_advisory(self, advisory: Dict) -> Dict:
        cvss    = float(advisory.get("cvss") or advisory.get("cvss_score") or 0)
        epss    = float(advisory.get("epss") or advisory.get("epss_score") or 0)
        kev     = advisory.get("kev_confirmed", False) or advisory.get("kev", False)
        title   = str(advisory.get("title", "")).lower()
        summary = str(advisory.get("summary", "")).lower()
        text    = title + " " + summary

        # 1. CVSS contribution (35%)
        cvss_c = cvss * 0.35

        # 2. EPSS contribution (25%)
        epss_c = epss * 10 * 0.25

        # 3. KEV + exploitability bonus (25%)
        exploit_c = 0.0
        if kev: exploit_c += 2.5
        if any(k in text for k in ["actively exploit", "exploit in the wild"]): exploit_c += 1.5
        if any(k in text for k in ["public exploit", "poc", "metasploit"]): exploit_c += 1.0
        exploit_c = min(exploit_c, 2.5)

        # 4. Business impact (15%)
        biz_factor = max(
            (BUSINESS_IMPACT_FACTORS.get(k, 0) for k in BUSINESS_IMPACT_FACTORS
             if k in text),
            default=BUSINESS_IMPACT_FACTORS["default"]
        )
        biz_c = min(1.5, (biz_factor - 1.0) * 0.5)

        total = round(min(10.0, cvss_c + epss_c + exploit_c + biz_c), 2)
        severity = ("CRITICAL" if total >= 9 else "HIGH" if total >= 7
                    else "MEDIUM" if total >= 4 else "LOW")

        return {
            "advisory_id":    advisory.get("stix_id", ""),
            "composite_score": total,
            "severity":       severity,
            "score_breakdown": {
                "cvss_contribution":    round(cvss_c, 2),
                "epss_contribution":    round(epss_c, 2),
                "exploit_contribution": round(exploit_c, 2),
                "business_contribution":round(biz_c, 2),
            },
            "raw_scores": {"cvss": cvss, "epss": epss, "kev": kev},
            "action_required": total >= 7.0,
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }

    def score_batch(self, advisories: List[Dict]) -> List[Dict]:
        return sorted(
            [self.score_advisory(a) for a in advisories],
            key=lambda x: x["composite_score"], reverse=True
        )

    def get_top_risks(self, advisories: List[Dict], top_n: int = 10) -> List[Dict]:
        return self.score_batch(advisories)[:top_n]
