"""
CYBERDUDEBIVASH® SENTINEL APEX
EXPLOITABILITY & RISK SCORING ENGINE v1.1
CVE prioritization, EPSS enrichment, business impact scoring.

v1.1 (v161.3) fixes:
  - EPSS scale normalization: detect 0-100 % storage vs 0-1 fraction at intake
  - CVE floor: unscored CVEs get MEDIUM floor (5.0) not zero
  - biz_c floor: all advisories get minimum business impact contribution (0.5)
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

# CVE keyword threat signals — extra score boost for dangerous vulnerability classes
CVE_THREAT_KEYWORDS = {
    "remote code execution": 2.5, "rce": 2.5,
    "buffer overflow": 2.0, "heap overflow": 2.0,
    "privilege escalation": 1.8, "privesc": 1.8,
    "zero.day": 2.5, "zero-day": 2.5, "0-day": 2.5,
    "actively exploit": 2.5, "exploit in the wild": 2.5,
    "unauthenticated": 1.5, "auth bypass": 1.8, "authentication bypass": 1.8,
    "command injection": 2.0, "os command": 2.0,
    "sql injection": 1.6, "sqli": 1.6,
    "public exploit": 1.5, "poc": 1.2, "metasploit": 1.8,
    "ransomware": 2.5, "supply chain": 2.0,
    "ssrf": 1.5, "csrf": 1.2, "xxe": 1.5,
    "deserialization": 1.8,
}


class ScoringEngine:
    """
    Multi-dimensional risk scoring: CVSS + EPSS + KEV + Business Impact.
    Produces normalized 0-10 composite risk score.

    v1.1 changes:
    - EPSS normalised to 0-1 fraction at intake (handles both 0-1 and 0-100 storage)
    - CVE floor: advisory with a CVE ID but no CVSS/EPSS gets floor = 5.0 (MEDIUM)
    - Keyword scoring: title/description signals add direct score contribution
    - biz_c minimum floor = 0.5 (every advisory has some operational relevance)
    """

    def score_advisory(self, advisory: Dict) -> Dict:
        def safe_float(v, default=0.0):
            try: return float(v) if v is not None else default
            except (ValueError, TypeError): return default

        cvss = safe_float(advisory.get("cvss") or advisory.get("cvss_score"))
        _epss_raw = safe_float(advisory.get("epss") or advisory.get("epss_score"))
        # v1.1 FIX: EPSS is sometimes stored as 0-100 %; normalise to 0-1 fraction
        epss = _epss_raw / 100.0 if _epss_raw > 1.0 else _epss_raw

        kev  = bool(
            advisory.get("kev_confirmed")
            or advisory.get("kev", False)
            or advisory.get("kev_present", False)
        )
        has_cve = bool(
            advisory.get("cve_ids")
            or advisory.get("cve_id")
            or advisory.get("cves")
            or (str(advisory.get("title", "")).upper().startswith("CVE-"))
        )
        title   = str(advisory.get("title", "")).lower()
        summary = str(advisory.get("summary", "") or advisory.get("description", "")).lower()
        text    = title + " " + summary

        # 1. CVSS contribution (35% weight, max 3.5 pts)
        cvss_c = cvss * 0.35

        # 2. EPSS contribution (25% weight, max 2.5 pts — EPSS now in 0-1 fraction)
        epss_c = epss * 10.0 * 0.25   # 1.0 fraction → 10*0.25 = 2.5 max

        # 3. KEV + exploitability bonus (25% weight, max 2.5 pts)
        exploit_c = 0.0
        if kev:
            exploit_c += 2.5
        exploit_c = min(exploit_c, 2.5)

        # 4. Keyword threat signals (additive, capped at 2.5)
        kw_score = 0.0
        for kw, pts in CVE_THREAT_KEYWORDS.items():
            if kw in text:
                kw_score = max(kw_score, pts)   # take max keyword match, not sum
        kw_score = min(kw_score, 2.5)

        # 5. Business impact (15% weight, max 1.5 pts, floor 0.5)
        biz_factor = max(
            (BUSINESS_IMPACT_FACTORS.get(k, 0) for k in BUSINESS_IMPACT_FACTORS
             if k in text),
            default=BUSINESS_IMPACT_FACTORS["default"]
        )
        biz_c = max(0.5, min(1.5, (biz_factor - 1.0) * 0.5 + 0.5))

        raw_total = cvss_c + epss_c + exploit_c + kw_score + biz_c

        # v1.1: CVE floor — a CVE with no external enrichment is at minimum MEDIUM
        if has_cve and raw_total < 5.0:
            raw_total = max(raw_total, 5.0)

        total = round(min(10.0, raw_total), 2)
        severity = (
            "CRITICAL" if total >= 9.0 else
            "HIGH"     if total >= 7.0 else
            "MEDIUM"   if total >= 4.0 else
            "LOW"
        )

        return {
            "advisory_id":    advisory.get("stix_id", ""),
            "composite_score": total,
            "severity":       severity,
            "score_breakdown": {
                "cvss_contribution":     round(cvss_c,    2),
                "epss_contribution":     round(epss_c,    2),
                "exploit_contribution":  round(exploit_c, 2),
                "keyword_contribution":  round(kw_score,  2),
                "business_contribution": round(biz_c,     2),
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
