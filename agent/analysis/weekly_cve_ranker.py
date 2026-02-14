"""
Weekly CVE Risk Ranking Engine
FINAL • PRODUCTION • EXPLOITATION-FOCUSED

Ranks CVEs based on real-world exploitation signals,
not just raw severity scores.
"""

from typing import List, Dict


SEVERITY_WEIGHT = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
}


def rank_weekly_cves(
    cves: List[Dict],
    kev_items: List[Dict],
    top_n: int = 10,
) -> List[Dict]:
    """
    Rank CVEs by operational exploitation risk.

    Risk Score Formula:
        CVSS
      + (EPSS × 10)
      + Severity Weight
      + KEV Bonus (+5)

    Returns:
        Top N highest-risk CVEs
    """

    kev_ids = {k.get("cveID") for k in kev_items if k.get("cveID")}
    ranked: List[Dict] = []

    for cve in cves:
        cve_id = cve.get("id")
        if not cve_id:
            continue

        cvss = float(cve.get("cvss") or 0.0)
        epss = float(cve.get("epss") or 0.0)
        severity = (cve.get("severity") or "").upper()

        score = (
            cvss
            + (epss * 10)
            + SEVERITY_WEIGHT.get(severity, 0)
            + (5 if cve_id in kev_ids else 0)
        )

        ranked.append({
            **cve,
            "risk_score": round(score, 2),
            "is_kev": cve_id in kev_ids,
        })

    ranked.sort(key=lambda x: x["risk_score"], reverse=True)
    return ranked[:top_n]
