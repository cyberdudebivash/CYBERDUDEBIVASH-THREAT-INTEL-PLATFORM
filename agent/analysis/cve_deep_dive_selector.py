"""
CVE Deep-Dive Selection Engine
FINAL • PRODUCTION • STRICT PRIORITIZATION

Selects only high-impact CVEs suitable for long-form authority posts.
"""

from typing import List, Dict


def select_cves_for_deep_dive(
    cves: List[Dict],
    kev_items: List[Dict],
    min_epss: float = 0.40,
    min_cvss: float = 9.0,
) -> List[Dict]:
    """
    Select CVEs eligible for authority-grade deep dives.

    Rules:
    - Severity must be HIGH or CRITICAL
    - AND one of:
        - EPSS >= min_epss
        - CVSS >= min_cvss
        - Present in CISA KEV
    """

    kev_ids = {k.get("cveID") for k in kev_items if k.get("cveID")}
    selected: List[Dict] = []

    for cve in cves:
        cve_id = cve.get("id")
        severity = (cve.get("severity") or "").upper()
        cvss = float(cve.get("cvss") or 0.0)
        epss = float(cve.get("epss") or 0.0)

        if severity not in {"CRITICAL", "HIGH"}:
            continue

        if (
            epss >= min_epss
            or cvss >= min_cvss
            or cve_id in kev_ids
        ):
            selected.append(cve)

    return selected
