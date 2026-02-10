"""
MITRE ATT&CK Coverage Gap Analysis – FINAL PRODUCTION VERSION

Purpose:
Identify MITRE ATT&CK techniques actively used by current threats
that are NOT covered by existing detections.

Outputs:
- Risk-weighted coverage gaps
- SOC / Purple Team actionable insights

Designed for:
SOC • Purple Team • Detection Engineering • ATT&CK Navigator
"""

from typing import List, Dict, Set


# =================================================
# BASELINE SOC COVERAGE (CLAIMED DETECTIONS)
# =================================================
# NOTE:
# This represents techniques the SOC *claims* to detect.
# In production, this should be loaded from:
# - SIEM exports
# - ATT&CK Navigator layers
# - YAML / JSON configs
# - Detection-as-Code repos
# =================================================

DETECTED_TECHNIQUES: Set[str] = {
    "T1059",        # Command and Scripting Interpreter
    "T1059.001",    # PowerShell
    "T1105",        # Ingress Tool Transfer
}


# =================================================
# GAP SEVERITY ENGINE
# =================================================

def _calculate_gap_severity(
    cves: List[Dict],
    epss_accelerating: bool,
) -> str:
    """
    Determine severity of an ATT&CK coverage gap
    using exploitation likelihood and velocity.
    """

    severity = "MEDIUM"

    for cve in cves:
        cve_sev = cve.get("severity")

        if cve_sev == "CRITICAL":
            return "CRITICAL"

        if cve_sev == "HIGH":
            severity = "HIGH"

        # Escalate on EPSS acceleration
        if cve.get("epss_acceleration") in ("ACCELERATING", "RAPID ACCELERATION"):
            return "CRITICAL"

    if epss_accelerating:
        severity = "HIGH"

    return severity


# =================================================
# ATT&CK COVERAGE GAP ANALYSIS
# =================================================

def analyze_attack_coverage(
    cves: List[Dict],
    malware_items: List[Dict],
    attack_techniques: List[Dict],
) -> List[Dict]:
    """
    Analyze ATT&CK coverage gaps.

    Args:
        cves: Enriched CVE list (severity, EPSS, acceleration)
        malware_items: Active malware campaigns
        attack_techniques: ATT&CK techniques used by campaigns

    Returns:
        List of coverage gap findings with severity and context.
    """

    # Techniques observed in current threat activity
    observed_techniques: Set[str] = set(
        tech["external_id"] for tech in attack_techniques
    )

    # Determine uncovered techniques
    uncovered = observed_techniques - DETECTED_TECHNIQUES

    coverage_gaps = []

    for tech in attack_techniques:
        tech_id = tech["external_id"]

        if tech_id not in uncovered:
            continue

        # Detect if malware campaigns are active
        active_malware = len(malware_items) > 0

        # Detect EPSS acceleration across CVEs
        epss_accelerating = any(
            cve.get("epss_acceleration") in ("ACCELERATING", "RAPID ACCELERATION")
            for cve in cves
        )

        gap_severity = _calculate_gap_severity(
            cves=cves,
            epss_accelerating=epss_accelerating,
        )

        coverage_gaps.append({
            "technique_id": tech_id,
            "technique_name": tech.get("name"),
            "tactic": tech.get("tactic"),
            "status": "UNDETECTED",
            "gap_severity": gap_severity,
            "active_malware": active_malware,
            "epss_accelerating": epss_accelerating,
            "recommended_action": "DETECTION REQUIRED",
        })

    return coverage_gaps


# =================================================
# HUMAN-READABLE SUMMARY (OPTIONAL)
# =================================================

def summarize_gaps(coverage_gaps: List[Dict]) -> str:
    """
    Generate a human-readable summary for reports or blogs.
    """
    if not coverage_gaps:
        return "✅ No ATT&CK coverage gaps detected."

    lines = ["🚨 ATT&CK Coverage Gaps Identified:\n"]

    for gap in coverage_gaps:
        lines.append(
            f"- [{gap['gap_severity']}] "
            f"{gap['technique_id']} ({gap['technique_name']}) | "
            f"Tactic: {gap['tactic']} | "
            f"Action: {gap['recommended_action']}"
        )

    return "\n".join(lines)
