"""
MITRE ATT&CK Navigator Layer Export – FINAL PRODUCTION VERSION

Purpose:
Generate ATT&CK Navigator-compatible heatmap JSON
based on ATT&CK coverage gap analysis.

Highlights:
- Risk-weighted coloring (CRITICAL / HIGH / MEDIUM / COVERED)
- Tactic-aware technique mapping
- Human-readable annotations
- Navigator v4.x compliant

Designed for:
SOC • Purple Team • Detection Engineering • CISO Reporting
"""

import json
from typing import List, Dict
from datetime import datetime, timezone


# =================================================
# COLOR SCHEME (ATT&CK NAVIGATOR STANDARD)
# =================================================
# Red     = Critical coverage gap
# Orange  = High coverage gap
# Yellow  = Medium coverage gap
# Green   = Covered technique
# =================================================

SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff944d",
    "MEDIUM": "#ffd24d",
    "COVERED": "#5cd65c",
}


# =================================================
# ATT&CK NAVIGATOR EXPORT ENGINE
# =================================================

def export_attack_navigator_layer(
    coverage_gaps: List[Dict],
    attack_techniques: List[Dict],
    output_path: str,
) -> str:
    """
    Export MITRE ATT&CK Navigator heatmap layer.

    Args:
        coverage_gaps: Output from attack_coverage.analyze_attack_coverage()
        attack_techniques: MITRE_ATTACK_TECHNIQUES list
        output_path: Destination JSON file path

    Returns:
        Path to generated Navigator layer JSON
    """

    # Map gaps by technique ID for quick lookup
    gap_map = {
        gap["technique_id"]: gap
        for gap in coverage_gaps
    }

    techniques_layer = []

    for tech in attack_techniques:
        tech_id = tech.get("external_id")
        tactic = tech.get("tactic")

        if tech_id in gap_map:
            gap = gap_map[tech_id]
            severity = gap.get("gap_severity", "MEDIUM")

            color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["MEDIUM"])
            score = {
                "CRITICAL": 100,
                "HIGH": 80,
                "MEDIUM": 50,
            }.get(severity, 50)

            comment = (
                f"UNDETECTED | Severity: {severity} | "
                f"Tactic: {tactic} | "
                f"Action: Detection required"
            )
        else:
            color = SEVERITY_COLORS["COVERED"]
            score = 10
            comment = "Covered by existing detections"

        techniques_layer.append({
            "techniqueID": tech_id,
            "tactic": tactic,
            "score": score,
            "color": color,
            "comment": comment,
            "enabled": True,
        })

    navigator_layer = {
        "name": "ATT&CK Coverage Heatmap – CYBERDUDEBIVASH",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": (
            "ATT&CK coverage heatmap generated from active threat intelligence, "
            "coverage gap analysis, CVE severity, and EPSS exploitation trends."
        ),
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"]
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True
        },
        "hideDisabled": False,
        "legendItems": [
            {"label": "Critical Coverage Gap", "color": SEVERITY_COLORS["CRITICAL"]},
            {"label": "High Coverage Gap", "color": SEVERITY_COLORS["HIGH"]},
            {"label": "Medium Coverage Gap", "color": SEVERITY_COLORS["MEDIUM"]},
            {"label": "Covered Technique", "color": SEVERITY_COLORS["COVERED"]},
        ],
        "techniques": techniques_layer,
        "metadata": [
            {
                "name": "Generated",
                "value": datetime.now(timezone.utc).isoformat()
            },
            {
                "name": "Source",
                "value": "CDB-SENTINEL Threat Intelligence Platform"
            },
            {
                "name": "Use Case",
                "value": "ATT&CK Coverage Gap Analysis"
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(navigator_layer, f, indent=2)

    return output_path
