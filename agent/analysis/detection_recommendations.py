"""
Detection Recommendation Engine – FINAL PRODUCTION VERSION

Purpose:
Generate Sigma and KQL detection recommendations
for uncovered MITRE ATT&CK techniques identified
by ATT&CK coverage gap analysis.

Designed for:
SOC • Detection Engineering • Purple Team • Microsoft Sentinel • SIEM Teams
"""

from typing import List, Dict


# =================================================
# DETECTION KNOWLEDGE BASE (ATT&CK → DETECTIONS)
# =================================================
# NOTE:
# These are BASELINE detection recommendations.
# In production, teams should refine thresholds,
# allowlists, and tuning per environment.
# =================================================

DETECTION_LIBRARY = {
    "T1059": {
        "title": "Suspicious Command Interpreter Execution",
        "description": "Detects execution of common command interpreters often abused by malware.",
        "sigma": {
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "Image|endswith": [
                        "\\cmd.exe",
                        "\\powershell.exe",
                        "\\wscript.exe",
                        "\\cscript.exe"
                    ]
                },
                "condition": "selection"
            }
        },
        "kql": """
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\cmd.exe"
   or NewProcessName endswith "\\powershell.exe"
   or NewProcessName endswith "\\wscript.exe"
   or NewProcessName endswith "\\cscript.exe"
"""
    },

    "T1059.001": {
        "title": "Suspicious PowerShell Execution",
        "description": "Detects PowerShell executions commonly used for payload delivery or execution.",
        "sigma": {
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "Image|endswith": ["\\powershell.exe"],
                    "CommandLine|contains": [
                        "-enc",
                        "IEX",
                        "Invoke-Expression",
                        "DownloadString"
                    ]
                },
                "condition": "selection"
            }
        },
        "kql": """
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\powershell.exe"
| where CommandLine contains "-enc"
   or CommandLine contains "IEX"
   or CommandLine contains "Invoke-Expression"
   or CommandLine contains "DownloadString"
"""
    },

    "T1105": {
        "title": "Ingress Tool Transfer via Network",
        "description": "Detects suspicious network-based payload retrieval activity.",
        "sigma": {
            "logsource": {
                "category": "network_connection",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "DestinationPort": [80, 443],
                    "Initiated": "true"
                },
                "condition": "selection"
            }
        },
        "kql": """
DeviceNetworkEvents
| where RemotePort in (80, 443)
| where InitiatingProcessFileName has_any (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe"
)
"""
    },

    "T1190": {
        "title": "Exploit Attempt on Public-Facing Application",
        "description": "Detects potential exploitation attempts against web applications.",
        "sigma": {
            "logsource": {
                "category": "webserver",
                "product": "generic"
            },
            "detection": {
                "selection": {
                    "cs-method": ["POST"],
                    "cs-uri-query|contains": [
                        "cmd=",
                        "exec=",
                        "powershell",
                        "base64"
                    ]
                },
                "condition": "selection"
            }
        },
        "kql": """
AzureDiagnostics
| where httpMethod_s == "POST"
| where requestUri_s has_any (
    "cmd=",
    "exec=",
    "powershell",
    "base64"
)
"""
    },

    "T1027": {
        "title": "Obfuscated or Encoded Payload Execution",
        "description": "Detects execution of encoded or obfuscated commands.",
        "sigma": {
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "CommandLine|contains": [
                        "-enc",
                        "FromBase64String",
                        "Base64"
                    ]
                },
                "condition": "selection"
            }
        },
        "kql": """
SecurityEvent
| where EventID == 4688
| where CommandLine contains "-enc"
   or CommandLine contains "FromBase64String"
   or CommandLine contains "Base64"
"""
    },
}


# =================================================
# RECOMMENDATION ENGINE
# =================================================

def generate_detection_recommendations(
    coverage_gaps: List[Dict]
) -> List[Dict]:
    """
    Generate Sigma and KQL detection recommendations
    for uncovered ATT&CK techniques.

    Args:
        coverage_gaps: Output from attack_coverage.analyze_attack_coverage()

    Returns:
        List of detection recommendations.
    """

    recommendations: List[Dict] = []

    for gap in coverage_gaps:
        tech_id = gap.get("technique_id")
        severity = gap.get("gap_severity")

        if tech_id not in DETECTION_LIBRARY:
            continue

        detection = DETECTION_LIBRARY[tech_id]

        priority = "P3"
        if severity == "CRITICAL":
            priority = "P1"
        elif severity == "HIGH":
            priority = "P2"

        recommendations.append({
            "technique_id": tech_id,
            "technique_name": gap.get("technique_name"),
            "tactic": gap.get("tactic"),
            "gap_severity": severity,
            "priority": priority,
            "detection_title": detection["title"],
            "detection_description": detection["description"],
            "sigma_rule": {
                "title": detection["title"],
                "logsource": detection["sigma"]["logsource"],
                "detection": detection["sigma"]["detection"],
            },
            "kql_query": detection["kql"].strip(),
            "recommended_action": "IMPLEMENT DETECTION",
        })

    return recommendations


# =================================================
# REPORTING / SUMMARY UTILITIES
# =================================================

def summarize_recommendations(recommendations: List[Dict]) -> str:
    """
    Generate a human-readable summary for reports, blogs, or tickets.
    """
    if not recommendations:
        return "✅ No detection recommendations required."

    lines = ["🛡️ Detection Recommendations (SOC Action Required):\n"]

    for rec in recommendations:
        lines.append(
            f"- [{rec['gap_severity']}] "
            f"{rec['technique_id']} – {rec['detection_title']} | "
            f"Priority: {rec['priority']}"
        )

    return "\n".join(lines)
