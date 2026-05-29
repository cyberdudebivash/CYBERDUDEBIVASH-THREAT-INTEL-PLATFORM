"""
CYBERDUDEBIVASH SENTINEL APEX — Phase 98
Customer Exposure Intelligence Engine
Port: 8513

Maps customer profiles to relevant CVEs, active threat campaigns, and ATT&CK
techniques to generate tailored exposure reports and prioritized remediation actions.
"""

import uuid
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
customer_profiles: dict = {}
cve_catalog: dict = {}
campaign_catalog: dict = {}
technique_catalog: dict = {}

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
def _seed():
    now = datetime.utcnow()

    # 3 org profiles
    profiles = [
        {
            "org_id": "ORG-FINTECH-001",
            "industry": "FinTech",
            "tech_stack": ["AWS", "Kubernetes", "PostgreSQL", "React", "Python", "SWIFT"],
            "geography": "US",
            "company_size": "mid",
        },
        {
            "org_id": "ORG-HEALTH-002",
            "industry": "Healthcare",
            "tech_stack": ["Azure", "Windows Server", "SQL Server", "Epic EHR", ".NET"],
            "geography": "US",
            "company_size": "large",
        },
        {
            "org_id": "ORG-MANUF-003",
            "industry": "Manufacturing",
            "tech_stack": ["OT/ICS", "Windows", "Siemens PLC", "VPN", "SAP"],
            "geography": "EU",
            "company_size": "large",
        },
    ]
    for p in profiles:
        customer_profiles[p["org_id"]] = p

    # 8 CVEs
    cves = [
        {
            "cve_id": "CVE-2024-21413",
            "cvss_score": 9.8,
            "description": "Microsoft Outlook Remote Code Execution via malicious link preview",
            "affected_products": ["Windows", ".NET", "Outlook"],
            "published": (now - timedelta(days=40)).strftime("%Y-%m-%d"),
            "remediation": "Apply MS Patch KB5034763; disable link preview",
            "detection_available": True,
        },
        {
            "cve_id": "CVE-2024-3400",
            "cvss_score": 10.0,
            "description": "PAN-OS GlobalProtect OS command injection — zero-day",
            "affected_products": ["VPN", "Palo Alto"],
            "published": (now - timedelta(days=20)).strftime("%Y-%m-%d"),
            "remediation": "Upgrade PAN-OS >= 10.2.9-h1; disable GlobalProtect if not required",
            "detection_available": True,
        },
        {
            "cve_id": "CVE-2024-20353",
            "cvss_score": 8.6,
            "description": "Cisco ASA/FTD denial-of-service via crafted HTTP request",
            "affected_products": ["AWS", "Kubernetes"],
            "published": (now - timedelta(days=55)).strftime("%Y-%m-%d"),
            "remediation": "Upgrade Cisco ASA to 9.16.4.67 or later",
            "detection_available": False,
        },
        {
            "cve_id": "CVE-2024-1709",
            "cvss_score": 10.0,
            "description": "ConnectWise ScreenConnect authentication bypass — actively exploited",
            "affected_products": ["Windows Server", "SQL Server"],
            "published": (now - timedelta(days=30)).strftime("%Y-%m-%d"),
            "remediation": "Upgrade to ScreenConnect 23.9.8 immediately",
            "detection_available": True,
        },
        {
            "cve_id": "CVE-2023-46604",
            "cvss_score": 9.8,
            "description": "Apache ActiveMQ RCE via ClassInfo OpenWire protocol",
            "affected_products": ["Python", "AWS", "Kubernetes"],
            "published": (now - timedelta(days=180)).strftime("%Y-%m-%d"),
            "remediation": "Upgrade ActiveMQ >= 5.15.16; block port 61616 externally",
            "detection_available": True,
        },
        {
            "cve_id": "CVE-2024-21887",
            "cvss_score": 9.1,
            "description": "Ivanti Connect Secure command injection — mass exploitation observed",
            "affected_products": ["VPN", "Windows Server"],
            "published": (now - timedelta(days=70)).strftime("%Y-%m-%d"),
            "remediation": "Apply Ivanti patches; run integrity checker tool",
            "detection_available": True,
        },
        {
            "cve_id": "CVE-2024-4978",
            "cvss_score": 7.8,
            "description": "Siemens S7 PLC firmware privilege escalation",
            "affected_products": ["OT/ICS", "Siemens PLC"],
            "published": (now - timedelta(days=15)).strftime("%Y-%m-%d"),
            "remediation": "Apply Siemens firmware update; segment OT network",
            "detection_available": False,
        },
        {
            "cve_id": "CVE-2024-6387",
            "cvss_score": 8.1,
            "description": "OpenSSH regreSSHion — signal handler race condition RCE",
            "affected_products": ["AWS", "Kubernetes", "Azure", "Python"],
            "published": (now - timedelta(days=10)).strftime("%Y-%m-%d"),
            "remediation": "Upgrade OpenSSH >= 9.8p1; set LoginGraceTime=0 as temporary mitigation",
            "detection_available": True,
        },
    ]
    for c in cves:
        cve_catalog[c["cve_id"]] = c

    # 4 campaigns
    campaigns = [
        {
            "campaign_id": "CAMP-001",
            "name": "Scattered Spider — Financial Sector BEC Wave",
            "threat_actor": "Scattered Spider (UNC3944)",
            "targeted_industries": ["FinTech", "Banking", "Insurance"],
            "targeted_geos": ["US", "UK"],
            "attck_techniques": ["T1566.002", "T1078", "T1621", "T1530"],
            "severity": "critical",
        },
        {
            "campaign_id": "CAMP-002",
            "name": "Volt Typhoon — Critical Infrastructure Pre-positioning",
            "threat_actor": "Volt Typhoon (BRONZE SILHOUETTE)",
            "targeted_industries": ["Manufacturing", "Energy", "Utilities"],
            "targeted_geos": ["US", "EU"],
            "attck_techniques": ["T1190", "T1133", "T1505.003", "T1071.001"],
            "severity": "critical",
        },
        {
            "campaign_id": "CAMP-003",
            "name": "BlackCat ALPHV — Healthcare Ransomware Campaign",
            "threat_actor": "ALPHV/BlackCat",
            "targeted_industries": ["Healthcare", "Pharma"],
            "targeted_geos": ["US", "CA"],
            "attck_techniques": ["T1486", "T1490", "T1083", "T1560"],
            "severity": "high",
        },
        {
            "campaign_id": "CAMP-004",
            "name": "LockBit 3.0 — Mid-Market Supply Chain Targeting",
            "threat_actor": "LockBit 3.0",
            "targeted_industries": ["FinTech", "Manufacturing", "Retail"],
            "targeted_geos": ["US", "EU", "APAC"],
            "attck_techniques": ["T1195", "T1059.001", "T1486", "T1027"],
            "severity": "high",
        },
    ]
    for c in campaigns:
        campaign_catalog[c["campaign_id"]] = c

    # 10 ATT&CK techniques
    techniques = [
        ("T1566.002", "Spearphishing Link", "Initial Access", "Email gateway filtering, URL sandboxing"),
        ("T1078", "Valid Accounts", "Defense Evasion", "MFA enforcement, privileged access review"),
        ("T1190", "Exploit Public-Facing Application", "Initial Access", "Patch management, WAF rules"),
        ("T1133", "External Remote Services", "Persistence", "VPN access review, geo-based controls"),
        ("T1486", "Data Encrypted for Impact", "Impact", "Offline backups, endpoint behavioral detection"),
        ("T1059.001", "PowerShell", "Execution", "Script block logging, AMSI integration"),
        ("T1505.003", "Web Shell", "Persistence", "File integrity monitoring, web server hardening"),
        ("T1083", "File and Directory Discovery", "Discovery", "Least-privilege filesystem controls"),
        ("T1560", "Archive Collected Data", "Collection", "DLP policy, egress monitoring"),
        ("T1195", "Supply Chain Compromise", "Initial Access", "Software bill of materials, vendor vetting"),
    ]
    for tid, name, tactic, action in techniques:
        technique_catalog[tid] = {
            "technique_id": tid,
            "name": name,
            "tactic": tactic,
            "detection_available": random.choice([True, True, False]),
            "recommended_action": action,
        }

_seed()

# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------

def _score_cve_relevance(cve: dict, profile: dict) -> int:
    """Score 0-100 how relevant a CVE is to the org's tech stack."""
    matches = sum(1 for prod in cve["affected_products"] if prod in profile["tech_stack"])
    base = int((matches / max(len(cve["affected_products"]), 1)) * 60)
    base += int(cve["cvss_score"] * 4)
    return min(100, base)


def _score_campaign_relevance(campaign: dict, profile: dict) -> int:
    industry_match = profile["industry"] in campaign["targeted_industries"]
    geo_match = profile["geography"] in campaign["targeted_geos"]
    score = 0
    if industry_match:
        score += 55
    if geo_match:
        score += 25
    if campaign["severity"] == "critical":
        score += 20
    elif campaign["severity"] == "high":
        score += 10
    return min(100, score)


def _score_technique_relevance(technique_id: str, campaigns_relevant: list) -> int:
    count = sum(1 for c in campaigns_relevant if technique_id in c["attck_techniques"])
    return min(100, count * 35 + 10)


def get_relevant_cves(org_id: str, min_cvss: float = 7.0) -> list:
    profile = customer_profiles.get(org_id)
    if not profile:
        raise KeyError(f"Org {org_id} not found")
    results = []
    for cve in cve_catalog.values():
        if cve["cvss_score"] < min_cvss:
            continue
        rel = _score_cve_relevance(cve, profile)
        entry = dict(cve)
        entry["org_relevance_score"] = rel
        results.append(entry)
    return sorted(results, key=lambda x: (x["org_relevance_score"], x["cvss_score"]), reverse=True)


def get_active_campaigns(org_id: str) -> list:
    profile = customer_profiles.get(org_id)
    if not profile:
        raise KeyError(f"Org {org_id} not found")
    results = []
    for camp in campaign_catalog.values():
        rel = _score_campaign_relevance(camp, profile)
        if rel > 0:
            entry = dict(camp)
            entry["org_relevance_score"] = rel
            results.append(entry)
    return sorted(results, key=lambda x: x["org_relevance_score"], reverse=True)


def get_attck_exposure(org_id: str) -> list:
    profile = customer_profiles.get(org_id)
    if not profile:
        raise KeyError(f"Org {org_id} not found")
    relevant_campaigns = get_active_campaigns(org_id)
    results = []
    for tid, tech in technique_catalog.items():
        rel = _score_technique_relevance(tid, relevant_campaigns)
        entry = dict(tech)
        entry["org_relevance_score"] = rel
        results.append(entry)
    return sorted(results, key=lambda x: x["org_relevance_score"], reverse=True)


def calculate_exposure_score(org_id: str) -> int:
    cves = get_relevant_cves(org_id)
    campaigns = get_active_campaigns(org_id)
    techniques = get_attck_exposure(org_id)

    critical_cves = sum(1 for c in cves if c["cvss_score"] >= 9.0 and c["org_relevance_score"] >= 50)
    critical_campaigns = sum(1 for c in campaigns if c["severity"] == "critical" and c["org_relevance_score"] >= 50)
    high_techs = sum(1 for t in techniques if t["org_relevance_score"] >= 50)

    score = min(100, critical_cves * 12 + critical_campaigns * 18 + high_techs * 5)
    return score


def get_recommended_actions(org_id: str) -> list:
    cves = get_relevant_cves(org_id)
    techniques = get_attck_exposure(org_id)
    actions = []

    for cve in cves[:3]:
        actions.append({
            "priority": "critical" if cve["cvss_score"] >= 9.0 else "high",
            "type": "patch",
            "title": f"Patch {cve['cve_id']}",
            "detail": cve["remediation"],
            "cvss": cve["cvss_score"],
        })

    for tech in techniques[:3]:
        if tech["org_relevance_score"] >= 40:
            actions.append({
                "priority": "high",
                "type": "detection",
                "title": f"Improve detection for {tech['name']} ({tech['technique_id']})",
                "detail": tech["recommended_action"],
            })

    return sorted(actions, key=lambda a: (0 if a["priority"] == "critical" else 1))


def get_org_exposure(org_id: str) -> dict:
    profile = customer_profiles.get(org_id)
    if not profile:
        raise KeyError(f"Org {org_id} not found")
    cves = get_relevant_cves(org_id)
    campaigns = get_active_campaigns(org_id)
    techniques = get_attck_exposure(org_id)
    score = calculate_exposure_score(org_id)
    actions = get_recommended_actions(org_id)

    return {
        "org_id": org_id,
        "org_name": profile["industry"],
        "generated_at": datetime.utcnow().isoformat(),
        "overall_exposure_score": score,
        "critical_cves": [c for c in cves if c["cvss_score"] >= 9.0],
        "active_campaigns": campaigns,
        "high_risk_techniques": [t for t in techniques if t["org_relevance_score"] >= 40],
        "recommended_actions": actions,
        "summary": {
            "total_relevant_cves": len(cves),
            "total_relevant_campaigns": len(campaigns),
            "attck_techniques_exposed": len([t for t in techniques if t["org_relevance_score"] > 0]),
        },
    }

# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/api/exposure/<org_id>", methods=["GET"])
def api_full_exposure(org_id):
    """Return full exposure report for an organization."""
    try:
        return jsonify(get_org_exposure(org_id))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/exposure/<org_id>/cves", methods=["GET"])
def api_relevant_cves(org_id):
    """Return CVEs relevant to the organization, sorted by relevance."""
    try:
        min_cvss = float(request.args.get("min_cvss", 7.0))
        return jsonify(get_relevant_cves(org_id, min_cvss))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/exposure/<org_id>/campaigns", methods=["GET"])
def api_campaigns(org_id):
    """Return active threat campaigns relevant to the organization."""
    try:
        return jsonify(get_active_campaigns(org_id))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/exposure/<org_id>/techniques", methods=["GET"])
def api_techniques(org_id):
    """Return ATT&CK techniques relevant to the organization."""
    try:
        return jsonify(get_attck_exposure(org_id))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/exposure/<org_id>/actions", methods=["GET"])
def api_actions(org_id):
    """Return prioritized recommended actions for the organization."""
    try:
        return jsonify(get_recommended_actions(org_id))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "exposure_intelligence_engine", "phase": 98})


if __name__ == "__main__":
    print("CYBERDUDEBIVASH SENTINEL APEX — Phase 98: Customer Exposure Intelligence Engine")
    print("Running on http://0.0.0.0:8513")
    app.run(host="0.0.0.0", port=8513, debug=False)
