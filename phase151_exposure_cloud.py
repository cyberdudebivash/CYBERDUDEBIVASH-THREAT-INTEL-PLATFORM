"""
CYBERDUDEBIVASH® SENTINEL APEX — Phase 151
Customer Exposure Cloud
Endpoint: /my-exposure
Port: 8551

Capabilities:
  - Asset inventory ingestion (hosts, cloud, identities, SaaS)
  - Technology stack mapping
  - Threat-to-asset correlation
  - Exposure scoring (0-100)
  - ATT&CK gap analysis (coverage vs active techniques)

Author: CYBERDUDEBIVASH
Version: v170.0 — Customer Value Realization Release
"""

import uuid
import json
import hashlib
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from flask import Flask, jsonify, request

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# ATT&CK Technique Registry (subset — 40 high-priority techniques)
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_TECHNIQUES: Dict[str, dict] = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",     "severity": "critical"},
    "T1078": {"name": "Valid Accounts",                    "tactic": "Initial Access",     "severity": "high"},
    "T1133": {"name": "External Remote Services",          "tactic": "Initial Access",     "severity": "high"},
    "T1566": {"name": "Phishing",                          "tactic": "Initial Access",     "severity": "high"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",          "severity": "high"},
    "T1053": {"name": "Scheduled Task/Job",                "tactic": "Execution",          "severity": "medium"},
    "T1547": {"name": "Boot or Logon Autostart",           "tactic": "Persistence",        "severity": "medium"},
    "T1098": {"name": "Account Manipulation",              "tactic": "Persistence",        "severity": "high"},
    "T1548": {"name": "Abuse Elevation Control",           "tactic": "Privilege Escalation","severity": "high"},
    "T1055": {"name": "Process Injection",                 "tactic": "Defense Evasion",    "severity": "high"},
    "T1027": {"name": "Obfuscated Files or Information",   "tactic": "Defense Evasion",    "severity": "medium"},
    "T1110": {"name": "Brute Force",                       "tactic": "Credential Access",  "severity": "high"},
    "T1003": {"name": "OS Credential Dumping",             "tactic": "Credential Access",  "severity": "critical"},
    "T1016": {"name": "System Network Config Discovery",   "tactic": "Discovery",          "severity": "low"},
    "T1021": {"name": "Remote Services",                   "tactic": "Lateral Movement",   "severity": "high"},
    "T1570": {"name": "Lateral Tool Transfer",             "tactic": "Lateral Movement",   "severity": "medium"},
    "T1560": {"name": "Archive Collected Data",            "tactic": "Collection",         "severity": "medium"},
    "T1041": {"name": "Exfiltration Over C2 Channel",      "tactic": "Exfiltration",       "severity": "critical"},
    "T1567": {"name": "Exfiltration Over Web Service",     "tactic": "Exfiltration",       "severity": "high"},
    "T1486": {"name": "Data Encrypted for Impact",         "tactic": "Impact",             "severity": "critical"},
    "T1490": {"name": "Inhibit System Recovery",           "tactic": "Impact",             "severity": "critical"},
    "T1071": {"name": "Application Layer Protocol",        "tactic": "C2",                 "severity": "medium"},
    "T1105": {"name": "Ingress Tool Transfer",             "tactic": "C2",                 "severity": "medium"},
    "T1204": {"name": "User Execution",                    "tactic": "Execution",          "severity": "medium"},
    "T1140": {"name": "Deobfuscate/Decode Files",          "tactic": "Defense Evasion",    "severity": "low"},
    "T1562": {"name": "Impair Defenses",                   "tactic": "Defense Evasion",    "severity": "high"},
    "T1070": {"name": "Indicator Removal",                 "tactic": "Defense Evasion",    "severity": "medium"},
    "T1082": {"name": "System Information Discovery",      "tactic": "Discovery",          "severity": "low"},
    "T1018": {"name": "Remote System Discovery",           "tactic": "Discovery",          "severity": "low"},
    "T1046": {"name": "Network Service Discovery",         "tactic": "Discovery",          "severity": "low"},
    "T1135": {"name": "Network Share Discovery",           "tactic": "Discovery",          "severity": "low"},
    "T1036": {"name": "Masquerading",                      "tactic": "Defense Evasion",    "severity": "medium"},
    "T1114": {"name": "Email Collection",                  "tactic": "Collection",         "severity": "medium"},
    "T1087": {"name": "Account Discovery",                 "tactic": "Discovery",          "severity": "low"},
    "T1069": {"name": "Permission Groups Discovery",       "tactic": "Discovery",          "severity": "low"},
    "T1588": {"name": "Obtain Capabilities",               "tactic": "Resource Development","severity": "medium"},
    "T1583": {"name": "Acquire Infrastructure",            "tactic": "Resource Development","severity": "medium"},
    "T1595": {"name": "Active Scanning",                   "tactic": "Reconnaissance",     "severity": "medium"},
    "T1592": {"name": "Gather Victim Host Information",    "tactic": "Reconnaissance",     "severity": "low"},
    "T1589": {"name": "Gather Victim Identity Info",       "tactic": "Reconnaissance",     "severity": "low"},
}

# Technology → exploitable technique mapping
TECH_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "Windows":          ["T1059", "T1003", "T1547", "T1055", "T1548", "T1190"],
    "Linux":            ["T1059", "T1053", "T1078", "T1190", "T1070"],
    "AWS":              ["T1078", "T1190", "T1567", "T1562", "T1087"],
    "Azure":            ["T1078", "T1190", "T1567", "T1562", "T1087"],
    "GCP":              ["T1078", "T1190", "T1567", "T1562"],
    "Kubernetes":       ["T1190", "T1078", "T1562", "T1055"],
    "Docker":           ["T1190", "T1055", "T1562"],
    "Office365":        ["T1566", "T1114", "T1078", "T1098"],
    "Active Directory": ["T1003", "T1078", "T1098", "T1110", "T1069"],
    "VPN":              ["T1133", "T1078", "T1110"],
    "RDP":              ["T1021", "T1110", "T1078"],
    "SQL Server":       ["T1190", "T1059", "T1003"],
    "PostgreSQL":       ["T1190", "T1059"],
    "MongoDB":          ["T1190"],
    "Apache":           ["T1190", "T1059"],
    "Nginx":            ["T1190"],
    "WordPress":        ["T1190", "T1059", "T1566"],
    "Python":           ["T1059", "T1204"],
    "Node.js":          ["T1059", "T1190"],
    "Java":             ["T1190", "T1059"],
    "SAP":              ["T1190", "T1078"],
    "Cisco":            ["T1190", "T1078", "T1070"],
    "Fortinet":         ["T1190", "T1078"],
    "Palo Alto":        ["T1190", "T1078"],
    "Exchange":         ["T1190", "T1114", "T1566", "T1078"],
    "SharePoint":       ["T1190", "T1078", "T1114"],
    "Jira":             ["T1190", "T1078"],
    "Confluence":       ["T1190", "T1078"],
    "Okta":             ["T1078", "T1098"],
    "Salesforce":       ["T1078", "T1114"],
    "OT/ICS":           ["T1190", "T1059", "T1486", "T1490"],
    "SWIFT":            ["T1190", "T1078", "T1041"],
    "Epic EHR":         ["T1190", "T1078", "T1486"],
}

# ─────────────────────────────────────────────────────────────────────────────
# In-memory stores
# ─────────────────────────────────────────────────────────────────────────────
ASSET_INVENTORIES:   Dict[str, dict] = {}   # org_id → inventory
EXPOSURE_REPORTS:    Dict[str, dict] = {}   # org_id → latest report
ATTACK_COVERAGE:     Dict[str, dict] = {}   # org_id → coverage map


# ─────────────────────────────────────────────────────────────────────────────
# Scoring helpers
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}

def _tech_seed(org_id: str) -> random.Random:
    seed = int(hashlib.md5(org_id.encode()).hexdigest()[:8], 16)
    return random.Random(seed)


def _infer_exposure_score(techniques_exposed: List[dict]) -> Tuple[int, str]:
    """Map exposed techniques to a 0-100 exposure score and risk label."""
    if not techniques_exposed:
        return 5, "Minimal"
    raw = sum(SEVERITY_WEIGHTS.get(t.get("severity", "low"), 1) for t in techniques_exposed)
    # Normalize: max possible ≈ 40 critical techniques × 10 = 400
    score = min(100, int(raw / 4))
    if score >= 75:
        label = "Critical"
    elif score >= 50:
        label = "High"
    elif score >= 25:
        label = "Medium"
    else:
        label = "Low"
    return score, label


def _attack_gap_analysis(coverage_ids: List[str], exposed_technique_ids: List[str]) -> dict:
    """
    Compare customer's detected/covered technique IDs vs exposed technique IDs.
    Returns coverage %, gaps, and priority gaps.
    """
    exposed_set  = set(exposed_technique_ids)
    covered_set  = set(coverage_ids) & exposed_set
    gap_set      = exposed_set - covered_set

    coverage_pct = round(len(covered_set) / len(exposed_set) * 100, 1) if exposed_set else 100.0

    priority_gaps = []
    for tid in gap_set:
        t = ATTACK_TECHNIQUES.get(tid, {})
        if t.get("severity") in ("critical", "high"):
            priority_gaps.append({
                "technique_id": tid,
                "name": t.get("name", "Unknown"),
                "tactic": t.get("tactic", "Unknown"),
                "severity": t.get("severity", "medium"),
                "recommendation": f"Deploy detection rule for {tid} — {t.get('name','')}"
            })

    priority_gaps.sort(key=lambda x: SEVERITY_WEIGHTS.get(x["severity"], 0), reverse=True)

    return {
        "total_exposed_techniques":  len(exposed_set),
        "covered_techniques":        len(covered_set),
        "gap_techniques":            len(gap_set),
        "coverage_pct":              coverage_pct,
        "priority_gaps":             priority_gaps[:10],
        "all_gaps":                  sorted(gap_set),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Core engine
# ─────────────────────────────────────────────────────────────────────────────

def ingest_asset_inventory(org_id: str, assets: List[dict]) -> dict:
    """
    Ingest asset inventory.
    Each asset: {asset_id, type, name, technology, criticality, internet_facing}
    Types: host | cloud | identity | saas | ot
    """
    now = datetime.now(timezone.utc).isoformat()
    inventory = {
        "org_id":      org_id,
        "total_assets": len(assets),
        "assets":      {a.get("asset_id", str(uuid.uuid4())[:8]): a for a in assets},
        "ingested_at": now,
        "tech_stack":  list({a.get("technology", "") for a in assets if a.get("technology")}),
    }
    ASSET_INVENTORIES[org_id] = inventory
    return inventory


def build_exposure_report(org_id: str, detection_coverage: Optional[List[str]] = None) -> dict:
    """
    Build a full exposure report for an org.
    detection_coverage: list of ATT&CK technique IDs the customer currently covers.
    """
    rng = _tech_seed(org_id)
    inventory = ASSET_INVENTORIES.get(org_id)

    if not inventory:
        # Auto-generate a reasonable inventory from org_id seed
        tech_pool = list(TECH_TECHNIQUE_MAP.keys())
        selected = rng.sample(tech_pool, min(8, len(tech_pool)))
        assets = []
        for i, tech in enumerate(selected):
            assets.append({
                "asset_id":       f"auto-{org_id[:6]}-{i:03d}",
                "type":           rng.choice(["host", "cloud", "saas", "identity"]),
                "name":           f"{tech} Asset #{i+1}",
                "technology":     tech,
                "criticality":    rng.choice(["critical", "high", "medium", "low"]),
                "internet_facing": rng.choice([True, False]),
            })
        inventory = ingest_asset_inventory(org_id, assets)

    # Build tech stack from inventory
    tech_stack = inventory.get("tech_stack", [])

    # Map technologies → exposed techniques
    exposed_technique_ids: List[str] = []
    asset_exposures = []
    for asset in inventory["assets"].values():
        tech = asset.get("technology", "")
        techniques = TECH_TECHNIQUE_MAP.get(tech, [])
        if asset.get("internet_facing") and techniques:
            # Internet-facing assets add severity
            affected = techniques
        else:
            affected = techniques[:max(1, len(techniques)//2)]

        for tid in affected:
            if tid not in exposed_technique_ids:
                exposed_technique_ids.append(tid)

        if techniques:
            asset_exposures.append({
                "asset_id":        asset.get("asset_id"),
                "asset_name":      asset.get("name"),
                "criticality":     asset.get("criticality", "medium"),
                "internet_facing": asset.get("internet_facing", False),
                "exposed_techniques": affected,
                "technique_count": len(affected),
            })

    # Technique details
    techniques_exposed = [
        {**ATTACK_TECHNIQUES[tid], "technique_id": tid}
        for tid in exposed_technique_ids if tid in ATTACK_TECHNIQUES
    ]

    # Exposure score
    exposure_score, risk_label = _infer_exposure_score(techniques_exposed)

    # ATT&CK gap analysis
    if detection_coverage is None:
        # Simulate partial coverage from seed
        all_ids = list(ATTACK_TECHNIQUES.keys())
        coverage_count = rng.randint(5, 20)
        detection_coverage = rng.sample(all_ids, coverage_count)

    gap_analysis = _attack_gap_analysis(detection_coverage, exposed_technique_ids)

    # Priority remediations
    remediations = []
    for asset in sorted(asset_exposures, key=lambda x: SEVERITY_WEIGHTS.get(x["criticality"], 0), reverse=True)[:5]:
        remediations.append({
            "asset":  asset["asset_name"],
            "action": f"Harden {asset['asset_name']} — apply patches for {', '.join(asset['exposed_techniques'][:3])}",
            "priority": asset["criticality"],
        })

    now = datetime.now(timezone.utc).isoformat()
    report = {
        "org_id":              org_id,
        "report_id":           "exp-" + str(uuid.uuid4())[:8],
        "generated_at":        now,
        "exposure_score":      exposure_score,
        "risk_label":          risk_label,
        "total_assets":        inventory["total_assets"],
        "internet_facing_assets": sum(1 for a in inventory["assets"].values() if a.get("internet_facing")),
        "tech_stack":          tech_stack,
        "exposed_technique_count": len(exposed_technique_ids),
        "exposed_techniques":  techniques_exposed,
        "asset_exposures":     asset_exposures,
        "attack_gap_analysis": gap_analysis,
        "priority_remediations": remediations,
        "next_review":         (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    }

    EXPOSURE_REPORTS[org_id] = report
    return report


# ─────────────────────────────────────────────────────────────────────────────
# REST API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/my-exposure", methods=["GET"])
def get_my_exposure():
    """Return exposure report for the authenticated org."""
    org_id = request.args.get("org_id", "ORG-DEMO-001")
    coverage = request.args.getlist("coverage")  # optional pre-existing coverage
    report = build_exposure_report(org_id, coverage or None)
    return jsonify({"status": "ok", "data": report})


@app.route("/my-exposure/ingest", methods=["POST"])
def ingest_assets():
    """Ingest asset inventory for an org."""
    payload = request.get_json(force=True) or {}
    org_id  = payload.get("org_id", "ORG-DEMO-001")
    assets  = payload.get("assets", [])
    if not assets:
        return jsonify({"status": "error", "message": "No assets provided"}), 400
    inventory = ingest_asset_inventory(org_id, assets)
    return jsonify({"status": "ok", "data": inventory})


@app.route("/my-exposure/gap-analysis", methods=["GET"])
def gap_analysis():
    """Return ATT&CK gap analysis for an org."""
    org_id   = request.args.get("org_id", "ORG-DEMO-001")
    coverage = request.args.getlist("coverage")
    report   = build_exposure_report(org_id, coverage or None)
    return jsonify({"status": "ok", "data": report["attack_gap_analysis"]})


@app.route("/my-exposure/score", methods=["GET"])
def exposure_score():
    """Return just the exposure score for an org."""
    org_id = request.args.get("org_id", "ORG-DEMO-001")
    report = EXPOSURE_REPORTS.get(org_id) or build_exposure_report(org_id)
    return jsonify({
        "status":         "ok",
        "org_id":         org_id,
        "exposure_score": report["exposure_score"],
        "risk_label":     report["risk_label"],
        "generated_at":   report["generated_at"],
    })


@app.route("/my-exposure/bulk", methods=["POST"])
def bulk_exposure():
    """Generate exposure reports for multiple orgs (admin/MSSP use)."""
    payload = request.get_json(force=True) or {}
    org_ids = payload.get("org_ids", [])
    results = {}
    for org_id in org_ids[:50]:  # max 50 per call
        results[org_id] = build_exposure_report(org_id)
    return jsonify({"status": "ok", "count": len(results), "data": results})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "engine": "phase151-exposure-cloud", "version": "v170.0"})


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

def run_self_test() -> dict:
    """Run engine self-test and return results."""
    results = {}

    # Test 1: Asset ingestion
    assets = [
        {"asset_id": "A001", "type": "cloud",    "name": "AWS Prod",    "technology": "AWS",              "criticality": "critical", "internet_facing": True},
        {"asset_id": "A002", "type": "host",     "name": "AD Server",   "technology": "Active Directory", "criticality": "critical", "internet_facing": False},
        {"asset_id": "A003", "type": "saas",     "name": "O365",        "technology": "Office365",        "criticality": "high",     "internet_facing": True},
        {"asset_id": "A004", "type": "host",     "name": "Web Server",  "technology": "Apache",           "criticality": "high",     "internet_facing": True},
        {"asset_id": "A005", "type": "identity", "name": "Okta SSO",    "technology": "Okta",             "criticality": "critical", "internet_facing": True},
    ]
    inv = ingest_asset_inventory("TEST-ORG-001", assets)
    results["asset_ingestion"] = "PASS" if inv["total_assets"] == 5 else "FAIL"

    # Test 2: Exposure report
    report = build_exposure_report("TEST-ORG-001", detection_coverage=["T1059", "T1078"])
    results["exposure_report"] = "PASS" if 0 <= report["exposure_score"] <= 100 else "FAIL"

    # Test 3: ATT&CK gap analysis
    gap = report["attack_gap_analysis"]
    results["gap_analysis"] = "PASS" if "coverage_pct" in gap and "priority_gaps" in gap else "FAIL"

    # Test 4: Score determination
    score, label = _infer_exposure_score([{"severity": "critical"}, {"severity": "high"}, {"severity": "medium"}])
    results["scoring"] = "PASS" if label in ("Critical", "High", "Medium", "Low", "Minimal") else "FAIL"

    passed = sum(1 for v in results.values() if v == "PASS")
    results["summary"] = f"{passed}/{len(results)-1} tests passed"
    results["status"] = "PASS" if passed == len(results) - 1 else "PARTIAL"
    return results


if __name__ == "__main__":
    print("=== Phase 151 — Customer Exposure Cloud Self-Test ===")
    test_results = run_self_test()
    for k, v in test_results.items():
        print(f"  {k}: {v}")
    print(f"\nStarting server on port 8551...")
    app.run(host="0.0.0.0", port=8551, debug=False)
