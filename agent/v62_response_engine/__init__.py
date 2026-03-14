"""
CYBERDUDEBIVASH® SENTINEL APEX v62.0 — Automated Response Engine
================================================================
Generates automated mitigation and remediation actions (simulation layer).
Produces actionable response recommendations with audit trail.

Input:  data/incidents/incidents.json
Output: data/responses/response_log.json

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RESPONSE-ENGINE] %(levelname)s %(message)s")
logger = logging.getLogger("v62_response_engine")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
INCIDENTS_FILE = BASE_DIR / "data" / "incidents" / "incidents.json"
OUTPUT_DIR = BASE_DIR / "data" / "responses"
OUTPUT_FILE = OUTPUT_DIR / "response_log.json"

RESPONSE_RULES = [
    {
        "condition": lambda inc: any("ipv4" in str(inc.get("ioc_breakdown", {})).lower() and inc.get("ioc_breakdown", {}).get(k, 0) for k in ("ipv4",)),
        "check": lambda inc: inc.get("ioc_breakdown", {}).get("ipv4", 0) > 0,
        "action_type": "block_ip",
        "description": "Block malicious IP addresses at perimeter firewall and WAF",
        "target_template": "Firewall ACL + WAF rules",
        "automation_level": "SEMI_AUTO",
    },
    {
        "check": lambda inc: inc.get("severity") in ("CRITICAL", "HIGH") and any(t.startswith("T1566") for t in inc.get("mitre_techniques", [])),
        "action_type": "remove_phishing_email",
        "description": "Purge phishing emails from all mailboxes via admin search-and-destroy",
        "target_template": "Email gateway + Exchange/M365 admin",
        "automation_level": "AUTO",
    },
    {
        "check": lambda inc: any(t in ("T1078", "T1078.001") for t in inc.get("mitre_techniques", [])),
        "action_type": "disable_account",
        "description": "Disable compromised accounts and force credential rotation",
        "target_template": "Active Directory / IdP",
        "automation_level": "SEMI_AUTO",
    },
    {
        "check": lambda inc: inc.get("severity") == "CRITICAL",
        "action_type": "quarantine_host",
        "description": "Isolate affected endpoints via EDR network containment",
        "target_template": "EDR console (CrowdStrike/SentinelOne/Defender)",
        "automation_level": "AUTO",
    },
    {
        "check": lambda inc: inc.get("cvss_score") and float(inc.get("cvss_score", 0) or 0) >= 7.0,
        "action_type": "patch_vulnerability",
        "description": "Emergency patch deployment for actively exploited vulnerability",
        "target_template": "Patch management (WSUS/SCCM/Intune)",
        "automation_level": "SCHEDULED",
    },
    {
        "check": lambda inc: inc.get("kev_present", False),
        "action_type": "patch_vulnerability",
        "description": "CISA KEV mandated patching — compliance deadline active",
        "target_template": "Vulnerability management platform",
        "automation_level": "URGENT",
    },
    {
        "check": lambda inc: any("T1486" in t for t in inc.get("mitre_techniques", [])),
        "action_type": "isolate_network_segment",
        "description": "Isolate affected network segment to prevent ransomware lateral spread",
        "target_template": "Network switch ACLs / microsegmentation",
        "automation_level": "AUTO",
    },
    {
        "check": lambda inc: inc.get("ioc_breakdown", {}).get("domain", 0) > 0 if isinstance(inc.get("ioc_breakdown", {}).get("domain", 0), int) else len(inc.get("ioc_breakdown", {}).get("domain", [])) > 0,
        "action_type": "block_domain",
        "description": "Add malicious domains to DNS sinkhole and proxy blocklist",
        "target_template": "DNS resolver + web proxy",
        "automation_level": "AUTO",
    },
]


def generate_responses(incidents: List[Dict]) -> List[Dict]:
    responses = []
    ts = datetime.now(timezone.utc).isoformat()

    for incident in incidents:
        for rule in RESPONSE_RULES:
            try:
                if rule["check"](incident):
                    action_id = hashlib.md5(
                        f"{incident['incident_id']}:{rule['action_type']}:{ts}".encode()
                    ).hexdigest()[:12]

                    responses.append({
                        "action_id": f"RSP-{action_id.upper()}",
                        "incident_id": incident["incident_id"],
                        "action_type": rule["action_type"],
                        "description": rule["description"],
                        "target": rule["target_template"],
                        "automation_level": rule["automation_level"],
                        "severity": incident.get("severity", "MEDIUM"),
                        "threat_actor": incident.get("threat_actor", "Unknown"),
                        "status": "RECOMMENDED",
                        "executed": False,
                        "timestamp": ts,
                    })
            except Exception:
                continue

    return responses


def run():
    logger.info("=" * 60)
    logger.info("  SENTINEL APEX v62.0 — Automated Response Engine")
    logger.info("=" * 60)

    if not INCIDENTS_FILE.exists():
        logger.error(f"Incidents file not found: {INCIDENTS_FILE}")
        return {"status": "error", "actions": 0}

    with open(INCIDENTS_FILE) as f:
        data = json.load(f)
    incidents = data.get("incidents", [])
    logger.info(f"Loaded {len(incidents)} incidents")

    responses = generate_responses(incidents)

    by_type = {}
    for r in responses:
        t = r["action_type"]
        by_type[t] = by_type.get(t, 0) + 1

    output = {
        "engine": "v62_response_engine",
        "version": "62.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_actions": len(responses),
        "action_breakdown": by_type,
        "automation_stats": {
            "AUTO": sum(1 for r in responses if r["automation_level"] == "AUTO"),
            "SEMI_AUTO": sum(1 for r in responses if r["automation_level"] == "SEMI_AUTO"),
            "SCHEDULED": sum(1 for r in responses if r["automation_level"] == "SCHEDULED"),
            "URGENT": sum(1 for r in responses if r["automation_level"] == "URGENT"),
        },
        "response_actions": responses,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    logger.info(f"✅ {len(responses)} response actions generated")
    for atype, count in by_type.items():
        logger.info(f"   {atype}: {count}")
    return output


if __name__ == "__main__":
    result = run()
    print(json.dumps({"actions": result.get("total_actions", 0), "status": "OK"}, indent=2))
