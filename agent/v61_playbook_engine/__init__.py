"""
CYBERDUDEBIVASH® SENTINEL APEX v61.0 — AI Playbook Generator
==============================================================
Automatically generates response playbooks for each incident.
Produces investigation, containment, remediation, and recovery steps.

Input:  data/incidents/incidents.json
Output: data/playbooks/playbook_<incident_id>.json

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PLAYBOOK-ENGINE] %(levelname)s %(message)s")
logger = logging.getLogger("v61_playbook_engine")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
INCIDENTS_FILE = BASE_DIR / "data" / "incidents" / "incidents.json"
PLAYBOOK_DIR = BASE_DIR / "data" / "playbooks"

MITRE_INVESTIGATION = {
    "T1566": "Check email gateway logs for phishing indicators. Analyze email headers, URLs, and attachments.",
    "T1190": "Review WAF/IDS logs for exploitation attempts. Check web server access logs for anomalous requests.",
    "T1078": "Audit authentication logs for compromised credential usage. Check for impossible travel or unusual login times.",
    "T1059": "Search endpoint logs for suspicious script execution. Check PowerShell, CMD, bash history.",
    "T1203": "Analyze exploit artifacts on affected systems. Review crash dumps and process memory.",
    "T1486": "Check for ransomware artifacts: encrypted files, ransom notes, registry modifications.",
    "T1071": "Analyze network traffic for C2 communication patterns. Check DNS, HTTP, HTTPS anomalies.",
    "T1547": "Review startup persistence mechanisms: registry run keys, scheduled tasks, services.",
    "T1027": "Analyze obfuscated files/scripts. Use deobfuscation tools on detected samples.",
    "T1195": "Verify supply chain integrity. Check software update mechanisms and third-party dependencies.",
    "T1555": "Audit credential stores: browser password managers, vault access, keychain queries.",
    "T1105": "Monitor for ingress tool transfer. Check download logs and file creation events.",
}

CONTAINMENT_ACTIONS = {
    "CRITICAL": [
        "Immediately isolate affected systems from the network",
        "Block all identified malicious IPs/domains at perimeter firewall",
        "Disable compromised user accounts and rotate credentials",
        "Enable enhanced logging on all critical systems",
        "Activate incident response team and notify CISO",
        "Preserve forensic evidence — do not reboot affected systems",
    ],
    "HIGH": [
        "Quarantine affected endpoints via EDR",
        "Block IOCs (IPs, domains, hashes) at network boundary",
        "Reset credentials for affected accounts",
        "Enable threat hunting rules on SIEM",
        "Notify SOC team lead and escalate per runbook",
    ],
    "MEDIUM": [
        "Add IOCs to blocklists and monitoring watchlists",
        "Deploy updated detection rules to SIEM/EDR",
        "Review access logs for affected systems",
        "Schedule vulnerability scan of affected assets",
    ],
    "LOW": [
        "Add indicators to threat intelligence feed",
        "Update detection signatures",
        "Document findings for trend analysis",
    ],
}

REMEDIATION_STEPS = {
    "CRITICAL": [
        "Execute full malware removal and system restoration from clean backup",
        "Patch all exploited vulnerabilities within 24 hours",
        "Conduct full credential rotation for affected domain/accounts",
        "Deploy IOC-specific detection rules across all endpoints",
        "Perform threat hunt across enterprise for lateral movement indicators",
        "Engage forensics team for root cause analysis",
    ],
    "HIGH": [
        "Remove identified malware and unauthorized persistence",
        "Apply security patches for exploited CVEs within 48 hours",
        "Rotate affected credentials and enforce MFA",
        "Update firewall and proxy rules with new IOCs",
    ],
    "MEDIUM": [
        "Apply patches during next maintenance window",
        "Update endpoint protection signatures",
        "Review and harden security configurations",
    ],
    "LOW": [
        "Schedule patching in regular cycle",
        "Update security awareness training materials",
    ],
}

RECOVERY_STEPS = [
    "Verify system integrity before restoring to production",
    "Monitor recovered systems with enhanced logging for 72 hours",
    "Validate that all IOCs are blocked across security controls",
    "Conduct post-incident review and update playbooks",
    "Brief stakeholders on incident timeline and resolution",
    "Update threat model and risk register",
]


def generate_investigation_steps(mitre_techniques: List[str]) -> List[Dict]:
    steps = []
    for i, technique in enumerate(mitre_techniques[:8], 1):
        base_id = technique.split(".")[0]
        guidance = MITRE_INVESTIGATION.get(base_id, 
            f"Investigate activity associated with {technique}. Check relevant logs and artifacts.")
        steps.append({
            "step": i,
            "technique": technique,
            "action": guidance,
            "priority": "HIGH" if i <= 3 else "MEDIUM",
            "estimated_time_minutes": 30 if i <= 3 else 15,
        })
    return steps


def generate_playbook(incident: Dict) -> Dict:
    incident_id = incident.get("incident_id", "INC-UNKNOWN")
    severity = incident.get("severity", "MEDIUM")
    mitre = incident.get("mitre_techniques", [])
    
    investigation = generate_investigation_steps(mitre)
    containment = CONTAINMENT_ACTIONS.get(severity, CONTAINMENT_ACTIONS["MEDIUM"])
    remediation = REMEDIATION_STEPS.get(severity, REMEDIATION_STEPS["MEDIUM"])
    
    playbook = {
        "playbook_id": f"PB-{incident_id}",
        "incident_id": incident_id,
        "title": f"Response Playbook: {incident.get('title', 'Unknown Threat')[:80]}",
        "severity": severity,
        "threat_actor": incident.get("threat_actor", "Unknown"),
        "confidence": incident.get("confidence", 50),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": "61.0.0",
        "phases": {
            "1_investigation": {
                "phase": "Investigation",
                "priority": "IMMEDIATE",
                "steps": investigation,
                "estimated_duration_minutes": sum(s["estimated_time_minutes"] for s in investigation),
            },
            "2_containment": {
                "phase": "Containment",
                "priority": "IMMEDIATE" if severity in ("CRITICAL", "HIGH") else "URGENT",
                "actions": [{"step": i+1, "action": a} for i, a in enumerate(containment)],
                "estimated_duration_minutes": 60 if severity == "CRITICAL" else 30,
            },
            "3_remediation": {
                "phase": "Remediation",
                "priority": "URGENT",
                "actions": [{"step": i+1, "action": a} for i, a in enumerate(remediation)],
                "estimated_duration_minutes": 120 if severity == "CRITICAL" else 60,
            },
            "4_recovery": {
                "phase": "Recovery",
                "priority": "STANDARD",
                "actions": [{"step": i+1, "action": a} for i, a in enumerate(RECOVERY_STEPS)],
                "estimated_duration_minutes": 180,
            },
        },
        "total_steps": len(investigation) + len(containment) + len(remediation) + len(RECOVERY_STEPS),
        "ioc_summary": {
            "total_iocs": incident.get("ioc_count", 0),
            "breakdown": incident.get("ioc_breakdown", {}),
        },
        "affected_assets": incident.get("affected_assets", []),
        "compliance_references": ["NIST SP 800-61r3", "ISO 27035", "SANS IR Process"],
    }
    return playbook


def run():
    logger.info("=" * 60)
    logger.info("  SENTINEL APEX v61.0 — AI Playbook Generator")
    logger.info("=" * 60)

    if not INCIDENTS_FILE.exists():
        logger.error(f"Incidents file not found: {INCIDENTS_FILE}")
        return {"status": "error", "playbooks": 0}

    with open(INCIDENTS_FILE) as f:
        data = json.load(f)
    incidents = data.get("incidents", [])
    logger.info(f"Loaded {len(incidents)} incidents")

    PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
    generated = 0

    for incident in incidents:
        playbook = generate_playbook(incident)
        filename = f"playbook_{incident['incident_id']}.json"
        filepath = PLAYBOOK_DIR / filename
        with open(filepath, "w") as f:
            json.dump(playbook, f, indent=2, default=str)
        generated += 1

    # Write summary index
    index = {
        "engine": "v61_playbook_engine",
        "version": "61.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_playbooks": generated,
        "playbook_files": [f"playbook_{i['incident_id']}.json" for i in incidents],
    }
    with open(PLAYBOOK_DIR / "playbook_index.json", "w") as f:
        json.dump(index, f, indent=2, default=str)

    logger.info(f"✅ {generated} playbooks generated → {PLAYBOOK_DIR}")
    return index


if __name__ == "__main__":
    result = run()
    print(json.dumps({"playbooks": result.get("total_playbooks", 0), "status": "OK"}, indent=2))
