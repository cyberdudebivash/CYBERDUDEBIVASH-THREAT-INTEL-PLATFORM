"""
CYBERDUDEBIVASH® SENTINEL APEX v63.0 — AI Threat Hunter Engine
================================================================
Generates proactive threat hunting hypotheses, hunt queries,
attack path analysis, and investigation leads.

Input:  data/stix/feed_manifest.json + data/incidents/incidents.json
Output: data/threathunts/hunts.json

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import hashlib
import logging
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [THREAT-HUNTER] %(levelname)s %(message)s")
logger = logging.getLogger("v63_threathunter")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"
INCIDENTS_PATH = BASE_DIR / "data" / "incidents" / "incidents.json"
OUTPUT_DIR = BASE_DIR / "data" / "threathunts"
OUTPUT_FILE = OUTPUT_DIR / "hunts.json"

HUNT_TEMPLATES = {
    "T1566": {
        "hypothesis": "Threat actor is using spear-phishing to establish initial access",
        "kql": 'EmailEvents | where Subject has_any ("urgent","invoice","payment","verify") | where SenderFromDomain !in (trusted_domains) | project Timestamp, Subject, SenderFromDomain, RecipientEmailAddress',
        "splunk": 'index=email sourcetype=o365:management subject IN ("urgent","invoice","payment") | stats count by sender, recipient, subject',
        "data_sources": ["email_gateway", "o365_logs", "exchange_tracking"],
        "category": "initial_access",
    },
    "T1190": {
        "hypothesis": "External-facing application is being exploited for initial access",
        "kql": 'DeviceNetworkEvents | where RemoteIPType == "Public" | where ActionType == "InboundConnectionAccepted" | summarize ConnectionCount=count() by RemoteIP, LocalPort | where ConnectionCount > 50',
        "splunk": 'index=web sourcetype=access_combined status>=400 | stats count by clientip, uri_path | where count > 100',
        "data_sources": ["waf_logs", "web_server_logs", "ids_alerts"],
        "category": "exploitation",
    },
    "T1078": {
        "hypothesis": "Compromised credentials are being used for unauthorized access",
        "kql": 'SigninLogs | where ResultType == 0 | summarize DistinctIPs=dcount(IPAddress) by UserPrincipalName | where DistinctIPs > 5',
        "splunk": 'index=auth sourcetype=windows:security EventCode=4624 | stats dc(src_ip) as unique_ips by user | where unique_ips > 5',
        "data_sources": ["azure_ad_logs", "windows_security", "vpn_logs"],
        "category": "credential_abuse",
    },
    "T1059": {
        "hypothesis": "Malicious scripts are being executed for code execution",
        "kql": 'DeviceProcessEvents | where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe") | where ProcessCommandLine has_any ("-enc","-nop","bypass","hidden","downloadstring","invoke-expression")',
        "splunk": 'index=endpoint sourcetype=sysmon EventCode=1 (Image="*powershell*" OR Image="*cmd.exe*") (CommandLine="*-enc*" OR CommandLine="*bypass*" OR CommandLine="*hidden*")',
        "data_sources": ["edr_telemetry", "sysmon", "process_creation"],
        "category": "execution",
    },
    "T1486": {
        "hypothesis": "Ransomware encryption activity detected in the environment",
        "kql": 'DeviceFileEvents | where ActionType == "FileRenamed" | where FileName endswith_cs ".encrypted" or FileName endswith_cs ".locked" or FileName endswith_cs ".crypt" | summarize FileCount=count() by DeviceName, bin(Timestamp, 1h) | where FileCount > 100',
        "splunk": 'index=endpoint sourcetype=sysmon EventCode=11 (TargetFilename="*.encrypted" OR TargetFilename="*.locked") | stats count by ComputerName | where count > 50',
        "data_sources": ["file_monitoring", "edr", "backup_integrity"],
        "category": "impact",
    },
    "T1071": {
        "hypothesis": "C2 communication detected via application layer protocols",
        "kql": 'DeviceNetworkEvents | where RemotePort in (443,80,8080) | summarize BytesSent=sum(SentBytes), Connections=count() by RemoteIP | where BytesSent > 50000000 or Connections > 500',
        "splunk": 'index=proxy sourcetype=bluecoat | stats sum(bytes_out) as total_bytes count by dest_ip | where total_bytes > 50000000',
        "data_sources": ["proxy_logs", "firewall_logs", "dns_logs"],
        "category": "command_and_control",
    },
    "T1547": {
        "hypothesis": "Persistence mechanisms established via boot/logon autostart",
        "kql": 'DeviceRegistryEvents | where RegistryKey has_any ("Run","RunOnce","Winlogon") | where ActionType == "RegistryValueSet" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData',
        "splunk": 'index=endpoint sourcetype=sysmon EventCode=13 TargetObject="*\\Run*" OR TargetObject="*\\RunOnce*" | table _time, ComputerName, TargetObject, Details',
        "data_sources": ["registry_monitoring", "sysmon", "edr"],
        "category": "persistence",
    },
    "T1203": {
        "hypothesis": "Client-side exploitation via malicious documents or browser exploits",
        "kql": 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","chrome.exe","msedge.exe") | where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","rundll32.exe","regsvr32.exe")',
        "splunk": 'index=endpoint sourcetype=sysmon EventCode=1 (ParentImage="*winword*" OR ParentImage="*excel*" OR ParentImage="*chrome*") (Image="*cmd*" OR Image="*powershell*" OR Image="*wscript*")',
        "data_sources": ["edr", "sysmon", "application_logs"],
        "category": "exploitation",
    },
}

CAMPAIGN_PATTERNS = {
    "apt_espionage": {"actors": ["CDB-APT-22", "CDB-APT-41"], "techniques": ["T1566", "T1078", "T1059", "T1071"]},
    "ransomware_ops": {"actors": ["CDB-RAN-02", "CDB-FIN-09", "CDB-FIN-12"], "techniques": ["T1486", "T1190", "T1547"]},
    "financial_crime": {"actors": ["CDB-FIN-07", "CDB-FIN-11"], "techniques": ["T1566", "T1078", "T1555"]},
}


def detect_campaigns(incidents: List[Dict]) -> List[Dict]:
    campaigns = []
    actor_activity = Counter()
    for inc in incidents:
        actor_activity[inc.get("threat_actor", "")] += 1

    for campaign_name, pattern in CAMPAIGN_PATTERNS.items():
        matching_actors = [a for a in pattern["actors"] if actor_activity.get(a, 0) > 0]
        if matching_actors:
            related = [i for i in incidents if i.get("threat_actor") in matching_actors]
            campaigns.append({
                "campaign_id": f"CAMP-{hashlib.md5(campaign_name.encode()).hexdigest()[:8].upper()}",
                "campaign_name": campaign_name,
                "actors_involved": matching_actors,
                "incident_count": len(related),
                "avg_risk": round(sum(i.get("risk_score", 0) for i in related) / max(len(related), 1), 1),
                "techniques_observed": list(set(t for i in related for t in i.get("mitre_techniques", []))),
                "status": "ACTIVE",
            })
    return campaigns


def generate_hunts(intel: List[Dict], incidents: List[Dict]) -> List[Dict]:
    hunts = []
    all_techniques = Counter()

    for record in intel + incidents:
        for t in record.get("mitre_techniques", record.get("mitre_tactics", [])):
            all_techniques[t.split(".")[0]] += 1

    for technique, count in all_techniques.most_common(15):
        template = HUNT_TEMPLATES.get(technique)
        if not template:
            continue

        hunt_id = f"HUNT-{hashlib.md5(f'{technique}:{count}'.encode()).hexdigest()[:8].upper()}"
        hunts.append({
            "hunt_id": hunt_id,
            "technique": technique,
            "hypothesis": template["hypothesis"],
            "category": template["category"],
            "confidence": min(95, 50 + count * 5),
            "priority": "CRITICAL" if count >= 10 else "HIGH" if count >= 5 else "MEDIUM",
            "frequency": count,
            "queries": {
                "kql": template["kql"],
                "splunk": template["splunk"],
            },
            "data_sources": template["data_sources"],
            "status": "READY",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })

    hunts.sort(key=lambda h: h["confidence"], reverse=True)
    return hunts


def generate_attack_paths(incidents: List[Dict]) -> List[Dict]:
    paths = []
    for inc in incidents:
        techniques = inc.get("mitre_techniques", [])
        if len(techniques) >= 3:
            paths.append({
                "path_id": f"PATH-{inc['incident_id'][-8:]}",
                "incident_id": inc["incident_id"],
                "actor": inc.get("threat_actor", "Unknown"),
                "kill_chain": techniques,
                "chain_length": len(techniques),
                "severity": inc.get("severity", "MEDIUM"),
                "risk_score": inc.get("risk_score", 0),
            })
    paths.sort(key=lambda p: p["chain_length"], reverse=True)
    return paths[:20]


def run():
    logger.info("=" * 60)
    logger.info("  SENTINEL APEX v63.0 — AI Threat Hunter Engine")
    logger.info("=" * 60)

    intel = []
    if MANIFEST_PATH.exists():
        with open(MANIFEST_PATH) as f:
            data = json.load(f)
        intel = data if isinstance(data, list) else data.get("entries", [])
    logger.info(f"Loaded {len(intel)} intel records")

    incidents = []
    if INCIDENTS_PATH.exists():
        with open(INCIDENTS_PATH) as f:
            data = json.load(f)
        incidents = data.get("incidents", [])
    logger.info(f"Loaded {len(incidents)} incidents")

    hunts = generate_hunts(intel, incidents)
    campaigns = detect_campaigns(incidents)
    attack_paths = generate_attack_paths(incidents)

    output = {
        "engine": "v63_threathunter",
        "version": "63.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_hunts": len(hunts),
        "active_campaigns": len(campaigns),
        "attack_paths": len(attack_paths),
        "hunt_hypotheses": hunts,
        "campaign_intelligence": campaigns,
        "attack_path_analysis": attack_paths,
        "coverage": {
            "techniques_covered": len(hunts),
            "total_techniques_observed": sum(h["frequency"] for h in hunts),
        },
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    logger.info(f"✅ {len(hunts)} hunt hypotheses | {len(campaigns)} campaigns | {len(attack_paths)} attack paths")
    return output


if __name__ == "__main__":
    result = run()
    print(json.dumps({
        "hunts": result.get("total_hunts", 0),
        "campaigns": result.get("active_campaigns", 0),
        "attack_paths": result.get("attack_paths", 0),
        "status": "OK",
    }, indent=2))
