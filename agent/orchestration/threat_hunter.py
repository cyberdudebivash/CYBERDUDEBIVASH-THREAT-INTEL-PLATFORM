"""
CYBERDUDEBIVASH® SENTINEL APEX
THREAT HUNTER AGENT — Autonomous hypothesis-driven threat hunting
Generates hunt hypotheses from TTP data and validates against advisories.
"""
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-THREAT-HUNTER")

HUNT_HYPOTHESES = {
    "T1566": {
        "name": "Phishing-Based Initial Access Hunt",
        "hypothesis": "Threat actor is using phishing emails to gain initial access",
        "hunt_queries": [
            "parent_process=outlook.exe AND child_process IN (cmd.exe, powershell.exe, wscript.exe)",
            "email_attachment_type IN (.doc,.xls,.vbs,.lnk) AND macro_execution=true",
            "dns_query MATCHES '*.onion|bit.ly|tinyurl' FROM email_client_process",
        ],
        "data_sources": ["Email Gateway Logs", "EDR", "DNS Logs"],
        "mitre_tactic": "Initial Access",
    },
    "T1486": {
        "name": "Ransomware Pre-Deployment Hunt",
        "hypothesis": "Ransomware actor has gained access and is staging for encryption",
        "hunt_queries": [
            "process_name=vssadmin.exe AND args CONTAINS 'delete shadows'",
            "file_create_rate > 1000/minute AND extension_change=true",
            "registry_write PATH='HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'",
            "netsh.exe firewall set opmode disable",
        ],
        "data_sources": ["EDR", "Windows Event Logs", "SIEM"],
        "mitre_tactic": "Impact",
    },
    "T1078": {
        "name": "Credential Abuse Hunt",
        "hypothesis": "Valid credentials are being abused for lateral movement",
        "hunt_queries": [
            "auth_event=success AND source_ip NOT IN known_safe_ips AND time=off_hours",
            "failed_auth_count > 10 AND success_after_failure=true",
            "new_admin_logon AND account_created_within_24h=true",
        ],
        "data_sources": ["Active Directory Logs", "VPN Logs", "SIEM"],
        "mitre_tactic": "Defense Evasion / Persistence",
    },
    "T1055": {
        "name": "Process Injection Hunt",
        "hypothesis": "Malware is injecting into legitimate processes for stealth",
        "hunt_queries": [
            "WriteProcessMemory call FROM unsigned_process TO svchost.exe",
            "CreateRemoteThread target=lsass.exe",
            "unexpected_network_conn FROM explorer.exe OR svchost.exe",
        ],
        "data_sources": ["EDR", "Windows API Monitoring"],
        "mitre_tactic": "Defense Evasion",
    },
}


class ThreatHunterAgent:
    """
    Autonomous threat hunting agent.
    Generates hunt packages from TTPs observed in threat intel.
    """

    def __init__(self):
        self.hunts_generated = 0
        self.active_hunts: List[Dict] = []

    def generate_hunt_package(self, advisory: Dict) -> Dict:
        """Generate a complete threat hunt package from an advisory."""
        ttps = advisory.get("mitre_techniques", [])
        title = advisory.get("title", "")
        risk_score = float(advisory.get("risk_score") or advisory.get("cvss") or 5.0)

        hunts = []
        for ttp in ttps:
            ttp_id = str(ttp).upper()
            if ttp_id in HUNT_HYPOTHESES:
                hunt = dict(HUNT_HYPOTHESES[ttp_id])
                hunt["ttp_id"] = ttp_id
                hunt["priority"] = "HIGH" if risk_score >= 7 else "MEDIUM"
                hunt["triggered_by"] = title[:80]
                hunts.append(hunt)

        # Generate generic hunt if no specific TTP matches
        if not hunts:
            hunts.append(self._generate_generic_hunt(advisory))

        package = {
            "hunt_id": f"HNT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "advisory_title": title[:80],
            "risk_score": risk_score,
            "hunt_count": len(hunts),
            "hunts": hunts,
            "ioc_hunt_queries": self._generate_ioc_queries(advisory),
            "priority": "P1" if risk_score >= 8 else "P2" if risk_score >= 6 else "P3",
            "estimated_hunt_time": f"{len(hunts) * 30}-{len(hunts) * 60} minutes",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self.hunts_generated += 1
        self.active_hunts.append(package)
        logger.info(f"[THREAT-HUNTER] Hunt package generated: {package['hunt_id']} | {len(hunts)} hunts")
        return package

    def _generate_ioc_queries(self, advisory: Dict) -> List[str]:
        """Generate IOC-based hunt queries."""
        queries = []
        for ioc in advisory.get("iocs", [])[:10]:
            val = str(ioc.get("value", ioc) if isinstance(ioc, dict) else ioc)
            ioc_type = ioc.get("type", "string") if isinstance(ioc, dict) else "string"
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
                queries.append(f"network_connection dest_ip={val}")
            elif re.match(r"^https?://", val):
                queries.append(f"web_request url CONTAINS '{val}'")
            elif re.match(r"^[0-9a-f]{32,64}$", val, re.I):
                queries.append(f"file_hash={val}")
            elif "." in val and " " not in val:
                queries.append(f"dns_query domain={val}")
        return queries

    def _generate_generic_hunt(self, advisory: Dict) -> Dict:
        title = advisory.get("title", "")
        return {
            "ttp_id": "GENERIC",
            "name": f"Generic Hunt: {title[:50]}",
            "hypothesis": f"Threat actor associated with '{title[:60]}' has active presence",
            "hunt_queries": [
                "anomalous_process_execution=true AND parent_mismatch=true",
                "unusual_network_beacon_pattern=true",
                "new_scheduled_task AND creator NOT IN known_admins",
            ],
            "data_sources": ["EDR", "SIEM", "Network Logs"],
            "mitre_tactic": "General",
            "priority": "MEDIUM",
        }

    def get_stats(self) -> Dict:
        return {
            "hunts_generated": self.hunts_generated,
            "active_hunts": len(self.active_hunts),
            "agent": "ThreatHunterAgent v1.0",
        }
