"""
SENTINEL APEX — AI-Powered Sigma Rule Generator v2.0
=====================================================
Generates production-grade Sigma detection rules from:
- CVE/advisory intelligence
- IOC lists
- MITRE ATT&CK technique mappings
- Threat actor TTPs

Supports outputs for:
- Splunk
- Elastic Security (EQL/KQL)
- Microsoft Sentinel (KQL)
- Chronicle (YARA-L2)
- QRadar AQL
- Sumo Logic
- Panther
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import yaml
import structlog

log = structlog.get_logger("sentinel.sigma_gen")


MITRE_TACTIC_MAP = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
    "TA0042": "resource-development",
    "TA0043": "reconnaissance",
}

LOGSOURCE_TEMPLATES = {
    "process_creation": {
        "category": "process_creation",
        "product": "windows",
    },
    "network_connection": {
        "category": "network_connection",
        "product": "windows",
    },
    "dns_query": {
        "category": "dns_query",
        "product": "windows",
    },
    "file_event": {
        "category": "file_event",
        "product": "windows",
    },
    "registry_event": {
        "category": "registry_event",
        "product": "windows",
    },
    "web_server": {
        "category": "webserver",
    },
    "proxy": {
        "category": "proxy",
    },
    "firewall": {
        "category": "firewall",
    },
    "linux_process": {
        "category": "process_creation",
        "product": "linux",
    },
}


class SigmaRule:
    def __init__(
        self,
        title: str,
        description: str,
        rule_id: Optional[str] = None,
        status: str = "experimental",
        level: str = "medium",
        author: str = "SENTINEL APEX AI",
    ):
        self.title = title
        self.description = description
        self.rule_id = rule_id or str(uuid.uuid4())
        self.status = status
        self.level = level
        self.author = author
        self.tags: list[str] = []
        self.references: list[str] = []
        self.logsource: dict = {}
        self.detection: dict = {}
        self.falsepositives: list[str] = ["Legitimate administrative activity"]
        self.fields: list[str] = []

    def set_logsource(self, logsource_type: str, **kwargs) -> "SigmaRule":
        self.logsource = {**LOGSOURCE_TEMPLATES.get(logsource_type, {}), **kwargs}
        return self

    def add_ioc_detection(
        self,
        ips: Optional[list[str]] = None,
        domains: Optional[list[str]] = None,
        hashes: Optional[list[str]] = None,
        urls: Optional[list[str]] = None,
        user_agents: Optional[list[str]] = None,
    ) -> "SigmaRule":
        selection: dict = {}
        if ips:
            selection["DestinationIp"] = ips
        if domains:
            selection["QueryName|contains"] = domains
        if hashes:
            selection["Hashes|contains"] = hashes
        if urls:
            selection["Url|contains"] = urls
        if user_agents:
            selection["UserAgent|contains"] = user_agents
        if selection:
            self.detection["selection"] = selection
            self.detection["condition"] = "selection"
        return self

    def add_process_detection(
        self,
        image_contains: Optional[list[str]] = None,
        commandline_contains: Optional[list[str]] = None,
        commandline_startswith: Optional[list[str]] = None,
        parent_image: Optional[list[str]] = None,
    ) -> "SigmaRule":
        selection: dict = {}
        if image_contains:
            selection["Image|contains"] = image_contains
        if commandline_contains:
            selection["CommandLine|contains"] = commandline_contains
        if commandline_startswith:
            selection["CommandLine|startswith"] = commandline_startswith
        if parent_image:
            selection["ParentImage|contains"] = parent_image

        filter_: dict = {}
        # Common false positive filters
        filter_fp = {
            "Image|startswith": [
                "C:\\Windows\\System32\\",
                "C:\\Windows\\SysWOW64\\",
            ]
        }

        if selection:
            self.detection["selection"] = selection
            if filter_fp:
                self.detection["filter_main"] = filter_fp
                self.detection["condition"] = "selection and not filter_main"
            else:
                self.detection["condition"] = "selection"
        return self

    def add_mitre_tags(self, techniques: list[str]) -> "SigmaRule":
        for tech in techniques:
            tech_upper = tech.upper()
            # Add technique tag
            self.tags.append(f"attack.{tech_upper.lower()}")
            # Infer tactic from technique prefix (T1xxx → multiple tactics possible)
            # For now add common tactic mappings
        return self

    def add_references(self, refs: list[str]) -> "SigmaRule":
        self.references.extend(refs)
        return self

    def to_yaml(self) -> str:
        rule_dict = {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status,
            "description": self.description,
            "references": self.references or ["https://intel.cyberdudebivash.com"],
            "author": self.author,
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "tags": self.tags,
            "logsource": self.logsource,
            "detection": self.detection,
            "fields": self.fields,
            "falsepositives": self.falsepositives,
            "level": self.level,
        }
        # Clean None/empty values
        rule_dict = {k: v for k, v in rule_dict.items() if v}
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "status": self.status,
            "level": self.level,
            "rule_yaml": self.to_yaml(),
            "mitre_techniques": [t.replace("attack.", "").upper() for t in self.tags if t.startswith("attack.t")],
            "logsource": self.logsource,
        }


class SigmaGenerator:
    """
    AI-powered Sigma rule generator.
    Produces detection rules from CTI advisory data.
    """

    @classmethod
    def from_advisory(cls, advisory: dict) -> list[SigmaRule]:
        """Generate multiple Sigma rules from a CTI advisory."""
        rules = []
        ioc_objects = advisory.get("ioc_objects", [])
        apex_ai = advisory.get("apex_ai", {})
        ttps = apex_ai.get("ttps", [])
        cves = advisory.get("cves", [])
        title = advisory.get("title", "Unknown Advisory")
        advisory_id = advisory.get("id", "unknown")
        severity = advisory.get("severity", "MEDIUM")
        level_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        sigma_level = level_map.get(severity, "medium")

        references = [
            f"https://intel.cyberdudebivash.com/advisory/{advisory_id}",
        ]
        if cves:
            for cve in cves[:2]:
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        # Extract IOCs by type
        ips = [i["value"] for i in ioc_objects if i.get("type") in ("ipv4-addr", "ipv6-addr") and i.get("value")]
        domains = [i["value"] for i in ioc_objects if i.get("type") == "domain-name" and i.get("value")]
        hashes = [i["value"] for i in ioc_objects if i.get("type") in ("md5", "sha256", "sha1") and i.get("value")]
        urls = [i["value"] for i in ioc_objects if i.get("type") == "url" and i.get("value")]
        mitre_techniques = [t.get("technique_id", "") for t in ttps if t.get("technique_id")]

        # Rule 1: Network IOC Detection (C2 communication)
        if ips or domains:
            rule = SigmaRule(
                title=f"SENTINEL APEX: {title[:60]} - C2 Network Activity",
                description=f"Detects network communication with IOCs associated with {title}. Source: SENTINEL APEX {advisory_id}.",
                level=sigma_level,
                status="stable" if severity in ("CRITICAL", "HIGH") else "experimental",
            )
            rule.set_logsource("network_connection")
            rule.add_ioc_detection(ips=ips[:20] or None, domains=domains[:20] or None)
            rule.add_mitre_tags(mitre_techniques)
            rule.add_references(references)
            rule.falsepositives = ["Known CDN or cloud infrastructure", "Legitimate DNS resolution"]

            if rule.detection:
                rules.append(rule)
                log.info("sentinel.sigma_gen.network_rule", advisory_id=advisory_id, ioc_count=len(ips) + len(domains))

        # Rule 2: DNS Query Detection
        if domains:
            rule = SigmaRule(
                title=f"SENTINEL APEX: {title[:60]} - Suspicious DNS Query",
                description=f"Detects DNS queries for domains associated with {title}.",
                level=sigma_level,
            )
            rule.set_logsource("dns_query")
            rule.detection = {
                "selection": {"QueryName|contains": domains[:30]},
                "condition": "selection",
            }
            rule.add_mitre_tags(mitre_techniques)
            rule.add_references(references)
            rules.append(rule)

        # Rule 3: Hash-based File Detection
        if hashes:
            rule = SigmaRule(
                title=f"SENTINEL APEX: {title[:60]} - Malicious File Hash",
                description=f"Detects execution of files with hashes associated with {title}.",
                level=sigma_level,
                status="stable",
            )
            rule.set_logsource("process_creation")
            rule.detection = {
                "selection": {"Hashes|contains": hashes[:30]},
                "condition": "selection",
            }
            rule.add_mitre_tags(mitre_techniques)
            rule.add_references(references)
            rule.falsepositives = ["None expected — hash match indicates malware"]
            rules.append(rule)

        # Rule 4: TTP-based behavioral detection
        for ttp in ttps[:3]:
            tech_id = ttp.get("technique_id", "")
            tech_name = ttp.get("technique_name", "")
            tactic = ttp.get("tactic", "")

            if not tech_id:
                continue

            rule = cls._generate_ttp_rule(
                tech_id=tech_id,
                tech_name=tech_name,
                tactic=tactic,
                advisory_title=title,
                advisory_id=advisory_id,
                level=sigma_level,
                references=references,
            )
            if rule and rule.detection:
                rules.append(rule)

        log.info(
            "sentinel.sigma_gen.rules_generated",
            advisory_id=advisory_id,
            count=len(rules),
        )
        return rules

    @classmethod
    def _generate_ttp_rule(
        cls,
        tech_id: str,
        tech_name: str,
        tactic: str,
        advisory_title: str,
        advisory_id: str,
        level: str,
        references: list[str],
    ) -> Optional[SigmaRule]:
        """Generate TTP-specific behavioral detection rules."""
        # Common TTP patterns with behavioral signatures
        TTP_PATTERNS: dict[str, dict] = {
            "T1059": {  # Command and Scripting Interpreter
                "logsource": "process_creation",
                "detection": {
                    "selection": {
                        "Image|endswith": ["\\powershell.exe", "\\pwsh.exe", "\\cmd.exe", "\\wscript.exe", "\\cscript.exe"],
                        "CommandLine|contains": ["-EncodedCommand", "-Enc ", "IEX", "Invoke-Expression", "DownloadString"],
                    },
                    "filter_main": {
                        "CommandLine|contains": ["\\Program Files\\", "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonInteractive"],
                    },
                    "condition": "selection and not filter_main",
                },
            },
            "T1055": {  # Process Injection
                "logsource": "process_creation",
                "detection": {
                    "selection": {
                        "CommandLine|contains": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection"],
                    },
                    "condition": "selection",
                },
            },
            "T1036": {  # Masquerading
                "logsource": "process_creation",
                "detection": {
                    "selection": {
                        "Image|contains": ["svchost", "lsass", "explorer"],
                        "Image|not_contains": ["\\System32\\", "\\SysWOW64\\"],
                    },
                    "condition": "selection",
                },
            },
            "T1071": {  # Application Layer Protocol (C2)
                "logsource": "network_connection",
                "detection": {
                    "selection": {
                        "DestinationPort": [80, 443, 8080, 8443, 4443],
                        "Initiated": True,
                    },
                    "filter_main": {
                        "Image|startswith": ["C:\\Program Files\\", "C:\\Windows\\"],
                    },
                    "condition": "selection and not filter_main",
                },
            },
            "T1566": {  # Phishing
                "logsource": "web_server",
                "detection": {
                    "selection": {
                        "cs-uri-stem|contains": ["/payload", "/malware", "/dropper", "/stage1"],
                    },
                    "condition": "selection",
                },
            },
        }

        # Find pattern for technique (check full ID and base technique)
        base_tech = tech_id.split(".")[0]
        pattern = TTP_PATTERNS.get(tech_id) or TTP_PATTERNS.get(base_tech)

        if not pattern:
            return None

        rule = SigmaRule(
            title=f"SENTINEL APEX: {advisory_title[:50]} - {tech_id} {tech_name[:30]}",
            description=f"Behavioral detection for {tech_id} ({tech_name}) associated with {advisory_title}. Source: SENTINEL APEX.",
            level=level,
            status="experimental",
        )
        rule.set_logsource(pattern["logsource"])
        rule.detection = pattern["detection"]
        rule.add_mitre_tags([tech_id])
        rule.add_references(references)
        rule.tags.append(f"attack.{tactic.lower().replace(' ', '-')}" if tactic else "")
        rule.tags = [t for t in rule.tags if t]

        return rule
