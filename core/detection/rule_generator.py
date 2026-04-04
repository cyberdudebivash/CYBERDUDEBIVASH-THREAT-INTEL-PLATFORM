#!/usr/bin/env python3
"""
rule_generator.py — CYBERDUDEBIVASH® SENTINEL APEX v82.0
════════════════════════════════════════════════════════════════════════════════
DETECTION RULE GENERATOR ENGINE

Auto-generates production-grade detection rules from correlated threat intel:
  - Sigma Rules:   SIEM-agnostic (Splunk, ELK, Microsoft Sentinel, QRadar)
  - YARA Rules:    File/Memory/Network artifact detection
  - Detection Playbooks: Step-by-step analyst response guides
  - MITRE ATT&CK Mapping: Full TTP tagging per rule

Rule generation pipeline:
  1. IOC ingestion (IP, domain, hash, URL, CVE, actor, malware family)
  2. Behavioral pattern extraction
  3. Rule template selection (based on IOC type + attack category)
  4. MITRE ATT&CK tagging
  5. Confidence scoring
  6. Output: Sigma YAML + YARA rule + playbook markdown

Multi-platform output support:
  - siem:      Generic Sigma (works with sigma-cli for any SIEM)
  - splunk:    SPL-ready Sigma with Splunk logsource
  - elastic:   EQL/KQL-compatible Sigma
  - sentinel:  Microsoft Sentinel-ready Sigma
  - edr:       CrowdStrike/SentinelOne/Carbon Black behavioral rules
  - network:   Suricata/Snort IDS rule format

Zero dependencies for core logic. YAML output via string formatting
(no PyYAML required for generation — only for loading existing rules).

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-RULE-GEN")

BASE_DIR         = Path(__file__).resolve().parent.parent.parent
SIGMA_OUTPUT_DIR = BASE_DIR / "data" / "intelligence" / "detection_rules" / "sigma" / "generated"
YARA_OUTPUT_DIR  = BASE_DIR / "data" / "intelligence" / "detection_rules" / "yara" / "generated"
PLAYBOOK_DIR     = BASE_DIR / "data" / "intelligence" / "playbooks"

# ════════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUE_NAMES: Dict[str, str] = {
    "T1059":     "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.006": "Python",
    "T1566":     "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1190":     "Exploit Public-Facing Application",
    "T1027":     "Obfuscated Files or Information",
    "T1055":     "Process Injection",
    "T1071":     "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1078":     "Valid Accounts",
    "T1486":     "Data Encrypted for Impact (Ransomware)",
    "T1490":     "Inhibit System Recovery",
    "T1562":     "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1070":     "Indicator Removal",
    "T1070.004": "File Deletion",
    "T1003":     "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1558":     "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1021":     "Remote Services",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1105":     "Ingress Tool Transfer",
    "T1133":     "External Remote Services",
    "T1195":     "Supply Chain Compromise",
    "T1550":     "Use Alternate Authentication Material",
    "T1537":     "Transfer Data to Cloud Account",
    "T1082":     "System Information Discovery",
    "T1016":     "System Network Configuration Discovery",
    "T1083":     "File and Directory Discovery",
    "T1570":     "Lateral Tool Transfer",
}

LOGSOURCE_MAP: Dict[str, Dict] = {
    "network": {"category": "network_connection", "product": "windows"},
    "process": {"category": "process_creation", "product": "windows"},
    "file":    {"category": "file_event", "product": "windows"},
    "dns":     {"category": "dns", "product": "windows"},
    "http":    {"category": "proxy", "product": None},
    "auth":    {"category": "authentication", "product": None},
    "sysmon":  {"category": "process_creation", "product": "windows", "service": "sysmon"},
    "linux":   {"category": "process_creation", "product": "linux"},
    "web":     {"category": "webserver", "product": None},
}


# ════════════════════════════════════════════════════════════════════════════════
# SIGMA RULE GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class SigmaRuleGenerator:
    """
    Generates production-grade Sigma rules from intelligence artifacts.

    Rule categories generated:
      - IP-based C2 detection (network connection rules)
      - Domain-based C2 detection (DNS + proxy rules)
      - File hash detection (file event rules)
      - CVE exploit detection (process/network patterns)
      - Malware behavioral patterns (process + file rules)
      - Ransomware indicators (file + registry rules)
    """

    SIGMA_TEMPLATE = """\
title: {title}
id: {rule_id}
status: {status}
description: |
    {description}
author: CYBERDUDEBIVASH® SENTINEL APEX v82.0
date: {date}
modified: {date}
references:
{references}
tags:
{tags}
logsource:
    category: {logsource_category}
{logsource_extra}detection:
    selection:
{detection_selection}    condition: selection
falsepositives:
{falsepositives}
level: {level}
"""

    def generate_ip_rule(self, ips: List[str], intel_context: Dict) -> Optional[Dict]:
        """Generate Sigma rule for malicious IP C2 detection."""
        if not ips:
            return None

        ips_filtered = ips[:50]
        title = f"CDB - Malicious C2 IP Communication - {intel_context.get('title', 'Unknown')[:50]}"
        rule_id = str(uuid.uuid4())

        tags = self._build_tags(
            intel_context.get("ttps", ["T1071.001"]),
            intel_context.get("malware_families", []),
        )

        detection_ips = "\n".join(f"            - '{ip}'" for ip in ips_filtered)
        detection_block = f"        DestinationIp|contains:\n{detection_ips}\n"

        description = (
            f"Detects network connections to known malicious C2 IP addresses associated with "
            f"{', '.join(intel_context.get('malware_families', ['unknown malware'])) or 'threat actor activity'}. "
            f"Source: {intel_context.get('source_url', 'CDB SENTINEL APEX')}. "
            f"Risk Score: {intel_context.get('risk_score', 'N/A')}/100."
        )

        refs = [f"    - '{intel_context.get('source_url', 'https://intel.cyberdudebivash.com')}'" ]
        for cve in intel_context.get("cves", [])[:3]:
            refs.append(f"    - 'https://nvd.nist.gov/vuln/detail/{cve}'")

        sigma_yaml = self.SIGMA_TEMPLATE.format(
            title=title,
            rule_id=rule_id,
            status="stable" if len(ips_filtered) >= 5 else "experimental",
            description=description,
            date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            references="\n".join(refs),
            tags=tags,
            logsource_category="network_connection",
            logsource_extra="    product: windows\n",
            detection_selection=detection_block,
            falsepositives="    - Legitimate services using these IPs (verify before blocking)",
            level=self._risk_to_level(intel_context.get("risk_score", 50)),
        )

        return {
            "rule_id": rule_id,
            "rule_type": "sigma",
            "category": "c2_ip",
            "title": title,
            "level": self._risk_to_level(intel_context.get("risk_score", 50)),
            "yaml_content": sigma_yaml,
            "ioc_count": len(ips_filtered),
            "platforms": ["windows", "linux"],
            "siem_targets": ["splunk", "elastic", "sentinel", "qradar"],
            "mitre_ttps": intel_context.get("ttps", ["T1071.001"]),
        }

    def generate_domain_rule(self, domains: List[str], intel_context: Dict) -> Optional[Dict]:
        """Generate Sigma rule for malicious domain DNS/proxy detection."""
        if not domains:
            return None

        domains_filtered = domains[:50]
        title = f"CDB - Malicious Domain C2 - {intel_context.get('title', 'Unknown')[:50]}"
        rule_id = str(uuid.uuid4())

        tags = self._build_tags(
            intel_context.get("ttps", ["T1071.001", "T1071.004"]),
            intel_context.get("malware_families", []),
        )

        # DNS query rule
        detection_domains = "\n".join(f"            - '{d}'" for d in domains_filtered)
        detection_block = f"        QueryName|contains:\n{detection_domains}\n"

        description = (
            f"Detects DNS queries to known malicious C2 domains associated with threat actor activity. "
            f"Domains linked to: {', '.join(intel_context.get('malware_families', ['unknown malware']))}. "
            f"Risk Score: {intel_context.get('risk_score', 'N/A')}/100."
        )

        sigma_yaml = self.SIGMA_TEMPLATE.format(
            title=title,
            rule_id=rule_id,
            status="stable" if len(domains_filtered) >= 3 else "experimental",
            description=description,
            date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            references=f"    - '{intel_context.get('source_url', 'https://intel.cyberdudebivash.com')}'",
            tags=tags,
            logsource_category="dns",
            logsource_extra="",
            detection_selection=detection_block,
            falsepositives="    - CDN/legitimate services with overlapping domain patterns",
            level=self._risk_to_level(intel_context.get("risk_score", 50)),
        )

        return {
            "rule_id": rule_id,
            "rule_type": "sigma",
            "category": "c2_domain",
            "title": title,
            "level": self._risk_to_level(intel_context.get("risk_score", 50)),
            "yaml_content": sigma_yaml,
            "ioc_count": len(domains_filtered),
            "platforms": ["windows", "linux", "network"],
            "siem_targets": ["splunk", "elastic", "sentinel"],
            "mitre_ttps": ["T1071.001", "T1071.004"],
        }

    def generate_hash_rule(self, hashes: Dict[str, List[str]], intel_context: Dict) -> Optional[Dict]:
        """Generate Sigma file hash detection rule."""
        all_hashes = []
        for hash_type, vals in hashes.items():
            if hash_type in ("sha256", "sha1", "md5"):
                all_hashes.extend([(hash_type, v) for v in vals[:20]])

        if not all_hashes:
            return None

        title = f"CDB - Malicious File Hash - {intel_context.get('title', 'Unknown')[:50]}"
        rule_id = str(uuid.uuid4())

        tags = self._build_tags(
            intel_context.get("ttps", ["T1105"]),
            intel_context.get("malware_families", []),
        )

        detection_lines = []
        for hash_type, hval in all_hashes:
            field_map = {"sha256": "SHA256", "sha1": "SHA1", "md5": "MD5"}
            field = field_map.get(hash_type, "SHA256")
            detection_lines.append(f"        Hashes|contains: '{field}={hval}'")

        detection_block = "\n".join(detection_lines) + "\n"

        sigma_yaml = self.SIGMA_TEMPLATE.format(
            title=title,
            rule_id=rule_id,
            status="stable",
            description=f"Detects files with known malicious hashes associated with "
                        f"{', '.join(intel_context.get('malware_families', ['unknown malware']))}. "
                        f"Risk Score: {intel_context.get('risk_score', 'N/A')}/100.",
            date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            references=f"    - '{intel_context.get('source_url', 'https://intel.cyberdudebivash.com')}'",
            tags=tags,
            logsource_category="file_event",
            logsource_extra="    product: windows\n",
            detection_selection=detection_block,
            falsepositives="    - None expected (exact hash match)",
            level=self._risk_to_level(intel_context.get("risk_score", 60)),
        )

        return {
            "rule_id": rule_id,
            "rule_type": "sigma",
            "category": "malicious_hash",
            "title": title,
            "level": self._risk_to_level(intel_context.get("risk_score", 60)),
            "yaml_content": sigma_yaml,
            "ioc_count": len(all_hashes),
            "platforms": ["windows", "linux"],
            "siem_targets": ["splunk", "elastic", "sentinel", "qradar"],
            "mitre_ttps": ["T1105"],
        }

    def generate_ransomware_behavioral_rule(self, malware_families: List[str], intel_context: Dict) -> Optional[Dict]:
        """Generate behavioral Sigma rule for ransomware patterns."""
        ransomware_families = [f for f in malware_families if f in (
            "lockbit", "blackcat", "conti", "revil", "ryuk", "cl0p",
            "darkside", "maze", "ragnar", "wannacry",
        )]

        if not ransomware_families:
            return None

        title = f"CDB - Ransomware Behavioral Pattern - {', '.join(ransomware_families[:3]).title()}"
        rule_id = str(uuid.uuid4())

        # Ransomware behavioral indicators
        detection_block = """\
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
        selection_recover:
        CommandLine|contains|all:
            - 'wbadmin'
            - 'delete'
        selection_bcdedit:
        CommandLine|contains|all:
            - 'bcdedit'
            - 'recoveryenabled'
            - 'no'
"""

        tags = self._build_tags(["T1486", "T1490", "T1059.003"], ransomware_families)

        sigma_yaml = self.SIGMA_TEMPLATE.format(
            title=title,
            rule_id=rule_id,
            status="stable",
            description=(
                f"Detects behavioral patterns associated with {', '.join(ransomware_families)} ransomware: "
                f"shadow copy deletion, backup tampering, and recovery inhibition. "
                f"High confidence ransomware pre-encryption activity."
            ),
            date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            references=(
                f"    - 'https://intel.cyberdudebivash.com'\n"
                f"    - 'https://attack.mitre.org/techniques/T1490/'"
            ),
            tags=tags,
            logsource_category="process_creation",
            logsource_extra="    product: windows\n",
            detection_selection=detection_block,
            falsepositives="    - Legitimate system administration (review context carefully)",
            level="critical",
        )

        return {
            "rule_id": rule_id,
            "rule_type": "sigma",
            "category": "ransomware_behavioral",
            "title": title,
            "level": "critical",
            "yaml_content": sigma_yaml,
            "ioc_count": 0,
            "platforms": ["windows"],
            "siem_targets": ["splunk", "elastic", "sentinel", "qradar"],
            "mitre_ttps": ["T1486", "T1490", "T1059.003"],
        }

    def generate_cve_exploit_rule(self, cve_id: str, cve_data: Dict, intel_context: Dict) -> Optional[Dict]:
        """Generate CVE-specific exploit detection rule."""
        cvss = cve_data.get("cvss_score", 0.0)
        if cvss < 7.0 and not cve_data.get("kev_status"):
            return None  # Only generate rules for HIGH/CRITICAL or KEV CVEs

        title = f"CDB - {cve_id} Exploit Attempt Detection"
        rule_id = str(uuid.uuid4())
        cve_name = intel_context.get("exploit_name", cve_id)

        affected = cve_data.get("affected_products", [])
        product_keywords = []
        for prod in affected[:5]:
            parts = prod.split(":")
            if len(parts) >= 2:
                product_keywords.append(parts[1])

        tags = self._build_tags(["T1190", "T1059"], intel_context.get("malware_families", []))
        tags += f"\n    - 'cve.{cve_id.lower().replace('-', '.')}'"

        if product_keywords:
            detection_block = (
                "        CommandLine|contains:\n" +
                "\n".join(f"            - '{kw}'" for kw in product_keywords[:5]) +
                "\n"
            )
        else:
            detection_block = (
                f"        CommandLine|contains:\n"
                f"            - '{cve_id}'\n"
                f"            - 'exploit'\n"
            )

        kev_note = " [CISA KEV - ACTIVELY EXPLOITED]" if cve_data.get("kev_status") else ""
        epss_note = f" EPSS: {cve_data.get('epss_score', 0):.1%}" if cve_data.get("epss_score") else ""

        sigma_yaml = self.SIGMA_TEMPLATE.format(
            title=title,
            rule_id=rule_id,
            status="stable" if cve_data.get("kev_status") else "experimental",
            description=(
                f"Detects exploitation attempts of {cve_id} ({cve_name}){kev_note}.{epss_note} "
                f"CVSS: {cvss}/10. Affected: {', '.join(affected[:3]) or 'See NVD'}."
            ),
            date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            references=(
                f"    - 'https://nvd.nist.gov/vuln/detail/{cve_id}'\n"
                f"    - 'https://intel.cyberdudebivash.com'"
            ),
            tags=tags,
            logsource_category="process_creation",
            logsource_extra="    product: windows\n",
            detection_selection=detection_block,
            falsepositives=(
                "    - Legitimate use of affected products\n"
                "    - Security scanners performing vulnerability assessment"
            ),
            level="critical" if cve_data.get("kev_status") else self._risk_to_level(cvss * 10),
        )

        return {
            "rule_id": rule_id,
            "rule_type": "sigma",
            "category": "cve_exploit",
            "title": title,
            "cve_id": cve_id,
            "level": "critical" if cve_data.get("kev_status") else self._risk_to_level(cvss * 10),
            "yaml_content": sigma_yaml,
            "ioc_count": 0,
            "platforms": ["windows", "linux"],
            "siem_targets": ["splunk", "elastic", "sentinel"],
            "mitre_ttps": ["T1190"],
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _build_tags(self, ttps: List[str], malware_families: List[str]) -> str:
        lines = []
        for ttp in ttps[:10]:
            ttp_clean = ttp.replace(".", "/")
            lines.append(f"    - 'attack.{ttp_clean.lower()}'")
        tactic_map = {
            "T1566": "attack.initial_access", "T1190": "attack.initial_access",
            "T1059": "attack.execution", "T1486": "attack.impact",
            "T1490": "attack.impact", "T1071": "attack.command_and_control",
            "T1055": "attack.defense_evasion", "T1027": "attack.defense_evasion",
        }
        tactics = set()
        for ttp in ttps:
            base = ttp.split(".")[0]
            if base in tactic_map:
                tactics.add(tactic_map[base])
        for tactic in tactics:
            if tactic not in [l.strip(" '") for l in lines]:
                lines.append(f"    - '{tactic}'")
        for fam in malware_families[:3]:
            fam_tag = fam.lower().replace(" ", "_")
            lines.append(f"    - 'detection.cdb.{fam_tag}'")
        return "\n".join(lines) if lines else "    - 'attack.t0000'"

    def _risk_to_level(self, risk_score: float) -> str:
        if risk_score >= 85:  return "critical"
        if risk_score >= 70:  return "high"
        if risk_score >= 45:  return "medium"
        if risk_score >= 20:  return "low"
        return "informational"


# ════════════════════════════════════════════════════════════════════════════════
# YARA RULE GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class YARAGenerator:
    """
    Generates YARA rules from IOC artifacts for file, memory, and network scanning.

    Rule types:
      - Hash rules:     Direct file hash matching
      - String rules:   Pattern-based content matching (domains, IPs in binaries)
      - Behavioral:     Malware family behavioral signatures
      - Network:        Network artifact detection (for Zeek/Snort YARA integration)
    """

    YARA_HEADER = """\
/*
 * CYBERDUDEBIVASH® SENTINEL APEX — YARA Rule
 * Generated: {date}
 * Rule ID:   {rule_id}
 * Severity:  {severity}
 * MITRE:     {mitre}
 * Source:    {source}
 *
 * PRODUCTION DEPLOYMENT:
 *   yara -r this_rule.yar /path/to/scan/
 *   or import into EDR platform (CrowdStrike, SentinelOne, etc.)
 */
"""

    def generate_hash_yara(self, hashes: Dict[str, List[str]], intel_context: Dict) -> Optional[Dict]:
        """Generate YARA rule for file hash matching."""
        sha256_list = hashes.get("sha256", [])[:50]
        sha1_list   = hashes.get("sha1", [])[:50]
        md5_list    = hashes.get("md5", [])[:50]

        if not (sha256_list or sha1_list or md5_list):
            return None

        rule_id = f"CDB_{hashlib.sha256(str(hashes).encode()).hexdigest()[:8].upper()}"
        malware_names = [f.replace(" ", "_").upper() for f in intel_context.get("malware_families", ["UNKNOWN"])]
        rule_name = f"CDB_MalHash_{'_'.join(malware_names[:2])}_{rule_id}"

        condition_parts = []
        meta_hashes = []

        if sha256_list:
            for i, h in enumerate(sha256_list[:5]):
                meta_hashes.append(f'    sha256_{i} = "{h}"')
            condition_parts.append(
                "hash.sha256(0, filesize) in {\n            " +
                ",\n            ".join(f'"{h}"' for h in sha256_list[:20]) +
                "\n        }"
            )

        if sha1_list:
            condition_parts.append(
                "hash.sha1(0, filesize) in {\n            " +
                ",\n            ".join(f'"{h}"' for h in sha1_list[:20]) +
                "\n        }"
            )

        if md5_list:
            condition_parts.append(
                "hash.md5(0, filesize) in {\n            " +
                ",\n            ".join(f'"{h}"' for h in md5_list[:20]) +
                "\n        }"
            )

        condition = " or\n        ".join(condition_parts)

        yara_content = (
            self.YARA_HEADER.format(
                date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                rule_id=rule_id,
                severity=intel_context.get("severity", "HIGH"),
                mitre=", ".join(intel_context.get("ttps", ["T1105"])[:5]),
                source=intel_context.get("source_url", "https://intel.cyberdudebivash.com"),
            ) +
            f"rule {rule_name} {{\n"
            f"    meta:\n"
            f'        description = "Detects malicious files by hash - {intel_context.get("title", "")[:80]}"\n'
            f'        author = "CYBERDUDEBIVASH SENTINEL APEX v82.0"\n'
            f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"\n'
            f'        severity = "{intel_context.get("severity", "HIGH")}"\n'
            f'        risk_score = {intel_context.get("risk_score", 50)}\n'
            f'        hash_count = {len(sha256_list) + len(sha1_list) + len(md5_list)}\n'
            + "\n".join(meta_hashes[:5]) + "\n"
            f"    condition:\n"
            f"        {condition}\n"
            f"}}\n"
        )

        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "rule_type": "yara",
            "category": "file_hash",
            "yara_content": yara_content,
            "hash_count": len(sha256_list) + len(sha1_list) + len(md5_list),
            "severity": intel_context.get("severity", "HIGH"),
            "platforms": ["windows", "linux", "macos"],
            "mitre_ttps": ["T1105"],
        }

    def generate_domain_yara(self, domains: List[str], intel_context: Dict) -> Optional[Dict]:
        """Generate YARA rule for domains embedded in binary artifacts."""
        if not domains or len(domains) < 2:
            return None

        domains_filtered = [d for d in domains[:30] if len(d) > 4]
        if not domains_filtered:
            return None

        rule_id = f"CDB_{hashlib.sha256(str(domains_filtered).encode()).hexdigest()[:8].upper()}"
        rule_name = f"CDB_MalDomain_C2_{rule_id}"

        strings_block = "\n".join(
            f'        $d{i} = "{domain}" ascii wide nocase'
            for i, domain in enumerate(domains_filtered[:20])
        )

        yara_content = (
            self.YARA_HEADER.format(
                date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                rule_id=rule_id,
                severity=intel_context.get("severity", "HIGH"),
                mitre="T1071.001, T1071.004",
                source=intel_context.get("source_url", "https://intel.cyberdudebivash.com"),
            ) +
            f"rule {rule_name} {{\n"
            f"    meta:\n"
            f'        description = "Detects malicious C2 domains embedded in file artifacts"\n'
            f'        author = "CYBERDUDEBIVASH SENTINEL APEX v82.0"\n'
            f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"\n'
            f'        severity = "{intel_context.get("severity", "HIGH")}"\n'
            f'        domain_count = {len(domains_filtered)}\n'
            f"    strings:\n"
            f"{strings_block}\n"
            f"    condition:\n"
            f"        any of ($d*)\n"
            f"}}\n"
        )

        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "rule_type": "yara",
            "category": "c2_domain_embedded",
            "yara_content": yara_content,
            "domain_count": len(domains_filtered),
            "severity": intel_context.get("severity", "HIGH"),
            "platforms": ["windows", "linux", "macos"],
            "mitre_ttps": ["T1071.001", "T1071.004"],
        }

    def generate_malware_behavioral_yara(self, malware_family: str) -> Optional[Dict]:
        """Generate behavioral YARA rules for known malware families."""
        BEHAVIORAL_SIGNATURES: Dict[str, Dict] = {
            "cobalt strike": {
                "strings": [
                    ("$beacon1", "beacon.x64.dll", "ascii wide"),
                    ("$beacon2", "ReflectiveDll", "ascii wide"),
                    ("$cs_named_pipe", "\\\\.\\pipe\\", "ascii"),
                    ("$malleable", "Content-Type: application/octet-stream", "ascii"),
                    ("$cfg_xor", r"\x69\x68\x69\x68", ""),
                ],
                "condition": "2 of them",
                "ttps": ["T1055", "T1071.001", "T1021.002"],
            },
            "mimikatz": {
                "strings": [
                    ("$mk1", "sekurlsa::logonpasswords", "ascii wide nocase"),
                    ("$mk2", "lsadump::sam", "ascii wide nocase"),
                    ("$mk3", "privilege::debug", "ascii wide nocase"),
                    ("$mk4", "Benjamin DELPY", "ascii wide"),
                    ("$mk5", "mimikatz", "ascii wide nocase"),
                ],
                "condition": "3 of them",
                "ttps": ["T1003.001", "T1003.002"],
            },
            "emotet": {
                "strings": [
                    ("$emo1", "Global\\M", "ascii"),
                    ("$emo2", r"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", ""),
                    ("$emo3", "WriteFile", "ascii"),
                    ("$emo4", "WSAStartup", "ascii"),
                ],
                "condition": "3 of them",
                "ttps": ["T1566.001", "T1059.003"],
            },
            "lockbit": {
                "strings": [
                    ("$lb1", "LockBit", "ascii wide nocase"),
                    ("$lb2", ".lockbit", "ascii wide nocase"),
                    ("$lb3", "vssadmin delete shadows", "ascii wide nocase"),
                    ("$lb4", "Restore-My-Files.txt", "ascii wide"),
                ],
                "condition": "2 of them",
                "ttps": ["T1486", "T1490"],
            },
        }

        fam_lower = malware_family.lower()
        sig = BEHAVIORAL_SIGNATURES.get(fam_lower)
        if not sig:
            return None

        rule_id = f"CDB_{malware_family.upper().replace(' ', '_')}_{hashlib.sha256(malware_family.encode()).hexdigest()[:6].upper()}"
        rule_name = f"CDB_Malware_{malware_family.replace(' ', '_').title()}_{rule_id[-6:]}"

        strings_block = "\n".join(
            f"        {name} = \"{pattern}\" {modifiers}"
            for name, pattern, modifiers in sig["strings"]
        )

        yara_content = (
            self.YARA_HEADER.format(
                date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                rule_id=rule_id,
                severity="CRITICAL",
                mitre=", ".join(sig["ttps"]),
                source="https://intel.cyberdudebivash.com",
            ) +
            f"rule {rule_name} {{\n"
            f"    meta:\n"
            f'        description = "Detects {malware_family.title()} malware behavioral artifacts"\n'
            f'        author = "CYBERDUDEBIVASH SENTINEL APEX v82.0"\n'
            f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"\n'
            f'        malware_family = "{malware_family.title()}"\n'
            f'        severity = "CRITICAL"\n'
            f"    strings:\n"
            f"{strings_block}\n"
            f"    condition:\n"
            f"        {sig['condition']}\n"
            f"}}\n"
        )

        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "rule_type": "yara",
            "category": "malware_behavioral",
            "malware_family": malware_family,
            "yara_content": yara_content,
            "severity": "CRITICAL",
            "platforms": ["windows", "linux", "macos"],
            "mitre_ttps": sig["ttps"],
        }


# ════════════════════════════════════════════════════════════════════════════════
# DETECTION PLAYBOOK GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class PlaybookGenerator:
    """
    Generates structured analyst response playbooks from correlated threat intel.
    Output: Markdown with triage steps, investigation queries, containment actions.
    """

    def generate_playbook(self, correlation_result: Dict) -> str:
        """Generate a complete incident response playbook."""
        risk = correlation_result.get("risk_scoring", {})
        score = risk.get("risk_score", 0)
        severity = risk.get("severity", "UNKNOWN")
        cves = correlation_result.get("cves", [])
        malware = correlation_result.get("malware_correlation", {}).get("families", [])
        actors = [a.get("actor_id", "Unknown") for a in correlation_result.get("actor_correlation", [])[:3]]
        iocs = correlation_result.get("iocs", {})
        ttps = correlation_result.get("malware_correlation", {}).get("ttps", [])
        title = correlation_result.get("title", "Unknown Threat")
        intel_id = correlation_result.get("intel_id", "UNK")

        pb = []
        pb.append(f"# 🚨 INCIDENT RESPONSE PLAYBOOK — {severity}")
        pb.append(f"**Intel ID:** `{intel_id}` | **Risk Score:** `{score}/100` | **Severity:** `{severity}`")
        pb.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
        pb.append(f"**Threat:** {title[:100]}")
        pb.append("")

        # Triage classification
        pb.append("## 1. TRIAGE CLASSIFICATION")
        pb.append("")
        if score >= 85:
            pb.append("🔴 **CRITICAL — Immediate P1 Response Required**")
            pb.append("- Escalate to SOC Lead and CISO immediately")
            pb.append("- Activate incident response team")
            pb.append("- Consider network isolation of affected assets")
        elif score >= 70:
            pb.append("🟠 **HIGH — Priority P2 Response**")
            pb.append("- Assign senior analyst immediately")
            pb.append("- Alert SOC Lead within 30 minutes")
        elif score >= 45:
            pb.append("🟡 **MEDIUM — Standard P3 Response**")
            pb.append("- Assign to next available analyst")
            pb.append("- Complete initial triage within 4 hours")
        else:
            pb.append("🟢 **LOW/INFO — Monitor and Document**")
            pb.append("- Log for trending analysis")
            pb.append("- Review during next threat intel cycle")
        pb.append("")

        # Threat context
        pb.append("## 2. THREAT CONTEXT")
        pb.append("")
        if cves:
            pb.append(f"**CVEs:** {', '.join(cves)}")
        if malware:
            pb.append(f"**Malware Families:** {', '.join(m.title() for m in malware)}")
        if actors:
            pb.append(f"**Attributed Actors:** {', '.join(actors)}")
        if ttps:
            pb.append(f"**MITRE TTPs:** {', '.join(ttps[:10])}")
        pb.append("")

        # IOC inventory
        pb.append("## 3. IOC INVENTORY")
        pb.append("")
        pb.append("| Type | Count | Action |")
        pb.append("|------|-------|--------|")
        for ioc_type, vals in iocs.items():
            if isinstance(vals, list) and vals:
                action = {
                    "ipv4": "Block at firewall/NAC", "domain": "Block at DNS/proxy",
                    "sha256": "Add to EDR/AV blocklist", "sha1": "Add to EDR/AV blocklist",
                    "md5": "Add to EDR/AV blocklist", "url": "Block at proxy/CASB",
                    "cve": "Patch immediately if KEV",
                }.get(ioc_type, "Investigate")
                pb.append(f"| {ioc_type} | {len(vals)} | {action} |")
        pb.append("")

        # Investigation steps
        pb.append("## 4. INVESTIGATION STEPS")
        pb.append("")
        pb.append("### 4.1 Initial Scope")
        pb.append("```")
        pb.append("# Check for IOC presence across environment")
        for ioc_type, vals in iocs.items():
            if isinstance(vals, list) and vals:
                for val in vals[:3]:
                    if ioc_type == "ipv4":
                        pb.append(f"# Search for connections to: {val}")
                        pb.append(f'index=network_logs dest_ip="{val}" | stats count by src_ip')
                    elif ioc_type == "domain":
                        pb.append(f"# Search for DNS queries to: {val}")
                        pb.append(f'index=dns_logs query="{val}" | stats count by src_ip')
                    elif ioc_type in ("sha256", "sha1"):
                        pb.append(f"# Search for file hash: {val}")
                        pb.append(f'index=endpoint_logs hash="{val}" | stats count by host')
        pb.append("```")
        pb.append("")

        # Splunk hunting queries
        pb.append("### 4.2 Splunk Threat Hunting Queries")
        pb.append("")
        ip_list = iocs.get("ipv4", [])[:5]
        domain_list = iocs.get("domain", [])[:5]
        hash_list = iocs.get("sha256", [])[:5]

        if ip_list:
            ip_str = '", "'.join(ip_list)
            pb.append("```spl")
            pb.append(f'(index=network_logs OR index=firewall) dest_ip IN ("{ip_str}")')
            pb.append("| stats count, values(src_ip) as source_ips by dest_ip")
            pb.append("| sort -count")
            pb.append("```")
            pb.append("")

        if domain_list:
            domain_str = '", "'.join(domain_list)
            pb.append("```spl")
            pb.append(f'(index=dns OR index=proxy) (query IN ("{domain_str}") OR url IN ("{domain_str}"))')
            pb.append("| stats count, values(src_ip) as hosts by query")
            pb.append("| sort -count")
            pb.append("```")
            pb.append("")

        if hash_list:
            hash_str = '", "'.join(hash_list)
            pb.append("```spl")
            pb.append(f'index=endpoint (hash IN ("{hash_str}") OR sha256 IN ("{hash_str}"))')
            pb.append("| stats count, values(host) as hosts by hash")
            pb.append("```")
            pb.append("")

        # CVE remediation
        if cves:
            pb.append("## 5. CVE REMEDIATION")
            pb.append("")
            for cve_id in cves[:5]:
                cve_data = correlation_result.get("cve_enrichments", {}).get(cve_id, {})
                kev = cve_data.get("kev_status", False)
                cvss = cve_data.get("cvss_score", "N/A")
                epss = cve_data.get("epss_score", 0)
                priority = "🔴 PATCH NOW (KEV)" if kev else f"🟡 PATCH WITHIN {'24H' if float(cvss or 0) >= 9.0 else '7D'}"
                pb.append(f"### {cve_id}")
                pb.append(f"- **Priority:** {priority}")
                pb.append(f"- **CVSS:** {cvss} | **EPSS:** {epss:.1%}" if isinstance(epss, float) else f"- **CVSS:** {cvss}")
                pb.append(f"- **Action:** Apply vendor patch. See: https://nvd.nist.gov/vuln/detail/{cve_id}")
                affected = cve_data.get("affected_products", [])
                if affected:
                    pb.append(f"- **Affected:** {', '.join(affected[:5])}")
                pb.append("")

        # Containment actions
        pb.append("## 6. CONTAINMENT ACTIONS")
        pb.append("")
        pb.append("### Immediate (0-2 hours)")
        if ip_list:
            pb.append(f"- [ ] Block IPs at perimeter firewall: `{', '.join(ip_list[:3])}`")
        if domain_list:
            pb.append(f"- [ ] Block domains at DNS sinkholes: `{', '.join(domain_list[:3])}`")
        if hash_list:
            pb.append(f"- [ ] Add file hashes to EDR/AV blocklist")
        if "ransomware" in str(malware).lower() or any(f in ["lockbit", "blackcat", "conti", "revil"] for f in malware):
            pb.append("- [ ] Disable SMB shares on affected segments")
            pb.append("- [ ] Verify backup integrity immediately")
            pb.append("- [ ] Consider isolating affected VLAN")
        pb.append("")
        pb.append("### Short-term (2-24 hours)")
        pb.append("- [ ] Conduct full endpoint sweep for IOCs")
        pb.append("- [ ] Review authentication logs for lateral movement")
        pb.append("- [ ] Check patch status for identified CVEs")
        pb.append("- [ ] Brief executive stakeholders if CRITICAL")
        pb.append("")

        # Post-incident
        pb.append("## 7. POST-INCIDENT")
        pb.append("")
        pb.append("- [ ] Document timeline and affected assets")
        pb.append("- [ ] Update threat intelligence platform with new IOCs")
        pb.append("- [ ] Conduct lessons-learned review")
        pb.append("- [ ] Update detection rules based on findings")
        pb.append("- [ ] Share sanitized IOCs with ISAC/ISAO partners")
        pb.append("")

        pb.append("---")
        pb.append(f"*Generated by CYBERDUDEBIVASH® SENTINEL APEX v82.0 — {datetime.now(timezone.utc).isoformat()}*")

        return "\n".join(pb)


# ════════════════════════════════════════════════════════════════════════════════
# MASTER DETECTION RULE GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class DetectionRuleGenerator:
    """
    Master detection engine: generates all rule types from a correlation result.

    Usage:
        gen = DetectionRuleGenerator()
        rules = gen.generate_all(correlation_result)
        # returns: {"sigma_rules": [...], "yara_rules": [...], "playbook": "..."}
    """

    def __init__(self):
        self.sigma_gen    = SigmaRuleGenerator()
        self.yara_gen     = YARAGenerator()
        self.playbook_gen = PlaybookGenerator()
        self._stats       = {"rules_generated": 0, "sigma": 0, "yara": 0, "playbooks": 0}
        SIGMA_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        YARA_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("DetectionRuleGenerator initialized")

    def generate_all(self, correlation_result: Dict) -> Dict:
        """
        Generate complete detection package for a correlated intel item.

        Returns:
            {
                "sigma_rules":  [list of sigma rule dicts],
                "yara_rules":   [list of yara rule dicts],
                "playbook":     "markdown string",
                "rule_summary": {counts, coverage, ...}
            }
        """
        iocs = correlation_result.get("iocs", {})
        cve_enrichments = correlation_result.get("cve_enrichments", {})
        malware_families = correlation_result.get("malware_correlation", {}).get("families", [])
        ttps = correlation_result.get("malware_correlation", {}).get("ttps", [])
        risk = correlation_result.get("risk_scoring", {})
        title = correlation_result.get("title", "Unknown")
        intel_id = correlation_result.get("intel_id", "UNK")

        intel_context = {
            "title": title,
            "risk_score": risk.get("risk_score", 0),
            "severity": risk.get("severity", "MEDIUM"),
            "malware_families": malware_families,
            "ttps": ttps,
            "cves": correlation_result.get("cves", []),
            "source_url": correlation_result.get("source_url", ""),
        }

        sigma_rules = []
        yara_rules  = []

        # ── Sigma: IP C2 ────────────────────────────────────────────────
        ips = iocs.get("ipv4", [])
        if ips:
            rule = self.sigma_gen.generate_ip_rule(ips, intel_context)
            if rule:
                sigma_rules.append(rule)
                self._save_sigma(rule, intel_id)

        # ── Sigma: Domain C2 ───────────────────────────────────────────
        domains = iocs.get("domain", [])
        if domains:
            rule = self.sigma_gen.generate_domain_rule(domains, intel_context)
            if rule:
                sigma_rules.append(rule)
                self._save_sigma(rule, intel_id)

        # ── Sigma: Hash ────────────────────────────────────────────────
        hash_iocs = {k: v for k, v in iocs.items() if k in ("sha256", "sha1", "md5") and v}
        if hash_iocs:
            rule = self.sigma_gen.generate_hash_rule(hash_iocs, intel_context)
            if rule:
                sigma_rules.append(rule)
                self._save_sigma(rule, intel_id)

        # ── Sigma: Ransomware behavioral ───────────────────────────────
        if malware_families:
            rule = self.sigma_gen.generate_ransomware_behavioral_rule(malware_families, intel_context)
            if rule:
                sigma_rules.append(rule)
                self._save_sigma(rule, intel_id)

        # ── Sigma: CVE exploit rules ───────────────────────────────────
        for cve_id, cve_data in cve_enrichments.items():
            rule = self.sigma_gen.generate_cve_exploit_rule(cve_id, cve_data, intel_context)
            if rule:
                sigma_rules.append(rule)
                self._save_sigma(rule, intel_id)

        # ── YARA: Hash rules ───────────────────────────────────────────
        if hash_iocs:
            rule = self.yara_gen.generate_hash_yara(hash_iocs, intel_context)
            if rule:
                yara_rules.append(rule)
                self._save_yara(rule, intel_id)

        # ── YARA: Domain embedded ──────────────────────────────────────
        if domains:
            rule = self.yara_gen.generate_domain_yara(domains, intel_context)
            if rule:
                yara_rules.append(rule)
                self._save_yara(rule, intel_id)

        # ── YARA: Malware behavioral ───────────────────────────────────
        for fam in malware_families:
            rule = self.yara_gen.generate_malware_behavioral_yara(fam)
            if rule:
                yara_rules.append(rule)
                self._save_yara(rule, fam.replace(" ", "_"))

        # ── Playbook ──────────────────────────────────────────────────
        playbook_md = self.playbook_gen.generate_playbook(correlation_result)
        self._save_playbook(playbook_md, intel_id)

        # ── Stats ─────────────────────────────────────────────────────
        self._stats["rules_generated"] += len(sigma_rules) + len(yara_rules)
        self._stats["sigma"] += len(sigma_rules)
        self._stats["yara"] += len(yara_rules)
        self._stats["playbooks"] += 1

        rule_summary = {
            "sigma_count":   len(sigma_rules),
            "yara_count":    len(yara_rules),
            "total_rules":   len(sigma_rules) + len(yara_rules),
            "has_playbook":  True,
            "mitre_coverage": list(set(
                ttp for rule in sigma_rules + yara_rules
                for ttp in rule.get("mitre_ttps", [])
            )),
            "severity_breakdown": {
                "critical": sum(1 for r in sigma_rules if r.get("level") == "critical"),
                "high":     sum(1 for r in sigma_rules if r.get("level") == "high"),
                "medium":   sum(1 for r in sigma_rules if r.get("level") == "medium"),
            },
        }

        logger.info(
            f"Detection rules generated | Intel: {intel_id[:20]} | "
            f"Sigma: {len(sigma_rules)} | YARA: {len(yara_rules)} | Playbook: 1"
        )

        return {
            "sigma_rules":  sigma_rules,
            "yara_rules":   yara_rules,
            "playbook":     playbook_md,
            "rule_summary": rule_summary,
        }

    def get_stats(self) -> Dict:
        return self._stats

    # ── File I/O ─────────────────────────────────────────────────────────────

    def _save_sigma(self, rule: Dict, intel_id: str):
        try:
            safe_id = re.sub(r'[^\w\-]', '_', intel_id)[:40]
            fname = f"{safe_id}_{rule['rule_id'][:8]}.yml"
            path = SIGMA_OUTPUT_DIR / fname
            path.write_text(rule["yaml_content"])
        except Exception as e:
            logger.debug(f"Sigma save failed: {e}")

    def _save_yara(self, rule: Dict, context_id: str):
        try:
            safe_id = re.sub(r'[^\w\-]', '_', context_id)[:40]
            fname = f"{safe_id}_{rule['rule_id'][:8]}.yar"
            path = YARA_OUTPUT_DIR / fname
            path.write_text(rule["yara_content"])
        except Exception as e:
            logger.debug(f"YARA save failed: {e}")

    def _save_playbook(self, content: str, intel_id: str):
        try:
            safe_id = re.sub(r'[^\w\-]', '_', intel_id)[:40]
            fname = f"PLAYBOOK_{safe_id}.md"
            path = PLAYBOOK_DIR / fname
            path.write_text(content)
        except Exception as e:
            logger.debug(f"Playbook save failed: {e}")


# ════════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ════════════════════════════════════════════════════════════════════════════════

detection_rule_generator = DetectionRuleGenerator()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    # Demo generation
    demo_correlation = {
        "intel_id": "DEMO-CORR-001",
        "title": "LockBit 3.0 Active Campaign — CVE-2021-44228 Exploitation Chain",
        "cves": ["CVE-2021-44228"],
        "cve_enrichments": {
            "CVE-2021-44228": {
                "cvss_score": 10.0, "cvss_severity": "CRITICAL",
                "epss_score": 0.97, "kev_status": True,
                "description": "Log4Shell RCE in Apache Log4j 2.x",
                "affected_products": ["apache:log4j"],
            }
        },
        "exploit_correlation": {"exploit_maturity": "in_wild"},
        "malware_correlation": {
            "families": ["lockbit", "cobalt strike"],
            "ttps": ["T1486", "T1490", "T1059.003", "T1055", "T1190"],
        },
        "actor_correlation": [
            {"actor_id": "LockBit", "attribution_confidence": 0.87, "aliases": ["LockBit 3.0"]},
        ],
        "risk_scoring": {"risk_score": 97, "severity": "CRITICAL"},
        "iocs": {
            "ipv4": ["198.51.100.10", "203.0.113.50"],
            "domain": ["lockbit-c2.example.com", "payload-delivery.net"],
            "sha256": ["deadbeef" * 8],
        },
        "source_url": "https://intel.cyberdudebivash.com",
    }

    gen = DetectionRuleGenerator()
    result = gen.generate_all(demo_correlation)

    print("\n" + "="*70)
    print("CYBERDUDEBIVASH® — DETECTION RULE GENERATOR v82.0")
    print("="*70)
    print(f"\n✅ Rules Generated:")
    print(f"   Sigma Rules: {result['rule_summary']['sigma_count']}")
    print(f"   YARA Rules:  {result['rule_summary']['yara_count']}")
    print(f"   Playbook:    {'Yes' if result['rule_summary']['has_playbook'] else 'No'}")
    print(f"   MITRE TTPs:  {result['rule_summary']['mitre_coverage']}")
    if result["sigma_rules"]:
        print(f"\nSample Sigma Rule:\n{'='*50}")
        print(result["sigma_rules"][0]["yaml_content"][:500])
