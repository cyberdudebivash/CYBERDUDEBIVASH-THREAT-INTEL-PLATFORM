"""
CYBERDUDEBIVASH SENTINEL APEX v49 — Detection Rule Generator (API-embedded)
Generates Sigma, YARA, Suricata, Snort, KQL, SPL rules from IOC values.
"""

import re
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any


class DetectionRuleGenerator:
    """Generate multi-format detection rules from IOC indicators."""

    IOC_PATTERNS = {
        "ipv4": re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"),
        "domain": re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"),
        "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
        "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
        "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
        "url": re.compile(r"^https?://"),
        "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
        "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    }

    def classify_ioc(self, value: str) -> str:
        for ioc_type, pattern in self.IOC_PATTERNS.items():
            if pattern.match(value.strip()):
                return ioc_type
        return "unknown"

    def generate(self, ioc_values: List[str], formats: List[str]) -> Dict[str, Any]:
        classified = {}
        for ioc in ioc_values:
            ioc = ioc.strip()
            if not ioc:
                continue
            ioc_type = self.classify_ioc(ioc)
            if ioc_type not in classified:
                classified[ioc_type] = []
            classified[ioc_type].append(ioc)

        rules = {}
        rule_id = hashlib.md5("|".join(sorted(ioc_values)).encode()).hexdigest()[:12]
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        for fmt in formats:
            fmt = fmt.lower().strip()
            if fmt == "sigma":
                rules["sigma"] = self._gen_sigma(classified, rule_id, ts)
            elif fmt == "yara":
                rules["yara"] = self._gen_yara(classified, rule_id, ts)
            elif fmt == "suricata":
                rules["suricata"] = self._gen_suricata(classified, rule_id, ts)
            elif fmt == "snort":
                rules["snort"] = self._gen_snort(classified, rule_id, ts)
            elif fmt == "kql":
                rules["kql"] = self._gen_kql(classified, rule_id)
            elif fmt == "spl":
                rules["spl"] = self._gen_spl(classified, rule_id)

        return {
            "rule_id": rule_id,
            "generated_at": ts,
            "ioc_count": len(ioc_values),
            "classified": {k: len(v) for k, v in classified.items()},
            "rules": rules,
        }

    def _gen_sigma(self, classified: Dict, rule_id: str, ts: str) -> List[str]:
        rules = []

        # Network IOCs
        ips = classified.get("ipv4", [])
        domains = classified.get("domain", [])
        if ips or domains:
            detection_items = []
            if ips:
                detection_items.append(f"        DestinationIp|contains:\n" + "\n".join(f"            - '{ip}'" for ip in ips))
            if domains:
                detection_items.append(f"        DestinationHostname|contains:\n" + "\n".join(f"            - '{d}'" for d in domains))

            rule = f"""title: CDB SENTINEL APEX - Malicious Network IOC Detection [{rule_id}]
id: cdb-net-{rule_id}
status: production
description: Detects network connections to known malicious infrastructure
author: CyberDudeBivash SENTINEL APEX
date: {ts[:10]}
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: firewall
    product: any
detection:
    selection:
{chr(10).join(detection_items)}
    condition: selection
level: high
falsepositives:
    - Legitimate services sharing infrastructure
references:
    - https://intel.cyberdudebivash.com"""
            rules.append(rule)

        # File hash IOCs
        hashes = {
            "sha256": classified.get("sha256", []),
            "sha1": classified.get("sha1", []),
            "md5": classified.get("md5", []),
        }
        hash_items = []
        for hash_type, vals in hashes.items():
            for v in vals:
                hash_items.append(f"            - '{v}'")

        if hash_items:
            rule = f"""title: CDB SENTINEL APEX - Malicious File Hash Detection [{rule_id}]
id: cdb-hash-{rule_id}
status: production
description: Detects files matching known malicious hashes
author: CyberDudeBivash SENTINEL APEX
date: {ts[:10]}
tags:
    - attack.execution
    - attack.t1204
logsource:
    category: file_event
    product: any
detection:
    selection:
        Hashes|contains:
{chr(10).join(hash_items)}
    condition: selection
level: critical
falsepositives:
    - Hash collision (extremely rare)
references:
    - https://intel.cyberdudebivash.com"""
            rules.append(rule)

        return rules

    def _gen_yara(self, classified: Dict, rule_id: str, ts: str) -> List[str]:
        rules = []

        # Network IOC YARA
        ips = classified.get("ipv4", [])
        domains = classified.get("domain", [])
        if ips or domains:
            strings = []
            for i, ip in enumerate(ips):
                strings.append(f'        $ip_{i} = "{ip}" ascii wide nocase')
            for i, d in enumerate(domains):
                strings.append(f'        $dom_{i} = "{d}" ascii wide nocase')

            condition_parts = []
            if ips:
                condition_parts.append(f"any of ($ip_*)")
            if domains:
                condition_parts.append(f"any of ($dom_*)")

            rule = f"""rule CDB_SENTINEL_Network_IOC_{rule_id}
{{
    meta:
        author = "CyberDudeBivash SENTINEL APEX"
        description = "Detects known malicious network indicators"
        date = "{ts[:10]}"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        rule_id = "{rule_id}"

    strings:
{chr(10).join(strings)}

    condition:
        filesize < 50MB and ({' or '.join(condition_parts)})
}}"""
            rules.append(rule)

        # Hash YARA
        hashes_all = classified.get("sha256", []) + classified.get("sha1", []) + classified.get("md5", [])
        if hashes_all:
            hash_strings = []
            for i, h in enumerate(hashes_all):
                hash_strings.append(f'        $hash_{i} = "{h}" ascii wide nocase')

            rule = f"""rule CDB_SENTINEL_Hash_IOC_{rule_id}
{{
    meta:
        author = "CyberDudeBivash SENTINEL APEX"
        description = "Detects files containing known malicious hash references"
        date = "{ts[:10]}"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
{chr(10).join(hash_strings)}

    condition:
        filesize < 100MB and any of ($hash_*)
}}"""
            rules.append(rule)

        return rules

    def _gen_suricata(self, classified: Dict, rule_id: str, ts: str) -> List[str]:
        rules = []
        sid_base = int(rule_id[:6], 16) % 900000 + 9000000

        for i, ip in enumerate(classified.get("ipv4", [])):
            rules.append(
                f'alert ip any any -> {ip} any '
                f'(msg:"CDB SENTINEL - Malicious IP: {ip}"; '
                f'sid:{sid_base + i}; rev:1; '
                f'classtype:trojan-activity; '
                f'metadata:created_at {ts[:10]}, '
                f'source CyberDudeBivash_SENTINEL_APEX;)'
            )

        for i, domain in enumerate(classified.get("domain", [])):
            rules.append(
                f'alert dns any any -> any any '
                f'(msg:"CDB SENTINEL - Malicious Domain: {domain}"; '
                f'dns.query; content:"{domain}"; nocase; '
                f'sid:{sid_base + 1000 + i}; rev:1; '
                f'classtype:trojan-activity; '
                f'metadata:created_at {ts[:10]}, '
                f'source CyberDudeBivash_SENTINEL_APEX;)'
            )

        return rules

    def _gen_snort(self, classified: Dict, rule_id: str, ts: str) -> List[str]:
        rules = []
        sid_base = int(rule_id[:6], 16) % 900000 + 8000000

        for i, ip in enumerate(classified.get("ipv4", [])):
            rules.append(
                f'alert ip any any -> {ip} any '
                f'(msg:"CDB SENTINEL Malicious IP {ip}"; '
                f'sid:{sid_base + i}; rev:1; '
                f'classtype:trojan-activity;)'
            )

        for i, domain in enumerate(classified.get("domain", [])):
            rules.append(
                f'alert udp any any -> any 53 '
                f'(msg:"CDB SENTINEL Malicious DNS {domain}"; '
                f'content:"|{self._dns_encode(domain)}|"; nocase; '
                f'sid:{sid_base + 1000 + i}; rev:1; '
                f'classtype:trojan-activity;)'
            )

        return rules

    def _dns_encode(self, domain: str) -> str:
        """Encode domain for Snort DNS content match."""
        parts = domain.split(".")
        encoded = ""
        for part in parts:
            encoded += f"{len(part):02x} " + " ".join(f"{ord(c):02x}" for c in part) + " "
        return encoded.strip()

    def _gen_kql(self, classified: Dict, rule_id: str) -> List[str]:
        queries = []

        ips = classified.get("ipv4", [])
        if ips:
            ip_list = ", ".join(f'"{ip}"' for ip in ips)
            queries.append(
                f'// CDB SENTINEL APEX - Malicious IP Detection [{rule_id}]\n'
                f'let MaliciousIPs = dynamic([{ip_list}]);\n'
                f'DeviceNetworkEvents\n'
                f'| where RemoteIP in (MaliciousIPs)\n'
                f'| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName\n'
                f'| sort by TimeGenerated desc'
            )

        domains = classified.get("domain", [])
        if domains:
            dom_list = ", ".join(f'"{d}"' for d in domains)
            queries.append(
                f'// CDB SENTINEL APEX - Malicious Domain Detection [{rule_id}]\n'
                f'let MaliciousDomains = dynamic([{dom_list}]);\n'
                f'DnsEvents\n'
                f'| where Name has_any (MaliciousDomains)\n'
                f'| project TimeGenerated, Computer, Name, QueryType, IPAddresses\n'
                f'| sort by TimeGenerated desc'
            )

        return queries

    def _gen_spl(self, classified: Dict, rule_id: str) -> List[str]:
        queries = []

        ips = classified.get("ipv4", [])
        if ips:
            ip_search = " OR ".join(f'dest_ip="{ip}"' for ip in ips)
            queries.append(
                f'`comment("CDB SENTINEL APEX - Malicious IP Detection [{rule_id}]")`\n'
                f'index=firewall ({ip_search})\n'
                f'| stats count by dest_ip, src_ip, dest_port, action\n'
                f'| sort -count'
            )

        domains = classified.get("domain", [])
        if domains:
            dom_search = " OR ".join(f'query="{d}"' for d in domains)
            queries.append(
                f'`comment("CDB SENTINEL APEX - Malicious Domain Detection [{rule_id}]")`\n'
                f'index=dns ({dom_search})\n'
                f'| stats count by query, src_ip, record_type\n'
                f'| sort -count'
            )

        return queries
