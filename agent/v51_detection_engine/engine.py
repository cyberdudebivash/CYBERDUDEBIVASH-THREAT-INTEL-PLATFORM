"""
CYBERDUDEBIVASH SENTINEL APEX v51 — Detection Engine
Automated detection rule generation from intelligence feeds.

Reads IOC data from existing STIX bundles and feed manifests,
generates production Sigma, YARA, and Suricata rules.

Outputs:
    data/intelligence/detection_rules/sigma/
    data/intelligence/detection_rules/yara/
    data/intelligence/detection_rules/suricata/
    data/intelligence/detection_rules/rule_manifest.json
"""

import json
import re
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
STIX_DIR = DATA_DIR / "stix"
INTEL_DIR = DATA_DIR / "intelligence"
RULES_DIR = INTEL_DIR / "detection_rules"
SIGMA_DIR = RULES_DIR / "sigma"
YARA_DIR = RULES_DIR / "yara"
SURICATA_DIR = RULES_DIR / "suricata"
MANIFEST_FILE = RULES_DIR / "rule_manifest.json"

for d in (SIGMA_DIR, YARA_DIR, SURICATA_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECT-ENGINE] %(levelname)s %(message)s")
logger = logging.getLogger("detection_engine")

# ---------------------------------------------------------------------------
# IOC Classification
# ---------------------------------------------------------------------------

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|ga|ml|cf|gq|work|click|link|online|site|live|pro|tech|club|space)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "url": re.compile(r"https?://[^\s<>\"']+"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "registry": re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\[^\s\"']+"),
}

PRIVATE_IP_RANGES = [
    (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
    (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8
]

FALSE_POSITIVE_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "cloudflare.com",
    "amazonaws.com", "azure.com", "facebook.com", "twitter.com",
    "linkedin.com", "apple.com", "akamai.com", "fastly.com",
    "mozilla.org", "w3.org", "schema.org", "example.com",
}

# MITRE ATT&CK mapping for IOC types
IOC_TO_MITRE = {
    "ipv4": [("T1071", "Application Layer Protocol"), ("T1090", "Proxy")],
    "domain": [("T1071", "Application Layer Protocol"), ("T1568", "Dynamic Resolution")],
    "url": [("T1071.001", "Web Protocols"), ("T1105", "Ingress Tool Transfer")],
    "sha256": [("T1204", "User Execution"), ("T1059", "Command and Scripting Interpreter")],
    "sha1": [("T1204", "User Execution")],
    "md5": [("T1204", "User Execution")],
    "email": [("T1566", "Phishing"), ("T1598", "Phishing for Information")],
    "registry": [("T1112", "Modify Registry"), ("T1547.001", "Registry Run Keys")],
}


def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def is_private_ip(ip: str) -> bool:
    try:
        ip_int = ip_to_int(ip)
        for start, end in PRIVATE_IP_RANGES:
            if start <= ip_int <= end:
                return True
    except (ValueError, IndexError):
        pass
    return False


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class ExtractedIOC:
    value: str
    ioc_type: str
    source_advisory: str
    risk_score: float = 0.0
    actor_tag: str = ""
    mitre_tactics: List[str] = field(default_factory=list)
    confidence: float = 0.0

@dataclass
class GeneratedRule:
    rule_id: str
    rule_type: str  # sigma, yara, suricata
    title: str
    content: str
    ioc_count: int
    ioc_types: List[str]
    severity: str
    mitre_techniques: List[str]
    generated_at: str
    source_advisories: List[str]
    filename: str


# ---------------------------------------------------------------------------
# IOC Extractor
# ---------------------------------------------------------------------------

class IOCExtractor:
    """Extract and classify IOCs from intelligence feeds."""

    def extract_from_manifest(self, manifest_path: Path) -> List[ExtractedIOC]:
        """Extract IOCs from feed_manifest.json."""
        iocs: List[ExtractedIOC] = []

        if not manifest_path.exists():
            logger.warning(f"Manifest not found: {manifest_path}")
            return iocs

        try:
            with open(manifest_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load manifest: {e}")
            return iocs

        entries = data if isinstance(data, list) else data.get("entries", [])

        for entry in entries:
            title = entry.get("title", "Unknown Advisory")
            risk_score = entry.get("risk_score", 0)
            actor_tag = entry.get("actor_tag", "")
            mitre = entry.get("mitre_tactics", [])

            # Extract from iocs field
            ioc_data = entry.get("iocs", entry.get("ioc_counts", {}))
            if isinstance(ioc_data, dict):
                for ioc_type, values in ioc_data.items():
                    if isinstance(values, list):
                        for val in values:
                            val_str = str(val).strip()
                            if self._validate_ioc(val_str, ioc_type):
                                iocs.append(ExtractedIOC(
                                    value=val_str,
                                    ioc_type=ioc_type,
                                    source_advisory=title,
                                    risk_score=risk_score,
                                    actor_tag=actor_tag,
                                    mitre_tactics=mitre,
                                    confidence=0.85,
                                ))

            # Also extract from description/content text
            content = entry.get("description", "") + " " + entry.get("content", "")
            if content.strip():
                text_iocs = self._extract_from_text(content, title, risk_score, actor_tag, mitre)
                iocs.extend(text_iocs)

        # Deduplicate
        seen: Set[str] = set()
        deduped = []
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in seen:
                seen.add(key)
                deduped.append(ioc)

        logger.info(f"Extracted {len(deduped)} unique IOCs from manifest ({len(entries)} advisories)")
        return deduped

    def extract_from_stix(self, stix_dir: Path) -> List[ExtractedIOC]:
        """Extract IOCs from STIX bundles."""
        iocs: List[ExtractedIOC] = []

        if not stix_dir.exists():
            return iocs

        for stix_file in stix_dir.glob("*.json"):
            if stix_file.name == "feed_manifest.json":
                continue
            try:
                with open(stix_file, "r") as f:
                    bundle = json.load(f)
                if bundle.get("type") != "bundle":
                    continue
                for obj in bundle.get("objects", []):
                    if obj.get("type") == "indicator":
                        pattern = obj.get("pattern", "")
                        name = obj.get("name", "STIX Indicator")
                        # Parse STIX pattern: [ipv4-addr:value = '1.2.3.4']
                        for ioc_type, regex in IOC_PATTERNS.items():
                            matches = regex.findall(pattern)
                            for m in matches:
                                if self._validate_ioc(m, ioc_type):
                                    iocs.append(ExtractedIOC(
                                        value=m, ioc_type=ioc_type,
                                        source_advisory=name,
                                        confidence=0.9,
                                    ))
            except Exception:
                continue

        logger.info(f"Extracted {len(iocs)} IOCs from STIX bundles")
        return iocs

    def _extract_from_text(self, text: str, source: str, risk: float,
                            actor: str, mitre: List[str]) -> List[ExtractedIOC]:
        results = []
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = pattern.findall(text)
            for m in matches:
                if self._validate_ioc(m, ioc_type):
                    results.append(ExtractedIOC(
                        value=m, ioc_type=ioc_type,
                        source_advisory=source,
                        risk_score=risk, actor_tag=actor,
                        mitre_tactics=mitre, confidence=0.7,
                    ))
        return results

    def _validate_ioc(self, value: str, ioc_type: str) -> bool:
        if not value or len(value) < 3:
            return False
        if ioc_type == "ipv4" and is_private_ip(value):
            return False
        if ioc_type == "domain":
            domain_lower = value.lower()
            if domain_lower in FALSE_POSITIVE_DOMAINS:
                return False
            for fp in FALSE_POSITIVE_DOMAINS:
                if domain_lower.endswith(f".{fp}"):
                    return False
        return True


# ---------------------------------------------------------------------------
# Rule Generators
# ---------------------------------------------------------------------------

class SigmaRuleGenerator:
    """Generate production Sigma detection rules."""

    def generate(self, iocs: List[ExtractedIOC], batch_id: str) -> List[GeneratedRule]:
        rules = []
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Group by type
        by_type: Dict[str, List[ExtractedIOC]] = {}
        for ioc in iocs:
            by_type.setdefault(ioc.ioc_type, []).append(ioc)

        # Network IOC rule
        net_iocs = by_type.get("ipv4", []) + by_type.get("domain", [])
        if net_iocs:
            ips = [i for i in net_iocs if i.ioc_type == "ipv4"]
            domains = [i for i in net_iocs if i.ioc_type == "domain"]
            max_severity = max((i.risk_score for i in net_iocs), default=0)
            severity = "critical" if max_severity >= 80 else "high" if max_severity >= 60 else "medium"

            detection_lines = []
            if ips:
                detection_lines.append("        DestinationIp:")
                for ip_ioc in ips[:100]:
                    detection_lines.append(f"            - '{ip_ioc.value}'")
            if domains:
                detection_lines.append("        DestinationHostname|contains:")
                for dom_ioc in domains[:100]:
                    detection_lines.append(f"            - '{dom_ioc.value}'")

            mitre_tags = set()
            for i in net_iocs:
                for t in i.mitre_tactics:
                    mitre_tags.add(t)
            for technique_id, _ in IOC_TO_MITRE.get("ipv4", []):
                mitre_tags.add(technique_id)

            advisories = list(set(i.source_advisory for i in net_iocs))[:10]
            rule_id = f"cdb-net-{batch_id}"

            content = f"""title: CDB SENTINEL APEX - Network Threat Intel [{batch_id}]
id: {rule_id}
status: production
description: >
    Auto-generated detection rule for {len(ips)} malicious IPs and {len(domains)} malicious domains
    from CYBERDUDEBIVASH SENTINEL APEX threat intelligence feeds.
author: CyberDudeBivash SENTINEL APEX v51
date: {ts}
modified: {ts}
tags:
    - attack.command_and_control
{chr(10).join(f"    - attack.{t.lower()}" for t in sorted(mitre_tags))}
logsource:
    category: firewall
    product: any
detection:
    selection:
{chr(10).join(detection_lines)}
    condition: selection
level: {severity}
falsepositives:
    - Shared hosting infrastructure
    - CDN/cloud provider IP overlap
references:
    - https://intel.cyberdudebivash.com
    - https://cyberdudebivash.com/threat-intel"""

            filename = f"cdb_network_ioc_{batch_id}.yml"
            rules.append(GeneratedRule(
                rule_id=rule_id, rule_type="sigma", title=f"Network IOC Detection [{batch_id}]",
                content=content, ioc_count=len(net_iocs),
                ioc_types=["ipv4", "domain"], severity=severity,
                mitre_techniques=sorted(mitre_tags),
                generated_at=datetime.now(timezone.utc).isoformat(),
                source_advisories=advisories, filename=filename,
            ))

        # File hash rule
        hash_iocs = by_type.get("sha256", []) + by_type.get("sha1", []) + by_type.get("md5", [])
        if hash_iocs:
            hash_lines = []
            for h_ioc in hash_iocs[:200]:
                hash_lines.append(f"            - '{h_ioc.value}'")

            severity = "critical"
            rule_id = f"cdb-hash-{batch_id}"

            content = f"""title: CDB SENTINEL APEX - Malicious File Hash Detection [{batch_id}]
id: {rule_id}
status: production
description: >
    Auto-generated detection rule for {len(hash_iocs)} malicious file hashes
    from CYBERDUDEBIVASH SENTINEL APEX threat intelligence feeds.
author: CyberDudeBivash SENTINEL APEX v51
date: {ts}
tags:
    - attack.execution
    - attack.t1204
    - attack.defense_evasion
logsource:
    category: file_event
    product: any
detection:
    selection:
        Hashes|contains:
{chr(10).join(hash_lines)}
    condition: selection
level: {severity}
falsepositives:
    - Hash collision (negligible probability)
references:
    - https://intel.cyberdudebivash.com"""

            filename = f"cdb_file_hash_{batch_id}.yml"
            rules.append(GeneratedRule(
                rule_id=rule_id, rule_type="sigma", title=f"File Hash Detection [{batch_id}]",
                content=content, ioc_count=len(hash_iocs),
                ioc_types=["sha256", "sha1", "md5"], severity=severity,
                mitre_techniques=["T1204", "T1059"],
                generated_at=datetime.now(timezone.utc).isoformat(),
                source_advisories=list(set(i.source_advisory for i in hash_iocs))[:10],
                filename=filename,
            ))

        # Email/phishing rule
        email_iocs = by_type.get("email", [])
        if email_iocs:
            email_lines = [f"            - '{e.value}'" for e in email_iocs[:50]]
            rule_id = f"cdb-phish-{batch_id}"
            content = f"""title: CDB SENTINEL APEX - Phishing Sender Detection [{batch_id}]
id: {rule_id}
status: production
description: Detects emails from known malicious senders
author: CyberDudeBivash SENTINEL APEX v51
date: {ts}
tags:
    - attack.initial_access
    - attack.t1566
logsource:
    category: email
    product: any
detection:
    selection:
        SenderAddress:
{chr(10).join(email_lines)}
    condition: selection
level: high
falsepositives:
    - Spoofed sender addresses
references:
    - https://intel.cyberdudebivash.com"""

            filename = f"cdb_phishing_{batch_id}.yml"
            rules.append(GeneratedRule(
                rule_id=rule_id, rule_type="sigma", title=f"Phishing Detection [{batch_id}]",
                content=content, ioc_count=len(email_iocs),
                ioc_types=["email"], severity="high",
                mitre_techniques=["T1566"],
                generated_at=datetime.now(timezone.utc).isoformat(),
                source_advisories=list(set(i.source_advisory for i in email_iocs))[:10],
                filename=filename,
            ))

        return rules


class YARAGenerator:
    """Generate production YARA rules from IOCs."""

    def generate(self, iocs: List[ExtractedIOC], batch_id: str) -> List[GeneratedRule]:
        rules = []
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        by_type: Dict[str, List[ExtractedIOC]] = {}
        for ioc in iocs:
            by_type.setdefault(ioc.ioc_type, []).append(ioc)

        # Network IOC YARA
        net_iocs = by_type.get("ipv4", []) + by_type.get("domain", [])
        if net_iocs:
            strings = []
            for i, ioc in enumerate(net_iocs[:150]):
                prefix = "ip" if ioc.ioc_type == "ipv4" else "dom"
                strings.append(f'        ${prefix}_{i} = "{ioc.value}" ascii wide nocase')

            content = f"""rule CDB_SENTINEL_Network_Intel_{batch_id}
{{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "{ts}"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "{batch_id}"
        ioc_count = {len(net_iocs)}

    strings:
{chr(10).join(strings)}

    condition:
        filesize < 100MB and any of them
}}"""

            filename = f"cdb_network_intel_{batch_id}.yar"
            rules.append(GeneratedRule(
                rule_id=f"yara-net-{batch_id}", rule_type="yara",
                title=f"Network Intel YARA [{batch_id}]",
                content=content, ioc_count=len(net_iocs),
                ioc_types=["ipv4", "domain"], severity="high",
                mitre_techniques=["T1071", "T1090"],
                generated_at=datetime.now(timezone.utc).isoformat(),
                source_advisories=list(set(i.source_advisory for i in net_iocs))[:10],
                filename=filename,
            ))

        # Hash YARA
        hash_iocs = by_type.get("sha256", []) + by_type.get("md5", [])
        if hash_iocs:
            strings = [f'        $h_{i} = "{h.value}" ascii nocase' for i, h in enumerate(hash_iocs[:200])]
            content = f"""rule CDB_SENTINEL_Hash_Intel_{batch_id}
{{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "{ts}"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
{chr(10).join(strings)}

    condition:
        filesize < 100MB and any of them
}}"""

            filename = f"cdb_hash_intel_{batch_id}.yar"
            rules.append(GeneratedRule(
                rule_id=f"yara-hash-{batch_id}", rule_type="yara",
                title=f"Hash Intel YARA [{batch_id}]",
                content=content, ioc_count=len(hash_iocs),
                ioc_types=["sha256", "md5"], severity="critical",
                mitre_techniques=["T1204"],
                generated_at=datetime.now(timezone.utc).isoformat(),
                source_advisories=list(set(i.source_advisory for i in hash_iocs))[:10],
                filename=filename,
            ))

        return rules


class SuricataGenerator:
    """Generate production Suricata rules from IOCs."""

    def generate(self, iocs: List[ExtractedIOC], batch_id: str) -> List[GeneratedRule]:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        by_type: Dict[str, List[ExtractedIOC]] = {}
        for ioc in iocs:
            by_type.setdefault(ioc.ioc_type, []).append(ioc)

        rule_lines = []
        sid_base = int(hashlib.md5(batch_id.encode()).hexdigest()[:6], 16) % 900000 + 9000000

        # IP rules
        for i, ip_ioc in enumerate(by_type.get("ipv4", [])[:200]):
            rule_lines.append(
                f'alert ip any any -> {ip_ioc.value} any '
                f'(msg:"CDB SENTINEL v51 - Threat Intel IP: {ip_ioc.value}"; '
                f'sid:{sid_base + i}; rev:1; '
                f'classtype:trojan-activity; '
                f'metadata:created_at {ts}, '
                f'severity high, '
                f'source CDB_SENTINEL_APEX_v51;)'
            )

        # DNS rules
        for i, dom_ioc in enumerate(by_type.get("domain", [])[:200]):
            rule_lines.append(
                f'alert dns any any -> any any '
                f'(msg:"CDB SENTINEL v51 - Threat Intel Domain: {dom_ioc.value}"; '
                f'dns.query; content:"{dom_ioc.value}"; nocase; '
                f'sid:{sid_base + 1000 + i}; rev:1; '
                f'classtype:trojan-activity; '
                f'metadata:created_at {ts}, '
                f'severity high, '
                f'source CDB_SENTINEL_APEX_v51;)'
            )

        # URL rules
        for i, url_ioc in enumerate(by_type.get("url", [])[:100]):
            # Extract path from URL
            path = url_ioc.value.split("//", 1)[-1].split("/", 1)[-1] if "//" in url_ioc.value else url_ioc.value
            if len(path) > 128:
                path = path[:128]
            rule_lines.append(
                f'alert http any any -> any any '
                f'(msg:"CDB SENTINEL v51 - Threat Intel URL"; '
                f'http.uri; content:"{path}"; nocase; '
                f'sid:{sid_base + 2000 + i}; rev:1; '
                f'classtype:trojan-activity; '
                f'metadata:created_at {ts}, '
                f'source CDB_SENTINEL_APEX_v51;)'
            )

        if not rule_lines:
            return []

        content = f"# CDB SENTINEL APEX v51 — Auto-Generated Suricata Rules\n"
        content += f"# Batch: {batch_id} | Generated: {ts}\n"
        content += f"# IOC Count: {sum(len(v) for v in by_type.values())}\n"
        content += f"# Source: https://intel.cyberdudebivash.com\n\n"
        content += "\n".join(rule_lines)

        filename = f"cdb_threat_intel_{batch_id}.rules"
        all_iocs = [i for iocs_list in by_type.values() for i in iocs_list]

        return [GeneratedRule(
            rule_id=f"suricata-{batch_id}", rule_type="suricata",
            title=f"Suricata Threat Intel [{batch_id}]",
            content=content, ioc_count=len(rule_lines),
            ioc_types=list(by_type.keys()), severity="high",
            mitre_techniques=["T1071", "T1090", "T1568"],
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_advisories=list(set(i.source_advisory for i in all_iocs))[:10],
            filename=filename,
        )]


# ---------------------------------------------------------------------------
# Detection Engine Orchestrator
# ---------------------------------------------------------------------------

class DetectionEngine:
    """Orchestrate detection rule generation from intelligence feeds."""

    def __init__(self):
        self.extractor = IOCExtractor()
        self.sigma_gen = SigmaRuleGenerator()
        self.yara_gen = YARAGenerator()
        self.suricata_gen = SuricataGenerator()

    def run(self) -> Dict[str, Any]:
        """Execute the full detection rule generation pipeline."""
        start_time = datetime.now(timezone.utc)
        batch_id = hashlib.md5(start_time.isoformat().encode()).hexdigest()[:12]

        logger.info(f"Detection Engine v51 starting — batch {batch_id}")

        # Phase 1: Extract IOCs
        logger.info("[1/4] Extracting IOCs from intelligence feeds")
        manifest_iocs = self.extractor.extract_from_manifest(STIX_DIR / "feed_manifest.json")
        stix_iocs = self.extractor.extract_from_stix(STIX_DIR)

        # Merge and deduplicate
        seen: Set[str] = set()
        all_iocs: List[ExtractedIOC] = []
        for ioc in manifest_iocs + stix_iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in seen:
                seen.add(key)
                all_iocs.append(ioc)

        logger.info(f"  → {len(all_iocs)} unique IOCs extracted")
        if not all_iocs:
            logger.warning("No IOCs found — aborting rule generation")
            return {"status": "no_iocs", "batch_id": batch_id}

        # Phase 2: Generate Sigma rules
        logger.info("[2/4] Generating Sigma rules")
        sigma_rules = self.sigma_gen.generate(all_iocs, batch_id)
        for rule in sigma_rules:
            self._write_rule(SIGMA_DIR / rule.filename, rule.content)
        logger.info(f"  → {len(sigma_rules)} Sigma rules generated")

        # Phase 3: Generate YARA rules
        logger.info("[3/4] Generating YARA rules")
        yara_rules = self.yara_gen.generate(all_iocs, batch_id)
        for rule in yara_rules:
            self._write_rule(YARA_DIR / rule.filename, rule.content)
        logger.info(f"  → {len(yara_rules)} YARA rules generated")

        # Phase 4: Generate Suricata rules
        logger.info("[4/4] Generating Suricata rules")
        suricata_rules = self.suricata_gen.generate(all_iocs, batch_id)
        for rule in suricata_rules:
            self._write_rule(SURICATA_DIR / rule.filename, rule.content)
        logger.info(f"  → {len(suricata_rules)} Suricata rule sets generated")

        # Build manifest
        all_rules = sigma_rules + yara_rules + suricata_rules
        manifest = {
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "module": "v51_detection_engine",
            "version": "51.0.0",
            "batch_id": batch_id,
            "generated_at": start_time.isoformat(),
            "ioc_count": len(all_iocs),
            "ioc_type_breakdown": {},
            "rules_generated": {
                "sigma": len(sigma_rules),
                "yara": len(yara_rules),
                "suricata": len(suricata_rules),
                "total": len(all_rules),
            },
            "rules": [asdict(r) for r in all_rules],
        }

        # IOC breakdown
        for ioc in all_iocs:
            manifest["ioc_type_breakdown"][ioc.ioc_type] = manifest["ioc_type_breakdown"].get(ioc.ioc_type, 0) + 1

        with open(MANIFEST_FILE, "w") as f:
            json.dump(manifest, f, indent=2, default=str)

        logger.info(
            f"Detection Engine complete: {len(all_rules)} rules generated from {len(all_iocs)} IOCs"
        )

        return manifest

    def _write_rule(self, path: Path, content: str):
        with open(path, "w") as f:
            f.write(content)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    engine = DetectionEngine()
    result = engine.run()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
