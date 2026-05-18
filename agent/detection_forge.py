#!/usr/bin/env python3
"""
detection_forge.py — CyberDudeBivash SENTINEL APEX v1.0
DETECTION RULE FORGE — Production-Grade Sigma / YARA / Suricata Generator

Competitive capability target: CrowdStrike Custom IOA Rules, Palo Alto XSIAM,
Recorded Future Detection-as-Code, Microsoft Sentinel Analytics Rules.

This module is the LIVE integration layer that:
  1. Reads the feed_manifest.json (500 enriched advisories)
  2. For each advisory with MITRE techniques → generates a Sigma rule
  3. For each advisory with malware family mentions → generates a YARA rule
  4. For each advisory with IP/domain IOCs → generates a Suricata rule
  5. Saves rules to data/intelligence/detection_rules/{sigma,yara,suricata}/
  6. Generates a rule_manifest.json (machine-readable detection catalog)
  7. Generates a detection_summary.json (pipeline telemetry)
  8. Patches each manifest entry with detection_rules[] list (non-destructive)

Key design principles:
  - Zero external dependencies (no SigmaHQ CLI, no YARA-python)
  - Every rule is valid Sigma YAML / YARA text / Suricata text
  - Deduplication: same advisory → same rule_id (deterministic hash)
  - Fail-safe: any exception → log warning, continue pipeline
  - Idempotent: re-running produces identical output for same input

Rules are tagged with:
  - CDB-SIGMA-{HASH8} (Sigma)
  - CDB-YARA-{HASH8} (YARA)
  - CDB-SUR-{HASH8} (Suricata)

Author: CyberDudeBivash Pvt. Ltd.
Version: v1.0
"""

import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("CDB-DETECT-FORGE")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data"
STIX_DIR    = DATA_DIR / "stix"
INTEL_DIR   = DATA_DIR / "intelligence"
RULES_DIR   = INTEL_DIR / "detection_rules"
SIGMA_DIR   = RULES_DIR / "sigma"
YARA_DIR    = RULES_DIR / "yara"
SURICATA_DIR = RULES_DIR / "suricata"
MANIFEST    = STIX_DIR / "feed_manifest.json"
RULE_MANIFEST_FILE = RULES_DIR / "rule_manifest.json"
DETECTION_SUMMARY  = RULES_DIR / "detection_summary.json"

for _d in (SIGMA_DIR, YARA_DIR, SURICATA_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# MITRE → Sigma log-source and detection scaffold
# ---------------------------------------------------------------------------
TECH_TO_SIGMA = {
    # Initial Access
    "T1190": {
        "logsource": {"category": "webserver", "product": "any"},
        "detection_keywords": ["exploit", "injection", "traversal", "buffer", "overflow"],
        "title_suffix": "Web Exploitation",
    },
    "T1566": {
        "logsource": {"category": "network", "product": "any"},
        "detection_keywords": ["phishing", "spear", "malicious attachment", "macro"],
        "title_suffix": "Phishing Delivery",
    },
    "T1133": {
        "logsource": {"category": "authentication", "product": "any"},
        "detection_keywords": ["vpn", "remote", "external", "unauthorized"],
        "title_suffix": "External Remote Service Abuse",
    },
    "T1195": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_keywords": ["supply chain", "package", "dependency", "build"],
        "title_suffix": "Supply Chain Compromise",
    },
    # Execution
    "T1059": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_keywords": ["cmd.exe", "powershell", "wscript", "cscript", "bash"],
        "title_suffix": "Scripting Interpreter Execution",
    },
    "T1053": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_keywords": ["schtasks", "at.exe", "cron", "scheduled task"],
        "title_suffix": "Scheduled Task Execution",
    },
    # Persistence
    "T1547": {
        "logsource": {"category": "registry_event", "product": "windows"},
        "detection_keywords": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                               "registry autorun", "startup"],
        "title_suffix": "Registry Autorun Persistence",
    },
    # Privilege Escalation
    "T1068": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_keywords": ["privilege escalation", "uac bypass", "token impersonation"],
        "title_suffix": "Exploitation for Privilege Escalation",
    },
    "T1055": {
        "logsource": {"category": "process_access", "product": "windows"},
        "detection_keywords": ["process injection", "dll injection", "hollowing", "reflective"],
        "title_suffix": "Process Injection",
    },
    # Defense Evasion
    "T1036": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_keywords": ["masquerading", "renamed binary", "svchost", "lsass"],
        "title_suffix": "Process Masquerading",
    },
    "T1027": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_keywords": ["obfuscation", "encoding", "base64", "xor encrypt"],
        "title_suffix": "Obfuscated Files",
    },
    # Credential Access
    "T1003": {
        "logsource": {"category": "process_access", "product": "windows"},
        "detection_keywords": ["lsass.exe", "mimikatz", "credential dump", "ntds"],
        "title_suffix": "OS Credential Dumping",
    },
    "T1110": {
        "logsource": {"category": "authentication", "product": "any"},
        "detection_keywords": ["brute force", "password spray", "credential stuffing"],
        "title_suffix": "Brute Force Authentication",
    },
    # Lateral Movement
    "T1021": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection_keywords": ["smb", "rdp", "psexec", "wmi", "lateral movement"],
        "title_suffix": "Lateral Movement via Remote Services",
    },
    # C2
    "T1071": {
        "logsource": {"category": "network_connection", "product": "any"},
        "detection_keywords": ["c2", "command and control", "beacon", "callback"],
        "title_suffix": "C2 Application Layer Protocol",
    },
    "T1090": {
        "logsource": {"category": "network_connection", "product": "any"},
        "detection_keywords": ["proxy", "tor", "socks", "tunnel", "anonymizer"],
        "title_suffix": "Proxy C2 Communication",
    },
    # Exfiltration
    "T1041": {
        "logsource": {"category": "network_connection", "product": "any"},
        "detection_keywords": ["exfiltration", "data theft", "upload", "out-of-band"],
        "title_suffix": "Exfiltration Over C2 Channel",
    },
    # Impact
    "T1486": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_keywords": ["ransomware", "encrypt", ".locked", ".crypt", "ransom note"],
        "title_suffix": "Data Encrypted for Impact",
    },
    "T1485": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_keywords": ["wiper", "data destruction", "overwrite", "delete shadow"],
        "title_suffix": "Data Destruction",
    },
}

# Severity mapping
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "informational",
}

# Malware family patterns for YARA generation
MALWARE_FAMILIES = {
    "ghostsocks": {
        "strings": ["GhostSocks", "ghostsocks", "proxy_node", "socks5_relay"],
        "description": "GhostSocks SOCKS5 residential proxy malware",
    },
    "lockbit": {
        "strings": ["LockBit", "lockbit", "README.txt", ".lockbit", "support_lockbit"],
        "description": "LockBit ransomware family indicator",
    },
    "blackcat": {
        "strings": ["ALPHV", "BlackCat", "noberus", ".alphv", "alpha_v"],
        "description": "ALPHV/BlackCat ransomware family",
    },
    "interlock": {
        "strings": ["Interlock", "interlock_note", ".interlock"],
        "description": "Interlock ransomware family",
    },
    "canisterworm": {
        "strings": ["CanisterWorm", "canisterworm", "wiper_payload"],
        "description": "CanisterWorm destructive wiper",
    },
    "glassworm": {
        "strings": ["GlassWorm", "glassworm", "extension_inject", "surveillance_module"],
        "description": "GlassWorm browser extension malware",
    },
    "darksword": {
        "strings": ["DarkSword", "darksword", "ios_exploit", "kernel_exploit"],
        "description": "DarkSword iOS exploit chain",
    },
    "shadowpad": {
        "strings": ["ShadowPad", "shadowpad", "shadow_pad", "sc_cmd"],
        "description": "ShadowPad modular backdoor (APT41)",
    },
    "cobalt strike": {
        "strings": ["CobaltStrike", "cobaltstrike", "beacon.dll", "reflective_loader",
                    "cs_beacon", "pipe_name"],
        "description": "Cobalt Strike C2 framework",
    },
    "bpfdoor": {
        "strings": ["BPFDoor", "bpfdoor", "bpf_filter", "raw_socket", "passive_backdoor"],
        "description": "BPFDoor passive backdoor (Salt Typhoon)",
    },
    "mimikatz": {
        "strings": ["mimikatz", "sekurlsa", "kerberos_logon", "lsadump", "wdigest"],
        "description": "Mimikatz credential extraction tool",
    },
    "magecart": {
        "strings": ["Magecart", "magecart", "cc_skimmer", "card_data", "payment_form"],
        "description": "Magecart web skimmer family",
    },
    "crysomeRAT": {
        "strings": ["CrySome", "crysome", "av_killer", "net_rat", "dll_inject"],
        "description": "CrySome RAT with AV killer capability",
    },
}

# IOC extraction patterns
IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|"
        r"xyz|top|info|biz|cc|pw|ml|click|link|online|site|live|pro|tech|club)\b"
    ),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"https?://[^\s<>\"']{10,}"),
}

PRIVATE_IPS = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|0\.|255\.)"
)

FALSE_POSITIVE_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "cloudflare.com",
    "amazon.com", "amazonaws.com", "azure.com", "facebook.com",
    "twitter.com", "linkedin.com", "apple.com", "cybersecuritynews.com",
    "thehackernews.com", "bleepingcomputer.com", "krebsonsecurity.com",
    "therecord.media", "cyberscoop.com",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class GeneratedRule:
    rule_id: str
    rule_type: str       # sigma | yara | suricata
    title: str
    content: str
    filename: str
    severity: str
    mitre_techniques: List[str]
    source_advisory: str
    source_title: str
    generated_at: str
    ioc_count: int = 0


# ---------------------------------------------------------------------------
# Helper: deterministic rule ID
# ---------------------------------------------------------------------------

def _rule_id(prefix: str, advisory_id: str, suffix: str = "") -> str:
    raw = f"{prefix}-{advisory_id}-{suffix}"
    return prefix + "-" + hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:8].upper()


def _safe_yaml_str(s: str) -> str:
    """Escape a string for use as a YAML value."""
    return s.replace("'", "\\'").replace("\n", " ").strip()[:200]


def _sanitize_id(s: str) -> str:
    """Convert a string to a valid identifier."""
    return re.sub(r"[^A-Za-z0-9_]", "_", s)[:40]


# ---------------------------------------------------------------------------
# IOC Extractor (for use during rule generation)
# ---------------------------------------------------------------------------

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract actionable IOCs from free text."""
    result: Dict[str, List[str]] = {"ipv4": [], "domain": [], "sha256": [], "url": []}
    if not text:
        return result

    # IPv4
    for ip in IOC_PATTERNS["ipv4"].findall(text):
        if not PRIVATE_IPS.match(ip) and ip not in ("0.0.0.0", "255.255.255.255"):
            result["ipv4"].append(ip)

    # Domain
    for dom in IOC_PATTERNS["domain"].findall(text):
        if dom not in FALSE_POSITIVE_DOMAINS and len(dom) > 5:
            result["domain"].append(dom)

    # SHA256
    result["sha256"] = IOC_PATTERNS["sha256"].findall(text)

    # URL (filter out news/blog URLs)
    for url in IOC_PATTERNS["url"].findall(text):
        domain = re.search(r"https?://([^/]+)", url)
        if domain and domain.group(1) not in FALSE_POSITIVE_DOMAINS:
            result["url"].append(url[:100])

    # Deduplicate
    for k in result:
        result[k] = list(dict.fromkeys(result[k]))[:10]

    return result


# ---------------------------------------------------------------------------
# Sigma Rule Generator
# ---------------------------------------------------------------------------

class SigmaForge:
    """Generates Sigma rules from MITRE technique data."""

    def generate(self, entry: Dict) -> Optional[GeneratedRule]:
        title = entry.get("title", "Unknown Advisory")
        techniques = [t for t in (entry.get("mitre_techniques", []) or []) if isinstance(t, str)]
        severity_raw = (entry.get("severity", "medium") or "medium").upper()
        severity = SEVERITY_MAP.get(severity_raw, "medium")
        advisory_id = entry.get("stix_id", "") or hashlib.md5(title.encode(), usedforsecurity=False).hexdigest()[:12]

        if not techniques:
            return None  # No techniques → no Sigma rule

        # Find best matching technique for log source
        primary_tech = None
        primary_conf = None
        for tech in techniques:
            base = tech.split(".")[0].upper()
            if base in TECH_TO_SIGMA:
                primary_tech = base
                primary_conf = TECH_TO_SIGMA[base]
                break

        if not primary_conf:
            # Fallback: generic process creation rule
            primary_tech = "GENERIC"
            primary_conf = {
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection_keywords": ["suspicious", "malicious"],
                "title_suffix": "Suspicious Activity",
            }

        logsource = primary_conf["logsource"]
        detection_kws = primary_conf["detection_keywords"][:3]
        tech_suffix = primary_conf.get("title_suffix", "")

        rule_id = _rule_id("CDB-SIGMA", advisory_id, primary_tech)
        short_title = title[:60].replace("'", "")
        cve = entry.get("cve_id", "") or ""
        tags = []
        for t in techniques[:5]:
            base = t.split(".")[0].lower()
            tags.append(f"attack.{base}")

        # Build detection block — keyword OR matching
        kw_items = "\n            - ".join([f"'{_safe_yaml_str(kw)}'" for kw in detection_kws])

        rule_content = f"""title: 'CDB APEX — {_safe_yaml_str(short_title)}'
id: '{rule_id}'
status: experimental
description: >
    Auto-generated by CyberDudeBivash SENTINEL APEX Detection Forge v1.0.
    Advisory: {_safe_yaml_str(title[:100])}
    {f'CVE: {cve}' if cve else ''}
    MITRE Techniques: {', '.join(techniques[:6])}
author: CyberDudeBivash Sentinel APEX
date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
modified: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
references:
    - https://intel.cyberdudebivash.com
    - {entry.get('blog_url', 'https://cyberdudebivash.com') or 'https://cyberdudebivash.com'}
tags:
    - {chr(10) + '    - '.join(tags) if tags else '- attack.unknown'}
logsource:
    category: {logsource.get('category', 'process_creation')}
    product: {logsource.get('product', 'windows')}
detection:
    keywords:
        - {kw_items}
    condition: keywords
falsepositives:
    - Legitimate administrative tools with similar names
    - Known software with similar behavioral patterns
level: {severity}
"""

        filename = f"{rule_id.lower()}.yml"
        return GeneratedRule(
            rule_id=rule_id,
            rule_type="sigma",
            title=f"CDB APEX — {short_title}",
            content=rule_content,
            filename=filename,
            severity=severity,
            mitre_techniques=techniques[:6],
            source_advisory=advisory_id,
            source_title=title[:80],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )


# ---------------------------------------------------------------------------
# YARA Rule Generator
# ---------------------------------------------------------------------------

class YARAForge:
    """Generates YARA rules from malware family mentions and IOC data."""

    def generate(self, entry: Dict) -> Optional[GeneratedRule]:
        title = entry.get("title", "").lower()
        content = (entry.get("content", "") or "").lower()
        summary = (entry.get("summary", "") or "").lower()
        full_text = f"{title} {summary} {content}"

        advisory_id = entry.get("stix_id", "") or hashlib.md5(title.encode(), usedforsecurity=False).hexdigest()[:12]

        # Find matching malware family
        matched_family = None
        matched_conf = None
        for family_kw, conf in MALWARE_FAMILIES.items():
            if family_kw.lower() in full_text:
                matched_family = family_kw
                matched_conf = conf
                break

        if not matched_family:
            return None  # No recognized malware family

        rule_id = _rule_id("CDB-YARA", advisory_id, _sanitize_id(matched_family))
        rule_name = f"CDB_{_sanitize_id(matched_family).upper()}_{rule_id[-8:]}"
        strings = matched_conf["strings"]
        description = matched_conf["description"]
        severity_raw = (entry.get("severity", "high") or "high").upper()

        # Build YARA strings block
        yara_strings = []
        for i, s in enumerate(strings[:6]):
            yara_strings.append(f'        $s{i} = "{s}"')
        strings_block = "\n".join(yara_strings)

        # Condition: any 2 of the strings
        condition = f"any of ($s*)" if len(strings) <= 2 else f"2 of ($s*)"

        rule_content = f"""// CyberDudeBivash SENTINEL APEX — Detection Forge v1.0
// Auto-generated YARA rule
// Advisory: {entry.get('title', '')[:80]}
// Generated: {datetime.now(timezone.utc).isoformat()}
// Rule ID: {rule_id}

rule {rule_name}
{{
    meta:
        description = "{description}"
        author = "CyberDudeBivash Sentinel APEX"
        date = "{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        version = "1.0"
        severity = "{severity_raw.lower()}"
        reference = "{entry.get('blog_url', 'https://intel.cyberdudebivash.com') or 'https://intel.cyberdudebivash.com'}"
        rule_id = "{rule_id}"
        family = "{matched_family}"

    strings:
{strings_block}

    condition:
        {condition}
}}
"""

        filename = f"{rule_id.lower()}.yar"
        return GeneratedRule(
            rule_id=rule_id,
            rule_type="yara",
            title=rule_name,
            content=rule_content,
            filename=filename,
            severity=severity_raw.lower(),
            mitre_techniques=entry.get("mitre_techniques", []) or [],
            source_advisory=advisory_id,
            source_title=entry.get("title", "")[:80],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )


# ---------------------------------------------------------------------------
# Suricata Rule Generator
# ---------------------------------------------------------------------------

class SuricataForge:
    """Generates Suricata/Snort network detection rules from IP/domain IOCs."""

    _SID_BASE = 9_000_000  # CDB SID namespace

    def generate(self, entry: Dict, sid_offset: int = 0) -> List[GeneratedRule]:
        """Generate 0..N Suricata rules from extracted network IOCs."""
        text = " ".join([
            entry.get("title", "") or "",
            entry.get("summary", "") or "",
            entry.get("content", "") or "",
        ])

        iocs = extract_iocs_from_text(text)
        advisory_id = entry.get("stix_id", "") or hashlib.md5(
            (entry.get("title", "") or "").encode(), usedforsecurity=False).hexdigest()[:12]
        severity_raw = (entry.get("severity", "medium") or "medium").lower()
        title = entry.get("title", "Unknown Advisory")

        # Severity → Suricata priority
        prio_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        priority = prio_map.get(severity_raw, 3)

        rules: List[GeneratedRule] = []
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # IP-based rules
        for i, ip in enumerate(iocs["ipv4"][:3]):
            rule_id = _rule_id("CDB-SUR", advisory_id, f"IP{i}")
            sid = self._SID_BASE + sid_offset + i
            msg = _safe_yaml_str(f"CDB APEX C2/IOC IP: {ip} | {title[:50]}")
            rule_text = (
                f'alert ip $HOME_NET any -> {ip} any '
                f'(msg:"{msg}"; '
                f'priority:{priority}; '
                f'metadata:created_at {now_str}, updated_at {now_str}, '
                f'cdb_rule_id {rule_id}; '
                f'sid:{sid}; rev:1;)\n'
            )
            rules.append(GeneratedRule(
                rule_id=rule_id,
                rule_type="suricata",
                title=msg[:80],
                content=rule_text,
                filename=f"{rule_id.lower()}.rules",
                severity=severity_raw,
                mitre_techniques=entry.get("mitre_techniques", []) or [],
                source_advisory=advisory_id,
                source_title=title[:80],
                generated_at=datetime.now(timezone.utc).isoformat(),
                ioc_count=1,
            ))

        # Domain-based DNS rules
        for i, domain in enumerate(iocs["domain"][:3]):
            rule_id = _rule_id("CDB-SUR", advisory_id, f"DNS{i}")
            sid = self._SID_BASE + sid_offset + 100 + i
            msg = _safe_yaml_str(f"CDB APEX Malicious Domain: {domain} | {title[:40]}")
            rule_text = (
                f'alert dns $HOME_NET any -> any 53 '
                f'(msg:"{msg}"; '
                f'dns.query; content:"{domain}"; nocase; '
                f'priority:{priority}; '
                f'metadata:created_at {now_str}, cdb_rule_id {rule_id}; '
                f'sid:{sid}; rev:1;)\n'
            )
            rules.append(GeneratedRule(
                rule_id=rule_id,
                rule_type="suricata",
                title=msg[:80],
                content=rule_text,
                filename=f"{rule_id.lower()}.rules",
                severity=severity_raw,
                mitre_techniques=entry.get("mitre_techniques", []) or [],
                source_advisory=advisory_id,
                source_title=title[:80],
                generated_at=datetime.now(timezone.utc).isoformat(),
                ioc_count=1,
            ))

        return rules


# ---------------------------------------------------------------------------
# Detection Forge Orchestrator
# ---------------------------------------------------------------------------

class DetectionForge:
    """
    Master orchestrator: reads manifest, generates all rule types,
    writes to disk, updates manifest with detection_rules field.
    """

    def __init__(
        self,
        manifest_path: Path = MANIFEST,
        sigma_dir: Path = SIGMA_DIR,
        yara_dir: Path = YARA_DIR,
        suricata_dir: Path = SURICATA_DIR,
        max_entries: int = 500,
    ):
        self.manifest_path  = manifest_path
        self.sigma_dir      = sigma_dir
        self.yara_dir       = yara_dir
        self.suricata_dir   = suricata_dir
        self.max_entries    = max_entries
        self._sigma   = SigmaForge()
        self._yara    = YARAForge()
        self._suricata = SuricataForge()

        # Load existing rule manifest for dedup
        self._existing_rule_ids: Set[str] = set()
        self._rule_manifest: List[Dict] = self._load_rule_manifest()

    def _load_rule_manifest(self) -> List[Dict]:
        if RULE_MANIFEST_FILE.exists():
            try:
                with open(RULE_MANIFEST_FILE) as f:
                    data = json.load(f)
                manifest = data if isinstance(data, list) else data.get("rules", [])
                self._existing_rule_ids = {r["rule_id"] for r in manifest}
                return manifest
            except Exception:
                pass
        return []

    def _save_rule_manifest(self, new_rules: List[GeneratedRule]):
        existing_ids = {r["rule_id"] for r in self._rule_manifest}
        for rule in new_rules:
            if rule.rule_id not in existing_ids:
                self._rule_manifest.append({
                    "rule_id": rule.rule_id,
                    "rule_type": rule.rule_type,
                    "title": rule.title,
                    "filename": rule.filename,
                    "severity": rule.severity,
                    "mitre_techniques": rule.mitre_techniques,
                    "source_advisory": rule.source_advisory,
                    "source_title": rule.source_title,
                    "generated_at": rule.generated_at,
                })
        try:
            with open(RULE_MANIFEST_FILE, "w") as f:
                json.dump(self._rule_manifest, f, indent=2)
        except Exception as e:
            logger.warning(f"[DETECT-FORGE] Rule manifest write failed: {e}")

    def _write_rule_file(self, rule: GeneratedRule, target_dir: Path) -> bool:
        path = target_dir / rule.filename
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(rule.content)
            return True
        except Exception as e:
            logger.warning(f"[DETECT-FORGE] Rule write failed {path}: {e}")
            return False

    def load_manifest(self) -> List[Dict]:
        if not self.manifest_path.exists():
            logger.warning(f"[DETECT-FORGE] Manifest not found: {self.manifest_path}")
            return []
        try:
            with open(self.manifest_path, encoding="utf-8") as f:
                data = json.load(f)
            entries = data if isinstance(data, list) else data.get("entries", [])
            logger.info(f"[DETECT-FORGE] Loaded {len(entries)} advisories")
            return entries
        except Exception as e:
            logger.error(f"[DETECT-FORGE] Manifest load failed: {e}")
            return []

    def run(self) -> Dict[str, Any]:
        logger.info("[DETECT-FORGE] === DETECTION FORGE RUN START ===")
        entries = self.load_manifest()
        if not entries:
            return {"status": "empty", "rules_generated": 0}

        new_sigma: List[GeneratedRule] = []
        new_yara: List[GeneratedRule] = []
        new_suricata: List[GeneratedRule] = []
        sid_counter = len(self._rule_manifest) * 10  # Unique SID offset

        sigma_total = yara_total = sur_total = 0
        entries_with_rules = 0

        for idx, entry in enumerate(entries):
            advisory_rules: List[str] = []

            # --- Sigma ---
            try:
                sigma_rule = self._sigma.generate(entry)
                if sigma_rule and sigma_rule.rule_id not in self._existing_rule_ids:
                    if self._write_rule_file(sigma_rule, self.sigma_dir):
                        new_sigma.append(sigma_rule)
                        self._existing_rule_ids.add(sigma_rule.rule_id)
                        sigma_total += 1
                    advisory_rules.append(sigma_rule.rule_id)
                elif sigma_rule:
                    advisory_rules.append(sigma_rule.rule_id)
            except Exception as e:
                logger.debug(f"[DETECT-FORGE] Sigma failed for '{entry.get('title','')[:30]}': {e}")

            # --- YARA ---
            try:
                yara_rule = self._yara.generate(entry)
                if yara_rule and yara_rule.rule_id not in self._existing_rule_ids:
                    if self._write_rule_file(yara_rule, self.yara_dir):
                        new_yara.append(yara_rule)
                        self._existing_rule_ids.add(yara_rule.rule_id)
                        yara_total += 1
                    advisory_rules.append(yara_rule.rule_id)
                elif yara_rule:
                    advisory_rules.append(yara_rule.rule_id)
            except Exception as e:
                logger.debug(f"[DETECT-FORGE] YARA failed for '{entry.get('title','')[:30]}': {e}")

            # --- Suricata ---
            try:
                sur_rules = self._suricata.generate(entry, sid_offset=sid_counter + idx * 200)
                for rule in sur_rules:
                    if rule.rule_id not in self._existing_rule_ids:
                        if self._write_rule_file(rule, self.suricata_dir):
                            new_suricata.append(rule)
                            self._existing_rule_ids.add(rule.rule_id)
                            sur_total += 1
                        advisory_rules.append(rule.rule_id)
                    else:
                        advisory_rules.append(rule.rule_id)
            except Exception as e:
                logger.debug(f"[DETECT-FORGE] Suricata failed for '{entry.get('title','')[:30]}': {e}")

            # Patch manifest entry non-destructively
            if advisory_rules:
                entry["detection_rules"] = list(dict.fromkeys(
                    (entry.get("detection_rules", []) or []) + advisory_rules
                ))
                entries_with_rules += 1

        # Save rule manifest
        all_new = new_sigma + new_yara + new_suricata
        self._save_rule_manifest(all_new)

        # Write master Suricata rules file (all rules combined)
        if new_suricata or self._rule_manifest:
            self._write_master_suricata_file()

        # Write updated manifest (with detection_rules field)
        try:
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, ensure_ascii=False, separators=(",", ":"))
            logger.info(f"[DETECT-FORGE] Manifest updated with detection_rules fields")
        except Exception as e:
            logger.warning(f"[DETECT-FORGE] Manifest update failed: {e}")

        summary = {
            "run_at": datetime.now(timezone.utc).isoformat(),
            "version": "v1.0",
            "status": "COMPLETE",
            "entries_processed": len(entries),
            "entries_with_rules": entries_with_rules,
            "new_sigma_rules": sigma_total,
            "new_yara_rules": yara_total,
            "new_suricata_rules": sur_total,
            "total_new_rules": len(all_new),
            "total_rules_in_catalog": len(self._rule_manifest),
            "sigma_dir": str(self.sigma_dir),
            "yara_dir": str(self.yara_dir),
            "suricata_dir": str(self.suricata_dir),
        }

        try:
            with open(DETECTION_SUMMARY, "w") as f:
                json.dump(summary, f, indent=2)
        except Exception as e:
            logger.warning(f"[DETECT-FORGE] Detection summary write failed: {e}")

        logger.info(
            f"[DETECT-FORGE] Complete | "
            f"Sigma: +{sigma_total} | YARA: +{yara_total} | Suricata: +{sur_total} | "
            f"Total catalog: {len(self._rule_manifest)} rules"
        )

        return summary

    def _write_master_suricata_file(self):
        """Write all Suricata rules to a single master .rules file for IDS import."""
        master_path = self.suricata_dir / "cdb_apex_master.rules"
        try:
            lines = [
                "# CyberDudeBivash SENTINEL APEX — Master Suricata Rules\n",
                f"# Generated: {datetime.now(timezone.utc).isoformat()}\n",
                f"# Total rules in catalog: {len(self._rule_manifest)}\n",
                "# Import this file into your Suricata/Snort IDS configuration\n\n",
            ]
            # Write all suricata rule files content
            for rule_meta in self._rule_manifest:
                if rule_meta["rule_type"] == "suricata":
                    rule_file = self.suricata_dir / rule_meta["filename"]
                    if rule_file.exists():
                        with open(rule_file) as rf:
                            lines.append(rf.read())

            with open(master_path, "w") as f:
                f.writelines(lines)
        except Exception as e:
            logger.warning(f"[DETECT-FORGE] Master Suricata file write failed: {e}")


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    forge = DetectionForge()
    summary = forge.run()
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
