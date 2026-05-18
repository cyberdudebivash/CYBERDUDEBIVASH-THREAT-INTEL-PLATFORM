#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX                                            ║
║  AUTOMATED MITRE ATT&CK TTP ENGINE v1.0                                   ║
║  Full TTP Coverage · Correlation Engine · Auto-Generate Sigma/YARA/SIEM   ║
╚══════════════════════════════════════════════════════════════════════════════╝
Zero-regression · No duplicate mappings · Consistent taxonomy · Production-ready
"""

import os
import sys
import re
import json
import hashlib
import logging
import tempfile
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-TTP-ENGINE")
logging.basicConfig(level=logging.INFO, format="[TTP-ENGINE] %(asctime)s %(levelname)s %(message)s")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH   = os.path.join(BASE_DIR, "data", "enriched_manifest.json")
OUTPUT_DIR      = os.path.join(BASE_DIR, "data", "ttp_engine")
TTP_MATRIX      = os.path.join(OUTPUT_DIR, "ttp_coverage_matrix.json")
TTP_CORRELATIONS= os.path.join(OUTPUT_DIR, "ttp_correlations.json")
SIGMA_RULES_OUT = os.path.join(OUTPUT_DIR, "sigma_rules.yml")
YARA_RULES_OUT  = os.path.join(OUTPUT_DIR, "yara_rules.yar")
SIEM_RULES_OUT  = os.path.join(OUTPUT_DIR, "siem_rules.json")
ENGINE_META     = os.path.join(OUTPUT_DIR, "engine_meta.json")

# ── Complete MITRE ATT&CK Tactic → Technique mapping (Enterprise, v14) ───────
MITRE_TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

# ── High-fidelity TTP keyword triggers (technique_id → keywords) ─────────────
TTP_KEYWORD_MAP: Dict[str, Dict[str, Any]] = {
    # RECONNAISSANCE
    "T1595": {"tactic": "TA0043", "name": "Active Scanning",
              "keywords": ["scanning", "port scan", "nmap", "masscan", "shodan", "censys"]},
    "T1592": {"tactic": "TA0043", "name": "Gather Victim Host Information",
              "keywords": ["fingerprint", "banner grab", "os detection", "version detection"]},
    "T1589": {"tactic": "TA0043", "name": "Gather Victim Identity Information",
              "keywords": ["email harvest", "osint", "linkedin scrape", "employee data"]},
    "T1593": {"tactic": "TA0043", "name": "Search Open Websites/Domains",
              "keywords": ["google dork", "shodan search", "censys", "fofa"]},
    # RESOURCE DEVELOPMENT
    "T1583": {"tactic": "TA0042", "name": "Acquire Infrastructure",
              "keywords": ["c2 server", "command and control", "bulletproof hosting", "vps"]},
    "T1584": {"tactic": "TA0042", "name": "Compromise Infrastructure",
              "keywords": ["compromised server", "hijacked domain", "watering hole"]},
    "T1588": {"tactic": "TA0042", "name": "Obtain Capabilities",
              "keywords": ["exploit kit", "malware purchase", "tool acquisition"]},
    # INITIAL ACCESS
    "T1190": {"tactic": "TA0001", "name": "Exploit Public-Facing Application",
              "keywords": ["exploit", "remote code execution", "rce", "sql injection",
                           "xxe", "deserialization", "path traversal", "lfi", "rfi"]},
    "T1566": {"tactic": "TA0001", "name": "Phishing",
              "keywords": ["phishing", "spearphishing", "vishing", "smishing", "lure"]},
    "T1195": {"tactic": "TA0001", "name": "Supply Chain Compromise",
              "keywords": ["supply chain", "dependency confusion", "typosquatting",
                           "solarwinds", "xz utils", "polyfill", "upstream"]},
    "T1199": {"tactic": "TA0001", "name": "Trusted Relationship",
              "keywords": ["third-party", "trusted relationship", "msp compromise", "mssp"]},
    "T1078": {"tactic": "TA0001", "name": "Valid Accounts",
              "keywords": ["valid account", "stolen credential", "default password",
                           "credential stuffing", "account takeover"]},
    "T1189": {"tactic": "TA0001", "name": "Drive-by Compromise",
              "keywords": ["drive-by", "malicious ad", "malvertising", "browser exploit"]},
    # EXECUTION
    "T1059": {"tactic": "TA0002", "name": "Command and Scripting Interpreter",
              "keywords": ["powershell", "bash", "cmd", "command interpreter",
                           "script execution", "wscript", "cscript"]},
    "T1059.001": {"tactic": "TA0002", "name": "PowerShell",
                  "keywords": ["powershell", "ps1", "invoke-expression", "encoded command"]},
    "T1059.003": {"tactic": "TA0002", "name": "Windows Command Shell",
                  "keywords": ["cmd.exe", "command shell", "batch script", "net use"]},
    "T1203": {"tactic": "TA0002", "name": "Exploitation for Client Execution",
              "keywords": ["browser exploit", "office exploit", "pdf exploit",
                           "client-side exploit", "use after free", "heap spray"]},
    "T1204": {"tactic": "TA0002", "name": "User Execution",
              "keywords": ["macro", "malicious attachment", "user execution", "lnk file"]},
    # PERSISTENCE
    "T1053": {"tactic": "TA0003", "name": "Scheduled Task/Job",
              "keywords": ["scheduled task", "cron job", "crontab", "at command", "schtask"]},
    "T1543": {"tactic": "TA0003", "name": "Create or Modify System Process",
              "keywords": ["service creation", "systemd", "launchd", "windows service"]},
    "T1547": {"tactic": "TA0003", "name": "Boot or Logon Autostart Execution",
              "keywords": ["registry run", "autostart", "startup folder", "logon script"]},
    "T1136": {"tactic": "TA0003", "name": "Create Account",
              "keywords": ["create account", "rogue account", "backdoor account", "shadow admin"]},
    "T1098": {"tactic": "TA0003", "name": "Account Manipulation",
              "keywords": ["account manipulation", "ssh key", "access token", "oauth"]},
    # PRIVILEGE ESCALATION
    "T1068": {"tactic": "TA0004", "name": "Exploitation for Privilege Escalation",
              "keywords": ["privilege escalation", "local privilege", "lpe", "kernel exploit",
                           "sudo exploit", "suid", "token impersonation"]},
    "T1055": {"tactic": "TA0004", "name": "Process Injection",
              "keywords": ["process injection", "dll injection", "reflective dll",
                           "code injection", "shellcode injection"]},
    "T1078.003": {"tactic": "TA0004", "name": "Local Accounts",
                  "keywords": ["local admin", "local privilege", "built-in admin"]},
    # DEFENSE EVASION
    "T1027": {"tactic": "TA0005", "name": "Obfuscated Files or Information",
              "keywords": ["obfuscat", "base64 encode", "encrypted payload", "packer",
                           "code obfuscation", "steganography"]},
    "T1036": {"tactic": "TA0005", "name": "Masquerading",
              "keywords": ["masquerad", "filename spoof", "signed binary", "lolbin",
                           "living off land", "lolbas", "trusted binary"]},
    "T1070": {"tactic": "TA0005", "name": "Indicator Removal",
              "keywords": ["log deletion", "clear logs", "event log clear",
                           "anti-forensic", "artifact removal"]},
    "T1112": {"tactic": "TA0005", "name": "Modify Registry",
              "keywords": ["registry modification", "regedit", "reg add", "hklm"]},
    # CREDENTIAL ACCESS
    "T1003": {"tactic": "TA0006", "name": "OS Credential Dumping",
              "keywords": ["credential dump", "mimikatz", "lsass", "ntds.dit",
                           "sam database", "secretsdump", "hashdump"]},
    "T1110": {"tactic": "TA0006", "name": "Brute Force",
              "keywords": ["brute force", "password spray", "credential stuffing",
                           "dictionary attack", "rainbow table"]},
    "T1539": {"tactic": "TA0006", "name": "Steal Web Session Cookie",
              "keywords": ["cookie theft", "session hijack", "cookie stealer", "auth token theft"]},
    "T1552": {"tactic": "TA0006", "name": "Unsecured Credentials",
              "keywords": ["hardcoded credential", "plaintext password", "env variable",
                           "credential in code", "secret in git"]},
    # DISCOVERY
    "T1082": {"tactic": "TA0007", "name": "System Information Discovery",
              "keywords": ["system info", "os info", "host discovery", "uname", "systeminfo"]},
    "T1083": {"tactic": "TA0007", "name": "File and Directory Discovery",
              "keywords": ["file enumeration", "directory listing", "find command", "dir /s"]},
    "T1046": {"tactic": "TA0007", "name": "Network Service Discovery",
              "keywords": ["network scan", "port scan", "service discovery", "nmap"]},
    # LATERAL MOVEMENT
    "T1021": {"tactic": "TA0008", "name": "Remote Services",
              "keywords": ["rdp", "ssh lateral", "winrm", "smb", "psexec", "lateral movement"]},
    "T1550": {"tactic": "TA0008", "name": "Use Alternate Authentication Material",
              "keywords": ["pass the hash", "pth", "pass the ticket", "golden ticket",
                           "kerberoasting", "overpass the hash"]},
    # COLLECTION
    "T1005": {"tactic": "TA0009", "name": "Data from Local System",
              "keywords": ["data collection", "file collection", "data staging", "harvest"]},
    "T1114": {"tactic": "TA0009", "name": "Email Collection",
              "keywords": ["email collection", "mail exfiltration", "owa", "exchange hack"]},
    # EXFILTRATION
    "T1041": {"tactic": "TA0010", "name": "Exfiltration Over C2 Channel",
              "keywords": ["data exfiltration", "c2 exfil", "beaconing", "data theft"]},
    "T1537": {"tactic": "TA0010", "name": "Transfer Data to Cloud Account",
              "keywords": ["s3 upload", "cloud exfil", "dropbox", "mega.nz", "cloud upload"]},
    # COMMAND AND CONTROL
    "T1071": {"tactic": "TA0011", "name": "Application Layer Protocol",
              "keywords": ["c2 communication", "http beacon", "dns tunnel", "covert channel",
                           "cobalt strike", "metasploit", "sliver", "havoc c2"]},
    "T1095": {"tactic": "TA0011", "name": "Non-Application Layer Protocol",
              "keywords": ["icmp tunnel", "raw socket", "dns c2", "icmp c2"]},
    "T1572": {"tactic": "TA0011", "name": "Protocol Tunneling",
              "keywords": ["tunnel", "dns over https", "doh", "protocol encapsulation"]},
    # IMPACT
    "T1486": {"tactic": "TA0040", "name": "Data Encrypted for Impact",
              "keywords": ["ransomware", "encrypt files", "data encryption", "ransom demand",
                           "lockbit", "blackcat", "cl0p", "akira", "ransomhub"]},
    "T1485": {"tactic": "TA0040", "name": "Data Destruction",
              "keywords": ["data destruction", "wiper", "disk wipe", "whispergate", "notpetya"]},
    "T1498": {"tactic": "TA0040", "name": "Network Denial of Service",
              "keywords": ["ddos", "denial of service", "flood attack", "amplification"]},
    "T1496": {"tactic": "TA0040", "name": "Resource Hijacking",
              "keywords": ["cryptomining", "cryptojacking", "coinminer", "xmrig", "monero mine"]},
    "T1491": {"tactic": "TA0040", "name": "Defacement",
              "keywords": ["defacement", "website defaced", "web defacement"]},
    "T1489": {"tactic": "TA0040", "name": "Service Stop",
              "keywords": ["service stop", "process kill", "service disruption"]},
}


def _atomic_write(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _write_text_atomic(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def _load_manifest() -> List[Dict]:
    for candidate in [MANIFEST_PATH,
                      os.path.join(BASE_DIR, "data", "advisory_manifest.json"),
                      os.path.join(BASE_DIR, "data", "stix", "manifest.json")]:
        if os.path.exists(candidate):
            try:
                with open(candidate, encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else data.get("advisories", [])
            except Exception as e:
                logger.warning(f"Failed to load {candidate}: {e}")
    return []


def _ttp_id(ttp: str) -> str:
    return hashlib.md5(ttp.encode(), usedforsecurity=False).hexdigest()[:8].upper()


# ──────────────────────────────────────────────────────────────────────────────
# TTP MAPPER
# ──────────────────────────────────────────────────────────────────────────────
class TTPMapper:
    """Maps advisory text to MITRE ATT&CK techniques. No duplicate mappings."""

    def map(self, advisories: List[Dict]) -> Tuple[List[Dict], Dict[str, int]]:
        mapped = []
        ttp_freq: Dict[str, int] = Counter()
        seen: Set[str] = set()

        for adv in advisories:
            text = " ".join([
                adv.get("title", ""), adv.get("summary", ""),
                adv.get("description", ""), adv.get("actors", ""),
                str(adv.get("tags", [])),
            ]).lower()

            matched_ttps: Dict[str, Dict] = {}

            # Check keyword triggers (de-duplicate per advisory)
            for ttp_id, info in TTP_KEYWORD_MAP.items():
                hits = [kw for kw in info["keywords"] if kw in text]
                if hits:
                    if ttp_id not in matched_ttps:
                        matched_ttps[ttp_id] = {
                            "technique_id": ttp_id,
                            "technique_name": info["name"],
                            "tactic_id": info["tactic"],
                            "tactic_name": MITRE_TACTICS.get(info["tactic"], "Unknown"),
                            "trigger_keywords": hits[:3],
                            "confidence": min(1.0, 0.5 + len(hits) * 0.12),
                        }

            # Also preserve existing MITRE mappings from manifest
            for existing_ttp in adv.get("mitre_techniques", []):
                if existing_ttp in TTP_KEYWORD_MAP and existing_ttp not in matched_ttps:
                    info = TTP_KEYWORD_MAP[existing_ttp]
                    matched_ttps[existing_ttp] = {
                        "technique_id": existing_ttp,
                        "technique_name": info["name"],
                        "tactic_id": info["tactic"],
                        "tactic_name": MITRE_TACTICS.get(info["tactic"], "Unknown"),
                        "trigger_keywords": ["manifest_mapped"],
                        "confidence": 0.8,
                    }

            if matched_ttps:
                for ttp in matched_ttps:
                    ttp_freq[ttp] += 1

                mapped.append({
                    "advisory_id": adv.get("id", ""),
                    "cve_id": adv.get("cve_id", ""),
                    "title": adv.get("title", "")[:100],
                    "techniques": list(matched_ttps.values()),
                    "technique_count": len(matched_ttps),
                    "tactic_coverage": list(set(t["tactic_name"] for t in matched_ttps.values())),
                })

        return mapped, dict(ttp_freq)


# ──────────────────────────────────────────────────────────────────────────────
# TTP CORRELATION ENGINE
# ──────────────────────────────────────────────────────────────────────────────
class TTPCorrelationEngine:
    """Finds TTP co-occurrence patterns and kill chain sequences."""

    # Known ATT&CK kill chain sequences (tactic order)
    TACTIC_SEQUENCE = [
        "TA0043",  # Recon
        "TA0042",  # Resource Dev
        "TA0001",  # Initial Access
        "TA0002",  # Execution
        "TA0003",  # Persistence
        "TA0004",  # Privilege Escalation
        "TA0005",  # Defense Evasion
        "TA0006",  # Credential Access
        "TA0007",  # Discovery
        "TA0008",  # Lateral Movement
        "TA0009",  # Collection
        "TA0010",  # Exfiltration
        "TA0011",  # C2
        "TA0040",  # Impact
    ]

    def correlate(self, mapped_advisories: List[Dict], ttp_freq: Dict[str, int]) -> Dict:
        # Co-occurrence matrix
        cooccurrence: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for adv in mapped_advisories:
            techs = [t["technique_id"] for t in adv.get("techniques", [])]
            for i, t1 in enumerate(techs):
                for t2 in techs[i+1:]:
                    cooccurrence[t1][t2] += 1
                    cooccurrence[t2][t1] += 1

        # Top co-occurring pairs
        pairs = []
        seen_pairs: Set[frozenset] = set()
        for t1, others in cooccurrence.items():
            for t2, count in sorted(others.items(), key=lambda x: -x[1])[:5]:
                pair_key = frozenset([t1, t2])
                if pair_key not in seen_pairs and count >= 2:
                    seen_pairs.add(pair_key)
                    pairs.append({
                        "technique_1": t1,
                        "name_1": TTP_KEYWORD_MAP.get(t1, {}).get("name", t1),
                        "technique_2": t2,
                        "name_2": TTP_KEYWORD_MAP.get(t2, {}).get("name", t2),
                        "co_occurrence_count": count,
                    })

        pairs.sort(key=lambda x: -x["co_occurrence_count"])

        # Tactic coverage
        tactic_coverage = defaultdict(int)
        for ttp, freq in ttp_freq.items():
            tactic_id = TTP_KEYWORD_MAP.get(ttp, {}).get("tactic", "")
            if tactic_id:
                tactic_coverage[MITRE_TACTICS.get(tactic_id, tactic_id)] += freq

        return {
            "top_cooccurring_pairs": pairs[:30],
            "tactic_coverage": dict(sorted(tactic_coverage.items(), key=lambda x: -x[1])),
            "top_techniques": [
                {"technique_id": t, "frequency": f,
                 "name": TTP_KEYWORD_MAP.get(t, {}).get("name", t)}
                for t, f in sorted(ttp_freq.items(), key=lambda x: -x[1])[:20]
            ],
            "tactics_covered": len(tactic_coverage),
            "total_tactics": len(MITRE_TACTICS),
        }


# ──────────────────────────────────────────────────────────────────────────────
# SIGMA RULE GENERATOR
# ──────────────────────────────────────────────────────────────────────────────
class SigmaRuleGenerator:
    """Auto-generates Sigma detection rules for top TTPs."""

    SIGMA_TEMPLATES = {
        "T1059.001": """title: PowerShell Suspicious Execution - CDB-TTP
id: {rule_id}
status: experimental
description: Detects suspicious PowerShell execution patterns mapped to T1059.001
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: CYBERDUDEBIVASH SENTINEL APEX
date: {date}
modified: {date}
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-Enc '
      - 'IEX('
      - 'Invoke-Expression'
      - '-NoP'
      - 'bypass'
  condition: selection
falsepositives:
  - Legitimate administrative scripts
level: high
""",
        "T1003": """title: LSASS Memory Access - Credential Dump - CDB-TTP
id: {rule_id}
status: experimental
description: Detects credential dumping via LSASS memory access (T1003)
references:
  - https://attack.mitre.org/techniques/T1003/
author: CYBERDUDEBIVASH SENTINEL APEX
date: {date}
tags:
  - attack.credential_access
  - attack.t1003
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'
  condition: selection
falsepositives:
  - AV scanners, EDR solutions
level: critical
""",
        "T1486": """title: Ransomware File Encryption Activity - CDB-TTP
id: {rule_id}
status: experimental
description: Detects mass file rename/modification consistent with ransomware (T1486)
references:
  - https://attack.mitre.org/techniques/T1486/
author: CYBERDUDEBIVASH SENTINEL APEX
date: {date}
tags:
  - attack.impact
  - attack.t1486
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.encrypted'
      - '.locked'
      - '.crypt'
      - '.enc'
      - '_locked'
  timeframe: 30s
  condition: selection | count() > 50
falsepositives:
  - Legitimate encryption software
level: critical
""",
        "T1190": """title: Public-Facing Application Exploitation - CDB-TTP
id: {rule_id}
status: experimental
description: Detects exploitation patterns against public-facing applications (T1190)
references:
  - https://attack.mitre.org/techniques/T1190/
author: CYBERDUDEBIVASH SENTINEL APEX
date: {date}
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  product: webserver
  service: access
detection:
  selection:
    c-uri|contains:
      - '../../../'
      - '%2e%2e%2f'
      - 'etc/passwd'
      - '/cmd?'
      - ';exec('
      - 'union select'
      - '<?php'
  condition: selection
falsepositives:
  - Penetration testing
level: high
""",
    }

    def generate(self, top_ttps: List[str]) -> str:
        lines = [
            "# ╔══════════════════════════════════════════════════════════════════════╗",
            "# ║  CYBERDUDEBIVASH SENTINEL APEX — AUTO-GENERATED SIGMA RULES         ║",
            f"# ║  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC                              ║",
            "# ╚══════════════════════════════════════════════════════════════════════╝",
            "",
        ]
        rules_generated = 0
        for ttp in top_ttps:
            if ttp in self.SIGMA_TEMPLATES:
                rule_id = hashlib.md5(f"CDB-SIGMA-{ttp}".encode(), usedforsecurity=False).hexdigest()
                rule = self.SIGMA_TEMPLATES[ttp].format(
                    rule_id=rule_id,
                    date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
                )
                lines.append(f"# ── TTP: {ttp} ───────────────────────────────")
                lines.append(rule)
                lines.append("---")
                rules_generated += 1
        if rules_generated == 0:
            lines.append("# No Sigma templates available for current top TTPs")
        return "\n".join(lines), rules_generated


# ──────────────────────────────────────────────────────────────────────────────
# YARA RULE GENERATOR
# ──────────────────────────────────────────────────────────────────────────────
class YARARuleGenerator:
    """Auto-generates YARA rules for top malware families / TTPs."""

    def generate(self, ttp_freq: Dict[str, int]) -> str:
        lines = [
            "/*",
            " * CYBERDUDEBIVASH SENTINEL APEX — AUTO-GENERATED YARA RULES",
            f" * Generated: {datetime.now(timezone.utc).isoformat()}",
            " * For detection of threat indicators mapped to MITRE ATT&CK",
            " */",
            "",
        ]
        rules_generated = 0

        # Ransomware family rule
        if ttp_freq.get("T1486", 0) >= 2:
            lines.extend([
                'rule CDB_Ransomware_Indicator {',
                '    meta:',
                '        description = "Detects common ransomware file markers"',
                '        author = "CYBERDUDEBIVASH SENTINEL APEX"',
                f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"',
                '        mitre_technique = "T1486"',
                '    strings:',
                '        $ransom1 = "YOUR_FILES_ARE_ENCRYPTED" nocase',
                '        $ransom2 = "DECRYPT_INSTRUCTIONS" nocase',
                '        $ransom3 = "your data has been encrypted" nocase',
                '        $ransom4 = ".locked" nocase',
                '        $ransom5 = "bitcoin" nocase',
                '        $ransom6 = "tor browser" nocase',
                '        $ext1 = ".lockbit"',
                '        $ext2 = ".akira"',
                '        $ext3 = ".alphv"',
                '    condition:',
                '        2 of ($ransom*) or 1 of ($ext*)',
                '}',
                '',
            ])
            rules_generated += 1

        # Credential stealer rule
        if ttp_freq.get("T1003", 0) >= 1 or ttp_freq.get("T1539", 0) >= 1:
            lines.extend([
                'rule CDB_Credential_Stealer {',
                '    meta:',
                '        description = "Detects credential stealing tool markers"',
                '        author = "CYBERDUDEBIVASH SENTINEL APEX"',
                f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"',
                '        mitre_technique = "T1003,T1539"',
                '    strings:',
                '        $mimikatz1 = "mimikatz" nocase',
                '        $mimikatz2 = "sekurlsa" nocase',
                '        $stealer1 = "grabpasswords" nocase',
                '        $stealer2 = "StealPassword" nocase',
                '        $lsass1 = "lsass.exe" nocase',
                '        $cookie1 = "cookies.sqlite" nocase',
                '        $cookie2 = "Login Data" nocase',
                '    condition:',
                '        any of them',
                '}',
                '',
            ])
            rules_generated += 1

        # C2 beacon rule
        if ttp_freq.get("T1071", 0) >= 2:
            lines.extend([
                'rule CDB_C2_Beacon_Pattern {',
                '    meta:',
                '        description = "Detects common C2 framework beacon strings"',
                '        author = "CYBERDUDEBIVASH SENTINEL APEX"',
                f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"',
                '        mitre_technique = "T1071"',
                '    strings:',
                '        $cs1 = "CobaltStrike" nocase',
                '        $cs2 = "beacon.dll" nocase',
                '        $sliver1 = "sliver" nocase',
                '        $havoc1 = "havoc" nocase',
                '        $meta1 = "meterpreter" nocase',
                '    condition:',
                '        any of them',
                '}',
                '',
            ])
            rules_generated += 1

        if rules_generated == 0:
            lines.append("// No YARA templates triggered by current TTP frequency")

        return "\n".join(lines), rules_generated


# ──────────────────────────────────────────────────────────────────────────────
# TTP ENGINE ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────
class TTPEngine:
    def __init__(self):
        self.mapper = TTPMapper()
        self.correlator = TTPCorrelationEngine()
        self.sigma_gen = SigmaRuleGenerator()
        self.yara_gen = YARARuleGenerator()

    def run(self) -> int:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        logger.info("=== TTP ENGINE START ===")

        advisories = _load_manifest()
        if not advisories:
            logger.warning("No advisories — writing empty outputs")
            self._write_empty()
            return 0

        logger.info(f"Mapping TTPs for {len(advisories)} advisories")

        mapped, ttp_freq = self.mapper.map(advisories)
        logger.info(f"Advisories with TTPs: {len(mapped)}, unique TTPs: {len(ttp_freq)}")

        correlation = self.correlator.correlate(mapped, ttp_freq)
        logger.info(f"Tactics covered: {correlation['tactics_covered']}/{correlation['total_tactics']}")

        top_ttp_ids = [t["technique_id"] for t in correlation["top_techniques"][:10]]
        sigma_content, sigma_count = self.sigma_gen.generate(top_ttp_ids)
        yara_content, yara_count = self.yara_gen.generate(ttp_freq)

        # SIEM rules (JSON format)
        siem_rules = []
        for ttp_id, freq in sorted(ttp_freq.items(), key=lambda x: -x[1])[:20]:
            info = TTP_KEYWORD_MAP.get(ttp_id, {})
            siem_rules.append({
                "rule_id": f"CDB-TTP-{ttp_id}",
                "technique": ttp_id,
                "name": info.get("name", ttp_id),
                "tactic": MITRE_TACTICS.get(info.get("tactic", ""), "Unknown"),
                "frequency": freq,
                "splunk_query": (
                    'index=* sourcetype=* ("'
                    + '" OR "'.join(info.get("keywords", [ttp_id])[:3])
                    + '") | eval technique="' + ttp_id + '"'
                ),
                "kql_query": (
                    'SecurityEvent | where EventData has_any ("'
                    + '", "'.join(info.get("keywords", [ttp_id])[:3])
                    + '")'
                ),
            })

        # Atomic writes
        coverage_matrix = {
            "total_advisories": len(advisories),
            "advisories_with_ttps": len(mapped),
            "unique_techniques": len(ttp_freq),
            "ttp_frequency": {k: v for k, v in sorted(ttp_freq.items(), key=lambda x: -x[1])[:50]},
            "tactic_coverage": correlation["tactic_coverage"],
            "tactics_covered_count": correlation["tactics_covered"],
            "total_tactics": correlation["total_tactics"],
            "coverage_pct": round(correlation["tactics_covered"] / len(MITRE_TACTICS) * 100, 1),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(TTP_MATRIX, coverage_matrix)
        _atomic_write(TTP_CORRELATIONS, {
            **correlation,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(SIEM_RULES_OUT, {
            "rules": siem_rules,
            "total": len(siem_rules),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _write_text_atomic(SIGMA_RULES_OUT, sigma_content)
        _write_text_atomic(YARA_RULES_OUT, yara_content)

        meta = {
            "engine": "TTPEngine",
            "version": "1.0.0",
            "advisories_processed": len(advisories),
            "advisories_mapped": len(mapped),
            "unique_techniques": len(ttp_freq),
            "tactics_covered": correlation["tactics_covered"],
            "total_tactics": correlation["total_tactics"],
            "coverage_pct": coverage_matrix["coverage_pct"],
            "sigma_rules_generated": sigma_count,
            "yara_rules_generated": yara_count,
            "siem_rules_generated": len(siem_rules),
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(ENGINE_META, meta)

        logger.info(f"TTPs mapped: {len(ttp_freq)} unique techniques")
        logger.info(f"Tactic coverage: {correlation['tactics_covered']}/{len(MITRE_TACTICS)} ({coverage_matrix['coverage_pct']}%)")
        logger.info(f"Sigma rules: {sigma_count}, YARA rules: {yara_count}")
        logger.info("=== TTP ENGINE COMPLETE ===")
        return 0

    def _write_empty(self) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        for path in [TTP_MATRIX, TTP_CORRELATIONS, SIEM_RULES_OUT]:
            _atomic_write(path, {"generated_at": ts})
        for path in [SIGMA_RULES_OUT, YARA_RULES_OUT]:
            _write_text_atomic(path, f"# No data — {ts}\n")
        _atomic_write(ENGINE_META, {
            "engine": "TTPEngine", "version": "1.0.0",
            "advisories_processed": 0, "run_timestamp": ts,
        })


def main() -> int:
    try:
        engine = TTPEngine()
        return engine.run()
    except Exception as e:
        logger.error(f"TTPEngine fatal: {e}", exc_info=True)
        try:
            _atomic_write(ENGINE_META, {
                "engine": "TTPEngine", "version": "1.0.0",
                "error": str(e)[:500],
                "run_timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass
        return 0  # Never fail pipeline


if __name__ == "__main__":
    sys.exit(main())
