"""
detection_pack_builder.py — CyberDudeBivash SENTINEL APEX v20.0
DETECTION PACK BUILDER ENGINE — PRODUCTION UPGRADE

Changes from v1.0:
  - Real IOC-based Sigma rules (IPs, domains, hashes, CVEs) — not generic EventID:1
  - Real IOC-based YARA rule from extracted hashes and artifacts
  - Threat-scenario aware KQL/SPL (ransomware vs web exploit vs APT vs supply chain)
  - Enriched README with operator instructions
  - CVSS/EPSS metadata added to metadata.json
  - ZIP includes all artifacts cleanly labeled
  - Backward compatible — build_latest_pack() signature unchanged
"""

import re
import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

MANIFEST_PATH = Path("data/stix/feed_manifest.json")
OUTPUT_DIR    = Path("data/premium_packs")

# ─────────────────────────────────────────────
_SCENARIO_MAP = {
    "ransomware":     ["ransomware", "ransom", "lockbit", "blackcat", "cl0p"],
    "supply_chain":   ["supply chain", "dependency", "package poisoning", "npm", "pypi"],
    "apt":            ["apt", "nation-state", "volt typhoon", "lazarus"],
    "phishing":       ["phishing", "spear-phishing", "credential harvest", "clickfix"],
    "malware":        ["malware", "trojan", "stealer", "rat", "backdoor", "infostealer"],
    "xss":            ["xss", "cross-site scripting", "reflected xss", "stored xss"],
    "rce":            ["remote code execution", "rce", "privilege escalation", "zero-day"],
    "vulnerability":  ["cve-", "vulnerability", "patch", "security update"],
    "data_breach":    ["breach", "leak", "exposed records", "stolen data"],
}

def _detect_scenario(title: str) -> str:
    text = title.lower()
    scores = {s: sum(1 for kw in kws if kw in text) for s, kws in _SCENARIO_MAP.items()}
    valid = {s: v for s, v in scores.items() if v > 0}
    return max(valid, key=valid.get) if valid else "generic"

def _safe_t(title: str) -> str:
    return re.sub(r'[^a-zA-Z0-9 _\-]', '', title)[:80]

def _rule_id(title: str, suffix: str = "") -> str:
    return f"cdb-{abs(hash(title + suffix)) % 999999:06d}"

def load_manifest():
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found at {MANIFEST_PATH}")
    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)

def save_manifest(data):
    with MANIFEST_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def ensure_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def already_built(stix_id: str) -> bool:
    return (OUTPUT_DIR / f"{stix_id}.zip").exists()


# ─────────────────────────────────────────────
# IOC CSV
# ─────────────────────────────────────────────
def generate_ioc_csv(item: Dict, pack_dir: Path):
    tlp = item.get("tlp_label", "TLP:GREEN")
    indicators = item.get("indicators", [])
    ioc_counts = item.get("ioc_counts", {})
    cves = item.get("cves", [])

    with (pack_dir / "ioc_feed.csv").open("w", encoding="utf-8") as f:
        f.write("indicator_type,value,confidence,tlp\n")
        if indicators:
            for ioc in indicators:
                f.write(f"{ioc.get('type','unknown')},{ioc.get('value','')},high,{tlp}\n")
        elif ioc_counts:
            for key, count in ioc_counts.items():
                if count > 0:
                    f.write(f"{key},{count} indicators extracted,medium,{tlp}\n")
        for cve in (cves or []):
            f.write(f"cve,{cve},high,{tlp}\n")


# ─────────────────────────────────────────────
# SIGMA
# ─────────────────────────────────────────────
def generate_sigma_rule(item: Dict, pack_dir: Path):
    title    = item.get("title", "Unknown")
    scenario = _detect_scenario(title)
    safe     = _safe_t(title)
    date_str = datetime.utcnow().strftime('%Y/%m/%d')

    indicators = item.get("indicators", [])
    ips     = [i["value"] for i in indicators if i.get("type") in ("ipv4","ip")][:12]
    domains = [i["value"] for i in indicators if i.get("type") == "domain"][:12]
    hashes  = [i["value"] for i in indicators if i.get("type") in ("sha256","md5")][:8]
    artifacts = [i["value"] for i in indicators if i.get("type") == "artifact"][:8]
    cves    = item.get("cves", [])

    lines = [
        "# ================================================================",
        f"# CyberDudeBivash SENTINEL APEX v20.0 — Sigma Detection Rules",
        f"# Threat  : {safe}",
        f"# Scenario: {scenario.upper()}",
        f"# Generated: {datetime.utcnow().isoformat()} UTC",
        "# Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com",
        "# ================================================================", ""
    ]

    # Rule 1: Network IOCs
    if domains or ips:
        net = (domains[:8] + ips[:8])
        net_items = "\n      - ".join(net)
        lines += [
            f"title: 'CDB: {safe} - Network IOCs'",
            f"id: {_rule_id(title, 'net')}",
            "status: experimental",
            f"description: 'Detects malicious network traffic for: {safe}'",
            "references: ['https://intel.cyberdudebivash.com']",
            "author: 'CyberDudeBivash GOC (Automated)'",
            f"date: {date_str}",
            "tags: ['attack.command_and_control', 'attack.exfiltration']",
            "logsource:",
            "  category: dns",
            "  product: any",
            "detection:",
            "  selection_dns:",
            "    query|contains:",
            f"      - {net_items}",
            "  condition: selection_dns",
            "falsepositives: ['Legitimate traffic to similarly-named domains']",
            "level: high", "---", ""
        ]

    # Rule 2: File IOCs
    if hashes or artifacts:
        det_block = []
        conds = []
        if hashes:
            det_block.append("  selection_hash:")
            det_block.append("    Hashes|contains:")
            for h in hashes[:6]:
                det_block.append(f"      - '{h}'")
            conds.append("selection_hash")
        if artifacts:
            det_block.append("  selection_file:")
            det_block.append("    TargetFilename|endswith:")
            for a in artifacts[:6]:
                det_block.append(f"      - '{a}'")
            conds.append("selection_file")
        det_block.append(f"  condition: {' or '.join(conds)}")

        lines += [
            f"title: 'CDB: {safe} - File/Hash IOCs'",
            f"id: {_rule_id(title, 'file')}",
            "status: experimental",
            f"description: 'Detects malicious files/hashes for: {safe}'",
            "author: 'CyberDudeBivash GOC (Automated)'",
            f"date: {date_str}",
            "tags: ['attack.execution', 'attack.defense_evasion']",
            "logsource:",
            "  category: file_event",
            "  product: windows",
            "detection:",
        ] + det_block + ["falsepositives: ['Legitimate software with matching names']", "level: high", "---", ""]

    # Rule 3: Scenario-specific behavioral
    if scenario == "ransomware":
        lines += [
            f"title: 'CDB: {safe} - Ransomware VSS Deletion'",
            f"id: {_rule_id(title, 'ransom')}",
            "status: experimental",
            "description: 'Detects shadow copy deletion — ransomware pre-encryption'",
            "author: 'CyberDudeBivash GOC (Automated)'",
            f"date: {date_str}",
            "tags: ['attack.impact.t1486', 'attack.defense_evasion.t1490']",
            "logsource:",
            "  category: process_creation",
            "  product: windows",
            "detection:",
            "  selection_vss:",
            "    Image|endswith: ['\\\\vssadmin.exe', '\\\\wmic.exe', '\\\\wbadmin.exe']",
            "    CommandLine|contains: ['delete shadows', 'shadow copy delete', 'resize shadowstorage']",
            "  condition: selection_vss",
            "falsepositives: ['Legitimate backup software']",
            "level: critical", "---", ""
        ]
    elif scenario in ("xss", "rce", "vulnerability"):
        lines += [
            f"title: 'CDB: {safe} - Web Exploit Detection'",
            f"id: {_rule_id(title, 'web')}",
            "status: experimental",
            "description: 'Detects web application exploitation / injection patterns'",
            "author: 'CyberDudeBivash GOC (Automated)'",
            f"date: {date_str}",
            "tags: ['attack.initial_access.t1190', 'attack.execution.t1059']",
            "logsource:",
            "  category: webserver",
            "  product: any",
            "detection:",
            "  selection_xss:",
            "    c-uri|contains: ['<script>', 'javascript:', 'onerror=', '%3Cscript%3E']",
            "  selection_sqli:",
            "    c-uri|contains: [\"' OR '1'='1\", 'UNION SELECT', '../../../']",
            "  condition: selection_xss or selection_sqli",
            "falsepositives: ['Security testing / pen testing']",
            "level: high", "---", ""
        ]
    elif scenario == "apt":
        lines += [
            f"title: 'CDB: {safe} - APT Credential Dump'",
            f"id: {_rule_id(title, 'apt')}",
            "status: experimental",
            "description: 'Detects APT credential dumping and lateral movement'",
            "author: 'CyberDudeBivash GOC (Automated)'",
            f"date: {date_str}",
            "tags: ['attack.lateral_movement.t1021', 'attack.credential_access.t1003']",
            "logsource:",
            "  category: process_creation",
            "  product: windows",
            "detection:",
            "  selection_creds:",
            "    Image|endswith: ['\\\\mimikatz.exe', '\\\\procdump.exe']",
            "    CommandLine|contains: ['sekurlsa', 'lsadump', 'dcsync']",
            "  condition: selection_creds",
            "falsepositives: ['Legitimate admin credential management']",
            "level: critical", "---", ""
        ]
    elif scenario == "supply_chain":
        lines += [
            f"title: 'CDB: {safe} - Supply Chain Package Abuse'",
            f"id: {_rule_id(title, 'supply')}",
            "status: experimental",
            "description: 'Detects suspicious package manager activity and post-install hooks'",
            "author: 'CyberDudeBivash GOC (Automated)'",
            f"date: {date_str}",
            "tags: ['attack.initial_access.t1195', 'attack.execution.t1059.001']",
            "logsource:",
            "  category: process_creation",
            "  product: windows",
            "detection:",
            "  selection_pkg:",
            "    Image|endswith: ['\\\\npm.exe', '\\\\pip.exe', '\\\\pip3.exe']",
            "    CommandLine|contains: ['install', '--pre', '--index-url']",
            "  condition: selection_pkg",
            "falsepositives: ['Legitimate use of private package registries']",
            "level: high", "---", ""
        ]
    else:
        lines += [
            f"title: 'CDB: {safe} - Suspicious Script Execution'",
            f"id: {_rule_id(title, 'generic')}",
            "status: experimental",
            "description: 'Detects obfuscated PowerShell and script-based execution'",
            "author: 'CyberDudeBivash GOC (Automated)'",
            f"date: {date_str}",
            "tags: ['attack.execution', 'attack.defense_evasion']",
            "logsource:",
            "  category: process_creation",
            "  product: windows",
            "detection:",
            "  selection_ps:",
            "    CommandLine|contains: ['-EncodedCommand', '-enc ', 'IEX(', 'Invoke-Expression', 'DownloadFile']",
            "  condition: selection_ps",
            "falsepositives: ['Legitimate admin scripts']",
            "level: medium", "---", ""
        ]

    (pack_dir / "detection_sigma.yml").write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────────────────────────────
# YARA
# ─────────────────────────────────────────────
def generate_yara_rule(item: Dict, pack_dir: Path):
    title     = item.get("title", "Unknown")
    safe      = _safe_t(title)
    stix_id   = item.get("stix_id", "unknown")
    scenario  = _detect_scenario(title)
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', safe)[:50]
    date_str  = datetime.utcnow().strftime('%Y-%m-%d')

    indicators = item.get("indicators", [])
    hashes    = [i["value"] for i in indicators if i.get("type") == "sha256"][:6]
    md5s      = [i["value"] for i in indicators if i.get("type") == "md5"][:6]
    artifacts = [i["value"] for i in indicators if i.get("type") == "artifact"][:8]

    lines = [
        "// ================================================================",
        f"// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules",
        f"// Threat   : {safe}",
        f"// STIX ID  : {stix_id}",
        f"// Scenario : {scenario.upper()}",
        f"// Generated: {datetime.utcnow().isoformat()} UTC",
        "// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com",
        "// ================================================================", ""
    ]

    if artifacts:
        strings_block = "\n".join(f'        $art_{i+1} = "{a}" ascii wide nocase' for i, a in enumerate(artifacts))
        lines += [
            f"rule CDB_{rule_name}_Artifacts {{",
            "    meta:",
            f'        description = "Detects artifacts for: {safe}"',
            '        author = "CyberDudeBivash GOC (Automated)"',
            f'        date = "{date_str}"',
            f'        reference = "https://intel.cyberdudebivash.com"',
            f'        severity = "{item.get("severity", "HIGH")}"',
            f'        stix_id = "{stix_id}"',
            "    strings:",
            strings_block,
            "    condition:",
            "        any of ($art_*)",
            "}", ""
        ]

    if hashes or md5s:
        hash_meta = "\n".join(
            [f'        // sha256: "{h}"' for h in hashes] +
            [f'        // md5   : "{h}"' for h in md5s]
        )
        lines += [
            f"// Hash Reference — import directly into EDR hash-blocking",
            f"rule CDB_{rule_name}_Hashes {{",
            "    meta:",
            f'        description = "Hash IOCs for: {safe} — use EDR to block"',
            hash_meta,
            "    strings:",
            '        $ref = "CDB_SENTINEL_HASH_REFERENCE" ascii',
            "    condition:",
            "        false // Reference only — block hashes via EDR directly",
            "}", ""
        ]

    if not artifacts and not hashes and not md5s:
        # Behavioral YARA fallback
        if scenario == "ransomware":
            lines += [
                f"rule CDB_{rule_name}_Ransomware {{",
                "    meta:",
                f'        description = "Behavioral ransomware detection for: {safe}"',
                '        author = "CyberDudeBivash GOC (Automated)"',
                f'        date = "{date_str}"',
                "    strings:",
                '        $vss1 = "vssadmin delete shadows" ascii wide nocase',
                '        $vss2 = "Delete Shadows /All" ascii wide nocase',
                '        $enc1 = ".encrypted" ascii wide nocase',
                '        $enc2 = ".locked" ascii wide nocase',
                '        $note = "HOW_TO_DECRYPT" ascii wide nocase',
                "    condition:",
                "        any of ($vss*) or 2 of ($enc*) or any of ($note*)",
                "}", ""
            ]
        elif scenario in ("xss", "rce"):
            lines += [
                f"rule CDB_{rule_name}_WebExploit {{",
                "    meta:",
                f'        description = "Web exploit payload detection for: {safe}"',
                '        author = "CyberDudeBivash GOC (Automated)"',
                f'        date = "{date_str}"',
                "    strings:",
                '        $xss1 = "<script>alert(" ascii wide nocase',
                '        $xss2 = "javascript:eval(" ascii wide nocase',
                '        $xss3 = "onerror=alert(" ascii wide nocase',
                '        $rce1 = "/bin/bash" ascii',
                '        $rce2 = "cmd.exe /c" ascii wide nocase',
                "    condition:",
                "        any of them",
                "}", ""
            ]
        else:
            lines += [
                f"rule CDB_{rule_name}_Generic {{",
                "    meta:",
                f'        description = "Generic behavioral detection for: {safe}"',
                '        author = "CyberDudeBivash GOC (Automated)"',
                f'        date = "{date_str}"',
                '        reference = "https://intel.cyberdudebivash.com"',
                "    strings:",
                '        $ps_enc = "powershell -enc" ascii wide nocase',
                '        $ps_iex = "IEX(" ascii wide nocase',
                '        $dl     = "DownloadFile" ascii wide nocase',
                '        $wc     = "WebClient" ascii wide nocase',
                "    condition:",
                "        2 of them",
                "}", ""
            ]

    (pack_dir / "detection_yara.yar").write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────────────────────────────
# KQL
# ─────────────────────────────────────────────
def generate_kql_rule(item: Dict, pack_dir: Path):
    title    = item.get("title", "Unknown")
    safe     = _safe_t(title)
    scenario = _detect_scenario(title)
    risk     = item.get("risk_score", 5.0)
    sev      = item.get("severity", "HIGH")
    cves     = ", ".join(item.get("cves") or []) or "N/A"
    ts       = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    indicators = item.get("indicators", [])
    ips     = [i["value"] for i in indicators if i.get("type") in ("ipv4","ip")][:10]
    domains = [i["value"] for i in indicators if i.get("type") == "domain"][:10]
    hashes  = [i["value"] for i in indicators if i.get("type") in ("sha256","md5")][:8]

    lines = [
        "// ================================================================",
        f"// CyberDudeBivash SENTINEL APEX v20.0 — Microsoft Sentinel KQL",
        f"// Threat  : {safe}",
        f"// Scenario: {scenario.upper()} | CVEs: {cves}",
        f"// Generated: {ts}",
        "// Import into: Sentinel → Analytics → + Create → Scheduled Query",
        "// ================================================================", ""
    ]

    if ips or domains:
        ip_list  = ", ".join(f'"{v}"' for v in ips)  or '""'
        dom_list = ", ".join(f'"{v}"' for v in domains) or '""'
        lines += [
            "// Query 1: Network IOC Detection",
            f"let MaliciousIPs = dynamic([{ip_list}]);",
            f"let MaliciousDomains = dynamic([{dom_list}]);",
            "union",
            "(",
            "    DnsEvents | where TimeGenerated > ago(24h)",
            "    | where Name has_any (MaliciousDomains)",
            "    | extend AlertType = 'Malicious DNS Query', Indicator = Name",
            "),",
            "(",
            "    NetworkCommunicationEvents | where TimeGenerated > ago(24h)",
            "    | where RemoteIP has_any (MaliciousIPs) or RemoteUrl has_any (MaliciousDomains)",
            "    | extend AlertType = 'Malicious Connection', Indicator = RemoteIP",
            ")",
            "| summarize Count=count(), Hosts=make_set(Computer) by AlertType, Indicator",
            f'| extend ThreatName="{safe}", RiskScore={risk}, Severity="{sev}"', ""
        ]

    if hashes:
        hash_list = ", ".join(f'"{h}"' for h in hashes)
        lines += [
            "// Query 2: File Hash Detection",
            f"let MaliciousHashes = dynamic([{hash_list}]);",
            "DeviceFileEvents | where TimeGenerated > ago(7d)",
            "| where SHA256 has_any (MaliciousHashes) or MD5 has_any (MaliciousHashes)",
            f'| extend ThreatName="{safe}", Severity="CRITICAL"', ""
        ]

    if scenario == "ransomware":
        lines += [
            "// Query 3: Ransomware VSS Deletion",
            "SecurityEvent | where TimeGenerated > ago(4h)",
            "| where EventID == 4688",
            "| where CommandLine has_any ('vssadmin delete shadows', 'wbadmin delete catalog', 'bcdedit /set recoveryenabled')",
            f'| extend ThreatName="{safe}", Severity="CRITICAL"', ""
        ]
    elif scenario in ("xss", "rce", "vulnerability"):
        lines += [
            f"// Query 3: Web Exploit / CVE Detection ({cves})",
            "W3CIISLog | where TimeGenerated > ago(24h)",
            "| where csUriStem has_any ('<script>', 'javascript:', 'onerror=', 'UNION+SELECT', '../../')",
            f'| extend ThreatName="{safe}", CVEs="{cves}"',
            "| summarize Attempts=count() by csUriStem, cIP", ""
        ]
    elif scenario == "apt":
        lines += [
            "// Query 3: APT Credential Theft",
            "SecurityEvent | where TimeGenerated > ago(48h)",
            "| where EventID == 4688",
            "| where CommandLine has_any ('mimikatz', 'sekurlsa', 'lsadump', 'dcsync')",
            f'| extend ThreatName="{safe}", Severity="CRITICAL"', ""
        ]
    else:
        lines += [
            "// Query 3: Suspicious PowerShell",
            "SecurityEvent | where TimeGenerated > ago(24h)",
            "| where EventID == 4688",
            "| where CommandLine has_any ('-EncodedCommand', '-enc', 'IEX(', 'Invoke-Expression', 'DownloadFile')",
            f'| extend ThreatName="{safe}", Severity="{sev}"', ""
        ]

    (pack_dir / "detection_kql.txt").write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────────────────────────────
# SPL
# ─────────────────────────────────────────────
def generate_spl_rule(item: Dict, pack_dir: Path):
    title    = item.get("title", "Unknown")
    safe     = _safe_t(title)
    scenario = _detect_scenario(title)
    risk     = item.get("risk_score", 5.0)
    sev      = item.get("severity", "HIGH")
    ts       = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    indicators = item.get("indicators", [])
    ips     = [i["value"] for i in indicators if i.get("type") in ("ipv4","ip")][:10]
    domains = [i["value"] for i in indicators if i.get("type") == "domain"][:10]
    hashes  = [i["value"] for i in indicators if i.get("type") in ("sha256","md5")][:8]

    lines = [
        f"# CyberDudeBivash SENTINEL APEX v20.0 — Splunk SPL",
        f"# Threat  : {safe}",
        f"# Scenario: {scenario.upper()}",
        f"# Generated: {ts}",
        "# Import: Splunk Enterprise Security → Correlation Searches", ""
    ]

    if ips or domains:
        ip_or   = " OR ".join(f'dest="{v}"' for v in ips)   or 'dest="NONE"'
        dom_or  = " OR ".join(f'dest="{v}"' for v in domains) or 'dest="NONE"'
        lines += [
            f"| Network IOC Detection",
            f"index=network sourcetype=firewall ({ip_or} OR {dom_or})",
            "| stats count by src, dest, action, app",
            f'| eval ThreatName="{safe}", RiskScore={risk}', ""
        ]

    if hashes:
        hash_or = " OR ".join(f'FileHash="{h}"' for h in hashes)
        lines += [
            "| File Hash Detection",
            f"index=endpoint sourcetype=sysmon EventCode=1 ({hash_or})",
            f'| stats count by Computer, User, CommandLine, FileHash | eval ThreatName="{safe}"', ""
        ]

    if scenario == "ransomware":
        lines += [
            "| Ransomware VSS Deletion",
            'index=windows sourcetype=WinEventLog:Security EventCode=4688',
            '(CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wbadmin*delete*catalog*")',
            f'| stats count by host, user, CommandLine | eval ThreatName="{safe}", Severity="CRITICAL"', ""
        ]
    elif scenario in ("xss", "rce", "vulnerability"):
        lines += [
            "| Web Exploit Detection",
            "index=web sourcetype=iis OR sourcetype=apache:access",
            '(uri_query="*<script>*" OR uri_query="*UNION+SELECT*" OR uri_query="*../../*")',
            f'| stats count by src_ip, uri_path, status | eval ThreatName="{safe}"', ""
        ]
    else:
        lines += [
            "| Suspicious PowerShell",
            'index=windows sourcetype=WinEventLog:Security EventCode=4688',
            '(CommandLine="-EncodedCommand" OR CommandLine="IEX(" OR CommandLine="DownloadFile")',
            f'| stats count by host, user, CommandLine | eval ThreatName="{safe}"', ""
        ]

    (pack_dir / "detection_spl.txt").write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────────────────────────────
# METADATA
# ─────────────────────────────────────────────
def generate_metadata(item: Dict, pack_dir: Path):
    meta = {
        "title": item.get("title"),
        "stix_id": item.get("stix_id"),
        "risk_score": item.get("risk_score"),
        "severity": item.get("severity"),
        "confidence_score": item.get("confidence_score", item.get("confidence")),
        "tlp_label": item.get("tlp_label", "TLP:GREEN"),
        "cvss_score": item.get("cvss_score"),
        "epss_score": item.get("epss_score"),
        "kev_present": item.get("kev_present", False),
        "cves": item.get("cves", []),
        "mitre_tactics": item.get("mitre_tactics", []),
        "actor_tag": item.get("actor_tag", "UNC-CDB-99"),
        "feed_source": item.get("feed_source"),
        "blog_url": item.get("blog_url"),
        "generated_utc": datetime.utcnow().isoformat(),
        "source": "CyberDudeBivash SENTINEL APEX v20.0",
        "platform": "https://intel.cyberdudebivash.com",
    }
    with (pack_dir / "metadata.json").open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# ─────────────────────────────────────────────
# README
# ─────────────────────────────────────────────
def generate_readme(item: Dict, pack_dir: Path):
    title    = item.get("title", "Unknown")
    stix_id  = item.get("stix_id", "unknown")
    risk     = item.get("risk_score", 0)
    sev      = item.get("severity", "UNKNOWN")
    tlp      = item.get("tlp_label", "TLP:GREEN")
    cves     = ", ".join(item.get("cves") or []) or "None identified"
    blog_url = item.get("blog_url", "https://cyberbivash.blogspot.com")
    scenario = _detect_scenario(title)
    ioc_counts = item.get("ioc_counts", {})
    ioc_sum  = " | ".join(f"{k}: {v}" for k, v in ioc_counts.items() if v > 0) or "See ioc_feed.csv"

    content = f"""
CyberDudeBivash SENTINEL APEX v20.0 — Detection Pack
======================================================

THREAT  : {title}
STIX ID : {stix_id}
SCENARIO: {scenario.upper()}
RISK    : {risk}/10  |  SEVERITY: {sev}  |  TLP: {tlp}
CVEs    : {cves}
IOCs    : {ioc_sum}
REPORT  : {blog_url}
PLATFORM: https://intel.cyberdudebivash.com

PACK CONTENTS
─────────────
  ioc_feed.csv          IOC indicators (IPs, domains, hashes, CVEs)
  detection_sigma.yml   Sigma rules — real IOC + scenario-specific behavioral
  detection_yara.yar    YARA rules — file/memory/EDR scanning
  detection_kql.txt     Microsoft Sentinel KQL Analytics queries
  detection_spl.txt     Splunk SPL Correlation Search queries
  metadata.json         CVSS, EPSS, KEV, MITRE, TLP metadata
  README.txt            This file

DEPLOYMENT
──────────
  Sigma → sigma-cli: sigma convert -t splunk detection_sigma.yml
  YARA  → EDR (CrowdStrike, Defender ATP, Carbon Black)
  KQL   → Sentinel → Analytics → + Create → Scheduled Query
  SPL   → Splunk ES → Correlation Searches → New

OPERATOR NOTES
──────────────
  1. Block all IPs/domains from ioc_feed.csv at perimeter firewall
  2. Import Sigma via sigma-cli or Uncoder.io for your SIEM
  3. Deploy YARA in EDR for real-time and retro file scanning
  4. Run KQL/SPL for 90-day retrospective threat hunt
  5. Check metadata.json for CVSS/EPSS to prioritize patches

LICENSE  Enterprise Defensive Use Only
SUPPORT  bivash@cyberdudebivash.com | +91 8179881447
"""
    (pack_dir / "README.txt").write_text(content, encoding="utf-8")


# ─────────────────────────────────────────────
# ZIP
# ─────────────────────────────────────────────
def zip_pack(stix_id: str, pack_dir: Path) -> Path:
    zip_path = OUTPUT_DIR / f"{stix_id}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for file in pack_dir.iterdir():
            if file.is_file():
                z.write(file, file.name)
    return zip_path


# ─────────────────────────────────────────────
# ENTRY POINTS
# ─────────────────────────────────────────────
def build_latest_pack() -> Optional[Path]:
    """Build detection pack for latest manifest entry. Returns zip path or None."""
    ensure_directory(OUTPUT_DIR)
    manifest = load_manifest()
    if not manifest:
        print("Manifest empty.")
        return None
    latest  = manifest[-1]
    stix_id = latest.get("stix_id")
    if not stix_id:
        raise ValueError("Missing STIX ID in manifest.")
    if already_built(stix_id):
        print(f"Already built: {stix_id}")
        return OUTPUT_DIR / f"{stix_id}.zip"
    pack_dir = OUTPUT_DIR / stix_id
    ensure_directory(pack_dir)
    print(f"Building: {latest.get('title','?')} | Scenario: {_detect_scenario(latest.get('title',''))}")
    generate_ioc_csv(latest, pack_dir)
    generate_sigma_rule(latest, pack_dir)
    generate_yara_rule(latest, pack_dir)
    generate_kql_rule(latest, pack_dir)
    generate_spl_rule(latest, pack_dir)
    generate_metadata(latest, pack_dir)
    generate_readme(latest, pack_dir)
    zip_path = zip_pack(stix_id, pack_dir)
    print(f"✅ Pack: {zip_path}")
    return zip_path


def build_pack_for_item(item: Dict) -> Optional[Path]:
    """Build a detection pack for a specific manifest item dict. Used by pipeline."""
    ensure_directory(OUTPUT_DIR)
    stix_id = item.get("stix_id")
    if not stix_id:
        return None
    if already_built(stix_id):
        return OUTPUT_DIR / f"{stix_id}.zip"
    pack_dir = OUTPUT_DIR / stix_id
    ensure_directory(pack_dir)
    generate_ioc_csv(item, pack_dir)
    generate_sigma_rule(item, pack_dir)
    generate_yara_rule(item, pack_dir)
    generate_kql_rule(item, pack_dir)
    generate_spl_rule(item, pack_dir)
    generate_metadata(item, pack_dir)
    generate_readme(item, pack_dir)
    return zip_pack(stix_id, pack_dir)


if __name__ == "__main__":
    build_latest_pack()
