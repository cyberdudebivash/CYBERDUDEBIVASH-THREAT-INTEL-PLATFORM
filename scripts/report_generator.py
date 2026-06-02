#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — God Mode Report Generator
===========================================================
Version : v161.x
Purpose : Generate 20-section enterprise-grade HTML Tactical Dossiers for every
          intel advisory. God Mode template engine with:
            - MITRE ATT&CK v15 technique lookup (ID → name + tactic)
            - CVSS 3.1 vector string parser and component display
            - Vulnerability-class router (SQLi, path traversal, RCE, auth bypass, …)
            - Detection rule generators (Sigma, KQL, SPL) per vuln class
            - Financial impact (FAIR model) per severity
            - Regulatory compliance mapping (GDPR, PCI-DSS, NIS2, SOX, HIPAA)
            - Production IOC enrichment based on CVE class

Contract (unchanged from v134):
  generate_report(entry, stix_bundle_path) -> (success: bool, path_or_error: str)
  generate_reports_from_manifest(manifest_path, reports_base, skip_existing) -> dict
  Output: reports/{YYYY}/{MM}/{intel_id}.html
  Never raises — all exceptions caught, logged, returned as (False, msg)

Standalone usage:
  python3 scripts/report_generator.py --manifest data/stix/feed_manifest.json
  python3 scripts/report_generator.py --entry '{"id":"intel--abc","title":"Test"}'
  python3 scripts/report_generator.py --force  (re-generate existing reports)
"""
from __future__ import annotations

import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import html as _html
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-REPORT-GEN")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

REPORTS_BASE  = Path("reports")
PLATFORM_NAME = "CyberDudeBivash SENTINEL APEX"
PLATFORM_URL  = "https://intel.cyberdudebivash.com"
GUMROAD_URL   = "https://cyberdudebivash.gumroad.com/?utm_source=report&utm_medium=cta"

_SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#22c55e",
    "INFO":     "#3b82f6",
    "UNKNOWN":  "#6b7280",
}

# ─────────────────────────────────────────────────────────────────────────────
# GOD MODE QUALITY GATE CONSTANTS (v161.x)
# God mode reports must exceed these thresholds.
# Pipeline-generated placeholder reports (< threshold) are flagged in logs.
# Protected report IDs that must never be overwritten by the pipeline:
# ─────────────────────────────────────────────────────────────────────────────
GODMODE_MIN_SIZE_BYTES    = 60_000       # 60 KB minimum for god mode quality
GODMODE_MIN_SECTIONS      = 18           # Minimum section count (allow up to 20)
GODMODE_PROTECTED_IDS     = frozenset([  # These reports are operator-curated
    "intel--c687f56fd93c6ea6d1e3dd6a",   # CVE-2026-42208 LiteLLM CRITICAL 9.1
    "intel--1e41dd3a24f78d6ae239f84a",   # CVE-2026-42274 Heimdall HIGH 8.2
])

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK v15 LOOKUP TABLE
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_TECHNIQUES: Dict[str, Dict[str, str]] = {
    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application",      "tactic": "Initial Access",               "color": "#dc2626"},
    "T1133": {"name": "External Remote Services",               "tactic": "Initial Access / Persistence",  "color": "#dc2626"},
    "T1566": {"name": "Phishing",                               "tactic": "Initial Access",               "color": "#dc2626"},
    "T1566.001": {"name": "Spearphishing Attachment",           "tactic": "Initial Access",               "color": "#dc2626"},
    "T1566.002": {"name": "Spearphishing Link",                 "tactic": "Initial Access",               "color": "#dc2626"},
    "T1195": {"name": "Supply Chain Compromise",                "tactic": "Initial Access",               "color": "#dc2626"},
    "T1078": {"name": "Valid Accounts",                         "tactic": "Defense Evasion / Persistence", "color": "#ea580c"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter",      "tactic": "Execution",                    "color": "#f59e0b"},
    "T1059.001": {"name": "PowerShell",                         "tactic": "Execution",                    "color": "#f59e0b"},
    "T1059.003": {"name": "Windows Command Shell",              "tactic": "Execution",                    "color": "#f59e0b"},
    "T1059.006": {"name": "Python",                             "tactic": "Execution",                    "color": "#f59e0b"},
    "T1059.007": {"name": "JavaScript",                         "tactic": "Execution",                    "color": "#f59e0b"},
    "T1203": {"name": "Exploitation for Client Execution",      "tactic": "Execution",                    "color": "#f59e0b"},
    "T1204": {"name": "User Execution",                         "tactic": "Execution",                    "color": "#f59e0b"},
    "T1053": {"name": "Scheduled Task/Job",                     "tactic": "Persistence / Execution",      "color": "#f59e0b"},
    # Persistence
    "T1098": {"name": "Account Manipulation",                   "tactic": "Persistence",                  "color": "#8b5cf6"},
    "T1543": {"name": "Create or Modify System Process",        "tactic": "Persistence",                  "color": "#8b5cf6"},
    "T1546": {"name": "Event Triggered Execution",              "tactic": "Persistence",                  "color": "#8b5cf6"},
    "T1136": {"name": "Create Account",                         "tactic": "Persistence",                  "color": "#8b5cf6"},
    # Privilege Escalation
    "T1055": {"name": "Process Injection",                      "tactic": "Privilege Escalation",         "color": "#ec4899"},
    "T1068": {"name": "Exploitation for Privilege Escalation",  "tactic": "Privilege Escalation",         "color": "#ec4899"},
    "T1548": {"name": "Abuse Elevation Control Mechanism",      "tactic": "Privilege Escalation",         "color": "#ec4899"},
    # Defense Evasion
    "T1027": {"name": "Obfuscated Files or Information",        "tactic": "Defense Evasion",              "color": "#06b6d4"},
    "T1036": {"name": "Masquerading",                           "tactic": "Defense Evasion",              "color": "#06b6d4"},
    "T1562": {"name": "Impair Defenses",                        "tactic": "Defense Evasion",              "color": "#06b6d4"},
    "T1070": {"name": "Indicator Removal",                      "tactic": "Defense Evasion",              "color": "#06b6d4"},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping",                  "tactic": "Credential Access",            "color": "#f97316"},
    "T1110": {"name": "Brute Force",                            "tactic": "Credential Access",            "color": "#f97316"},
    "T1552": {"name": "Unsecured Credentials",                  "tactic": "Credential Access",            "color": "#f97316"},
    "T1555": {"name": "Credentials from Password Stores",       "tactic": "Credential Access",            "color": "#f97316"},
    "T1539": {"name": "Steal Web Session Cookie",               "tactic": "Credential Access",            "color": "#f97316"},
    # Discovery
    "T1046": {"name": "Network Service Discovery",              "tactic": "Discovery",                    "color": "#22c55e"},
    "T1083": {"name": "File and Directory Discovery",           "tactic": "Discovery",                    "color": "#22c55e"},
    "T1087": {"name": "Account Discovery",                      "tactic": "Discovery",                    "color": "#22c55e"},
    "T1082": {"name": "System Information Discovery",           "tactic": "Discovery",                    "color": "#22c55e"},
    "T1018": {"name": "Remote System Discovery",                "tactic": "Discovery",                    "color": "#22c55e"},
    # Lateral Movement
    "T1021": {"name": "Remote Services",                        "tactic": "Lateral Movement",             "color": "#0ea5e9"},
    "T1021.001": {"name": "Remote Desktop Protocol",            "tactic": "Lateral Movement",             "color": "#0ea5e9"},
    "T1021.006": {"name": "Windows Remote Management",          "tactic": "Lateral Movement",             "color": "#0ea5e9"},
    # Collection
    "T1213": {"name": "Data from Information Repositories",     "tactic": "Collection",                   "color": "#a78bfa"},
    "T1005": {"name": "Data from Local System",                 "tactic": "Collection",                   "color": "#a78bfa"},
    "T1074": {"name": "Data Staged",                            "tactic": "Collection",                   "color": "#a78bfa"},
    "T1560": {"name": "Archive Collected Data",                 "tactic": "Collection",                   "color": "#a78bfa"},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol",             "tactic": "Command and Control",          "color": "#64748b"},
    "T1105": {"name": "Ingress Tool Transfer",                  "tactic": "Command and Control",          "color": "#64748b"},
    "T1132": {"name": "Data Encoding",                          "tactic": "Command and Control",          "color": "#64748b"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel",           "tactic": "Exfiltration",                 "color": "#fb923c"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",                 "color": "#fb923c"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact",              "tactic": "Impact",                       "color": "#ef4444"},
    "T1489": {"name": "Service Stop",                           "tactic": "Impact",                       "color": "#ef4444"},
    "T1485": {"name": "Data Destruction",                       "tactic": "Impact",                       "color": "#ef4444"},
    "T1499": {"name": "Endpoint Denial of Service",             "tactic": "Impact",                       "color": "#ef4444"},
}


def _resolve_technique(tech_raw) -> Dict[str, str]:
    """Resolve technique string OR dict to {id, name, tactic, color}.

    Handles both legacy string format ('T1059') and enriched dict format
    ({'id': 'T1059', 'name': 'Command and Scripting Interpreter', ...})
    so that mixed-format mitre_tactics arrays never cause AttributeError.
    """
    # ── Dict path: already-resolved technique object ──────────────────────
    if isinstance(tech_raw, dict):
        tid = str(
            tech_raw.get("id") or
            tech_raw.get("technique_id") or
            tech_raw.get("technique") or ""
        ).upper().strip()
        # If we have a known TID, return the canonical entry (highest fidelity)
        if tid and tid in ATTACK_TECHNIQUES:
            return {"id": tid, **ATTACK_TECHNIQUES[tid]}
        # Fall back to whatever the dict contains
        name   = str(tech_raw.get("name") or tech_raw.get("technique_name") or tid or "Unknown")
        tactic = str(tech_raw.get("tactic") or tech_raw.get("tactic_name") or "Unknown")
        color  = str(tech_raw.get("color") or "#6b7280")
        return {"id": tid, "name": name, "tactic": tactic, "color": color}

    # ── String path: original behavior ────────────────────────────────────
    t = str(tech_raw).strip()
    if t.upper() in ATTACK_TECHNIQUES:
        info = ATTACK_TECHNIQUES[t.upper()]
        return {"id": t.upper(), **info}
    m = re.search(r'\b(T\d{4}(?:\.\d{3})?)\b', t, re.IGNORECASE)
    if m:
        tid = m.group(1).upper()
        if tid in ATTACK_TECHNIQUES:
            return {"id": tid, **ATTACK_TECHNIQUES[tid]}
        return {"id": tid, "name": t, "tactic": "Unknown", "color": "#6b7280"}
    for tid, info in ATTACK_TECHNIQUES.items():
        if info["name"].lower() in t.lower() or t.lower() in info["name"].lower():
            return {"id": tid, **info}
    return {"id": "", "name": t or "Unknown", "tactic": "Unknown", "color": "#6b7280"}


# ─────────────────────────────────────────────────────────────────────────────
# CVSS 3.1 VECTOR PARSER
# ─────────────────────────────────────────────────────────────────────────────

_CVSS_DECODE = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}
_CVSS_NAMES = {
    "AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required",
    "UI": "User Interaction", "S": "Scope",
    "C": "Confidentiality Impact", "I": "Integrity Impact", "A": "Availability Impact",
}
_CVSS_VAL_COLOR = {
    "Network": "#dc2626", "None": "#dc2626", "Low": "#f59e0b",
    "High": "#dc2626", "Adjacent": "#f59e0b", "Local": "#22c55e",
    "Physical": "#22c55e", "Required": "#22c55e",
    "Unchanged": "#22c55e", "Changed": "#ea580c",
}


def _parse_cvss_vector(vector_str: str) -> Optional[Dict[str, str]]:
    if not vector_str:
        return None
    raw = re.sub(r'^CVSS:[0-9.]+/', '', vector_str.strip())
    result: Dict[str, str] = {}
    for part in raw.split('/'):
        if ':' in part:
            k, v = part.split(':', 1)
            k, v = k.upper(), v.upper()
            if k in _CVSS_DECODE and v in _CVSS_DECODE[k]:
                result[k] = _CVSS_DECODE[k][v]
    return result if result else None


def _cvss_rows_html(components: Dict[str, str]) -> str:
    rows = []
    for key, full_name in _CVSS_NAMES.items():
        val = components.get(key, "—")
        col = _CVSS_VAL_COLOR.get(val, "#8b949e")
        rows.append(
            f'<tr><td class="meta-label" style="width:180px;">{_esc(full_name)}</td>'
            f'<td><span style="color:{col};font-weight:600;">{_esc(val)}</span></td></tr>'
        )
    return "".join(rows)


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY CLASS ROUTER
# ─────────────────────────────────────────────────────────────────────────────

_VULN_PATTERNS: Dict[str, List[str]] = {
    "sql_injection":    ["sql injection", "sqli", "cwe-89", "sql query", "union select", "blind sql"],
    "path_traversal":  ["path traversal", "directory traversal", "cwe-22", "cwe-863",
                         "path normalization", "dot-dot-slash", "../", "%2f", "%2e", "normalization mismatch"],
    "rce":             ["remote code execution", "rce", "command injection", "code injection",
                         "cwe-78", "cwe-94", "shell injection", "arbitrary code"],
    "auth_bypass":     ["authentication bypass", "auth bypass", "authorization bypass", "cwe-306",
                         "missing auth", "broken auth", "unauthenticated", "authentication flaw"],
    "xss":             ["cross-site scripting", "xss", "cwe-79", "reflected xss", "stored xss"],
    "ssrf":            ["server-side request forgery", "ssrf", "cwe-918", "internal request"],
    "deserialization": ["deserialization", "insecure deserialization", "cwe-502", "object injection"],
    "privesc":         ["privilege escalation", "local privilege", "sudo", "cwe-269", "privesc"],
    "info_disclosure": ["information disclosure", "information leakage", "cwe-200", "cwe-201",
                         "sensitive data exposure", "data leak"],
    "dos":             ["denial of service", "dos", "memory exhaustion", "cwe-400"],
    "mem_corruption":  ["buffer overflow", "use-after-free", "heap overflow", "stack overflow",
                         "cwe-119", "cwe-120", "cwe-122", "cwe-416", "memory corruption"],
}

_VULN_CLASS_LABELS: Dict[str, str] = {
    "sql_injection":    "SQL Injection (CWE-89)",
    "path_traversal":  "Path Traversal / Authorization Bypass (CWE-22 / CWE-863)",
    "rce":             "Remote Code Execution (CWE-78 / CWE-94)",
    "auth_bypass":     "Authentication Bypass (CWE-306)",
    "xss":             "Cross-Site Scripting (CWE-79)",
    "ssrf":            "Server-Side Request Forgery (CWE-918)",
    "deserialization": "Insecure Deserialization (CWE-502)",
    "privesc":         "Privilege Escalation (CWE-269)",
    "info_disclosure": "Information Disclosure (CWE-200)",
    "dos":             "Denial of Service (CWE-400)",
    "mem_corruption":  "Memory Corruption (CWE-119 / CWE-416)",
    "generic":         "Unclassified Vulnerability",
}


def _detect_vuln_class(entry: Dict[str, Any]) -> str:
    haystack = " ".join([
        str(entry.get("title") or ""),
        str(entry.get("description") or entry.get("summary") or ""),
        str(entry.get("cwe") or ""),
        " ".join(entry.get("tags") or []),
        " ".join(entry.get("vulnerability_types") or []),
    ]).lower()
    for cls, patterns in _VULN_PATTERNS.items():
        if any(p in haystack for p in patterns):
            return cls
    return "generic"


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION RULE GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

def _gen_sigma_rule(entry: Dict[str, Any], vuln_class: str, cve_id: str) -> str:
    title     = entry.get("title", "Threat Advisory")
    severity  = entry.get("severity", "high").lower()
    today_str = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    sig_id    = f"cdb-{cve_id.lower().replace(':', '-')}-det"

    if vuln_class == "sql_injection":
        return (
            f"title: SENTINEL APEX — {title}\n"
            f"id: {sig_id}\n"
            f"status: experimental\n"
            f"description: |\n"
            f"  Detects SQL injection exploitation of {cve_id}.\n"
            f"  Targets HTTP Authorization header and URI query parameter injection.\n"
            f"references:\n"
            f"  - {PLATFORM_URL}\n"
            f"author: CyberDudeBivash SENTINEL APEX\n"
            f"date: {today_str}\n"
            f"tags:\n"
            f"  - attack.initial_access\n"
            f"  - attack.t1190\n"
            f"  - attack.credential_access\n"
            f"  - attack.t1552\n"
            f"logsource:\n"
            f"  category: webserver\n"
            f"detection:\n"
            f"  selection_uri:\n"
            f"    cs-uri-query|contains|any:\n"
            f"      - \"' OR \"\n"
            f"      - \"' OR 1=1\"\n"
            f"      - \"UNION SELECT\"\n"
            f"      - \"1=1--\"\n"
            f"      - \"';--\"\n"
            f"      - \"OR '1'='1\"\n"
            f"  selection_header:\n"
            f"    cs(Authorization)|contains|any:\n"
            f"      - \"' OR \"\n"
            f"      - \"UNION SELECT\"\n"
            f"      - \"1=1--\"\n"
            f"  condition: selection_uri OR selection_header\n"
            f"falsepositives:\n"
            f"  - Security testing / penetration testing\n"
            f"level: {severity}"
        )
    elif vuln_class == "path_traversal":
        return (
            f"title: SENTINEL APEX — {title}\n"
            f"id: {sig_id}\n"
            f"status: experimental\n"
            f"description: |\n"
            f"  Detects path normalization bypass attempts targeting {cve_id}.\n"
            f"  Percent-encoded slashes bypass auth middleware but resolve at runtime.\n"
            f"references:\n"
            f"  - {PLATFORM_URL}\n"
            f"author: CyberDudeBivash SENTINEL APEX\n"
            f"date: {today_str}\n"
            f"tags:\n"
            f"  - attack.initial_access\n"
            f"  - attack.t1190\n"
            f"  - attack.defense_evasion\n"
            f"  - attack.t1027\n"
            f"logsource:\n"
            f"  category: webserver\n"
            f"detection:\n"
            f"  selection_encoded:\n"
            f"    cs-uri-stem|contains|any:\n"
            f"      - \"%2f\"\n"
            f"      - \"%252f\"\n"
            f"      - \"%2e%2e\"\n"
            f"      - \"%252e\"\n"
            f"      - \"..%2f\"\n"
            f"      - \"%2f.%2f\"\n"
            f"    cs-uri-stem|contains:\n"
            f"      - \"admin\"\n"
            f"  selection_bypass:\n"
            f"    cs-uri-stem|contains|any:\n"
            f"      - \"%252f\"\n"
            f"      - \"%252e\"\n"
            f"    c-status: \"200\"\n"
            f"  condition: selection_encoded OR selection_bypass\n"
            f"falsepositives:\n"
            f"  - Security testing / penetration testing\n"
            f"level: {severity}"
        )
    elif vuln_class == "rce":
        return (
            f"title: SENTINEL APEX — {title}\n"
            f"id: {sig_id}\n"
            f"status: experimental\n"
            f"description: Detects RCE payload patterns in HTTP requests targeting {cve_id}.\n"
            f"references:\n"
            f"  - {PLATFORM_URL}\n"
            f"author: CyberDudeBivash SENTINEL APEX\n"
            f"date: {today_str}\n"
            f"tags:\n"
            f"  - attack.execution\n"
            f"  - attack.t1059\n"
            f"  - attack.initial_access\n"
            f"  - attack.t1190\n"
            f"logsource:\n"
            f"  category: webserver\n"
            f"detection:\n"
            f"  selection:\n"
            f"    cs-uri-query|contains|any:\n"
            f"      - \"cmd=\"\n"
            f"      - \"exec=\"\n"
            f"      - \"system(\"\n"
            f"      - \"passthru(\"\n"
            f"      - \"|id;\"\n"
            f"      - \"; whoami\"\n"
            f"      - \"$(id)\"\n"
            f"  condition: selection\n"
            f"falsepositives:\n"
            f"  - Security testing / penetration testing\n"
            f"level: critical"
        )
    elif vuln_class == "auth_bypass":
        return (
            f"title: SENTINEL APEX — {title}\n"
            f"id: {sig_id}\n"
            f"status: experimental\n"
            f"description: |\n"
            f"  Detects authentication bypass: HTTP 200 to admin endpoints\n"
            f"  from unauthenticated sessions exploiting {cve_id}.\n"
            f"references:\n"
            f"  - {PLATFORM_URL}\n"
            f"author: CyberDudeBivash SENTINEL APEX\n"
            f"date: {today_str}\n"
            f"tags:\n"
            f"  - attack.initial_access\n"
            f"  - attack.t1190\n"
            f"  - attack.defense_evasion\n"
            f"  - attack.t1078\n"
            f"logsource:\n"
            f"  category: webserver\n"
            f"detection:\n"
            f"  selection:\n"
            f"    cs-uri-stem|contains|any:\n"
            f"      - \"/admin\"\n"
            f"      - \"/dashboard\"\n"
            f"      - \"/manage\"\n"
            f"      - \"/settings\"\n"
            f"    c-status: \"200\"\n"
            f"  filter_session:\n"
            f"    cs(Cookie)|contains: \"session=\"\n"
            f"  condition: selection AND NOT filter_session\n"
            f"falsepositives:\n"
            f"  - Applications with session-less admin endpoints\n"
            f"level: {severity}"
        )
    else:
        return (
            f"title: SENTINEL APEX — {title}\n"
            f"id: {sig_id}\n"
            f"status: experimental\n"
            f"description: Detects exploitation attempts related to {cve_id}.\n"
            f"references:\n"
            f"  - {PLATFORM_URL}\n"
            f"author: CyberDudeBivash SENTINEL APEX\n"
            f"date: {today_str}\n"
            f"tags:\n"
            f"  - attack.initial_access\n"
            f"  - attack.t1190\n"
            f"logsource:\n"
            f"  category: webserver\n"
            f"detection:\n"
            f"  keywords:\n"
            f"    - \"{cve_id}\"\n"
            f"  condition: keywords\n"
            f"falsepositives:\n"
            f"  - Security testing / penetration testing\n"
            f"level: {severity}"
        )


def _gen_kql_query(entry: Dict[str, Any], vuln_class: str, cve_id: str) -> str:
    title   = entry.get("title", "Threat Advisory")
    cve_tag = cve_id.replace("-", "")

    if vuln_class == "sql_injection":
        return (
            f"// SENTINEL APEX — {title}\n"
            f"// {cve_id} | SQL Injection | Microsoft Sentinel KQL\n"
            f"let time_window = ago(24h);\n"
            f"let sqli_patterns = dynamic([\"' OR \", \"UNION SELECT\", \"1=1--\", \"OR '1'='1\", \"';--\", \"' OR 1\"]);\n"
            f"CommonSecurityLog\n"
            f"| where TimeGenerated > time_window\n"
            f"| where AdditionalExtensions has_any (sqli_patterns)\n"
            f"    or RequestURL has_any (sqli_patterns)\n"
            f"    or Message has_any (sqli_patterns)\n"
            f"| extend Rule = \"APEX-SQLI-{cve_tag}\",\n"
            f"         Severity = \"{entry.get('severity', 'HIGH')}\",\n"
            f"         AttackType = \"SQLInjection\"\n"
            f"| project TimeGenerated, DeviceVendor, DeviceProduct,\n"
            f"          SourceIP, DestinationHostName, RequestURL,\n"
            f"          AdditionalExtensions, Rule, Severity, AttackType\n"
            f"| order by TimeGenerated desc"
        )
    elif vuln_class == "path_traversal":
        return (
            f"// SENTINEL APEX — {title}\n"
            f"// {cve_id} | Path Traversal / Auth Bypass | Microsoft Sentinel KQL\n"
            f"let time_window = ago(24h);\n"
            f"let traversal_patterns = dynamic([\"%2f\", \"%252f\", \"%2e%2e\", \"%252e\", \"..%2f\"]);\n"
            f"let admin_paths = dynamic([\"/admin\", \"/dashboard\", \"/manage\", \"/settings\"]);\n"
            f"CommonSecurityLog\n"
            f"| where TimeGenerated > time_window\n"
            f"| where RequestURL has_any (traversal_patterns)\n"
            f"    and RequestURL has_any (admin_paths)\n"
            f"| extend Rule = \"APEX-TRAVERSAL-{cve_tag}\",\n"
            f"         Severity = \"{entry.get('severity', 'HIGH')}\",\n"
            f"         AttackType = \"PathTraversalBypass\"\n"
            f"| project TimeGenerated, SourceIP, RequestURL, RequestMethod,\n"
            f"          DeviceAction, Rule, Severity, AttackType\n"
            f"| order by TimeGenerated desc"
        )
    elif vuln_class == "rce":
        return (
            f"// SENTINEL APEX — {title}\n"
            f"// {cve_id} | Remote Code Execution | Microsoft Sentinel KQL\n"
            f"let time_window = ago(24h);\n"
            f"let rce_patterns = dynamic([\"cmd=\", \"exec=\", \"system(\", \"|id;\", \"; whoami\", \"$(id)\"]);\n"
            f"CommonSecurityLog\n"
            f"| where TimeGenerated > time_window\n"
            f"| where RequestURL has_any (rce_patterns)\n"
            f"    or AdditionalExtensions has_any (rce_patterns)\n"
            f"| extend Rule = \"APEX-RCE-{cve_tag}\", Severity = \"CRITICAL\", AttackType = \"RCE\"\n"
            f"| project TimeGenerated, SourceIP, RequestURL, RequestMethod,\n"
            f"          DeviceAction, Rule, Severity, AttackType\n"
            f"| order by TimeGenerated desc"
        )
    else:
        return (
            f"// SENTINEL APEX — {title}\n"
            f"// {cve_id} | Threat Advisory | Microsoft Sentinel KQL\n"
            f"let time_window = ago(24h);\n"
            f"SecurityAlert\n"
            f"| where TimeGenerated > time_window\n"
            f"| where Description has \"{cve_id}\"\n"
            f"    or AlertName has \"{cve_id}\"\n"
            f"    or ExtendedProperties has \"{cve_id}\"\n"
            f"| extend Rule = \"APEX-{cve_tag}\", Severity = \"{entry.get('severity', 'HIGH')}\"\n"
            f"| project TimeGenerated, AlertName, AlertSeverity, Entities, Description, Rule, Severity\n"
            f"| order by TimeGenerated desc"
        )


def _gen_spl_query(entry: Dict[str, Any], vuln_class: str, cve_id: str) -> str:
    title   = entry.get("title", "Threat Advisory")
    cve_tag = cve_id.replace("-", "")

    if vuln_class == "sql_injection":
        return (
            f"| comment \"SENTINEL APEX — {title} | {cve_id} | Splunk ES\"\n"
            f"index=web OR index=proxy sourcetype=access_combined OR sourcetype=nginx:access\n"
            f"earliest=-24h\n"
            f"| rex field=_raw \"Authorization:\\\\s+Bearer\\\\s+(?P<bearer_token>[^\\\\s\\\\r\\\\n]+)\"\n"
            f"| eval sqli_hit=if(\n"
            f"    match(cs_uri_query, \"(?i)(' OR |UNION SELECT|1=1--|OR '1'='1|';--)\") OR\n"
            f"    match(bearer_token, \"(?i)(' OR |UNION SELECT|1=1--)\"), 1, 0)\n"
            f"| where sqli_hit=1\n"
            f"| eval rule=\"APEX-SQLI-{cve_tag}\", severity=\"{entry.get('severity', 'HIGH')}\"\n"
            f"| stats count min(_time) as first_seen max(_time) as last_seen\n"
            f"    values(cs_uri_query) as payloads values(bearer_token) as tokens\n"
            f"    by c_ip, rule, severity\n"
            f"| convert timeformat=\"%Y-%m-%dT%H:%M:%SZ\" ctime(first_seen) ctime(last_seen)\n"
            f"| sort -count"
        )
    elif vuln_class == "path_traversal":
        return (
            f"| comment \"SENTINEL APEX — {title} | {cve_id} | Splunk ES\"\n"
            f"index=web OR index=proxy sourcetype=access_combined OR sourcetype=nginx:access\n"
            f"earliest=-24h\n"
            f"| eval traversal_hit=if(\n"
            f"    match(cs_uri_stem, \"(?i)(%252f|%2f\\\\.%2f|%252e|\\\\.\\\\.\\\\.%2f)\") AND\n"
            f"    match(cs_uri_stem, \"(?i)(admin|dashboard|manage|settings)\"), 1, 0)\n"
            f"| where traversal_hit=1\n"
            f"| eval hunt_match=if(sc_status=\"200\" AND traversal_hit=1, \"CONFIRMED_BYPASS\", \"ATTEMPT\")\n"
            f"| eval rule=\"APEX-TRAVERSAL-{cve_tag}\", severity=\"{entry.get('severity', 'HIGH')}\"\n"
            f"| stats count min(_time) as first_seen max(_time) as last_seen\n"
            f"    values(cs_uri_stem) as paths values(sc_status) as codes\n"
            f"    by c_ip, hunt_match, rule, severity\n"
            f"| convert timeformat=\"%Y-%m-%dT%H:%M:%SZ\" ctime(first_seen) ctime(last_seen)\n"
            f"| sort -count"
        )
    else:
        escaped_cve = re.escape(cve_id)
        return (
            f"| comment \"SENTINEL APEX — {title} | {cve_id} | Splunk ES\"\n"
            f"index=web OR index=proxy OR index=network earliest=-24h\n"
            f"| eval threat_hit=if(match(_raw, \"(?i)({escaped_cve})\"), 1, 0)\n"
            f"| where threat_hit=1\n"
            f"| eval rule=\"APEX-{cve_tag}\", severity=\"{entry.get('severity', 'HIGH')}\"\n"
            f"| stats count min(_time) as first_seen max(_time) as last_seen\n"
            f"    by src_ip, dest_host, rule, severity\n"
            f"| convert timeformat=\"%Y-%m-%dT%H:%M:%SZ\" ctime(first_seen) ctime(last_seen)\n"
            f"| sort -count"
        )


# ─────────────────────────────────────────────────────────────────────────────
# FINANCIAL IMPACT (FAIR MODEL)
# ─────────────────────────────────────────────────────────────────────────────

_FINANCIAL_DATA: Dict[str, Dict[str, str]] = {
    "CRITICAL": {
        "range": "$2.4M — $12M", "median": "$5.8M", "regulatory": "$850K",
        "remediation": "$380K", "downtime": "$1.2M/day",
        "detail": (
            "Critical severity breaches trigger mandatory 72-hour regulatory disclosure (GDPR Art. 33), "
            "class action exposure, customer churn, and long-tail legal costs averaging 18-36 months post-incident."
        ),
    },
    "HIGH": {
        "range": "$800K — $4.5M", "median": "$1.8M", "regulatory": "$320K",
        "remediation": "$180K", "downtime": "$450K/day",
        "detail": (
            "High severity incidents activate IR retainers, forensic investigation (avg 47 days), "
            "credit monitoring for affected customers, and reputational damage impacting 12-18% of revenue."
        ),
    },
    "MEDIUM": {
        "range": "$150K — $900K", "median": "$380K", "regulatory": "$85K",
        "remediation": "$55K", "downtime": "$120K/day",
        "detail": (
            "Medium severity events require internal investigation, targeted customer notification, "
            "and control remediation. Average cost includes 340 hours of engineering time."
        ),
    },
    "LOW": {
        "range": "$20K — $180K", "median": "$60K", "regulatory": "N/A",
        "remediation": "$15K", "downtime": "$25K/day",
        "detail": (
            "Low severity findings require targeted patches and configuration hardening. "
            "Aggregated low-severity debt compounds to medium breach probability within 12 months."
        ),
    },
}


def _get_financial(severity: str) -> Dict[str, str]:
    return _FINANCIAL_DATA.get(severity.upper(), _FINANCIAL_DATA["MEDIUM"])


# ─────────────────────────────────────────────────────────────────────────────
# COMPLIANCE MAPPING
# ─────────────────────────────────────────────────────────────────────────────

_COMPLIANCE: Dict[str, List[Dict[str, str]]] = {
    "CRITICAL": [
        {"fw": "GDPR",          "ref": "Art. 33 / Art. 83(4)",  "color": "#dc2626",
         "obligation": "72-hour mandatory breach notification to DPA; fines up to 4% of global annual turnover"},
        {"fw": "PCI-DSS v4.0",  "ref": "Req. 6.3 / 6.4",       "color": "#dc2626",
         "obligation": "Critical patches within 1 month; compensating controls required during remediation window"},
        {"fw": "NIS2 Directive","ref": "Art. 23",               "color": "#dc2626",
         "obligation": "Early warning within 24h; full incident report within 72h for essential entities"},
        {"fw": "SOX / ICFR",   "ref": "Section 302 / 404",     "color": "#ea580c",
         "obligation": "Material cybersecurity weakness disclosure in 10-K/10-Q; CEO/CFO certification required"},
        {"fw": "HIPAA",         "ref": "45 CFR § 164.400",      "color": "#ea580c",
         "obligation": "Breach notification to HHS and affected individuals within 60 days; media notice if 500+ affected"},
        {"fw": "ISO 27001:2022","ref": "A.8.8 / A.5.29",       "color": "#f59e0b",
         "obligation": "Vulnerability management process; information security incident management documentation"},
    ],
    "HIGH": [
        {"fw": "GDPR",          "ref": "Art. 32 / Art. 33",    "color": "#ea580c",
         "obligation": "Implement appropriate technical measures; notify DPA if personal data affected"},
        {"fw": "PCI-DSS v4.0",  "ref": "Req. 6.3.3",           "color": "#ea580c",
         "obligation": "Security patches within 1 month of release; documented risk acceptance if deferred"},
        {"fw": "NIS2 Directive","ref": "Art. 21",              "color": "#ea580c",
         "obligation": "Risk management measures including vulnerability handling and disclosure policies"},
        {"fw": "NIST CSF 2.0",  "ref": "RS.MI / RC.RP",        "color": "#f59e0b",
         "obligation": "Incident mitigation and recovery planning; post-incident review mandatory"},
        {"fw": "ISO 27001:2022","ref": "A.8.8",                "color": "#f59e0b",
         "obligation": "Timely identification and remediation of technical vulnerabilities"},
    ],
    "MEDIUM": [
        {"fw": "PCI-DSS v4.0",  "ref": "Req. 6.3.3",           "color": "#f59e0b",
         "obligation": "Non-critical patches applied within 3 months"},
        {"fw": "NIST CSF 2.0",  "ref": "ID.RA / PR.PS",        "color": "#f59e0b",
         "obligation": "Vulnerability assessment and platform security policies"},
        {"fw": "ISO 27001:2022","ref": "A.8.8",                "color": "#f59e0b",
         "obligation": "Vulnerability management programme with documented remediation timelines"},
    ],
    "LOW": [
        {"fw": "ISO 27001:2022","ref": "A.8.8",                "color": "#22c55e",
         "obligation": "Track and remediate within standard 90-day patch cycle"},
        {"fw": "NIST CSF 2.0",  "ref": "ID.RA",                "color": "#22c55e",
         "obligation": "Include in regular vulnerability risk assessment"},
    ],
}


def _get_compliance(severity: str) -> List[Dict[str, str]]:
    return _COMPLIANCE.get(severity.upper(), _COMPLIANCE["MEDIUM"])


# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE PLAYBOOK
# ─────────────────────────────────────────────────────────────────────────────

def _gen_playbook(vuln_class: str, severity: str, product: str) -> Dict[str, List[str]]:
    pb: Dict[str, List[str]] = {
        "0_24h": [
            "Activate IR team; assign lead analyst and executive sponsor",
            f"Isolate or WAF-shield {product} instances exposed to internet",
            f"Enable verbose access logging on all {product} endpoints",
            "Pull last 72h of web server logs for forensic baselining",
            "Check threat intelligence feeds for IOC hits in your environment",
        ],
        "24_72h": [
            "Apply vendor patch or recommended mitigation",
            "Rotate all API keys, service account credentials, and session tokens",
            "Deploy detection rules (Sigma / KQL / SPL) from this dossier",
            "Conduct forensic timeline reconstruction for potential compromise window",
            "Notify relevant internal stakeholders and legal / compliance team",
        ],
        "7_day": [
            "Validate patch deployment across 100% of affected instances",
            "Conduct post-incident review and update runbooks",
            "Threat hunt for lateral movement or persistence artifacts",
            "Update asset inventory with patched version information",
            "Submit findings to internal risk register and CISO dashboard",
        ],
    }
    if vuln_class == "sql_injection":
        pb["0_24h"].insert(2, "Deploy WAF rule blocking SQLi patterns in Authorization header and request body")
        pb["0_24h"].insert(3, "Review database audit logs for anomalous SELECT / UNION queries")
        pb["24_72h"].insert(0, "Audit all database records for unauthorized access or data exfiltration indicators")
    elif vuln_class == "path_traversal":
        pb["0_24h"].insert(2, "Deploy WAF rule blocking percent-encoded path separators (%2f, %252f, %2e)")
        pb["0_24h"].insert(3, "Review logs for HTTP 200 responses to admin paths without session cookies")
        pb["24_72h"].insert(0, "Apply server-side path normalization before authorization check")
    elif vuln_class == "rce":
        pb["0_24h"].insert(2, "Consider taking vulnerable service offline or restricting to IP allowlist")
        pb["0_24h"].insert(3, "Scan for webshells and unauthorized processes spawned by application user")
        pb["24_72h"].insert(0, "Conduct full server forensic acquisition before applying patch")
    elif vuln_class == "auth_bypass":
        pb["0_24h"].insert(2, "Enforce multi-factor authentication on all administrative interfaces")
        pb["0_24h"].insert(3, "Audit all admin actions in the last 30 days for unauthorized activity")
    return pb


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _esc(s: Any) -> str:
    return _html.escape(str(s or ""), quote=True)


def _cve_from_entry(entry: Dict[str, Any]) -> str:
    for f in ("cve_id", "cve", "id"):
        v = str(entry.get(f) or "")
        m = re.search(r'CVE-\d{4}-\d+', v, re.IGNORECASE)
        if m:
            return m.group(0).upper()
    m2 = re.search(r'CVE-\d{4}-\d+', str(entry.get("title") or ""), re.IGNORECASE)
    return m2.group(0).upper() if m2 else "N/A"


# ─────────────────────────────────────────────────────────────────────────────
# GOD MODE HTML BUILDER — 15-SECTION ENTERPRISE DOSSIER
# ─────────────────────────────────────────────────────────────────────────────

def _build_html(
    entry: Dict[str, Any],
    stix_bundle_path: Optional[str],
    out_path: Path,
) -> str:
    # ── Extract fields ─────────────────────────────────────────────────────
    intel_id    = _esc(entry.get("id") or entry.get("stix_id") or "")
    title       = _esc(entry.get("title") or "Intel Advisory")

    # BUG-01 FIX: prefer apex_risk_label (computed by risk scoring engine) over raw severity label.
    # The raw `severity` field from the feed is the initial ingest label and is NEVER updated
    # by the APEX risk scoring engine.  apex_risk_label reflects CVSS + EPSS + KEV composite.
    severity    = str(
        entry.get("apex_risk_label") or
        entry.get("apex_risk_severity") or
        entry.get("severity") or
        "UNKNOWN"
    ).upper()

    # BUG-02 FIX: prefer apex_risk (evidence-weighted score) over legacy risk_score.
    risk_score  = float(
        entry.get("apex_risk") or
        entry.get("risk_score") or
        0.0
    )

    sev_color   = _SEV_COLOR.get(severity, "#6b7280")
    tlp         = _esc(entry.get("tlp") or entry.get("tlp_label") or "TLP:CLEAR")
    description = str(entry.get("description") or entry.get("summary") or
                      "Threat intelligence advisory generated by SENTINEL APEX.")
    actor_tag   = _esc(entry.get("actor_tag") or "UNC")
    feed_src    = _esc(entry.get("feed_source") or PLATFORM_NAME)
    source_url  = str(entry.get("source_url") or "")
    processed   = _esc(entry.get("processed_at") or entry.get("timestamp") or
                       datetime.now(timezone.utc).isoformat())

    # BUG-15 FIX: normalise confidence to 0-100 percentage scale.
    # enrich_feed_apex.py stores apex.confidence as a 0-1 fraction;
    # confidence_calibrator.py stores confidence_score as 0-100 integer.
    # We normalise both to the 0-100 scale for display.
    _raw_conf = (
        entry.get("confidence_score") or
        entry.get("confidence") or
        (entry.get("apex_ai") or {}).get("ai_confidence") or
        0.0
    )
    try:
        _conf_f = float(_raw_conf)
        confidence = _conf_f * 100.0 if _conf_f <= 1.0 and _conf_f > 0.0 else _conf_f
        confidence = max(5.0, min(100.0, confidence))
    except (ValueError, TypeError):
        confidence = 55.0
    # KEV floor: CISA KEV-confirmed advisories always have ≥75% confidence
    if entry.get("kev_present") or entry.get("kev") or entry.get("cisa_kev"):
        confidence = max(confidence, 75.0)

    # BUG-04 / BUG-05 FIX: broad CVSS field lookup — pipeline writes under multiple names.
    cvss_score  = (
        entry.get("cvss_score") or
        entry.get("cvss") or
        entry.get("cvss3") or
        entry.get("base_score") or
        entry.get("cvss_base_score") or
        (entry.get("apex_ai") or {}).get("cvss_score")
    )
    if cvss_score is not None:
        try:
            cvss_score = float(cvss_score) if float(cvss_score) > 0 else None
        except (ValueError, TypeError):
            cvss_score = None

    cvss_vector = str(entry.get("cvss_vector") or entry.get("cvss_v3_vector") or "")

    # BUG-04 FIX: broad EPSS field lookup; normalise to 0-100% display scale.
    _epss_raw = (
        entry.get("epss_score") or
        entry.get("epss") or
        entry.get("epss_30d") or
        (entry.get("apex_ai") or {}).get("epss_score")
    )
    epss = None
    if _epss_raw is not None:
        try:
            _epss_f = float(str(_epss_raw).rstrip("%"))
            # Normalise fraction (0-1) to percentage display (0-100)
            epss = round(_epss_f * 100.0 if _epss_f <= 1.0 else _epss_f, 2)
        except (ValueError, TypeError):
            epss = None

    kev         = bool(entry.get("kev_present") or entry.get("kev") or entry.get("cisa_kev"))
    cwe_raw     = str(entry.get("cwe") or "")
    patch_url   = str(entry.get("patch_url") or entry.get("fix_url") or "")
    affected_p  = entry.get("affected_products") or []
    affected_v  = entry.get("affected_versions") or []
    stix_url    = str(entry.get("stix_bundle_url") or "")
    tags_raw    = entry.get("tags") or []
    iocs_raw    = entry.get("iocs") or []
    mitre_raw   = entry.get("mitre_tactics") or entry.get("ttps") or []

    cve_id      = _cve_from_entry(entry)
    vuln_class  = _detect_vuln_class(entry)
    vuln_label  = _VULN_CLASS_LABELS.get(vuln_class, "Unclassified")
    product_1   = affected_p[0] if affected_p else "Affected Application"

    cvss_comp   = _parse_cvss_vector(cvss_vector)
    techniques  = [_resolve_technique(t) for t in mitre_raw[:10]]
    fin         = _get_financial(severity)
    compliance  = _get_compliance(severity)

    sigma = _gen_sigma_rule(entry, vuln_class, cve_id)
    kql   = _gen_kql_query(entry, vuln_class, cve_id)
    spl   = _gen_spl_query(entry, vuln_class, cve_id)
    pb    = _gen_playbook(vuln_class, severity, product_1)

    risk_pct      = min(100.0, max(0.0, risk_score * 10.0))
    # v166.3-FIX: use full relative path (year/month/file) not just parent.name (month only → 404)
    canonical_url = f"{PLATFORM_URL}/{out_path.as_posix().lstrip('/')}"

    # ── Section template helpers ───────────────────────────────────────────
    def sec(num: str, heading: str, body: str) -> str:
        return (
            '<div class="section">'
            '<div class="section-title">'
            f'<span class="sec-num">{_esc(num)}</span> {_esc(heading)}'
            '</div>'
            f'{body}'
            '</div>'
        )

    def mr(label: str, value_html: str) -> str:
        return (
            '<div class="meta-row">'
            f'<span class="meta-label">{_esc(label)}</span>'
            f'<span class="meta-value">{value_html}</span>'
            '</div>'
        )

    def cb(code: str, lang: str = "") -> str:
        lang_tag = f'<span class="code-lang">{_esc(lang)}</span>' if lang else ""
        return (
            '<div class="code-wrap">'
            f'{lang_tag}'
            f'<pre class="code-block">{_esc(code)}</pre>'
            '</div>'
        )

    def pblist(items: List[str]) -> str:
        li = "".join(f"<li>{_esc(i)}</li>" for i in items)
        return f'<ul class="pb-list">{li}</ul>'

    # ── 01 Executive Summary ───────────────────────────────────────────────
    # v161.x: NVD PRELIMINARY disclosure banner
    nvd_status = str(entry.get("nvd_status") or "").upper()
    nvd_disclosure = str(entry.get("nvd_disclosure") or "")
    _nvd_banner = ""
    if nvd_status == "PRELIMINARY":
        _nvd_banner = (
            '<div style="background:rgba(249,115,22,0.12);border:1px solid rgba(249,115,22,0.4);'
            'border-radius:4px;padding:12px 16px;margin-bottom:16px;display:flex;'
            'align-items:flex-start;gap:12px;">'
            '<span style="font-size:18px;flex-shrink:0;">⚠️</span>'
            '<div>'
            '<div style="font-family:var(--font-mono);font-size:10px;font-weight:700;'
            'color:#f97316;letter-spacing:2px;margin-bottom:4px;">NVD STATUS: PRELIMINARY — UNCONFIRMED</div>'
            f'<div style="font-size:12px;color:var(--text-muted);line-height:1.6;">{_esc(nvd_disclosure or "This CVE ID was not found in the NIST NVD database at time of enrichment. Intelligence is preliminary and unverified. CVSS severity is analyst-estimated.")}</div>'
            '</div></div>'
        )

    src_a = (
        f'<a href="{_esc(source_url)}" target="_blank" rel="noopener" class="src-link">'
        f'Source Article &#8599;</a>'
        if source_url else ""
    )
    s01 = sec("01", "Executive Summary", (
        _nvd_banner
        + f'<p class="body-text">{_esc(description)}</p>'
        '<div class="meta-grid" style="margin-top:18px;">'
        + mr("CVE / Advisory ID", f'<span class="mono">{_esc(cve_id)}</span>')
        + mr("Severity", f'<span class="badge sev-{severity.lower()}">{_esc(severity)}</span>')
        + mr("Risk Score", f'<span style="color:{sev_color};font-weight:700;font-family:var(--font-mono);">{risk_score:.1f} / 10</span>')
        + mr("NVD Status", f'<span class="mono" style="color:{"#f97316" if nvd_status == "PRELIMINARY" else "#00d4aa" if nvd_status == "CONFIRMED" else "#6b7280"};font-weight:700;">{nvd_status or "UNKNOWN"}</span>')
        + mr("Vulnerability Class", _esc(vuln_label))
        + mr("Threat Actor", f'<span class="mono">{_esc(actor_tag)}</span>')
        + mr("TLP Classification", f'<span class="badge badge-tlp">{_esc(tlp)}</span>')
        + '</div>'
        + (f'<div style="margin-top:12px;">{src_a}</div>' if src_a else "")
    ))

    # ── 02 Vulnerability Intelligence ──────────────────────────────────────
    # BUG-04 FIX: cvss_score already normalised above; display with one decimal.
    cvss_disp = f"{float(cvss_score):.1f}" if cvss_score is not None else "N/A"
    # BUG-03 FIX: epss is already in 0-100 display scale (normalised above).
    epss_disp = f"{float(epss):.2f}%" if epss is not None else "N/A"
    kev_color = "#ef4444" if kev else "#6b7280"
    vec_line  = (
        f'<div class="mono" style="color:#6b7280;font-size:10px;margin-top:4px;">{_esc(cvss_vector)}</div>'
        if cvss_vector else ""
    )
    comp_html = ""
    if cvss_comp:
        comp_html = (
            '<div style="margin-top:18px;">'
            '<div class="sub-title">CVSS 3.1 Vector Decomposition</div>'
            '<table class="score-table" style="margin-top:8px;"><tbody>'
            + _cvss_rows_html(cvss_comp)
            + '</tbody></table></div>'
        )
    cwe_line = (mr("CWE Reference", _esc(cwe_raw))
                if cwe_raw else "")
    s02 = sec("02", "Vulnerability Intelligence", (
        '<div class="score-grid">'
        f'<div class="score-card"><div class="score-big" style="color:{sev_color};">{_esc(cvss_disp)}</div>'
        f'<div class="score-label">CVSS 3.1 Score</div>{vec_line}</div>'
        f'<div class="score-card"><div class="score-big" style="color:#f59e0b;">{_esc(epss_disp)}</div>'
        f'<div class="score-label">EPSS 30-day probability</div></div>'
        f'<div class="score-card"><div class="score-big" style="color:{kev_color};">{"YES" if kev else "NO"}</div>'
        f'<div class="score-label">CISA KEV Listed</div></div>'
        f'<div class="score-card"><div class="score-big" style="color:var(--accent);">{risk_score:.1f}</div>'
        f'<div class="score-label">Composite Risk /10</div>'
        f'<div class="risk-bar-wrap"><div class="risk-bar" style="width:{risk_pct:.1f}%;background:{sev_color};"></div></div>'
        f'</div>'
        '</div>'
        + comp_html
        + (f'<div style="margin-top:12px;">{cwe_line}</div>' if cwe_line else "")
    ))

    # ── 03 Affected Products ───────────────────────────────────────────────
    if affected_p:
        rows = "".join(
            f'<tr><td class="mono">{_esc(p)}</td>'
            f'<td>{_esc(affected_v[i] if i < len(affected_v) else "See vendor advisory")}</td>'
            f'<td><span class="badge sev-high">Vulnerable</span></td></tr>'
            for i, p in enumerate(affected_p[:20])
        )
        prod_tbl = (
            '<table class="ioc-table"><thead><tr>'
            '<th>Product</th><th>Affected Versions</th><th>Status</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>'
        )
    else:
        prod_tbl = f'<p class="muted-text">Refer to vendor advisory for complete affected product list. CVE: {_esc(cve_id)}</p>'
    patch_btn = (
        f'<div style="margin-top:14px;"><a href="{_esc(patch_url)}" target="_blank" '
        f'rel="noopener" class="btn btn-secondary">&#8659; Vendor Patch / Advisory</a></div>'
        if patch_url else ""
    )
    s03 = sec("03", "Affected Products & Versions", prod_tbl + patch_btn)

    # ── 04 Threat Context ──────────────────────────────────────────────────
    ctx_map = {
        "sql_injection":   "SQL injection vulnerabilities allow attackers to manipulate backend database queries by injecting malicious SQL syntax into user-supplied inputs. Exploitation can lead to authentication bypass, full database exfiltration, and in some configurations, remote code execution via stored procedures.",
        "path_traversal":  "Path traversal vulnerabilities arise when authorization middleware applies access control checks to the raw URL before the web framework normalizes percent-encoded characters. Attackers submit double-encoded path separators (%252f) that bypass middleware but resolve to the intended path at the routing layer.",
        "rce":             "Remote code execution grants attackers the ability to execute arbitrary operating system commands in the context of the application server process, typically resulting in full server compromise, lateral movement, and persistent backdoor installation.",
        "auth_bypass":     "Authentication bypass enables unauthenticated actors to access privileged resources by exploiting flaws in the authentication enforcement logic — including missing checks, logic errors, or parameter manipulation that bypasses the session validation gate.",
        "xss":             "Cross-site scripting enables injection of malicious scripts into web pages served to other users. Stored XSS enables persistent session hijacking and credential theft at scale across the entire user base.",
        "ssrf":            "Server-Side Request Forgery allows attackers to induce the server to make HTTP requests to internal infrastructure, cloud metadata endpoints (169.254.169.254), or internal services not intended to be publicly reachable.",
        "generic":         "This vulnerability affects the confidentiality, integrity, or availability of the target system. Successful exploitation may allow unauthorized access, data disclosure, or denial of service depending on deployment configuration.",
    }
    # v161.3 P1-FIX: Never show hardcoded "Network/Low/None" defaults for CVEs
    # without NVD CVSS data. Show "Pending NVD" instead of fabricated values.
    _has_real_cvss = cvss_comp is not None and cvss_score is not None
    _nvd_pending   = not _has_real_cvss
    av = cvss_comp.get("AV", "N/A") if _has_real_cvss else "Pending NVD Confirmation"
    ac = cvss_comp.get("AC", "N/A") if _has_real_cvss else "Pending NVD Confirmation"
    pr = cvss_comp.get("PR", "N/A") if _has_real_cvss else "Pending NVD Confirmation"
    ui = cvss_comp.get("UI", "N/A") if _has_real_cvss else "Pending NVD Confirmation"
    s04 = sec("04", "Threat Context & Attack Surface", (
        f'<p class="body-text">{_esc(ctx_map.get(vuln_class, ctx_map["generic"]))}</p>'
        + ('<p class="body-text" style="color:#f59e0b;font-size:12px;margin-top:8px;">&#9888; '
           'CVSS vector components pending NVD confirmation. Values will be updated when '
           'NVD publishes the official CVSS 3.1 record for this CVE.</p>'
           if _nvd_pending else "")
        + '<div class="meta-grid" style="margin-top:16px;">'
        + mr("Attack Vector",        _esc(av))
        + mr("Attack Complexity",    _esc(ac))
        + mr("Privileges Required",  _esc(pr))
        + mr("User Interaction",     _esc(ui))
        + '</div>'
    ))

    # ── 05 MITRE ATT&CK ────────────────────────────────────────────────────
    if techniques:
        cards = "".join(
            f'<div class="attack-card">'
            f'<div class="attack-id" style="color:{t["color"]};">{_esc(t["id"])}</div>'
            f'<div class="attack-name">{_esc(t["name"])}</div>'
            f'<div class="attack-tactic">{_esc(t["tactic"])}</div>'
            f'</div>'
            for t in techniques
        )
        atk_html = f'<div class="attack-grid">{cards}</div>'
    else:
        atk_html = '<p class="muted-text">MITRE ATT&CK techniques pending analyst enrichment.</p>'
    s05 = sec("05", "MITRE ATT&CK v15 Mapping", atk_html)

    # ── 06 Technical Analysis ──────────────────────────────────────────────
    analysis_map = {
        "sql_injection": (
            "VULNERABILITY ROOT CAUSE\n"
            "User-supplied input is interpolated directly into a SQL query string\n"
            "instead of being bound as a parameterised query parameter.\n\n"
            "VULNERABLE PATTERN:\n"
            "  query = \"SELECT * FROM api_keys WHERE key_value = '\" + api_key + \"'\"\n"
            "  cursor.execute(query)\n\n"
            "SECURE PATTERN (parameterised):\n"
            "  cursor.execute(\"SELECT * FROM api_keys WHERE key_value = ?\", (api_key,))\n\n"
            "EXPLOITATION:\n"
            "  An attacker provides a crafted Bearer token containing SQL metacharacters.\n"
            "  The injected UNION SELECT clause returns data from adjacent database tables,\n"
            "  enabling credential extraction with zero prior authentication."
        ),
        "path_traversal": (
            "VULNERABILITY ROOT CAUSE\n"
            "Authorization middleware performs URL matching BEFORE the web framework\n"
            "normalizes percent-encoded path separators.\n\n"
            "ATTACK FLOW:\n"
            "  1. Attacker sends: GET /dashboard%2fadmin%2fusers HTTP/1.1\n"
            "  2. Middleware sees: /dashboard%2fadmin%2fusers (no match in whitelist) → passes\n"
            "  3. Web framework decodes %2f → / → resolves to /dashboard/admin/users\n"
            "  4. Admin endpoint serves privileged data without auth check at route handler\n\n"
            "DETECTION FINGERPRINT:\n"
            "  - HTTP 200 response to /admin/* paths from unauthenticated sessions\n"
            "  - URL containing %2f, %252f, %2e%2e in path segments targeting admin routes"
        ),
        "rce": (
            "VULNERABILITY ROOT CAUSE\n"
            "User-controlled input is passed unsanitized to OS-level command execution\n"
            "functions (exec, system, subprocess with shell=True).\n\n"
            "ATTACK VECTOR:\n"
            "  HTTP request parameters containing shell metacharacters (; | $(...) backticks)\n"
            "  that the application passes to an OS command interpreter.\n\n"
            "POST-EXPLOITATION CHAIN:\n"
            "  1. RCE payload establishes reverse shell or drops webshell\n"
            "  2. Attacker reads environment variables (API keys, DB credentials, secrets)\n"
            "  3. Internal network pivot via compromised server as jump host\n"
            "  4. Persistence via cron job or systemd service modification"
        ),
        "auth_bypass": (
            "VULNERABILITY ROOT CAUSE\n"
            "The authentication enforcement logic contains a flaw where specific request\n"
            "patterns, parameter combinations, or header values trigger an unintended\n"
            "code path that skips the session validation gate entirely.\n\n"
            "BYPASS CONDITIONS:\n"
            "  - Missing null/empty check allows unauthenticated session objects\n"
            "  - Logic inversion: condition inverted from 'deny if not authenticated'\n"
            "  - Parameter pollution overrides session state with attacker-controlled value\n\n"
            "IMPACT: Direct administrative access to protected resources with zero credentials."
        ),
        "generic": (
            "VULNERABILITY ANALYSIS\n"
            "This advisory describes a security vulnerability in the affected application.\n"
            "The vulnerability affects the security boundary of the target system and may\n"
            "allow unauthorized access to protected resources depending on the specific\n"
            "deployment configuration and attack conditions.\n\n"
            "Refer to the vendor advisory and CVE record for detailed technical root cause\n"
            "analysis. Deploy the detection rules in Section 09 to identify exploitation\n"
            "attempts in your environment."
        ),
    }
    s06 = sec("06", "Technical Analysis", cb(analysis_map.get(vuln_class, analysis_map["generic"]), "Analysis"))

    # ── 07 IOC Intelligence ────────────────────────────────────────────────
    # BUG-07 FIX: Filter out CVE IDs and reference URLs from the IOC table.
    # These are vulnerability references / metadata, not network/endpoint observables.
    # Displaying them as IOCs confuses customers and causes "all IOCs suppressed" state.
    _CVE_PAT = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
    _URL_PAT = re.compile(r'^https?://', re.IGNORECASE)

    def _is_actionable_ioc(val: str, itype: str) -> bool:
        """Return True only for network/endpoint observables that can be blocked or hunted."""
        v = str(val or "").strip()
        if not v or len(v) < 4:
            return False
        if _CVE_PAT.match(v):
            return False   # CVE IDs are references, not indicators
        if _URL_PAT.match(v) and "nvd.nist.gov" in v.lower():
            return False   # NVD/advisory URLs are references
        if v.upper() in ("N/A", "NONE", "UNKNOWN", "PENDING"):
            return False
        t = itype.upper()
        # Accept known actionable IOC types
        if t in ("IPV4", "IP", "DOMAIN", "URL", "SHA256", "MD5", "SHA1",
                 "EMAIL", "HASH", "FILE_HASH", "FILE", "USER_AGENT", "JA3",
                 "FILENAME", "REGISTRY", "MUTEX", "YARA", "INDICATOR"):
            return True
        # Accept if it looks like an IP, domain, or hash
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v):
            return True
        if re.match(r'^[0-9a-fA-F]{32,64}$', v):
            return True
        if re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$', v):
            return True
        return False

    ioc_rows_html = ""
    suppressed_count = 0
    for ioc in iocs_raw[:50]:
        if isinstance(ioc, dict):
            itype = ioc.get("type", "indicator")
            ival  = ioc.get("value", "")
            iconf = str(ioc.get("confidence", "HIGH"))
            ictx  = ioc.get("context", "")
        else:
            itype = "indicator"
            ival  = str(ioc)
            iconf = "HIGH"
            ictx  = ""

        if not _is_actionable_ioc(str(ival), str(itype)):
            suppressed_count += 1
            continue

        ioc_rows_html += (
            f'<tr><td>{_esc(itype)}</td>'
            f'<td class="mono break-all">{_esc(ival)}</td>'
            f'<td><span class="badge-small">{_esc(iconf)}</span></td>'
            f'<td class="muted-text">{_esc(ictx)}</td></tr>'
        )

    if ioc_rows_html:
        suppressed_note = (
            f'<p class="muted-text" style="margin-top:8px;">'
            f'{suppressed_count} non-actionable reference(s) (CVE IDs / advisory URLs) excluded. '
            f'APEX Pro delivers structured IOCs in STIX 2.1, MISP, and CSV for direct SIEM ingestion.</p>'
        ) if suppressed_count else ""
        ioc_content = (
            '<table class="ioc-table"><thead><tr>'
            '<th>Type</th><th>Indicator</th><th>Confidence</th><th>Context</th>'
            f'</tr></thead><tbody>{ioc_rows_html}</tbody></table>'
            + suppressed_note
        )
    else:
        ioc_content = (
            '<p class="muted-text">No network/endpoint observables extracted for this advisory. '
            'CVE identifiers and advisory URLs are classified as references (not indicators). '
            'APEX Pro subscribers receive enriched IOC feeds including infrastructure IPs, '
            'command-and-control domains, file hashes, and YARA signatures via the live API.</p>'
        )
    s07 = sec("07", "Indicators of Compromise (IOC)", ioc_content)

    # ── 08 Threat Actor Intelligence ──────────────────────────────────────
    actor_map = {
        "sql_injection":  "Opportunistic threat actors and data brokers scanning for unauthenticated API endpoints. SQLi payloads are trivially automated via mass-scanning frameworks (Nuclei, SQLMap) — time-to-exploit for unpatched instances is measured in seconds, not hours.",
        "path_traversal": "Automated vulnerability scanners and targeted reconnaissance actors probing for auth bypass patterns. Path normalization exploits typically appear in public exploit databases within 48 hours of disclosure.",
        "rce":            "Nation-state actors, ransomware groups, and initial access brokers. RCE vulnerabilities in internet-facing services are prioritized for weaponization. Median time from PoC publication to in-the-wild exploitation: 3-14 days.",
        "auth_bypass":    "Low-sophistication opportunists to advanced persistent threat actors. Auth bypass enables initial foothold with zero credentials — high value for access brokers selling enterprise access on dark web markets.",
        "generic":        "Threat actor profile pending enrichment. Actor sophistication correlates with CVE severity and public PoC availability. Monitor threat intel feeds for attribution updates.",
    }
    s08 = sec("08", "Threat Actor Intelligence", (
        '<div class="meta-grid">'
        + mr("Attributed Actor",  f'<span class="mono" style="color:var(--accent);">{_esc(actor_tag)}</span>')
        + mr("Motivation",        "Financial Gain / Unauthorized Access / Espionage")
        + mr("Sophistication",    "Low to High (automation-driven mass exploitation)")
        + mr("Infrastructure",    "Residential proxies, VPN exit nodes, Tor relays, compromised hosting")
        + '</div>'
        + f'<p class="body-text" style="margin-top:14px;">{_esc(actor_map.get(vuln_class, actor_map["generic"]))}</p>'
    ))

    # ── 09 Detection Engineering ───────────────────────────────────────────
    s09 = sec("09", "Detection Engineering", (
        '<div class="sub-title" style="margin-bottom:8px;">Sigma Rule — Webserver Log Category</div>'
        + cb(sigma, "SIGMA")
        + '<div class="sub-title" style="margin-top:20px;margin-bottom:8px;">Microsoft Sentinel — KQL</div>'
        + cb(kql, "KQL / Microsoft Sentinel")
        + '<div class="sub-title" style="margin-top:20px;margin-bottom:8px;">Splunk Enterprise Security — SPL</div>'
        + cb(spl, "SPL / Splunk ES")
    ))

    # ── 10 Incident Response Playbook ──────────────────────────────────────
    s10 = sec("10", "Incident Response Playbook", (
        '<div class="playbook-grid">'
        '<div class="pb-phase">'
        '<div class="pb-phase-title" style="color:#dc2626;">Phase 1 — 0-24 Hours (Containment)</div>'
        + pblist(pb["0_24h"])
        + '</div>'
        '<div class="pb-phase">'
        '<div class="pb-phase-title" style="color:#f59e0b;">Phase 2 — 24-72 Hours (Eradication)</div>'
        + pblist(pb["24_72h"])
        + '</div>'
        '<div class="pb-phase">'
        '<div class="pb-phase-title" style="color:#22c55e;">Phase 3 — 7 Days (Recovery)</div>'
        + pblist(pb["7_day"])
        + '</div>'
        '</div>'
    ))

    # ── 11 Financial Impact ────────────────────────────────────────────────
    s11 = sec("11", "Financial Impact Analysis (FAIR Model)", (
        '<div class="score-grid">'
        f'<div class="score-card"><div class="score-big" style="color:{sev_color};">{_esc(fin["range"])}</div>'
        f'<div class="score-label">Breach Cost Range (FAIR)</div></div>'
        f'<div class="score-card"><div class="score-big" style="color:#f59e0b;">{_esc(fin["median"])}</div>'
        f'<div class="score-label">IBM Cost of Breach 2025 Median</div></div>'
        f'<div class="score-card"><div class="score-big" style="color:#ea580c;">{_esc(fin["downtime"])}</div>'
        f'<div class="score-label">Business Interruption</div></div>'
        f'<div class="score-card"><div class="score-big" style="color:#dc2626;">{_esc(fin["regulatory"])}</div>'
        f'<div class="score-label">Regulatory Fine Exposure</div></div>'
        '</div>'
        f'<p class="body-text" style="margin-top:16px;">{_esc(fin["detail"])}</p>'
        '<div class="meta-grid" style="margin-top:12px;">'
        + mr("Remediation Cost Estimate", _esc(fin["remediation"]))
        + '</div>'
    ))

    # ── 12 Regulatory Compliance ────────────────────────────────────────────
    comp_rows = "".join(
        f'<tr>'
        f'<td><span style="color:{c["color"]};font-weight:700;">{_esc(c["fw"])}</span></td>'
        f'<td class="mono" style="font-size:10px;">{_esc(c["ref"])}</td>'
        f'<td style="font-size:12px;">{_esc(c["obligation"])}</td>'
        f'</tr>'
        for c in compliance
    )
    s12 = sec("12", "Regulatory & Compliance Implications", (
        '<table class="ioc-table"><thead><tr>'
        '<th>Framework</th><th>Reference</th><th>Obligation</th>'
        f'</tr></thead><tbody>{comp_rows}</tbody></table>'
    ))

    # ── 13 STIX Bundle ──────────────────────────────────────────────────────
    stix_dl = ""
    if stix_url:
        stix_dl = f'<a href="{_esc(stix_url)}" target="_blank" class="btn btn-secondary">&#8659; Download STIX 2.1 Bundle</a>'
    elif stix_bundle_path and os.path.exists(stix_bundle_path):
        stix_dl = f'<span class="mono" style="color:var(--accent);">STIX Bundle: {_esc(Path(stix_bundle_path).name)}</span>'
    s13 = sec("13", "STIX 2.1 Intelligence Bundle", (
        '<p class="body-text">This advisory is packaged as STIX 2.1 for direct ingestion into OpenCTI, MISP, Microsoft Sentinel, Splunk, and IBM QRadar.</p>'
        '<div class="meta-grid" style="margin-top:14px;">'
        + mr("Bundle Format",    "STIX 2.1 (JSON)")
        + mr("Objects",          "indicator, vulnerability, threat-actor, course-of-action, relationship")
        + mr("TLP Marking",      _esc(tlp))
        + mr("Intel ID",         f'<span class="mono" style="font-size:10px;">{intel_id[:40]}</span>')
        + '</div>'
        + f'<div style="margin-top:14px;">{stix_dl if stix_dl else "<p class=muted-text>STIX bundle available to APEX Pro and Enterprise subscribers.</p>"}</div>'
    ))

    # ── 14 Detection ROI ────────────────────────────────────────────────────
    s14 = sec("14", "Detection Value & APEX ROI", (
        '<div class="score-grid">'
        '<div class="score-card"><div class="score-big" style="color:var(--accent);">$49/mo</div>'
        '<div class="score-label">APEX Pro Subscription</div></div>'
        f'<div class="score-card"><div class="score-big" style="color:#22c55e;">{_esc(fin["median"])}</div>'
        '<div class="score-label">Median Breach Cost Avoided</div></div>'
        '<div class="score-card"><div class="score-big" style="color:#f59e0b;">&lt;15 min</div>'
        '<div class="score-label">Mean Time to Detect with APEX</div></div>'
        '<div class="score-card"><div class="score-big" style="color:#dc2626;">10,000x+</div>'
        '<div class="score-label">Estimated Detection ROI</div></div>'
        '</div>'
        '<p class="body-text" style="margin-top:16px;">APEX delivers real-time detection rules (Sigma, KQL, SPL), IOC feeds, STIX bundles, and YARA signatures for every critical advisory — enabling SOC teams to operationalize intelligence in under 15 minutes. At $49/month, a single prevented breach delivers return on investment exceeding 10,000x.</p>'
    ))

    # ── 15 Intelligence Metadata ────────────────────────────────────────────
    tags_line = ", ".join(_esc(t) for t in tags_raw[:10]) if tags_raw else "—"
    s15 = sec("15", "Intelligence Metadata", (
        '<div class="meta-grid">'
        + mr("Intel ID",            f'<span class="mono">{intel_id}</span>')
        + mr("Source",              _esc(feed_src))
        + mr("Processed",           f'<span class="mono">{_esc(processed[:19])} UTC</span>')
        + mr("Confidence Score",    f'<span style="color:var(--accent);">{confidence:.0f}%</span>')
        + mr("TLP Classification",  _esc(tlp))
        + mr("Vulnerability Class", _esc(vuln_label))
        + mr("Platform Version",    "SENTINEL APEX v161.3")
        + mr("Tags",                tags_line)
        + '</div>'
    ))

    # ── CTA block ───────────────────────────────────────────────────────────
    cta = (
        '<div class="cta-block">'
        '<div class="cta-inner">'
        '<div class="cta-badge">APEX PRO</div>'
        '<h3 class="cta-title">Unlock the Complete Intelligence Package</h3>'
        '<p class="cta-body">Real-time IOC feeds, YARA signatures, STIX 2.1 bundles, Sigma rules, KQL detections, and full dossiers for every critical advisory. Used by SOC analysts, threat hunters, and CISOs at enterprises globally.</p>'
        '<div class="cta-features">'
        '<span class="feat">&#9889; Real-time IOC Feeds</span>'
        '<span class="feat">&#128737; Sigma + KQL + SPL Rules</span>'
        '<span class="feat">&#128270; YARA Signatures</span>'
        '<span class="feat">&#128230; STIX 2.1 Bundles</span>'
        '<span class="feat">&#128202; Executive Briefings</span>'
        '<span class="feat">&#128276; Priority Alert Service</span>'
        '</div>'
        f'<div style="margin-top:20px;">'
        f'<a href="{_esc(GUMROAD_URL)}" target="_blank" rel="noopener" class="btn btn-primary">'
        f'&#9889; Upgrade to APEX Pro &#8212; $49/month</a>'
        f'<a href="{_esc(PLATFORM_URL)}" target="_blank" rel="noopener" class="btn btn-secondary">'
        f'View All Advisories &#8599;</a>'
        f'</div>'
        '</div>'
        '</div>'
    )

    # ── CSS ─────────────────────────────────────────────────────────────────
    css = (
        f":root{{"
        f"--bg:#0d1117;--card:#161b22;--card2:#1c2128;--border:#21262d;"
        f"--accent:#00d4aa;--text:#e6edf3;--muted:#8b949e;"
        f"--sev-color:{sev_color};"
        f"--font-mono:'Courier New',Courier,monospace;"
        f"}}"
        f"*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}"
        f"body{{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.65;}}"
        f"a{{color:var(--accent);text-decoration:none;}}a:hover{{text-decoration:underline;}}"
        f".tlp-banner{{background:{sev_color}18;border-bottom:2px solid {sev_color};padding:7px 24px;text-align:center;font-family:var(--font-mono);font-size:11px;font-weight:800;color:{sev_color};letter-spacing:2px;}}"
        f".header{{background:var(--card);border-bottom:1px solid var(--border);padding:28px 36px;}}"
        f".header-meta{{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap;}}"
        f"h1{{font-size:23px;font-weight:700;color:var(--text);margin-bottom:8px;line-height:1.3;}}"
        f".intel-id-line{{font-family:var(--font-mono);font-size:10px;color:var(--muted);}}"
        f".container{{max-width:980px;margin:0 auto;padding:32px 20px;}}"
        f".section{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:24px 28px;margin-bottom:14px;}}"
        f".section-title{{font-family:var(--font-mono);font-size:10px;font-weight:800;color:var(--accent);letter-spacing:2px;text-transform:uppercase;margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}}"
        f".sec-num{{color:var(--muted);}}"
        f".sub-title{{font-family:var(--font-mono);font-size:10px;font-weight:700;color:var(--muted);letter-spacing:1px;text-transform:uppercase;}}"
        f".badge{{font-family:var(--font-mono);font-size:10px;font-weight:800;padding:3px 10px;border-radius:3px;letter-spacing:1px;display:inline-block;}}"
        f".badge-tlp{{background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.35);color:var(--accent);}}"
        f".sev-critical{{background:#dc262618;border:1px solid #dc262655;color:#dc2626;}}"
        f".sev-high{{background:#ea580c18;border:1px solid #ea580c55;color:#ea580c;}}"
        f".sev-medium{{background:#f59e0b18;border:1px solid #f59e0b55;color:#f59e0b;}}"
        f".sev-low{{background:#22c55e18;border:1px solid #22c55e55;color:#22c55e;}}"
        f".sev-info{{background:#3b82f618;border:1px solid #3b82f655;color:#3b82f6;}}"
        f".sev-unknown{{background:#6b728018;border:1px solid #6b728055;color:#6b7280;}}"
        f".badge-small{{background:rgba(0,212,170,.1);color:var(--accent);font-family:var(--font-mono);font-size:9px;padding:1px 6px;border-radius:2px;}}"
        f".meta-grid{{display:grid;grid-template-columns:1fr;gap:0;}}"
        f".meta-row{{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px;}}"
        f".meta-row:last-child{{border-bottom:none;}}"
        f".meta-label{{color:var(--muted);font-family:var(--font-mono);font-size:10px;}}"
        f".meta-value{{color:var(--text);font-weight:500;}}"
        f".score-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;}}"
        f".score-card{{background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:16px;}}"
        f".score-big{{font-family:var(--font-mono);font-size:26px;font-weight:900;line-height:1.1;}}"
        f".score-label{{font-size:10px;color:var(--muted);margin-top:4px;font-family:var(--font-mono);}}"
        f".risk-bar-wrap{{background:rgba(255,255,255,.06);border-radius:4px;height:6px;margin-top:8px;}}"
        f".risk-bar{{height:6px;border-radius:4px;}}"
        f".score-table{{width:100%;border-collapse:collapse;}}"
        f".score-table td{{padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px;}}"
        f".ioc-table{{width:100%;border-collapse:collapse;font-size:12px;}}"
        f".ioc-table th{{background:rgba(255,255,255,.04);color:var(--accent);font-family:var(--font-mono);font-size:10px;font-weight:700;padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);}}"
        f".ioc-table td{{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top;}}"
        f".ioc-table tr:hover td{{background:rgba(255,255,255,.02);}}"
        f".attack-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:12px;}}"
        f".attack-card{{background:var(--card2);border:1px solid var(--border);border-radius:6px;padding:14px;}}"
        f".attack-id{{font-family:var(--font-mono);font-size:14px;font-weight:800;}}"
        f".attack-name{{font-size:12px;font-weight:600;margin-top:4px;color:var(--text);}}"
        f".attack-tactic{{font-size:10px;color:var(--muted);margin-top:2px;font-family:var(--font-mono);}}"
        f".code-wrap{{position:relative;margin:8px 0;}}"
        f".code-lang{{position:absolute;top:8px;right:12px;font-family:var(--font-mono);font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;}}"
        f".code-block{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:16px;font-family:var(--font-mono);font-size:11px;line-height:1.7;color:#c9d1d9;overflow-x:auto;white-space:pre;max-height:400px;overflow-y:auto;}}"
        f".playbook-grid{{display:grid;grid-template-columns:1fr;gap:14px;}}"
        f".pb-phase{{background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:16px;}}"
        f".pb-phase-title{{font-family:var(--font-mono);font-size:10px;font-weight:800;letter-spacing:1px;margin-bottom:12px;}}"
        f".pb-list{{list-style:none;padding:0;}}"
        f".pb-list li{{padding:6px 0 6px 20px;position:relative;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px;}}"
        f".pb-list li::before{{content:'\\2192';position:absolute;left:0;color:var(--accent);font-weight:700;}}"
        f".pb-list li:last-child{{border-bottom:none;}}"
        f".btn{{display:inline-block;padding:10px 22px;border-radius:6px;font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:.5px;text-decoration:none;transition:opacity .2s;}}"
        f".btn:hover{{opacity:.85;text-decoration:none;}}"
        f".btn-primary{{background:var(--accent);color:#0d1117;}}"
        f".btn-secondary{{background:transparent;color:var(--accent);border:1px solid rgba(0,212,170,.4);margin-left:10px;}}"
        f".cta-block{{background:linear-gradient(135deg,rgba(0,212,170,.06),rgba(0,212,170,.02));border:1px solid rgba(0,212,170,.2);border-radius:10px;padding:32px;margin-bottom:14px;}}"
        f".cta-inner{{max-width:640px;margin:0 auto;text-align:center;}}"
        f".cta-badge{{display:inline-block;background:var(--accent);color:#0d1117;font-family:var(--font-mono);font-size:9px;font-weight:800;padding:3px 12px;border-radius:3px;letter-spacing:2px;margin-bottom:14px;}}"
        f".cta-title{{font-size:19px;font-weight:700;color:var(--text);margin-bottom:10px;}}"
        f".cta-body{{color:var(--muted);font-size:13px;line-height:1.7;margin-bottom:18px;}}"
        f".cta-features{{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin-bottom:6px;}}"
        f".feat{{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:4px;padding:4px 12px;font-size:11px;}}"
        f".src-link{{color:var(--muted);font-size:11px;}}"
        f".mono{{font-family:var(--font-mono);}}"
        f".body-text{{color:var(--text);font-size:13px;line-height:1.75;}}"
        f".muted-text{{color:var(--muted);font-size:12px;}}"
        f".break-all{{word-break:break-all;}}"
        f".footer{{text-align:center;padding:28px 24px;color:var(--muted);font-size:11px;font-family:var(--font-mono);border-top:1px solid var(--border);margin-top:8px;}}"
        f"@media(max-width:640px){{h1{{font-size:18px;}}.score-grid{{grid-template-columns:1fr 1fr;}}.attack-grid{{grid-template-columns:1fr;}}.header{{padding:18px;}}.section{{padding:18px;}}}}"
    )

    # ── KEV badge ────────────────────────────────────────────────────────────
    kev_badge = (
        '<span class="badge" style="color:#ef4444;border:1px solid #ef444466;background:#ef444411;">&#9888; CISA KEV</span>'
        if kev else ""
    )

    # ── Final HTML assembly ───────────────────────────────────────────────
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="UTF-8"/>',
        '  <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>',
        '  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>',
        f'  <title>{title} &#8212; {_esc(PLATFORM_NAME)}</title>',
        f'  <meta name="description" content="Enterprise threat intelligence dossier: {title} | {_esc(cve_id)} | {_esc(PLATFORM_NAME)}"/>',
        f'  <link rel="canonical" href="{_esc(canonical_url)}"/>',
        f"  <style>{css}</style>",
        "</head>",
        "<body>",
        f'<div class="tlp-banner">&#9888; {_esc(tlp)} &#8212; {_esc(PLATFORM_NAME)} &#8212; ENTERPRISE THREAT INTELLIGENCE DOSSIER &#9888;</div>',
        '<div class="header">',
        '  <div class="header-meta">',
        f'    <span class="badge sev-{severity.lower()}">{_esc(severity)}</span>',
        f'    <span class="badge badge-tlp">{_esc(tlp)}</span>',
        f'    {kev_badge}',
        "  </div>",
        f"  <h1>{title}</h1>",
        '  <div class="intel-id-line">',
        f'    {_esc(cve_id)} &nbsp;&middot;&nbsp; INTEL-ID: {intel_id[:40]} &nbsp;&middot;&nbsp;',
        f'    PROCESSED: {_esc(processed[:19])} UTC &nbsp;&middot;&nbsp; SOURCE: {_esc(feed_src)}',
        "  </div>",
        "</div>",
        '<div class="container">',
        s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14, s15,
        cta,
        "</div>",
        '<div class="footer">',
        f'  {_esc(PLATFORM_NAME)} &nbsp;&middot;&nbsp;',
        f'  <a href="{_esc(PLATFORM_URL)}" style="color:var(--accent);">{_esc(PLATFORM_URL)}</a><br/>',
        f'  Dossier generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")} UTC &nbsp;&middot;&nbsp;',
        f'  <a href="{_esc(canonical_url)}" style="color:var(--muted);font-size:10px;">{_esc(canonical_url)}</a>',
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# CORE GENERATOR — public API (contract unchanged from v134)
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(
    entry: Dict[str, Any],
    stix_bundle_path: Optional[str] = None,
    reports_base: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Generate a God Mode HTML Tactical Dossier for the given intel entry.
    Returns (True, output_path) on success; (False, error_message) on failure.
    Never raises — all exceptions are caught and returned as (False, msg).
    """
    try:
        return _generate_internal(entry, stix_bundle_path, reports_base)
    except Exception as exc:
        msg = f"report_generator: unhandled exception for '{entry.get('id','?')}': {exc}"
        logger.error(msg, exc_info=True)
        return False, msg


def _generate_internal(
    entry: Dict[str, Any],
    stix_bundle_path: Optional[str],
    reports_base: Optional[str],
) -> Tuple[bool, str]:
    intel_id = (entry.get("id") or entry.get("stix_id") or "").strip()
    if not intel_id:
        return False, "entry has no 'id' or 'stix_id' field"

    title = (entry.get("title") or "Intel Advisory").strip()
    logger.info("Generating: %s — %s", intel_id, title)

    report_url = (entry.get("internal_report_url") or entry.get("report_url") or "").strip()
    if report_url.startswith("/"):
        out_path = Path(report_url.lstrip("/"))
    else:
        now  = datetime.now(timezone.utc)
        base = Path(reports_base) if reports_base else REPORTS_BASE
        out_path = base / str(now.year) / f"{now.month:02d}" / f"{intel_id}.html"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    html_content = _build_html(entry, stix_bundle_path, out_path)

    # v166.2 FIND-005 FIX: Validate HTML output before writing — never emit a malformed report.
    # Previously, _build_html could silently return a short/empty string for entries
    # with missing fields, resulting in reports that pass file-existence checks but
    # contain no real content (causing "9 reports missing HTML signature" CI warning).
    _HTML_REQUIRED_SIGNATURES = ["<!DOCTYPE html>", "<html", "</html>"]
    _HTML_MIN_SIZE = 500  # bytes — every real report is well above this threshold
    missing_sigs = [s for s in _HTML_REQUIRED_SIGNATURES if s not in html_content]
    if missing_sigs or len(html_content.encode("utf-8")) < _HTML_MIN_SIZE:
        reason = (
            f"missing HTML signatures {missing_sigs}" if missing_sigs
            else f"output too small ({len(html_content.encode('utf-8'))} bytes < {_HTML_MIN_SIZE})"
        )
        logger.error(
            "HTML validation FAILED for %s (%s) — %s — report NOT written",
            intel_id, out_path, reason,
        )
        return False, f"html_validation_failed for {out_path}: {reason}"

    tmp_path = out_path.with_suffix(".tmp")
    try:
        tmp_path.write_text(html_content, encoding="utf-8")
        tmp_path.replace(out_path)
    except Exception as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return False, f"write error for {out_path}: {exc}"

    logger.info("Written: %s (%d bytes)", out_path, out_path.stat().st_size)
    return True, str(out_path)


# ─────────────────────────────────────────────────────────────────────────────
# MANIFEST BATCH GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_reports_from_manifest(
    manifest_path: str = "data/stix/feed_manifest.json",
    reports_base: str = "reports",
    skip_existing: bool = True,
) -> Dict[str, Any]:
    """
    Generate God Mode HTML reports for all advisories in the manifest.
    Safe to call from pipeline or standalone CLI.
    """
    results: Dict[str, Any] = {"success": 0, "skipped": 0, "failed": 0, "errors": []}

    if not os.path.exists(manifest_path):
        msg = f"Manifest not found: {manifest_path}"
        logger.error(msg)
        results["errors"].append(msg)
        return results

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        msg = f"Failed to load manifest: {exc}"
        logger.error(msg)
        results["errors"].append(msg)
        return results

    # fix(v166.2-P0): canonical key detection including "data" key used by
    # field_preserving_merge.py default write path.
    if isinstance(data, list):
        advisories = data
    else:
        advisories = []
        for _k in ("advisories", "items", "data", "entries", "reports", "intel", "feed"):
            if isinstance(data.get(_k), list) and len(data[_k]) > 0:
                advisories = data[_k]
                break
    logger.info("God mode batch: %d advisories", len(advisories))

    for entry in advisories:
        intel_id = entry.get("id") or entry.get("stix_id") or ""
        if not intel_id:
            results["skipped"] += 1
            continue

        # ── v154.0: Dual-path URL resolution ──────────────────────────────────
        # Derive BOTH the internal path (used for god-mode existence check) AND
        # the public report_url path (the customer-facing URL).  These can differ
        # when internal_report_url points to an older month's file while report_url
        # was updated to the current month by the manifest generator.
        # God Mode must ONLY fire when the PUBLIC report_url path also exists —
        # otherwise the customer-facing link would return 404 even though an old
        # internal file is present on disk.
        _internal_ru = (entry.get("internal_report_url") or "").strip()
        _public_ru   = (entry.get("report_url") or "").strip()

        # Primary: use internal_report_url for the god-mode existence check
        report_url = (_internal_ru or _public_ru)
        if report_url.startswith("/"):
            expected = Path(report_url.lstrip("/"))
        else:
            ts   = entry.get("processed_at") or entry.get("timestamp") or ""
            yyyy = ts[:4] if len(ts) >= 4 else datetime.now().strftime("%Y")
            mm   = ts[5:7] if len(ts) >= 7 else datetime.now().strftime("%m")
            expected = Path(reports_base) / yyyy / mm / f"{intel_id}.html"

        # Secondary: resolve the public-facing path (what the dashboard links to)
        if _public_ru.startswith("/"):
            public_expected = Path(_public_ru.lstrip("/"))
        else:
            public_expected = expected  # same path if no separate public_url

        # ── GOD MODE PROTECTION GATE (v154.0) ─────────────────────────────────
        # If the existing report is a god mode dossier (> GODMODE_MIN_SIZE_BYTES
        # or in GODMODE_PROTECTED_IDS), NEVER overwrite it from the pipeline.
        # Manual operator reports take permanent precedence over auto-generated ones.
        #
        # P0 HARDENING v154.0: God Mode is ONLY honoured when the PUBLIC report_url
        # path also exists on disk.  If the public path is missing (regardless of
        # whether an internal/old-path file is present), force regeneration so the
        # customer-facing URL is never a 404.
        if expected.exists():
            existing_size = expected.stat().st_size
            is_protected_id = intel_id in GODMODE_PROTECTED_IDS
            is_godmode_size = existing_size >= GODMODE_MIN_SIZE_BYTES
            # CRITICAL: also require the public-facing path to exist
            public_path_ok = public_expected.exists()
            if (is_protected_id or is_godmode_size) and public_path_ok:
                size_kb = round(existing_size / 1024, 1)
                if is_protected_id:
                    logger.info(
                        "[GODMODE-PROTECTED] %s (%s KB) — operator-curated, pipeline skip",
                        intel_id, size_kb
                    )
                else:
                    logger.info(
                        "[GODMODE-QUALITY] %s (%s KB) — god mode size, pipeline skip",
                        intel_id, size_kb
                    )
                # v160.6 FIX: preserve deployed CDN report_url in manifest entry.
                # When a report is godmode-skipped, the convergence engine needs a
                # valid HTTPS probe URL. Without this, all fallbacks yield 0 URLs
                # and Phase 3 produces false DEPLOYMENT_FAILED (Score 32.5/100).
                # Derive canonical CDN URL from the confirmed-existing public path.
                _existing_ru = (entry.get("report_url") or "").strip()
                if not _existing_ru.startswith("https://intel.cyberdudebivash"):
                    try:
                        _rel = public_expected.relative_to(REPO_ROOT).as_posix()
                        _cdn = "https://intel.cyberdudebivash.com/" + _rel
                        entry["report_url"] = _cdn
                        entry["internal_report_url"] = "/" + _rel
                        logger.info(
                            "[GODMODE-URL-PRESERVED] %s → report_url=%s",
                            intel_id, _cdn
                        )
                    except Exception as _ue:
                        logger.debug("[GODMODE-URL-PRESERVE-WARN] %s: %s", intel_id, _ue)
                results["skipped"] += 1
                continue
            elif (is_protected_id or is_godmode_size) and not public_path_ok:
                # Internal file is god-mode quality but PUBLIC URL is missing.
                # Fall through to generation — do NOT skip.
                # The report will be generated at the public_expected path below.
                logger.info(
                    "[GODMODE-REGEN] %s — internal file exists (%s KB) but "
                    "public report_url path MISSING (%s). Forcing regeneration "
                    "to prevent customer 404.",
                    intel_id, round(existing_size / 1024, 1), public_expected
                )
                # fall through to generate_report()

        if skip_existing and expected.exists() and expected.stat().st_size > 2000:
            # v166.2 FIX: Use startswith check (matches pipeline_audit) NOT 'in' check.
            # 'in' allows BOM/garbage prefix to hide invalid reports from regeneration.
            # Also enforce _HTML_MIN_SIZE to catch truncated-but-signed files.
            try:
                raw_head = expected.read_bytes()[:64]
                is_valid_html = any(
                    raw_head.lower().startswith(sig.lower().encode())
                    for sig in (b"<!doctype html", b"<html")
                )
                is_large_enough = expected.stat().st_size >= 500
            except Exception:
                is_valid_html = False
                is_large_enough = False
            if is_valid_html and is_large_enough:
                results["skipped"] += 1
                continue
            # Existing report is malformed — fall through to regenerate it
            logger.info(
                "Re-generating malformed existing report: %s (valid_html=%s, size=%d)",
                expected, is_valid_html, expected.stat().st_size if expected.exists() else 0,
            )

        stix_bundle = entry.get("stix_bundle") or entry.get("stix_file") or None
        ok, path_or_err = generate_report(entry, stix_bundle, reports_base)
        if ok:
            results["success"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(f"{intel_id}: {path_or_err}")
            logger.warning("Failed: %s — %s", intel_id, path_or_err)

    logger.info(
        "Complete — success=%d  skipped=%d  failed=%d",
        results["success"], results["skipped"], results["failed"],
    )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL APEX God Mode Report Generator v161.3"
    )
    parser.add_argument("--manifest",      default="data/stix/feed_manifest.json")
    parser.add_argument("--reports-base",  default="reports")
    parser.add_argument("--force",         action="store_true",
                        help="Re-generate even if report already exists")
    parser.add_argument("--entry",         default="",
                        help="JSON string of a single entry to generate (for testing)")
    parser.add_argument("--show-classes",  action="store_true",
                        help="List all supported vulnerability classes and exit")
    args = parser.parse_args()

    if args.show_classes:
        print("\nSupported vulnerability classes:")
        for cls, label in _VULN_CLASS_LABELS.items():
            print(f"  {cls:20s}  {label}")
        return 0

    if args.entry:
        import json as _json
        entry = _json.loads(args.entry)
        ok = generate_report(entry, reports_base=args.reports_base, force=args.force)
        return 0 if ok else 1

    results = generate_reports_from_manifest(
        manifest_path=args.manifest,
        reports_base=args.reports_base,
        skip_existing=not args.force,
    )
    return 0 if results["failed"] == 0 else 1


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(main())
