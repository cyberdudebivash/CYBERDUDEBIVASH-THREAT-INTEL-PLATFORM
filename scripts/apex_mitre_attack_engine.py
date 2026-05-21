#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/apex_mitre_attack_engine.py — Evidence-Based ATT&CK Mapping Engine
================================================================================
Version : 152.0.0

PROBLEM SOLVED:
  Legacy ATT&CK mapping:
    - T1203 + T1213 assigned to EVERY CVE advisory
    - Justification: "Technique ID mapped from threat intelligence corpus"
    - No observed behavior documented
    - No detection guidance per technique
    - Same 2 techniques on all reports regardless of vulnerability class

SOLUTION:
  Evidence-based ATT&CK mapping using:
    1. Vulnerability TYPE → technique tier (primary techniques by class)
    2. Text analysis → behavior inference from title/description
    3. CWE mapping → technique alignment
    4. Per-technique: WHY it applies + observed behavior + detection + Sigma

MITRE ATT&CK VERSION: v16
================================================================================
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("apex.mitre_attack")
ENGINE_VERSION = "152.0.0"
ENGINE_ID      = "APEX-MAE"

# ── Technique Library ─────────────────────────────────────────────────────────
# technique_id → {name, tactic, description, detection_hint, sigma_tag, kql_hint}
TECHNIQUE_LIBRARY: Dict[str, Dict] = {
    "T1190": {
        "name":    "Exploit Public-Facing Application",
        "tactic":  "Initial Access",
        "applies_to": ["RCE", "unauthenticated", "web application", "public-facing",
                        "authentication bypass", "SOAP", "REST API", "buffer overflow", "injection"],
        "detection_hint": "Alert on unexpected process spawning from web server processes (IIS, Apache, nginx, Tomcat). Monitor for shell commands (cmd.exe, bash, sh) launched by web service accounts.",
        "sigma_tag": "attack.initial_access.t1190",
        "kql_hint": "DeviceProcessEvents | where InitiatingProcessFileName has_any ('w3wp.exe','httpd','nginx','tomcat') and FileName has_any ('cmd.exe','powershell.exe','bash','sh')",
    },
    "T1059": {
        "name":    "Command and Scripting Interpreter",
        "tactic":  "Execution",
        "applies_to": ["command execution", "script", "PowerShell", "bash", "python",
                        "code execution", "RCE", "shell", "eval", "injection"],
        "detection_hint": "Monitor for unusual parent-child process relationships. Alert on PowerShell with encoded commands, downloading content, or disabling security features.",
        "sigma_tag": "attack.execution.t1059",
        "kql_hint": "DeviceProcessEvents | where ProcessCommandLine has_any ('IEX','Invoke-Expression','-EncodedCommand','DownloadString','bypass')",
    },
    "T1059.001": {
        "name":    "PowerShell",
        "tactic":  "Execution",
        "applies_to": ["powershell", "ps1", "invoke-expression", "IEX", "encoded command"],
        "detection_hint": "Alert on powershell.exe with -EncodedCommand, -WindowStyle Hidden, -NonInteractive, or Invoke-Expression usage. Monitor for PowerShell downloading remote content.",
        "sigma_tag": "attack.execution.t1059.001",
        "kql_hint": "DeviceProcessEvents | where FileName =~ 'powershell.exe' and ProcessCommandLine has_any ('-enc','-EncodedCommand','IEX','Invoke-Expression','DownloadString')",
    },
    "T1055": {
        "name":    "Process Injection",
        "tactic":  "Defense Evasion / Privilege Escalation",
        "applies_to": ["process injection", "DLL injection", "code injection", "shellcode",
                        "reflective", "CreateRemoteThread", "VirtualAllocEx"],
        "detection_hint": "Monitor for cross-process memory writes, VirtualAllocEx/WriteProcessMemory API calls, and unusual thread creation in high-value processes (lsass, svchost, explorer).",
        "sigma_tag": "attack.defense_evasion.t1055",
        "kql_hint": "DeviceEvents | where ActionType == 'CreateRemoteThreadApiCall' | where InitiatingProcessFileName != FileName",
    },
    "T1078": {
        "name":    "Valid Accounts",
        "tactic":  "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "applies_to": ["credential", "authentication bypass", "account takeover", "default credentials",
                        "hardcoded credentials", "stolen credentials", "OAuth"],
        "detection_hint": "Alert on authentication from unusual IPs or geographies. Monitor for impossible travel scenarios. Alert on successful auth after multiple failures.",
        "sigma_tag": "attack.defense_evasion.t1078",
        "kql_hint": "SigninLogs | where ResultType == 0 | where TimeGenerated > ago(1h) | summarize count() by UserPrincipalName, IPAddress | where count_ > 5",
    },
    "T1110": {
        "name":    "Brute Force",
        "tactic":  "Credential Access",
        "applies_to": ["brute force", "credential stuffing", "password spray", "authentication attempt"],
        "detection_hint": "Alert on >5 failed authentication attempts from same IP within 5 minutes. Alert on distributed password spray (same password, many accounts).",
        "sigma_tag": "attack.credential_access.t1110",
        "kql_hint": "SigninLogs | where ResultType != 0 | summarize FailCount=count() by IPAddress, bin(TimeGenerated, 5m) | where FailCount > 5",
    },
    "T1203": {
        "name":    "Exploitation for Client Execution",
        "tactic":  "Execution",
        "applies_to": ["client-side", "browser", "office", "PDF", "media player", "email client",
                        "document exploit", "CVE.*browser", "CVE.*office", "CVE.*acrobat"],
        "detection_hint": "Monitor browser/Office process spawning unexpected child processes. Alert on browser plugins/extensions creating network connections.",
        "sigma_tag": "attack.execution.t1203",
        "kql_hint": "DeviceProcessEvents | where InitiatingProcessFileName has_any ('WINWORD.EXE','EXCEL.EXE','chrome.exe','firefox.exe','AcroRd32.exe') and FileName has_any ('cmd.exe','powershell.exe','wscript.exe','mshta.exe')",
    },
    "T1210": {
        "name":    "Exploitation of Remote Services",
        "tactic":  "Lateral Movement",
        "applies_to": ["lateral movement", "remote service", "SMB", "RDP", "WinRM", "DCOM",
                        "network exploit", "server-side", "cross-tenant"],
        "detection_hint": "Monitor for unusual inbound connections to SMB (445), RDP (3389), WinRM (5985/5986). Alert on lateral movement from unexpected source hosts.",
        "sigma_tag": "attack.lateral_movement.t1210",
        "kql_hint": "DeviceNetworkEvents | where RemotePort in (445, 3389, 5985, 5986, 135) | where ActionType == 'InboundConnectionAccepted' | summarize count() by DeviceName, RemoteIP, bin(Timestamp, 1h) | where count_ > 10",
    },
    "T1486": {
        "name":    "Data Encrypted for Impact",
        "tactic":  "Impact",
        "applies_to": ["ransomware", "encrypt", "ransom", "lockbit", "blackcat", "alphv",
                        "data destruction", "wiper"],
        "detection_hint": "Alert on mass file rename events (extension changes). Monitor for shadow copy deletion (vssadmin delete, wbadmin). Alert on crypto API usage by unexpected processes.",
        "sigma_tag": "attack.impact.t1486",
        "kql_hint": "DeviceFileEvents | where ActionType == 'FileModified' | where FileName matches regex '.*\\.(locked|encrypted|enc|ryuk|akira)$' | summarize count() by DeviceName, bin(Timestamp, 1m) | where count_ > 50",
    },
    "T1566": {
        "name":    "Phishing",
        "tactic":  "Initial Access",
        "applies_to": ["phishing", "spearphishing", "email", "malicious attachment", "lure",
                        "vishing", "smishing", "social engineering"],
        "detection_hint": "Alert on new email domains not seen in last 30 days. Monitor for emails with URLs using punycode or URL shorteners. Alert on password-protected attachments with macros.",
        "sigma_tag": "attack.initial_access.t1566",
        "kql_hint": "EmailEvents | where DeliveryAction == 'Delivered' | where not(SenderDomain in (trusted_domains)) | where AttachmentCount > 0 | project Timestamp, SenderAddress, Subject, AttachmentExtension",
    },
    "T1071": {
        "name":    "Application Layer Protocol",
        "tactic":  "Command and Control",
        "applies_to": ["C2", "command and control", "beaconing", "covert channel",
                        "exfiltration over HTTP", "DNS tunneling", "encrypted C2"],
        "detection_hint": "Monitor for regular beaconing patterns (connections at fixed intervals). Alert on DNS queries with unusually long subdomains (DGA or DNS tunneling).",
        "sigma_tag": "attack.command_and_control.t1071",
        "kql_hint": "DeviceNetworkEvents | summarize count(), dcount(RemoteUrl) by DeviceName, RemoteIP, bin(Timestamp, 1h) | where count_ > 20 and dcount_RemoteUrl < 3",
    },
    "T1083": {
        "name":    "File and Directory Discovery",
        "tactic":  "Discovery",
        "applies_to": ["directory traversal", "file inclusion", "path traversal",
                        "LFI", "RFI", "directory listing", "information disclosure"],
        "detection_hint": "Alert on ../ patterns in web request URLs. Monitor for access to sensitive directories (/etc/passwd, /proc, windows/system32). Alert on LFI/RFI patterns.",
        "sigma_tag": "attack.discovery.t1083",
        "kql_hint": "DeviceNetworkEvents | where RemoteUrl has_any ('../','..%2F','..%5C','/etc/passwd','/proc/self')",
    },
    "T1539": {
        "name":    "Steal Web Session Cookie",
        "tactic":  "Credential Access",
        "applies_to": ["cookie theft", "session hijacking", "XSS", "cross-site scripting",
                        "stored XSS", "reflected XSS", "document.cookie"],
        "detection_hint": "Monitor for JavaScript accessing document.cookie in unexpected contexts. Alert on session tokens appearing from new IPs after authenticated session.",
        "sigma_tag": "attack.credential_access.t1539",
        "kql_hint": "SecurityAlert | where AlertType contains 'XSS' or AlertName contains 'Cookie' | project TimeGenerated, DeviceName, Description",
    },
    "T1548": {
        "name":    "Abuse Elevation Control Mechanism",
        "tactic":  "Privilege Escalation",
        "applies_to": ["privilege escalation", "sudo", "SUID", "UAC bypass", "setuid",
                        "elevation", "local privilege", "LPE"],
        "detection_hint": "Monitor for sudo command usage with unusual arguments. Alert on SUID binary execution. Monitor UAC bypass techniques (fodhelper, eventvwr).",
        "sigma_tag": "attack.privilege_escalation.t1548",
        "kql_hint": "DeviceProcessEvents | where ProcessCommandLine has_any ('sudo','su -','chmod +s','UAC') | where AccountDomain != 'NT AUTHORITY'",
    },
    "T1041": {
        "name":    "Exfiltration Over C2 Channel",
        "tactic":  "Exfiltration",
        "applies_to": ["exfiltration", "data theft", "data leak", "exfil",
                        "data exfiltration", "cross-tenant exfiltration"],
        "detection_hint": "Alert on large data transfers (>100MB) to external IPs not in allowlist. Monitor for outbound connections on non-standard ports. Alert on data staging in temp directories.",
        "sigma_tag": "attack.exfiltration.t1041",
        "kql_hint": "DeviceNetworkEvents | where ActionType == 'ConnectionSuccess' | where RemoteIPType == 'Public' | summarize BytesSent=sum(SentBytes) by DeviceName, RemoteIP, bin(Timestamp, 1h) | where BytesSent > 104857600",
    },
    "T1098": {
        "name":    "Account Manipulation",
        "tactic":  "Persistence",
        "applies_to": ["account manipulation", "privilege assignment", "backdoor account",
                        "admin account", "user creation", "role assignment"],
        "detection_hint": "Alert on new admin/privileged account creation. Monitor for unexpected privilege assignments. Alert on MFA method modifications.",
        "sigma_tag": "attack.persistence.t1098",
        "kql_hint": "AuditLogs | where OperationName has_any ('Add member to role','Add user','Grant','Assign') | where InitiatedBy.user.userPrincipalName !in (authorised_admins)",
    },
    "T1190.001": {
        "name":    "SQL Injection",
        "tactic":  "Initial Access",
        "applies_to": ["SQL injection", "SQLi", "ORM injection", "database injection", "UNION SELECT"],
        "detection_hint": "Alert on SQL injection patterns in web application logs (UNION, SELECT, ', --, xp_). Enable WAF SQL injection rules. Review application logs for unusual database query patterns.",
        "sigma_tag": "attack.initial_access.t1190",
        "kql_hint": "W3CIISLog | where csUriStem has_any ('UNION','SELECT','DROP','INSERT',\"'\",\"--\",\"xp_\") | project TimeGenerated, cIP, csUriStem, scStatus",
    },
}

# ── CWE to ATT&CK mapping ─────────────────────────────────────────────────────
CWE_TO_ATTACK: Dict[str, List[str]] = {
    "CWE-78":  ["T1059"],           # OS Command Injection
    "CWE-79":  ["T1539"],           # XSS → Cookie theft
    "CWE-89":  ["T1190.001"],       # SQL Injection
    "CWE-22":  ["T1083"],           # Path Traversal
    "CWE-94":  ["T1059"],           # Code Injection
    "CWE-119": ["T1055"],           # Buffer Overflow → Process injection
    "CWE-120": ["T1055"],
    "CWE-125": ["T1190"],           # Out of bounds read
    "CWE-287": ["T1078"],           # Authentication issues
    "CWE-306": ["T1190", "T1078"], # Missing auth → Public-facing + Valid accounts
    "CWE-416": ["T1055"],           # Use after free → Process injection
    "CWE-434": ["T1190"],           # Unrestricted upload
    "CWE-502": ["T1059"],           # Deserialization
    "CWE-611": ["T1190"],           # XXE
    "CWE-732": ["T1548"],           # Permission issues → Priv esc
    "CWE-798": ["T1078"],           # Hard-coded credentials
}

# ── Vocabulary-based technique inference ─────────────────────────────────────

def _infer_techniques(item: Dict) -> List[str]:
    """Infer applicable ATT&CK techniques from item content."""
    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "executive_summary",
        "vulnerability_type", "attack_vector", "cwe_id",
    )).lower()

    matched: Dict[str, float] = {}

    # CWE direct mapping
    cwe = str(item.get("cwe_id") or "")
    if cwe in CWE_TO_ATTACK:
        for tid in CWE_TO_ATTACK[cwe]:
            matched[tid] = matched.get(tid, 0) + 0.8

    # Vocabulary match
    for tid, tech in TECHNIQUE_LIBRARY.items():
        score = 0.0
        for keyword in tech["applies_to"]:
            if re.search(re.escape(keyword.lower()), all_text):
                score += 1.0
        if score > 0:
            # Normalise by keyword count
            matched[tid] = matched.get(tid, 0) + (score / len(tech["applies_to"]))

    # Sort by score, return top 5
    ranked = sorted(matched.items(), key=lambda x: -x[1])
    return [tid for tid, _ in ranked[:5]]


def _build_technique_entry(tid: str, item: Dict, match_score: float) -> Dict:
    """Build a full technique evidence entry."""
    tech = TECHNIQUE_LIBRARY.get(tid, {})
    if not tech:
        return {"technique_id": tid, "justification": "No evidence — technique not in APEX library"}

    # Infer WHY this technique applies to this specific advisory
    title = str(item.get("title") or "")
    desc  = str(item.get("description") or item.get("summary") or "")
    vuln_type = str(item.get("vulnerability_type") or "")

    # Find which keywords triggered this mapping
    triggered_by = []
    combined = (title + " " + desc + " " + vuln_type).lower()
    for keyword in tech["applies_to"]:
        if re.search(re.escape(keyword.lower()), combined):
            triggered_by.append(keyword)

    justification = (
        f"Technique applies because: {', '.join(triggered_by[:3]) if triggered_by else 'CWE mapping'}. "
        f"The {tech['name']} technique is relevant because this vulnerability's "
        f"{'attack mechanism' if triggered_by else 'CWE class'} aligns with "
        f"{tech['tactic']} phase behavior described in ATT&CK v16."
    )

    observed_behavior = (
        f"Based on the vulnerability description, an adversary exploiting '{title[:80]}' "
        f"would employ {tech['name']} ({tid}) during the {tech['tactic']} phase. "
        f"The exploitation mechanism directly enables the {tech['tactic']} objective."
    )

    return {
        "technique_id":       tid,
        "technique_name":     tech["name"],
        "tactic":             tech["tactic"],
        "justification":      justification,
        "observed_behavior":  observed_behavior,
        "detection_hint":     tech["detection_hint"],
        "sigma_tag":          tech["sigma_tag"],
        "kql_example":        tech["kql_hint"],
        "match_score":        round(match_score, 3),
        "confidence":         "HIGH" if match_score > 0.5 else "MEDIUM",
        "evidence_chain":     triggered_by[:5],
        "mapping_engine":     ENGINE_ID,
        "mapping_version":    ENGINE_VERSION,
    }


def enrich_attack_mapping(item: Dict) -> Dict:
    """Add evidence-based ATT&CK mapping to an item."""
    inferred_tids = _infer_techniques(item)

    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "vulnerability_type",
    )).lower()

    # Score each technique
    technique_entries = []
    for tid in inferred_tids:
        tech = TECHNIQUE_LIBRARY.get(tid, {})
        if not tech:
            continue
        score = sum(1.0 for kw in tech["applies_to"] if re.search(re.escape(kw.lower()), all_text))
        score = score / max(1, len(tech["applies_to"]))
        technique_entries.append(_build_technique_entry(tid, item, score))

    # If no techniques inferred, DO NOT fabricate them
    if not technique_entries:
        technique_entries = [{
            "technique_id":      "UNRESOLVED",
            "technique_name":    "Insufficient evidence for ATT&CK mapping",
            "tactic":            "UNKNOWN",
            "justification":     (
                "Insufficient technical detail in the advisory to map specific ATT&CK techniques. "
                "The vulnerability description does not contain enough behavioral indicators to "
                "justify a technique assignment. Analyst review required."
            ),
            "observed_behavior": "Not determinable from available intelligence.",
            "confidence":        "NONE",
            "mapping_engine":    ENGINE_ID,
            "mapping_version":   ENGINE_VERSION,
        }]

    item_out = dict(item)
    item_out["ttps"]            = technique_entries
    item_out["ttp_count"]       = len([t for t in technique_entries if t.get("technique_id") != "UNRESOLVED"])
    item_out["attack_engine"]   = ENGINE_ID
    item_out["attack_version"]  = ENGINE_VERSION
    item_out["attack_ts"]       = datetime.now(timezone.utc).isoformat()
    return item_out


def main() -> int:
    import argparse, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [MAE] %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="APEX ATT&CK Engine v" + ENGINE_VERSION)
    parser.add_argument("--manifest", default="data/stix/feed_manifest.json")
    parser.add_argument("--output",   default=None)
    args = parser.parse_args()

    path = Path(args.manifest)
    if not path.exists():
        log.error("Not found: %s", path)
        return 1
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("items", [])
    enriched = [enrich_attack_mapping(item) for item in items]
    log.info("ATT&CK-mapped %d items", len(enriched))

    out = Path(args.output) if args.output else path
    tmp = out.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)
    tmp.replace(out)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
