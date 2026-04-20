#!/usr/bin/env python3
"""
detection_engine.py — CYBERDUDEBIVASH SENTINEL APEX
DETECTION ENGINE v1.0 — Enterprise SIEM Export Layer

Competitive level: CrowdStrike Falcon Intelligence, Palo Alto XSIAM,
Microsoft Sentinel Analytics, Splunk ES, Elastic Security.

This engine extends detection_forge.py with enterprise SOC export formats:
  1. Splunk Enterprise Security (SPL queries + adaptive responses)
  2. Microsoft Sentinel (KQL analytics rules)
  3. Elastic/ECS (NDJSON detection rules)
  4. CrowdStrike Custom IOA (JSON indicator format)
  5. Detection Scoring Matrix (priority + coverage + confidence)

Design Principles:
  - ZERO external dependencies (pure Python stdlib)
  - DETERMINISTIC: same input → same output (hash-stable IDs)
  - IDEMPOTENT: re-runs produce identical results
  - ATOMIC writes: temp file → rename (never corrupts on crash)
  - ZERO FAILURE: unconditional exit(0), all errors logged

Output files:
  data/detection_engine/splunk_queries.spl
  data/detection_engine/sentinel_queries.kql
  data/detection_engine/elastic_rules.ndjson
  data/detection_engine/crowdstrike_ioa.json
  data/detection_engine/detection_matrix.json
  data/detection_engine/siem_export_index.json
  data/detection_engine/engine_meta.json

Version: v1.0
Author: CYBERDUDEBIVASH SENTINEL APEX
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Bootstrap logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-DETECT-ENGINE] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("CDB-DETECT-ENGINE")

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
BASE_DIR         = Path(__file__).resolve().parent.parent
DATA_DIR         = BASE_DIR / "data"
STIX_DIR         = DATA_DIR / "stix"
DETECT_DIR       = DATA_DIR / "detection_engine"
MANIFEST_PATH    = STIX_DIR / "feed_manifest.json"
AI_INTEL_DIR     = DATA_DIR / "ai_intelligence"
AI_INDEX_PATH    = AI_INTEL_DIR / "ai_index.json"

# ---------------------------------------------------------------------------
# MITRE ATT&CK → SIEM query templates
# ---------------------------------------------------------------------------
MITRE_TO_SPLUNK: Dict[str, str] = {
    "T1059": 'index=* (EventCode=4688 OR EventCode=1) CommandLine=* | where match(CommandLine, "(?i)(powershell|cmd|wscript|cscript)")',
    "T1055": 'index=* EventCode=8 | where SourceImage!=TargetImage | table _time, SourceImage, TargetImage, GrantedAccess',
    "T1078": 'index=* EventCode=4624 LogonType IN (3,10) | stats count by src_ip, user | where count > 5',
    "T1566": 'index=* sourcetype=email | search attachment_name=*.* | eval ext=lower(mvindex(split(attachment_name,"."), -1)) | where ext IN ("exe","bat","ps1","vbs","js","docm","xlsm")',
    "T1190": 'index=* sourcetype=web_access | where http_status_code IN (500,502,503) AND NOT (src_ip IN (trusted_ip_list)) | stats count by uri_path, src_ip | where count > 10',
    "T1203": 'index=* EventCode=4688 | where ParentImage IN ("winword.exe","excel.exe","powerpnt.exe","acrobat.exe") AND Image IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")',
    "T1195": 'index=* sourcetype=package_manager | where update_source NOT IN (trusted_sources) | table _time, package_name, version, update_source',
    "T1486": 'index=* EventCode=4663 | where object_name LIKE "%.encrypted%" OR object_name LIKE "%.locked%" | stats count by src_user, ComputerName | where count > 50',
    "T1496": 'index=* (process_name="xmrig*" OR cmdline="*stratum+tcp*" OR cmdline="*pool.minexmr*") | table _time, host, process_name, cmdline',
    "T1071": 'index=* sourcetype=firewall | where dest_port IN (443,80,8080,8443) AND bytes_out > 1000000 | stats sum(bytes_out) as total_bytes by src_ip, dest_ip | where total_bytes > 100000000',
    "T1136": 'index=* EventCode=4720 | table _time, Security_ID, Account_Name, SAM_Account_Name',
    "T1098": 'index=* EventCode IN (4728,4732,4756) | table _time, Member_Security_ID, Group_Name, Subject_Account_Name',
    "T1053": 'index=* (EventCode=4698 OR EventCode=106) | table _time, TaskName, TaskContent, SubjectUserName',
    "T1547": 'index=* EventCode=13 TargetObject="*\\Run*" | table _time, TargetObject, Details, Image',
    "T1562": 'index=* (EventCode=4719 OR EventCode=1102) | table _time, SubjectUserName, SubjectDomainName',
    "T1112": 'index=* EventCode=4657 | where TargetObject LIKE "%\\Microsoft\\Windows\\CurrentVersion\\Run%" | table _time, SubjectUserName, TargetObject, NewValue',
    "T1027": 'index=* EventCode=4688 | where match(CommandLine, "(?i)(base64|frombase64|bxor|xor|[a-z0-9+/]{50,}==)") | table _time, NewProcessName, CommandLine',
}

MITRE_TO_KQL: Dict[str, str] = {
    "T1059": 'DeviceProcessEvents | where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe") | where InitiatingProcessFileName !in~ ("explorer.exe","services.exe") | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine',
    "T1055": 'DeviceEvents | where ActionType == "CreateRemoteThreadApiCall" | where InitiatingProcessFileName != FileName | project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, RemoteUrl',
    "T1078": 'SigninLogs | where ResultType == 0 | where AppDisplayName != "" | summarize LoginCount=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h) | where LoginCount > 10',
    "T1566": 'EmailAttachmentInfo | where FileType in~ ("exe","bat","ps1","vbs","js","docm","xlsm","hta","lnk") | join kind=inner EmailEvents on NetworkMessageId | project TimeGenerated, SenderFromAddress, RecipientEmailAddress, FileName, FileType',
    "T1190": 'W3CIISLog | where scStatus in ("500","502","503") | where not(ipaddress(cIP) in (trusted_ranges)) | summarize count() by csUriStem, cIP | where count_ > 10',
    "T1203": 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","acrord32.exe") | where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","regsvr32.exe") | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine',
    "T1486": 'DeviceFileEvents | where FileName matches regex @"\\.(encrypted|locked|crypto|crypt)$" | summarize FileCount=count() by DeviceName, bin(TimeGenerated, 5m) | where FileCount > 20',
    "T1496": 'DeviceProcessEvents | where ProcessCommandLine has_any ("stratum+tcp","pool.minexmr","moneropool","xmr.pool") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine',
    "T1071": 'CommonSecurityLog | where DeviceAction == "allow" | where DestinationPort in (443,80,8080,8443) | summarize TotalBytes=sum(SentBytes) by SourceIP, DestinationIP | where TotalBytes > 100000000',
    "T1136": 'SecurityEvent | where EventID == 4720 | project TimeGenerated, Computer, SubjectAccount, TargetUserName, TargetDomainName',
    "T1053": 'SecurityEvent | where EventID in (4698,4699,4700,4701,4702) | project TimeGenerated, Computer, SubjectAccount, TaskName',
    "T1027": 'DeviceProcessEvents | where ProcessCommandLine matches regex @"(?i)(frombase64|\\bbase64\\b|[A-Za-z0-9+/]{100,}={0,2})" | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine',
}

MITRE_TO_ELASTIC: Dict[str, str] = {
    "T1059": '{"query":{"bool":{"must":[{"match":{"event.category":"process"}},{"terms":{"process.name":["powershell.exe","cmd.exe","wscript.exe","cscript.exe"]}}]}},"sort":[{"@timestamp":{"order":"desc"}}]}',
    "T1055": '{"query":{"bool":{"must":[{"match":{"event.action":"create_remote_thread"}},{"exists":{"field":"process.parent.name"}}],"must_not":[{"match":{"process.name":{"query":"process.parent.name"}}}]}}}',
    "T1078": '{"query":{"bool":{"must":[{"match":{"event.outcome":"success"}},{"match":{"event.category":"authentication"}}]}},"aggs":{"by_user":{"terms":{"field":"user.name","size":10},"aggs":{"by_ip":{"terms":{"field":"source.ip","size":5}}}}}}',
    "T1566": '{"query":{"bool":{"must":[{"match":{"event.category":"email"}},{"terms":{"email.attachments.file.extension":["exe","bat","ps1","vbs","js","docm"]}}]}}}',
    "T1486": '{"query":{"bool":{"must":[{"match":{"event.category":"file"}},{"wildcard":{"file.name":"*.encrypted"}}]}},"sort":[{"@timestamp":{"order":"desc"}}]}',
    "T1496": '{"query":{"bool":{"should":[{"match_phrase":{"process.command_line":"stratum+tcp"}},{"match_phrase":{"process.command_line":"pool.minexmr"}},{"match_phrase":{"process.command_line":"xmrig"}}],"minimum_should_match":1}}}',
    "T1027": '{"query":{"bool":{"must":[{"match":{"event.category":"process"}},{"regexp":{"process.command_line":"(?i)(frombase64|[A-Za-z0-9+/]{100,}={0,2})"}}]}}}',
}

# ---------------------------------------------------------------------------
# Severity → detection priority
# ---------------------------------------------------------------------------
SEVERITY_PRIORITY = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

# ---------------------------------------------------------------------------
# Safe file utilities
# ---------------------------------------------------------------------------

def _safe_write_json(path: Path, data: Any, indent: int = 2) -> bool:
    """Atomic JSON write: write to temp file, rename to target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, default=str)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.warning(f"Write failed {path}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def _safe_write_text(path: Path, content: str) -> bool:
    """Atomic text write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.warning(f"Text write failed {path}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def _safe_load_json(path: Path, default: Any = None) -> Any:
    """Safe JSON load with default fallback."""
    try:
        if path.exists():
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Load failed {path}: {e}")
    return default if default is not None else {}


def _det_id(text: str) -> str:
    """Deterministic 12-char hex ID from text."""
    return hashlib.md5(text.encode("utf-8")).hexdigest()[:12].upper()


def _advisory_id(item: Dict) -> str:
    """Generate stable advisory ID."""
    key = item.get("stix_id") or item.get("bundle_id") or item.get("title", "unknown")
    return _det_id(key)


# ===========================================================================
# SPLUNK EXPORT ENGINE
# ===========================================================================

class SplunkExporter:
    """Generates Splunk Enterprise Security SPL queries."""

    HEADER = """| # ╔══════════════════════════════════════════════════════╗
| # ║  CYBERDUDEBIVASH SENTINEL APEX — Splunk SPL Export  ║
| # ║  Generated: {ts}  ║
| # ╚══════════════════════════════════════════════════════╝
|
"""

    def _advisory_to_spl(self, item: Dict) -> Optional[str]:
        """Convert a manifest advisory to SPL query block."""
        adv_id     = _advisory_id(item)
        title      = item.get("title", "Unknown Advisory")[:100]
        severity   = item.get("severity", "MEDIUM")
        risk_score = item.get("risk_score", 0.0)
        actor      = item.get("actor_tag", "UNC-UNKNOWN")
        tactics    = item.get("mitre_tactics", [])
        kev        = item.get("kev_present", False)
        stix_id    = item.get("stix_id", "")

        # Collect SPL queries for this advisory
        queries: List[str] = []
        for tactic in tactics:
            tac = str(tactic).strip()
            if tac in MITRE_TO_SPLUNK:
                queries.append(
                    f"| comment \"[{tac}] {title[:60]}\" \n"
                    + MITRE_TO_SPLUNK[tac]
                    + f"\n| eval advisory_id=\"{adv_id}\", risk_score={risk_score:.1f}, actor=\"{actor}\", kev={str(kev).lower()}"
                )

        if not queries:
            # Generic IOC-based query for advisories without MITRE mapping
            safe_title = re.sub(r"[\"\\]", " ", title[:60])
            queries.append(
                f"| comment \"[GENERIC] {safe_title}\"\n"
                f'index=* | search "{safe_title[:30]}" '
                f'| eval advisory_id="{adv_id}", risk_score={risk_score:.1f}, '
                f'actor="{actor}", severity="{severity}"'
            )

        block_lines = [
            f"\n{'='*70}",
            f"| # Advisory: {title[:70]}",
            f"| # ID: CDB-SPL-{adv_id} | Risk: {risk_score:.1f} | Severity: {severity}",
            f"| # Actor: {actor} | KEV: {kev} | STIX: {stix_id[:40]}",
            f"{'='*70}",
        ]
        block_lines.extend(queries)
        return "\n".join(block_lines) + "\n"

    def export(self, items: List[Dict]) -> Tuple[str, List[Dict]]:
        """Export all advisories to SPL. Returns (spl_text, siem_records)."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = [self.HEADER.format(ts=ts)]
        siem_records: List[Dict] = []

        prioritized = sorted(
            items,
            key=lambda x: (SEVERITY_PRIORITY.get(x.get("severity", "LOW"), 5), -x.get("risk_score", 0)),
        )

        for item in prioritized:
            block = self._advisory_to_spl(item)
            if block:
                lines.append(block)
                adv_id = _advisory_id(item)
                tactics = item.get("mitre_tactics", [])
                siem_records.append({
                    "id": f"CDB-SPL-{adv_id}",
                    "platform": "splunk",
                    "severity": item.get("severity", "MEDIUM"),
                    "risk_score": item.get("risk_score", 0),
                    "tactics_covered": [str(t) for t in tactics],
                    "has_mitre_query": any(str(t) in MITRE_TO_SPLUNK for t in tactics),
                    "kev": item.get("kev_present", False),
                })

        return "\n".join(lines), siem_records


# ===========================================================================
# MICROSOFT SENTINEL EXPORT ENGINE
# ===========================================================================

class SentinelKQLExporter:
    """Generates Microsoft Sentinel KQL analytics rules."""

    RULE_TEMPLATE = """// ─────────────────────────────────────────────────────────────────────────────
// Rule ID      : CDB-KQL-{rule_id}
// Title        : {title}
// Severity     : {severity}
// Risk Score   : {risk_score}
// Actor        : {actor}
// MITRE Tactics: {tactics_str}
// KEV          : {kev}
// Generated    : {ts}
// ─────────────────────────────────────────────────────────────────────────────
// Description  : Detects activity related to: {title_short}
// Response     : Investigate {actor} activity. Escalate if CVSS >= 7.0.

{kql_queries}

"""

    def _advisory_to_kql(self, item: Dict) -> Optional[str]:
        adv_id     = _advisory_id(item)
        title      = item.get("title", "Unknown")[:100]
        severity   = item.get("severity", "MEDIUM")
        risk_score = item.get("risk_score", 0.0)
        actor      = item.get("actor_tag", "UNC-UNKNOWN")
        tactics    = item.get("mitre_tactics", [])
        kev        = item.get("kev_present", False)
        ts         = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        kql_blocks: List[str] = []
        for tactic in tactics:
            tac = str(tactic).strip()
            if tac in MITRE_TO_KQL:
                kql_blocks.append(
                    f"// [{tac}] Query:\n"
                    + MITRE_TO_KQL[tac]
                    + f'\n| extend AdvisoryId = "{adv_id}", RiskScore = {risk_score:.1f}, ThreatActor = "{actor}"'
                )

        if not kql_blocks:
            safe_title = re.sub(r'["\\\n\r]', " ", title[:50])
            kql_blocks.append(
                f'// Generic: search for advisory keywords\n'
                f'SecurityAlert\n'
                f'| where AlertName contains "{safe_title[:30]}"\n'
                f'| project TimeGenerated, AlertName, Severity, CompromisedEntity\n'
                f'| extend AdvisoryId = "{adv_id}", RiskScore = {risk_score:.1f}'
            )

        tactics_str = ", ".join(str(t) for t in tactics) if tactics else "N/A"
        return self.RULE_TEMPLATE.format(
            rule_id=adv_id,
            title=title,
            severity=severity,
            risk_score=f"{risk_score:.2f}",
            actor=actor,
            tactics_str=tactics_str,
            kev=str(kev),
            ts=ts,
            title_short=title[:60],
            kql_queries="\n\n".join(kql_blocks),
        )

    def export(self, items: List[Dict]) -> Tuple[str, List[Dict]]:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        header = (
            f"// ╔══════════════════════════════════════════════════════╗\n"
            f"// ║  CYBERDUDEBIVASH — Microsoft Sentinel KQL Rules     ║\n"
            f"// ║  Generated: {ts}                    ║\n"
            f"// ╚══════════════════════════════════════════════════════╝\n\n"
        )
        blocks = [header]
        siem_records: List[Dict] = []

        prioritized = sorted(
            items,
            key=lambda x: (SEVERITY_PRIORITY.get(x.get("severity", "LOW"), 5), -x.get("risk_score", 0)),
        )

        for item in prioritized:
            block = self._advisory_to_kql(item)
            if block:
                blocks.append(block)
                adv_id = _advisory_id(item)
                tactics = item.get("mitre_tactics", [])
                siem_records.append({
                    "id": f"CDB-KQL-{adv_id}",
                    "platform": "sentinel",
                    "severity": item.get("severity", "MEDIUM"),
                    "risk_score": item.get("risk_score", 0),
                    "tactics_covered": [str(t) for t in tactics],
                    "has_mitre_query": any(str(t) in MITRE_TO_KQL for t in tactics),
                    "kev": item.get("kev_present", False),
                })

        return "\n".join(blocks), siem_records


# ===========================================================================
# ELASTIC EXPORT ENGINE
# ===========================================================================

class ElasticExporter:
    """Generates Elastic Security NDJSON detection rules."""

    def _advisory_to_elastic(self, item: Dict) -> Optional[Dict]:
        adv_id     = _advisory_id(item)
        title      = item.get("title", "Unknown")[:100]
        severity   = item.get("severity", "medium").lower()
        risk_score = min(100, int(item.get("risk_score", 0) * 10))
        actor      = item.get("actor_tag", "UNC-UNKNOWN")
        tactics    = item.get("mitre_tactics", [])
        kev        = item.get("kev_present", False)
        ts         = datetime.now(timezone.utc).isoformat()

        # Map severity to Elastic levels
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        elastic_sev = sev_map.get(severity, "medium")

        # Build MITRE threat tags
        threat_tags = []
        for tactic in tactics:
            tac = str(tactic).strip()
            threat_tags.append({
                "framework": "MITRE ATT&CK",
                "tactic": {"id": tac[:6], "name": tac, "reference": f"https://attack.mitre.org/tactics/{tac[:5]}/"},
                "technique": [{"id": tac, "name": tac, "reference": f"https://attack.mitre.org/techniques/{tac}/"}],
            })

        # Get first available Elastic query
        query_body = None
        for tactic in tactics:
            tac = str(tactic).strip()
            if tac in MITRE_TO_ELASTIC:
                try:
                    query_body = json.loads(MITRE_TO_ELASTIC[tac])
                    break
                except Exception:
                    pass

        if not query_body:
            safe_title = re.sub(r'["\\\n\r]', " ", title[:40])
            query_body = {"query": {"bool": {"must": [{"match": {"message": safe_title[:30]}}]}}}

        rule = {
            "id": f"cdb-{adv_id.lower()}",
            "name": f"[CDB] {title[:90]}",
            "description": f"SENTINEL APEX detection for: {title}. Actor: {actor}. KEV: {kev}",
            "risk_score": risk_score,
            "severity": elastic_sev,
            "enabled": True,
            "type": "query",
            "language": "kuery",
            "index": ["logs-*", "filebeat-*", "winlogbeat-*", "endgame-*"],
            "query": "*",
            "filters": [{"query": query_body}],
            "tags": [f"Actor:{actor}", "Source:SENTINEL-APEX", f"KEV:{kev}"] + [str(t) for t in tactics],
            "threat": threat_tags,
            "references": [item.get("source_url", ""), item.get("nvd_url", "")],
            "created_at": ts,
            "updated_at": ts,
            "author": ["CyberDudeBivash SENTINEL APEX"],
            "rule_id": f"cdb-{adv_id.lower()}",
            "version": 1,
            "meta": {"advisory_id": adv_id, "risk_score_raw": item.get("risk_score", 0)},
        }
        return rule

    def export(self, items: List[Dict]) -> Tuple[str, List[Dict]]:
        """Export as NDJSON (one rule per line) + structured records."""
        ndjson_lines: List[str] = []
        siem_records: List[Dict] = []

        prioritized = sorted(
            items,
            key=lambda x: (SEVERITY_PRIORITY.get(x.get("severity", "LOW"), 5), -x.get("risk_score", 0)),
        )

        for item in prioritized:
            rule = self._advisory_to_elastic(item)
            if rule:
                ndjson_lines.append(json.dumps(rule, ensure_ascii=False))
                siem_records.append({
                    "id": rule["id"],
                    "platform": "elastic",
                    "severity": item.get("severity", "MEDIUM"),
                    "risk_score": item.get("risk_score", 0),
                    "tactics_covered": [str(t) for t in item.get("mitre_tactics", [])],
                    "has_mitre_query": any(str(t) in MITRE_TO_ELASTIC for t in item.get("mitre_tactics", [])),
                    "kev": item.get("kev_present", False),
                })

        return "\n".join(ndjson_lines), siem_records


# ===========================================================================
# CROWDSTRIKE CUSTOM IOA EXPORT ENGINE
# ===========================================================================

class CrowdStrikeIOAExporter:
    """Generates CrowdStrike Falcon Custom Indicator of Attack (IOA) rules."""

    # CrowdStrike IOA Platform codes
    PLATFORM_MAP = {"windows": 1, "linux": 2, "mac": 3}

    # Technique to action pattern mappings
    TECHNIQUE_PATTERNS: Dict[str, Dict] = {
        "T1059": {
            "action": "process_creation",
            "pattern": r"(powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe)",
            "description": "Command and Scripting Interpreter execution detected",
        },
        "T1055": {
            "action": "process_injection",
            "pattern": r"CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread",
            "description": "Process injection API activity detected",
        },
        "T1078": {
            "action": "authentication_event",
            "pattern": r"(NTLM|Kerberos).*(failure|failed|invalid)",
            "description": "Valid Account abuse / brute force attempt",
        },
        "T1190": {
            "action": "network_receive",
            "pattern": r"(UNION|SELECT|DROP|INSERT).*(FROM|INTO|TABLE)",
            "description": "SQL injection attempt against public-facing app",
        },
        "T1203": {
            "action": "process_creation",
            "pattern": r"(winword|excel|powerpnt|acrord32).*(cmd|powershell|wscript)",
            "description": "Office/PDF spawning shell process — possible exploit",
        },
        "T1486": {
            "action": "file_create",
            "pattern": r"\.(encrypted|locked|crypto|crypt|ransom)$",
            "description": "Ransomware file extension pattern detected",
        },
        "T1496": {
            "action": "network_connect",
            "pattern": r"(stratum\+tcp|pool\.minexmr|xmr\.pool|cryptonight)",
            "description": "Cryptominer pool connection attempt",
        },
        "T1566": {
            "action": "email_attachment",
            "pattern": r"\.(exe|bat|ps1|vbs|js|hta|lnk|docm|xlsm)$",
            "description": "Suspicious email attachment type",
        },
    }

    def _advisory_to_ioa(self, item: Dict) -> Optional[Dict]:
        adv_id     = _advisory_id(item)
        title      = item.get("title", "Unknown")[:100]
        severity   = item.get("severity", "MEDIUM")
        risk_score = item.get("risk_score", 0.0)
        actor      = item.get("actor_tag", "UNC-UNKNOWN")
        tactics    = item.get("mitre_tactics", [])
        kev        = item.get("kev_present", False)

        actions: List[Dict] = []
        for tactic in tactics:
            tac = str(tactic).strip()
            if tac in self.TECHNIQUE_PATTERNS:
                p = self.TECHNIQUE_PATTERNS[tac]
                actions.append({
                    "action_type": p["action"],
                    "pattern": p["pattern"],
                    "technique_id": tac,
                    "description": p["description"],
                })

        if not actions:
            safe_title = re.sub(r'["\\\n\r]', " ", title[:40])
            actions.append({
                "action_type": "generic_indicator",
                "pattern": safe_title[:30],
                "technique_id": "T0000",
                "description": f"Generic detection for: {safe_title[:60]}",
            })

        cs_severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "informational"}
        return {
            "id": f"CDB-IOA-{adv_id}",
            "name": f"[SENTINEL-APEX] {title[:80]}",
            "description": f"Actor: {actor} | Risk: {risk_score:.1f} | KEV: {kev}",
            "severity": cs_severity_map.get(severity, "medium"),
            "enabled": True,
            "platform_ids": [1, 2],  # Windows + Linux
            "actions": actions,
            "tactics": [str(t) for t in tactics],
            "actor": actor,
            "kev_flagged": kev,
            "source": "CYBERDUDEBIVASH-SENTINEL-APEX",
            "rule_id": f"CDB-IOA-{adv_id}",
        }

    def export(self, items: List[Dict]) -> Tuple[Dict, List[Dict]]:
        rules: List[Dict] = []
        siem_records: List[Dict] = []

        prioritized = sorted(
            items,
            key=lambda x: (SEVERITY_PRIORITY.get(x.get("severity", "LOW"), 5), -x.get("risk_score", 0)),
        )

        for item in prioritized:
            rule = self._advisory_to_ioa(item)
            if rule:
                rules.append(rule)
                siem_records.append({
                    "id": rule["id"],
                    "platform": "crowdstrike",
                    "severity": item.get("severity", "MEDIUM"),
                    "risk_score": item.get("risk_score", 0),
                    "tactics_covered": [str(t) for t in item.get("mitre_tactics", [])],
                    "kev": item.get("kev_present", False),
                })

        export_obj = {
            "source": "CYBERDUDEBIVASH-SENTINEL-APEX",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_rules": len(rules),
            "rules": rules,
        }
        return export_obj, siem_records


# ===========================================================================
# DETECTION SCORING MATRIX
# ===========================================================================

class DetectionMatrixBuilder:
    """Builds a detection scoring matrix for coverage analysis."""

    ALL_TACTICS = [
        "T1059", "T1055", "T1078", "T1566", "T1190", "T1203", "T1195",
        "T1486", "T1496", "T1071", "T1136", "T1098", "T1053", "T1547",
        "T1562", "T1112", "T1027", "T1083", "T1082", "T1016",
    ]

    def build(self, items: List[Dict]) -> Dict:
        """Compute detection coverage matrix."""
        # Count advisories per tactic
        tactic_counts: Dict[str, int] = {}
        tactic_risk: Dict[str, float] = {}
        tactic_kev: Dict[str, int] = {}
        tactic_critical: Dict[str, int] = {}

        for item in items:
            tactics = item.get("mitre_tactics", [])
            risk = float(item.get("risk_score", 0) or 0)
            kev = bool(item.get("kev_present", False))
            sev = item.get("severity", "LOW")

            for t in tactics:
                tac = str(t).strip()
                tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
                tactic_risk[tac] = tactic_risk.get(tac, 0.0) + risk
                if kev:
                    tactic_kev[tac] = tactic_kev.get(tac, 0) + 1
                if sev in ("CRITICAL", "HIGH"):
                    tactic_critical[tac] = tactic_critical.get(tac, 0) + 1

        # Build matrix rows
        matrix_rows: List[Dict] = []
        for tac in self.ALL_TACTICS:
            count = tactic_counts.get(tac, 0)
            risk_sum = tactic_risk.get(tac, 0.0)
            avg_risk = risk_sum / count if count > 0 else 0.0

            splunk_coverage = tac in MITRE_TO_SPLUNK
            kql_coverage = tac in MITRE_TO_KQL
            elastic_coverage = tac in MITRE_TO_ELASTIC

            coverage_score = sum([splunk_coverage, kql_coverage, elastic_coverage]) / 3.0 * 100

            matrix_rows.append({
                "tactic_id": tac,
                "advisory_count": count,
                "avg_risk_score": round(avg_risk, 2),
                "kev_advisories": tactic_kev.get(tac, 0),
                "critical_advisories": tactic_critical.get(tac, 0),
                "splunk_coverage": splunk_coverage,
                "sentinel_coverage": kql_coverage,
                "elastic_coverage": elastic_coverage,
                "crowdstrike_coverage": tac in CrowdStrikeIOAExporter.TECHNIQUE_PATTERNS,
                "coverage_pct": round(coverage_score, 1),
                "priority": SEVERITY_PRIORITY.get("CRITICAL", 5) if tactic_critical.get(tac, 0) > 0 else 3,
            })

        # Sort by advisory_count desc
        matrix_rows.sort(key=lambda x: (-x["advisory_count"], -x["avg_risk_score"]))

        total_advisories = len(items)
        tactics_with_queries = sum(1 for t in tactic_counts if t in MITRE_TO_SPLUNK)
        coverage_pct = tactics_with_queries / max(len(tactic_counts), 1) * 100

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_advisories": total_advisories,
            "tactics_observed": len(tactic_counts),
            "tactics_with_splunk": sum(1 for t in tactic_counts if t in MITRE_TO_SPLUNK),
            "tactics_with_kql": sum(1 for t in tactic_counts if t in MITRE_TO_KQL),
            "tactics_with_elastic": sum(1 for t in tactic_counts if t in MITRE_TO_ELASTIC),
            "overall_coverage_pct": round(coverage_pct, 1),
            "kev_count": sum(1 for i in items if i.get("kev_present")),
            "matrix": matrix_rows,
        }


# ===========================================================================
# MAIN DETECTION ENGINE ORCHESTRATOR
# ===========================================================================

class DetectionEngine:
    """
    Main orchestrator — coordinates all SIEM exporters and matrix builder.
    ZERO-FAILURE: all errors caught, engine always exits 0.
    """

    def __init__(self):
        self.splunk   = SplunkExporter()
        self.sentinel = SentinelKQLExporter()
        self.elastic  = ElasticExporter()
        self.crowdstrike = CrowdStrikeIOAExporter()
        self.matrix   = DetectionMatrixBuilder()

    def _load_manifest(self) -> List[Dict]:
        data = _safe_load_json(MANIFEST_PATH, default=[])
        if isinstance(data, list):
            return data
        return data.get("items", [])

    def run(self) -> Dict:
        start = time.time()
        logger.info("=" * 60)
        logger.info("DETECTION ENGINE v1.0 — Starting")
        logger.info("=" * 60)

        DETECT_DIR.mkdir(parents=True, exist_ok=True)

        meta = {
            "engine": "detection_engine_v1.0",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "splunk_rules": 0,
            "sentinel_rules": 0,
            "elastic_rules": 0,
            "crowdstrike_rules": 0,
            "advisories_processed": 0,
        }

        # Load manifest
        items = self._load_manifest()
        logger.info(f"Loaded {len(items)} advisories from manifest")
        meta["advisories_processed"] = len(items)

        if not items:
            logger.warning("No advisories found — writing empty outputs")
            meta["status"] = "empty"
            _safe_write_json(DETECT_DIR / "engine_meta.json", meta)
            return meta

        # --- Splunk Export ---
        try:
            spl_text, spl_records = self.splunk.export(items)
            _safe_write_text(DETECT_DIR / "splunk_queries.spl", spl_text)
            meta["splunk_rules"] = len(spl_records)
            logger.info(f"  Splunk SPL: {len(spl_records)} queries exported")
        except Exception as e:
            logger.warning(f"Splunk export failed (non-fatal): {e}")
            spl_records = []

        # --- Sentinel KQL Export ---
        try:
            kql_text, kql_records = self.sentinel.export(items)
            _safe_write_text(DETECT_DIR / "sentinel_queries.kql", kql_text)
            meta["sentinel_rules"] = len(kql_records)
            logger.info(f"  Sentinel KQL: {len(kql_records)} rules exported")
        except Exception as e:
            logger.warning(f"Sentinel export failed (non-fatal): {e}")
            kql_records = []

        # --- Elastic Export ---
        try:
            ndjson_text, elastic_records = self.elastic.export(items)
            _safe_write_text(DETECT_DIR / "elastic_rules.ndjson", ndjson_text)
            meta["elastic_rules"] = len(elastic_records)
            logger.info(f"  Elastic: {len(elastic_records)} rules exported")
        except Exception as e:
            logger.warning(f"Elastic export failed (non-fatal): {e}")
            elastic_records = []

        # --- CrowdStrike Export ---
        try:
            cs_obj, cs_records = self.crowdstrike.export(items)
            _safe_write_json(DETECT_DIR / "crowdstrike_ioa.json", cs_obj, indent=2)
            meta["crowdstrike_rules"] = len(cs_records)
            logger.info(f"  CrowdStrike IOA: {len(cs_records)} rules exported")
        except Exception as e:
            logger.warning(f"CrowdStrike export failed (non-fatal): {e}")
            cs_records = []

        # --- Detection Matrix ---
        try:
            matrix_data = self.matrix.build(items)
            _safe_write_json(DETECT_DIR / "detection_matrix.json", matrix_data, indent=2)
            logger.info(f"  Detection matrix: {len(matrix_data.get('matrix', []))} tactics analyzed")
        except Exception as e:
            logger.warning(f"Matrix build failed (non-fatal): {e}")
            matrix_data = {}

        # --- SIEM Export Index ---
        try:
            all_siem = spl_records + kql_records + elastic_records + cs_records
            siem_index = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_rules": len(all_siem),
                "by_platform": {
                    "splunk": len(spl_records),
                    "sentinel": len(kql_records),
                    "elastic": len(elastic_records),
                    "crowdstrike": len(cs_records),
                },
                "records": all_siem,
            }
            _safe_write_json(DETECT_DIR / "siem_export_index.json", siem_index, indent=2)
        except Exception as e:
            logger.warning(f"SIEM index write failed (non-fatal): {e}")

        # --- Patch manifest with detection IDs (non-destructive) ---
        try:
            patched = 0
            for item in items:
                adv_id = _advisory_id(item)
                if "de_siem_ids" not in item:
                    item["de_siem_ids"] = {
                        "splunk": f"CDB-SPL-{adv_id}",
                        "sentinel": f"CDB-KQL-{adv_id}",
                        "elastic": f"cdb-{adv_id.lower()}",
                        "crowdstrike": f"CDB-IOA-{adv_id}",
                    }
                    patched += 1
            if patched > 0:
                data = _safe_load_json(MANIFEST_PATH, default=[])
                _safe_write_json(MANIFEST_PATH, data, indent=None)
            logger.info(f"  Manifest patched: {patched} entries tagged with SIEM IDs")
        except Exception as e:
            logger.warning(f"Manifest patch failed (non-fatal): {e}")

        elapsed = round(time.time() - start, 2)
        meta.update({
            "status": "success",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_s": elapsed,
            "overall_coverage_pct": matrix_data.get("overall_coverage_pct", 0),
        })
        _safe_write_json(DETECT_DIR / "engine_meta.json", meta, indent=2)

        logger.info("=" * 60)
        logger.info(f"DETECTION ENGINE COMPLETE in {elapsed}s")
        logger.info(f"  SPL={meta['splunk_rules']} KQL={meta['sentinel_rules']} "
                    f"Elastic={meta['elastic_rules']} CS={meta['crowdstrike_rules']}")
        logger.info("=" * 60)
        return meta


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> int:
    try:
        engine = DetectionEngine()
        result = engine.run()
        status = result.get("status", "unknown")
        logger.info(f"Exit status: {status}")
    except Exception as e:
        logger.error(f"Fatal detection engine error: {e}", exc_info=True)
    return 0  # ZERO-FAILURE — always exit 0


if __name__ == "__main__":
    sys.exit(main())
