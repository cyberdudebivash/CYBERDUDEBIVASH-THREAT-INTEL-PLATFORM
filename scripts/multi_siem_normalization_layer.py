#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/multi_siem_normalization_layer.py — Multi-SIEM Compatibility Layer v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Normalizes Sigma detection rules into 11 target SIEM/EDR query formats.
  Provides field name mapping, logsource translation, and platform-specific
  syntax generation with enterprise deployment packages.

SUPPORTED TARGETS:
  1. Microsoft Sentinel (KQL)
  2. Splunk Enterprise Security (SPL)
  3. Elastic SIEM (EQL + Lucene)
  4. IBM QRadar (AQL)
  5. Google Chronicle (YARA-L + UDM)
  6. CrowdStrike Falcon (NG-SIEM EQL)
  7. SentinelOne (Power Query)
  8. Suricata IDS (from network sigma rules)
  9. Falco (for cloud/container)
  10. OSQuery (for endpoint fleet)
  11. STIX Indicator Pattern (portable)
================================================================================
"""
from __future__ import annotations
import hashlib,json,logging,re
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-MSNL"
log = logging.getLogger("apex.multi_siem")

# ── Field Mappings per SIEM ────────────────────────────────────────────────
SIGMA_TO_KQL = {
    "ProcessId":              "ProcessId",
    "Image":                  "FileName",
    "CommandLine":            "ProcessCommandLine",
    "ParentImage":            "InitiatingProcessFileName",
    "ParentCommandLine":      "InitiatingProcessCommandLine",
    "User":                   "AccountName",
    "Computer":               "DeviceName",
    "DestinationIp":          "RemoteIP",
    "DestinationPort":        "RemotePort",
    "SourceIp":               "LocalIP",
    "TargetFilename":         "FileName",
    "EventID":                "ActionType",
    "RegistryKey":            "RegistryKey",
    "RegistryValue":          "RegistryValueName",
    "RegistryValueData":      "RegistryValueData",
    "cs-uri-query":           "RequestUri",
    "cs-uri-stem":            "RequestUri",
    "sc-status":              "ResponseCode",
    "c-ip":                   "ClientIP",
    "TargetUserName":         "TargetAccountName",
    "SubjectUserName":        "AccountName",
    "LogonType":              "LogonType",
    "ProcessCommandLine":     "ProcessCommandLine",
    "sha256":                 "SHA256",
    "md5":                    "MD5",
}

SIGMA_TO_SPL = {
    "ProcessId":              "ProcessId",
    "Image":                  "process_name",
    "CommandLine":            "CommandLine",
    "ParentImage":            "ParentProcessName",
    "ParentCommandLine":      "ParentCommandLine",
    "User":                   "user",
    "Computer":               "ComputerName",
    "DestinationIp":          "dest_ip",
    "DestinationPort":        "dest_port",
    "SourceIp":               "src_ip",
    "TargetFilename":         "file_name",
    "cs-uri-query":           "uri_query",
    "cs-uri-stem":            "uri_path",
    "sc-status":              "status",
    "c-ip":                   "clientip",
    "sha256":                 "file_hash",
    "md5":                    "file_hash",
    "RegistryKey":            "registry_key_name",
    "RegistryValue":          "registry_value_name",
}

SIGMA_TO_ELASTIC = {
    "ProcessId":              "process.pid",
    "Image":                  "process.name",
    "CommandLine":            "process.command_line",
    "ParentImage":            "process.parent.name",
    "ParentCommandLine":      "process.parent.command_line",
    "User":                   "user.name",
    "Computer":               "host.name",
    "DestinationIp":          "destination.ip",
    "DestinationPort":        "destination.port",
    "SourceIp":               "source.ip",
    "TargetFilename":         "file.name",
    "cs-uri-query":           "url.query",
    "cs-uri-stem":            "url.path",
    "sc-status":              "http.response.status_code",
    "c-ip":                   "client.ip",
    "sha256":                 "file.hash.sha256",
    "md5":                    "file.hash.md5",
    "RegistryKey":            "registry.key",
    "RegistryValue":          "registry.value.name",
}

LOGSOURCE_TO_PLATFORM = {
    "process_creation": {
        "kql":      "DeviceProcessEvents",
        "spl":      'index=windows sourcetype=WinEventLog:Security EventCode=4688',
        "elastic":  "process",
        "qradar":   "events WHERE category = 'Process Created'",
        "falco":    "syscall",
        "osquery":  "process_events",
    },
    "network_connection": {
        "kql":      "DeviceNetworkEvents",
        "spl":      'index=network sourcetype=stream:tcp',
        "elastic":  "network",
        "qradar":   "flows",
        "suricata": "tcp/udp any any -> any any",
    },
    "file_event": {
        "kql":      "DeviceFileEvents",
        "spl":      'index=windows sourcetype=WinEventLog:Security EventCode=4663',
        "elastic":  "file",
        "osquery":  "file_events",
        "falco":    "syscall",
    },
    "registry_event": {
        "kql":      "DeviceRegistryEvents",
        "spl":      'index=windows sourcetype=WinEventLog:Security EventCode=4657',
        "elastic":  "registry",
    },
    "dns_query": {
        "kql":      "DnsEvents | union DeviceNetworkEvents",
        "spl":      'index=network sourcetype=stream:dns',
        "elastic":  "dns",
        "suricata": "dns any any -> any any",
        "osquery":  "dns_resolvers",
    },
    "authentication": {
        "kql":      "SigninLogs | union SecurityEvent",
        "spl":      'index=windows sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625 OR EventCode=4648)',
        "elastic":  "authentication",
        "qradar":   "events WHERE category ILIKE '%auth%'",
    },
    "webserver": {
        "kql":      "DeviceNetworkEvents | union W3CIISLog",
        "spl":      'index=web sourcetype=access_combined',
        "elastic":  "http",
        "qradar":   "events WHERE category ILIKE '%web%'",
    },
    "cloud": {
        "kql":      "AuditLogs | union CloudAppEvents | union AzureActivity",
        "spl":      'index=cloud (sourcetype=aws:cloudtrail OR sourcetype=azure:audit OR sourcetype=gcp:audit)',
        "elastic":  "cloud",
    },
    "powershell": {
        "kql":      "DeviceEvents | where ActionType == 'PowerShellCommand'",
        "spl":      'index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational (EventCode=4103 OR EventCode=4104)',
        "elastic":  "process where process.name == 'powershell.exe'",
    },
    "wmi_event": {
        "kql":      "DeviceEvents | where ActionType startswith 'WmiBinding' or ActionType startswith 'WmiFilter'",
        "spl":      'index=windows sourcetype=WinEventLog:Microsoft-Windows-WMI-Activity/Operational',
        "elastic":  "process where process.name =~ 'WmiPrvSE.exe'",
    },
}


@dataclass
class NormalizedRuleSet:
    advisory_id: str
    title: str
    sigma_source: str
    rules: Dict[str,str] = field(default_factory=dict)
    normalized_at: str   = ""
    platforms_generated: List[str] = field(default_factory=list)
    normalization_warnings: List[str] = field(default_factory=list)
    deployment_notes: Dict[str,str]   = field(default_factory=dict)
    engine_version: str = ENGINE_VERSION

    def to_dict(self): return asdict(self)


class SigmaParser:
    """Minimal Sigma rule parser for normalization."""

    def parse(self, sigma_text:str) -> Dict:
        """Extract key fields from Sigma YAML (no external deps)."""
        result={"title":"","id":"","logsource":{},"detection":{},"level":"medium",
                "tags":[],"falsepositives":[],"description":""}

        # Title
        m = re.search(r'^title:\s*(.+)$',sigma_text,re.MULTILINE)
        if m: result["title"] = m.group(1).strip()

        # Level
        m = re.search(r'^level:\s*(\S+)',sigma_text,re.MULTILINE)
        if m: result["level"] = m.group(1).strip()

        # Tags
        tags_block = re.search(r'^tags:(.*?)(?=\n\w|\Z)',sigma_text,re.DOTALL|re.MULTILINE)
        if tags_block:
            result["tags"] = re.findall(r'[-\s]+(\S+)',tags_block.group(1))

        # Logsource
        ls_block = re.search(r'^logsource:(.*?)(?=\n\w|\Z)',sigma_text,re.DOTALL|re.MULTILINE)
        if ls_block:
            ls_text = ls_block.group(1)
            for key in ("category","product","service"):
                m = re.search(rf'{key}:\s*(\S+)',ls_text)
                if m: result["logsource"][key] = m.group(1).strip()

        # Detection: Extract condition and all field:value pairs
        det_block = re.search(r'^detection:(.*?)(?=\nfalsepositives|\nfields|\nlevel|\Z)',
                              sigma_text,re.DOTALL|re.MULTILINE)
        if det_block:
            det_text = det_block.group(1)
            # Extract condition
            m = re.search(r'condition:\s*(.+)',det_text)
            if m: result["detection"]["condition"] = m.group(1).strip()
            # Extract field→value mappings
            field_blocks = re.findall(r'(\w+):\s*([\w.*\-_]+)',det_text)
            result["detection"]["fields"] = field_blocks

            # Extract contains patterns
            contains = re.findall(r'(?:contains|endswith|startswith):\s*[\'"]([^\'"]+)[\'"]',det_text)
            result["detection"]["patterns"] = contains

        return result


class MultiSIEMNormalizationLayer:
    """Normalizes Sigma rules into all target SIEM formats."""

    def __init__(self):
        self.parser = SigmaParser()

    def normalize(self, sigma_rule:str, advisory_id:str="",
                 title:str="", target_platforms:Optional[List[str]]=None) -> NormalizedRuleSet:
        """Normalize one Sigma rule into all target formats."""
        if not target_platforms:
            target_platforms = ["kql","spl","elastic_eql","elastic_lucene",
                               "qradar_aql","chronicle_yaral","crowdstrike",
                               "sentinelone","falco","osquery","stix_pattern"]

        parsed = self.parser.parse(sigma_rule)
        logsource_cat = parsed["logsource"].get("category","")
        logsource_product = parsed["logsource"].get("product","")
        level = parsed.get("level","medium")
        tags  = parsed.get("tags",[])
        tech_tags = [t.replace("attack.","T").upper() for t in tags if re.match(r'attack\.t\d{4}',t.lower())]

        ruleset = NormalizedRuleSet(
            advisory_id=advisory_id,
            title=title or parsed.get("title",""),
            sigma_source=sigma_rule,
            normalized_at=datetime.now(timezone.utc).isoformat()
        )

        patterns = parsed["detection"].get("patterns",[])
        fields   = parsed["detection"].get("fields",[])
        condition= parsed["detection"].get("condition","")

        for platform in target_platforms:
            try:
                rule_text = self._generate_platform_rule(
                    platform, parsed, logsource_cat, logsource_product,
                    patterns, fields, level, tech_tags, advisory_id, title
                )
                if rule_text:
                    ruleset.rules[platform] = rule_text
                    ruleset.platforms_generated.append(platform)
            except Exception as e:
                ruleset.normalization_warnings.append(f"{platform}: generation failed — {e}")

        # Add deployment notes
        ruleset.deployment_notes = self._deployment_notes(ruleset.platforms_generated, level)
        return ruleset

    def _generate_platform_rule(self, platform:str, parsed:Dict, logsource_cat:str,
                                logsource_product:str, patterns:List[str], fields:List,
                                level:str, tech_tags:List[str],
                                advisory_id:str, title:str) -> str:
        tech_str = " | ".join(tech_tags[:3]) or "Unknown"
        p_quoted = " OR ".join(f'"{p}"' for p in patterns[:5]) if patterns else '"<indicator>"'
        p_list   = ", ".join(f'"{p}"' for p in patterns[:5]) if patterns else '"<indicator>"'
        table    = LOGSOURCE_TO_PLATFORM.get(logsource_cat,{}).get("kql","DeviceProcessEvents")

        severity_map_kql = {"critical":"critical","high":"high","medium":"medium","low":"low","informational":"informational"}
        severity_kql = severity_map_kql.get(level,"medium")

        if platform == "kql":
            kql_table = LOGSOURCE_TO_PLATFORM.get(logsource_cat,{}).get("kql","DeviceProcessEvents")
            kql_field = SIGMA_TO_KQL.get(fields[0][0] if fields else "CommandLine","ProcessCommandLine")
            return (f"// Sentinel Rule: {title[:60]} | {advisory_id} | Techniques: {tech_str}\n"
                    f"// Severity: {severity_kql}\n"
                    f"{kql_table}\n"
                    f"| where TimeGenerated > ago(30d)\n"
                    f"| where {kql_field} has_any ({p_list})\n"
                    f"| project TimeGenerated, DeviceName, AccountName, {kql_field},\n"
                    f"          InitiatingProcessFileName, ProcessCommandLine\n"
                    f"| extend AdvisoryID=\"{advisory_id}\", Techniques=\"{tech_str}\"")

        elif platform == "spl":
            spl_src = LOGSOURCE_TO_PLATFORM.get(logsource_cat,{}).get("spl",'index=* sourcetype=WinEventLog')
            spl_field = SIGMA_TO_SPL.get(fields[0][0] if fields else "CommandLine","CommandLine")
            return (f'| comment "Splunk Rule: {title[:60]} | {advisory_id}"\n'
                    f"{spl_src} earliest=-30d latest=now\n"
                    f"({p_quoted})\n"
                    f"| eval hunt_id=\"{advisory_id}\" | eval severity=\"{level}\"\n"
                    f"| stats count AS hits, min(_time) AS first, max(_time) AS last,\n"
                    f"    dc(host) AS hosts BY {spl_field}, host, sourcetype\n"
                    f"| where hits > 0 | sort - hits")

        elif platform == "elastic_eql":
            eql_cat = LOGSOURCE_TO_PLATFORM.get(logsource_cat,{}).get("elastic","process")
            eql_field = SIGMA_TO_ELASTIC.get(fields[0][0] if fields else "CommandLine","process.command_line")
            pats = [f'{eql_field} like~ "*{p}*"' for p in patterns[:3]] or [f'{eql_field} != null']
            return (f"// Elastic EQL: {title[:60]} | Techniques: {tech_str}\n"
                    f"{eql_cat} where\n"
                    f"  ({' or '.join(pats)})")

        elif platform == "elastic_lucene":
            pats = " OR ".join(f'"{p}"' for p in patterns[:5]) or '"<indicator>"'
            return f'// Elastic Lucene: {advisory_id}\n({pats}) AND @timestamp:[now-30d TO now]'

        elif platform == "qradar_aql":
            qradar_src = LOGSOURCE_TO_PLATFORM.get(logsource_cat,{}).get("qradar","events")
            p_aql = " OR ".join(f"TEXT SEARCH '{p}'" for p in patterns[:3]) if patterns else "TEXT SEARCH '<indicator>'"
            return (f"/* QRadar AQL: {title[:60]} | {advisory_id} */\n"
                    f"SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS EventTime,\n"
                    f"  sourceip, destinationip, username, LOGSOURCENAME(logsourceid) AS Source,\n"
                    f"  QIDNAME(qid) AS EventName, '{advisory_id}' AS AdvisoryID\n"
                    f"FROM {qradar_src}\n"
                    f"WHERE ({p_aql})\n"
                    f"AND devicetime > (NOW() - 2592000)\n"
                    f"ORDER BY devicetime DESC LIMIT 10000\n"
                    f"START '30 days ago' STOP 'now'")

        elif platform == "chronicle_yaral":
            events = [f'  $e.metadata.description = "{p}"' for p in patterns[:3]] or ['  $e.metadata.event_type = "NETWORK_CONNECTION"']
            return (f"// Chronicle YARA-L: {title[:60]}\nrule apex_{advisory_id.replace('-','_').replace('--','_')[:30]} {{\n"
                    f"  meta:\n    description = \"{title[:80]}\"\n    author = \"CYBERDUDEBIVASH SENTINEL APEX\"\n"
                    f"    severity = \"{level.upper()}\"\n    attack_techniques = \"{tech_str}\"\n  events:\n"
                    + "\n".join(events) + f"\n  condition:\n    $e\n}}")

        elif platform == "crowdstrike":
            pats_cs = " OR ".join(f'CommandHistory contains "{p}"' for p in patterns[:3]) or 'CommandHistory contains "<indicator>"'
            return (f"// CrowdStrike NG-SIEM: {title[:60]}\n"
                    f"#type=ProcessRollup2 | head 10000\n"
                    f"| search ({pats_cs})\n"
                    f"| eval hunt_id=\"{advisory_id}\"\n"
                    f"| stats count by HostName, FileName, CommandLine")

        elif platform == "sentinelone":
            pats_s1 = " OR ".join(f'ProcessCmd Contains "{p}"' for p in patterns[:3]) or 'ProcessCmd Contains "<indicator>"'
            return (f"// SentinelOne Power Query: {title[:60]}\n"
                    f"EventType = 'Process Creation' AND\n"
                    f"({pats_s1})\n"
                    f"| columns SrcProcName, SrcProcCmdLine, AgentComputerName, SrcProcUser")

        elif platform == "falco":
            pats_f = " or ".join(f'contains(proc.cmdline,"{p}")' for p in patterns[:3]) or 'proc.cmdline contains "<indicator>"'
            return (f"- rule: APEX - {title[:60]}\n"
                    f"  desc: {advisory_id} - {tech_str}\n"
                    f"  condition: spawned_process and ({pats_f})\n"
                    f"  output: \"APEX Alert: %proc.name %proc.cmdline\"\n"
                    f"  priority: {level.upper()}\n  tags: [apex, {', '.join(tech_tags[:3])}]")

        elif platform == "osquery":
            pats_oq = " OR ".join(f"cmdline LIKE '%{p}%'" for p in patterns[:3]) or "cmdline LIKE '%indicator%'"
            return (f"-- OSQuery: {title[:60]} | {advisory_id}\n"
                    f"SELECT pid, name, cmdline, path, parent, uid\n"
                    f"FROM processes\n"
                    f"WHERE ({pats_oq});")

        elif platform == "stix_pattern":
            pats_stix = " OR ".join(f"[process:command_line LIKE '%{p}%']" for p in patterns[:3]) or "[process:command_line LIKE '%<indicator>%']"
            return (f"/* STIX Pattern: {advisory_id} */\n"
                    f"({pats_stix})")

        return ""

    def _deployment_notes(self, platforms:List[str], level:str) -> Dict[str,str]:
        notes = {}
        if "kql" in platforms:
            notes["kql"] = "Deploy via Microsoft Sentinel Analytics Rules. Set alert threshold, assign MITRE ATT&CK tactics, configure entity mapping."
        if "spl" in platforms:
            notes["spl"] = "Deploy via Splunk ES Correlation Rules. Set severity, suppress window, and notable event fields."
        if "elastic_eql" in platforms:
            notes["elastic_eql"] = "Deploy via Elastic Security Detection Rules. Set risk_score from level, configure rule schedule."
        if "qradar_aql" in platforms:
            notes["qradar_aql"] = "Deploy as QRadar Custom Rule using AQL. Configure offense threshold and magnitude."
        if "chronicle_yaral" in platforms:
            notes["chronicle_yaral"] = "Deploy via Google SecOps Rules. Set severity and outcome fields."
        if "falco" in platforms:
            notes["falco"] = "Deploy as Falco rule in /etc/falco/rules.d/. Reload with falcoctl."
        if "osquery" in platforms:
            notes["osquery"] = "Deploy as osquery scheduled query in fleet config. Set interval=300."
        return notes

    def normalize_batch(self, sigma_rules:List[Dict]) -> List[Dict]:
        """Normalize a batch of Sigma rules."""
        results=[]
        for item in sigma_rules:
            sigma_text = item.get("sigma","") or item.get("sigma_rule","")
            if sigma_text:
                ruleset = self.normalize(sigma_text,
                                        item.get("advisory_id",""),
                                        item.get("title",""))
                results.append(ruleset.to_dict())
        return results


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    layer = MultiSIEMNormalizationLayer()
    test_sigma = """title: APEX - SSRF Cloud Metadata Endpoint Detection
id: apex-ssrf-001
status: experimental
description: Detects SSRF exploiting cloud metadata
references:
    - https://intel.cyberdudebivash.com
author: CYBERDUDEBIVASH SENTINEL APEX
date: 2026/05/25
tags:
    - attack.initial_access
    - attack.t1190
logsource:
  category: webserver
detection:
  ssrf_meta:
    cs-uri-query|contains:
      - '169.254.169.254'
      - 'metadata.google.internal'
  condition: ssrf_meta
falsepositives:
  - Security scanners
level: high
"""
    result = layer.normalize(test_sigma, "intel--test001", "SSRF Detection Test")
    print(f"[MSNL] Platforms generated: {result.platforms_generated}")
    for platform, rule in result.rules.items():
        print(f"\n--- {platform.upper()} ---\n{rule[:200]}...")
