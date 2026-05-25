#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/telemetry_dependency_mapper.py — Telemetry Dependency Mapper v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Maps detection rules to their exact telemetry dependencies — what data
  sources, log types, and collection agents must be deployed for a rule
  to function. Enables deployment feasibility scoring.

OUTPUTS:
  - Per-rule telemetry dependency declaration
  - Collection gap analysis (what's missing to deploy a rule)
  - Telemetry coverage score per environment
  - Agent deployment recommendations
================================================================================
"""
from __future__ import annotations
import json,logging,re
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional,Set

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-TDM"
log = logging.getLogger("apex.telemetry_mapper")


TELEMETRY_REGISTRY: Dict[str,Dict] = {
    # Windows Event Logs
    "windows_security_4688": {
        "name":"Windows Security Event 4688 — Process Creation",
        "category":"process_creation","platform":"windows",
        "agent_required":"Windows Audit Policy (Command Line Logging)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
        "sigma_logsource_keys":["process_creation","windows"],
    },
    "sysmon_event1": {
        "name":"Sysmon EventID 1 — Process Creation",
        "category":"process_creation","platform":"windows",
        "agent_required":"Sysmon (SysInternals)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
        "sigma_logsource_keys":["process_creation","sysmon"],
        "enrichment_fields":["ParentImage","Hashes","Company","Product"],
    },
    "sysmon_event3": {
        "name":"Sysmon EventID 3 — Network Connection",
        "category":"network_connection","platform":"windows",
        "agent_required":"Sysmon (SysInternals)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
        "sigma_logsource_keys":["network_connection","sysmon"],
    },
    "sysmon_event7": {
        "name":"Sysmon EventID 7 — Image Load",
        "category":"image_load","platform":"windows",
        "agent_required":"Sysmon (SysInternals)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
    },
    "sysmon_event11": {
        "name":"Sysmon EventID 11/12/13 — File Events",
        "category":"file_event","platform":"windows",
        "agent_required":"Sysmon (SysInternals)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
    },
    "sysmon_event22": {
        "name":"Sysmon EventID 22 — DNS Query",
        "category":"dns_query","platform":"windows",
        "agent_required":"Sysmon v9+ (SysInternals)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
    },
    "windows_security_4624": {
        "name":"Windows Security 4624/4625 — Authentication Events",
        "category":"authentication","platform":"windows",
        "agent_required":"Windows Audit Policy",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
    },
    "windows_security_4657": {
        "name":"Windows Security 4657 — Registry Value Modified",
        "category":"registry_event","platform":"windows",
        "agent_required":"Windows Audit Policy (Object Access)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"MEDIUM",
    },
    "powershell_4103_4104": {
        "name":"PowerShell Module/ScriptBlock Logging 4103/4104",
        "category":"powershell","platform":"windows",
        "agent_required":"PowerShell Group Policy (Module Logging + ScriptBlock)",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
        "notes":"Enable via GPO: Computer Config → Admin Templates → Windows Components → Windows PowerShell",
    },
    "wmi_activity": {
        "name":"WMI Activity Log — WMI Events",
        "category":"wmi_event","platform":"windows",
        "agent_required":"Sysmon EventID 19/20/21 or WMI Activity Log",
        "collection_method":"Windows Event Log","cost_tier":"FREE",
        "deployment_complexity":"LOW",
    },
    # Network
    "zeek_conn": {
        "name":"Zeek conn.log — Network Connection Summary",
        "category":"network_connection","platform":"network",
        "agent_required":"Zeek Network Analysis Framework",
        "collection_method":"Network TAP/SPAN","cost_tier":"FREE",
        "deployment_complexity":"MEDIUM",
    },
    "zeek_dns": {
        "name":"Zeek dns.log — DNS Query Log",
        "category":"dns_query","platform":"network",
        "agent_required":"Zeek Network Analysis Framework",
        "collection_method":"Network TAP/SPAN","cost_tier":"FREE",
        "deployment_complexity":"MEDIUM",
    },
    "zeek_http": {
        "name":"Zeek http.log — HTTP Request Log",
        "category":"webserver","platform":"network",
        "agent_required":"Zeek Network Analysis Framework",
        "collection_method":"Network TAP/SPAN","cost_tier":"FREE",
        "deployment_complexity":"MEDIUM",
    },
    "suricata_network": {
        "name":"Suricata Network IDS Alerts",
        "category":"network_connection","platform":"network",
        "agent_required":"Suricata IDS v7+",
        "collection_method":"Inline/Mirror","cost_tier":"FREE",
        "deployment_complexity":"MEDIUM",
    },
    # Cloud
    "aws_cloudtrail": {
        "name":"AWS CloudTrail — API Call Logging",
        "category":"cloud","platform":"aws",
        "agent_required":"AWS CloudTrail enabled",
        "collection_method":"AWS Service","cost_tier":"PAID",
        "deployment_complexity":"LOW",
    },
    "azure_activity": {
        "name":"Azure Activity Log — Resource Operations",
        "category":"cloud","platform":"azure",
        "agent_required":"Azure Monitor / Diagnostic Settings",
        "collection_method":"Azure Service","cost_tier":"PAID",
        "deployment_complexity":"LOW",
    },
    "entra_signin": {
        "name":"Microsoft Entra ID Sign-in Logs",
        "category":"authentication","platform":"azure",
        "agent_required":"Microsoft Entra ID P1/P2",
        "collection_method":"Microsoft Service","cost_tier":"PAID",
        "deployment_complexity":"LOW",
    },
    # Endpoint / EDR
    "defender_xdr": {
        "name":"Microsoft Defender XDR — Advanced Hunting Tables",
        "category":"process_creation","platform":"windows",
        "agent_required":"Microsoft Defender for Endpoint",
        "collection_method":"EDR Agent","cost_tier":"PAID",
        "deployment_complexity":"LOW",
        "tables":["DeviceProcessEvents","DeviceNetworkEvents","DeviceFileEvents",
                  "DeviceRegistryEvents","DeviceAlertEvents"],
    },
    "crowdstrike_falcon": {
        "name":"CrowdStrike Falcon Sensor — Process/Network/File Events",
        "category":"process_creation","platform":"windows_linux_mac",
        "agent_required":"CrowdStrike Falcon Sensor",
        "collection_method":"EDR Agent","cost_tier":"PAID",
        "deployment_complexity":"LOW",
    },
    "sentinelone_agent": {
        "name":"SentinelOne Agent — Deep Visibility",
        "category":"process_creation","platform":"windows_linux_mac",
        "agent_required":"SentinelOne Agent",
        "collection_method":"EDR Agent","cost_tier":"PAID",
        "deployment_complexity":"LOW",
    },
    # Web
    "iis_access_log": {
        "name":"IIS/Apache/Nginx Access Logs",
        "category":"webserver","platform":"web",
        "agent_required":"Web server log forwarding (Filebeat/NXLog)",
        "collection_method":"Log Forwarding","cost_tier":"FREE",
        "deployment_complexity":"LOW",
    },
    "waf_log": {
        "name":"WAF (Web Application Firewall) Logs",
        "category":"webserver","platform":"web",
        "agent_required":"WAF (AWS WAF, Azure Front Door, Cloudflare)",
        "collection_method":"WAF Service","cost_tier":"PAID",
        "deployment_complexity":"LOW",
    },
}

LOGSOURCE_TO_TELEMETRY_IDS: Dict[str,List[str]] = {
    "process_creation":  ["sysmon_event1","windows_security_4688","defender_xdr","crowdstrike_falcon"],
    "network_connection":["sysmon_event3","zeek_conn","suricata_network","defender_xdr"],
    "file_event":        ["sysmon_event11","defender_xdr","crowdstrike_falcon"],
    "registry_event":    ["windows_security_4657","sysmon_event11","defender_xdr"],
    "dns_query":         ["sysmon_event22","zeek_dns","defender_xdr"],
    "webserver":         ["iis_access_log","waf_log","zeek_http"],
    "web":               ["waf_log","iis_access_log","zeek_http"],
    "authentication":    ["windows_security_4624","entra_signin","aws_cloudtrail"],
    "cloud":             ["aws_cloudtrail","azure_activity","entra_signin"],
    "powershell":        ["powershell_4103_4104","sysmon_event1"],
    "wmi_event":         ["wmi_activity","sysmon_event1"],
    "image_load":        ["sysmon_event7","defender_xdr"],
}


@dataclass
class TelemetryDependency:
    telemetry_id: str
    name: str
    category: str
    platform: str
    agent_required: str
    collection_method: str
    cost_tier: str
    deployment_complexity: str
    is_available: bool = False
    availability_confidence: float = 0.0

    def to_dict(self): return asdict(self)


@dataclass
class TelemetryMapping:
    rule_id: str
    advisory_id: str
    rule_format: str
    logsource_category: str
    required_telemetry: List[TelemetryDependency] = field(default_factory=list)
    optional_telemetry: List[TelemetryDependency] = field(default_factory=list)
    minimum_viable_telemetry: List[str]  = field(default_factory=list)
    deployment_feasibility_score: float  = 0.0
    collection_gaps: List[str]           = field(default_factory=list)
    deployment_recommendations: List[str]= field(default_factory=list)
    mapped_at: str = ""
    engine_version: str = ENGINE_VERSION

    def to_dict(self): return asdict(self)


class TelemetryDependencyMapper:
    """Maps detection rules to their telemetry dependencies."""

    def map_rule(self, rule_text:str, rule_format:str,
                rule_id:str="", advisory_id:str="",
                available_telemetry:Optional[List[str]]=None) -> TelemetryMapping:
        """Map a detection rule to required telemetry sources."""

        logsource_cat = self._extract_logsource(rule_text, rule_format)
        telemetry_ids = LOGSOURCE_TO_TELEMETRY_IDS.get(logsource_cat,[])

        if not telemetry_ids:
            # Infer from rule content
            logsource_cat = self._infer_from_content(rule_text)
            telemetry_ids = LOGSOURCE_TO_TELEMETRY_IDS.get(logsource_cat,["sysmon_event1"])

        required_deps=[]
        optional_deps=[]
        for i, tid in enumerate(telemetry_ids):
            if tid not in TELEMETRY_REGISTRY: continue
            t = TELEMETRY_REGISTRY[tid]
            dep = TelemetryDependency(
                telemetry_id=tid, name=t["name"],
                category=t["category"], platform=t["platform"],
                agent_required=t["agent_required"],
                collection_method=t["collection_method"],
                cost_tier=t["cost_tier"],
                deployment_complexity=t["deployment_complexity"],
                is_available=tid in (available_telemetry or []),
            )
            if i == 0: required_deps.append(dep)
            else:       optional_deps.append(dep)

        # Minimum viable = just the first (most common) source
        mvt = [required_deps[0].agent_required] if required_deps else ["Windows Event Logging"]

        # Feasibility score
        if available_telemetry:
            available_ids = set(available_telemetry)
            covered = sum(1 for d in required_deps if d.telemetry_id in available_ids)
            feasibility = (covered/len(required_deps)*100) if required_deps else 0
        else:
            # Assume basic Windows + Sysmon available
            basic_available = {"sysmon_event1","windows_security_4688","windows_security_4624",
                              "powershell_4103_4104","sysmon_event3"}
            covered = sum(1 for d in required_deps if d.telemetry_id in basic_available)
            feasibility = (covered/len(required_deps)*100) if required_deps else 50

        # Collection gaps
        gaps=[]
        for dep in required_deps:
            if not dep.is_available and dep.cost_tier=="FREE":
                gaps.append(f"MISSING (free): {dep.name} — {dep.agent_required}")
            elif not dep.is_available and dep.cost_tier=="PAID":
                gaps.append(f"MISSING (paid): {dep.name} — requires {dep.agent_required}")

        # Recommendations
        recs=[]
        if required_deps:
            recs.append(f"MINIMUM: Deploy {required_deps[0].agent_required} to enable this detection")
        free_sources = [d for d in optional_deps if d.cost_tier=="FREE" and not d.is_available]
        if free_sources:
            recs.append(f"FREE ENHANCEMENT: Add {free_sources[0].agent_required} for richer telemetry")
        if feasibility >= 75:
            recs.append("Telemetry sufficient for immediate deployment")
        elif feasibility >= 40:
            recs.append("Partial telemetry — rule will fire but with reduced fidelity")
        else:
            recs.append("Insufficient telemetry — deploy required agents before production deployment")

        return TelemetryMapping(
            rule_id=rule_id, advisory_id=advisory_id,
            rule_format=rule_format, logsource_category=logsource_cat,
            required_telemetry=required_deps, optional_telemetry=optional_deps,
            minimum_viable_telemetry=mvt,
            deployment_feasibility_score=round(feasibility,2),
            collection_gaps=gaps, deployment_recommendations=recs,
            mapped_at=datetime.now(timezone.utc).isoformat()
        )

    def _extract_logsource(self, rule_text:str, fmt:str) -> str:
        if fmt == "sigma":
            ls_block = re.search(r'logsource:(.*?)(?=\n\w|\Z)',rule_text,re.DOTALL)
            if ls_block:
                cat_m = re.search(r'category:\s*(\S+)',ls_block.group(1))
                if cat_m: return cat_m.group(1).lower()
        elif fmt == "kql":
            if "DeviceProcessEvents" in rule_text:     return "process_creation"
            elif "DeviceNetworkEvents" in rule_text:   return "network_connection"
            elif "DeviceFileEvents" in rule_text:      return "file_event"
            elif "DeviceRegistryEvents" in rule_text:  return "registry_event"
            elif "SigninLogs" in rule_text:            return "authentication"
            elif "DnsEvents" in rule_text:             return "dns_query"
        elif fmt == "spl":
            if re.search(r'WinEventLog:Security',rule_text): return "authentication"
            elif re.search(r'sysmon',rule_text,re.I):       return "process_creation"
            elif re.search(r'stream:dns',rule_text,re.I):   return "dns_query"
        return "process_creation"

    def _infer_from_content(self, rule_text:str) -> str:
        text = rule_text.lower()
        if any(t in text for t in ["commandline","process","cmd.exe","powershell"]): return "process_creation"
        if any(t in text for t in ["destinationip","remoteip","tcp","udp"]):         return "network_connection"
        if any(t in text for t in ["dns","domain","resolve"]):                       return "dns_query"
        if any(t in text for t in ["registry","hklm","hkcu"]):                      return "registry_event"
        if any(t in text for t in ["file","sha256","md5","path"]):                   return "file_event"
        if any(t in text for t in ["http","uri","web","request"]):                   return "webserver"
        if any(t in text for t in ["logon","auth","4624","4625"]):                   return "authentication"
        return "process_creation"

    def map_detection_pack(self, detection_pack:Dict[str,str],
                          advisory_id:str="") -> Dict:
        """Map all formats in a detection pack to their telemetry deps."""
        results={}
        for fmt, rule_text in detection_pack.items():
            if not rule_text: continue
            mapping = self.map_rule(rule_text, fmt, advisory_id=advisory_id)
            results[fmt] = mapping.to_dict()
        return {"advisory_id":advisory_id,"telemetry_mappings":results,
                "engine_version":ENGINE_VERSION}


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    mapper = TelemetryDependencyMapper()
    test_sigma = """title: APEX - PowerShell Encoded Command
logsource:
  category: process_creation
  product: windows
detection:
  encoded:
    CommandLine|contains: '-EncodedCommand'
  condition: encoded
level: high
"""
    result = mapper.map_rule(test_sigma,"sigma","apex-test-ps","intel--test001")
    print(f"[TDM] Logsource: {result.logsource_category}")
    print(f"[TDM] Feasibility: {result.deployment_feasibility_score}%")
    print(f"[TDM] Required telemetry:")
    for dep in result.required_telemetry:
        print(f"  - {dep.name} ({dep.cost_tier})")
    print(f"[TDM] Recommendations: {result.deployment_recommendations}")
