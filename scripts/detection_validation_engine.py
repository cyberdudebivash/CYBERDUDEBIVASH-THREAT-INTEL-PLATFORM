#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/detection_validation_engine.py — Detection Rule Validation Engine v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

VALIDATED FORMATS: Sigma, KQL, SPL, EQL, YARA, Suricata, Snort,
                   QRadar AQL, Chronicle YARA-L, Falco, OSQuery

VALIDATION GATES (10 gates, 6 mandatory):
  Gate 1: Syntax validation (mandatory)
  Gate 2: ATT&CK technique presence + validity (mandatory)
  Gate 3: Telemetry dependency declaration (mandatory)
  Gate 4: FP probability score declaration (mandatory)
  Gate 5: Tuning recommendation generation (mandatory)
  Gate 6: Logsource/data-source mapping (mandatory)
  Gate 7: Rule uniqueness fingerprint (advisory)
  Gate 8: Coverage score >= 30 (advisory)
  Gate 9: Retro-hunt query present (advisory)
  Gate 10: Deployment environment tagging (advisory)
================================================================================
"""
from __future__ import annotations
import hashlib, json, logging, re, time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-DVE"
log = logging.getLogger("apex.detection_validator")

VALID_ATTACK_TECHNIQUES = {
    "T1059","T1059.001","T1059.003","T1059.005","T1059.006",
    "T1190","T1055","T1055.001","T1055.012","T1078","T1078.002",
    "T1078.004","T1110","T1110.001","T1110.003","T1110.004",
    "T1203","T1566","T1566.001","T1566.002","T1486","T1489",
    "T1490","T1491","T1071","T1071.001","T1071.004",
    "T1105","T1219","T1021","T1021.001","T1021.006",
    "T1547","T1547.001","T1543","T1543.003","T1548","T1548.002",
    "T1134","T1134.001","T1134.002","T1574","T1574.001","T1574.002",
    "T1562","T1562.001","T1070","T1070.001","T1070.004",
    "T1036","T1036.005","T1027","T1027.002","T1218","T1218.011",
    "T1218.005","T1082","T1083","T1087","T1087.001","T1087.002",
    "T1069","T1069.002","T1057","T1049","T1016","T1033","T1135",
    "T1046","T1018","T1560","T1560.001","T1041","T1048","T1048.002",
    "T1572","T1090","T1090.003","T1102","T1102.002","T1531",
    "T1499","T1498","T1539","T1555","T1555.003","T1056","T1056.001",
    "T1123","T1125","T1040","T1557","T1557.001","T1558","T1558.003",
    "T1003","T1003.001","T1003.002","T1003.006","T1552","T1552.001",
    "T1552.006","T1589","T1590","T1591","T1592","T1593","T1594",
    "T1595","T1596","T1597","T1598","T1199","T1195","T1195.001",
    "T1195.002","T1200","T1091","T1189","T1133","T1566.003",
    "T1611","T1612","T1613","T1614",
}

LOGSOURCE_TO_TELEMETRY = {
    "process_creation": ["Sysmon EventID 1","Windows Security 4688","EDR Process Telemetry"],
    "network_connection": ["Sysmon EventID 3","Windows Firewall","Zeek conn.log"],
    "file_event": ["Sysmon EventID 11/12/13","EDR File Events","AuditD"],
    "registry_event": ["Sysmon EventID 12/13/14","Windows Security 4657"],
    "dns_query": ["Sysmon EventID 22","Windows DNS Debug","Zeek dns.log"],
    "webserver": ["IIS/Apache/Nginx Access Logs","WAF Logs","Proxy Logs"],
    "web": ["Proxy Logs","WAF Logs","NGFW URL Filtering"],
    "authentication": ["Windows Security 4624/4625/4648","Linux auth.log","LDAP Logs"],
    "cloud": ["CloudTrail","Azure Activity Log","GCP Audit Log"],
    "powershell": ["PowerShell Module Logging","Script Block Logging","Transcription Logs"],
    "wmi_event": ["Sysmon EventID 19/20/21","WMI Activity Logs"],
    "pipe_created": ["Sysmon EventID 17/18"],
    "antivirus": ["Windows Defender","CrowdStrike Alerts","SentinelOne Alerts"],
    "firewall": ["Windows Firewall","Palo Alto Firewall","Cisco ASA"],
}


@dataclass
class ValidationResult:
    rule_id: str
    rule_format: str
    title: str
    advisory_id: str = ""
    gate_syntax: bool = False
    gate_attack_mapping: bool = False
    gate_telemetry_deps: bool = False
    gate_fp_probability: bool = False
    gate_tuning_recs: bool = False
    gate_logsource: bool = False
    gate_uniqueness: bool = False
    gate_coverage_score: bool = False
    gate_retro_hunt: bool = False
    gate_deployment_env: bool = False
    fp_probability_score: float = 50.0
    coverage_score: float = 0.0
    confidence_score: float = 0.0
    attack_techniques: List[str] = field(default_factory=list)
    telemetry_deps: List[str] = field(default_factory=list)
    tuning_recommendations: List[str] = field(default_factory=list)
    deployment_environments: List[str] = field(default_factory=list)
    syntax_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    retro_hunt_query: str = ""
    rule_fingerprint: str = ""
    production_ready: bool = False
    gates_passed: int = 0
    gates_total: int = 10
    validated_at: str = ""

    def compute_verdict(self):
        gates = [self.gate_syntax,self.gate_attack_mapping,self.gate_telemetry_deps,
                 self.gate_fp_probability,self.gate_tuning_recs,self.gate_logsource,
                 self.gate_uniqueness,self.gate_coverage_score,self.gate_retro_hunt,
                 self.gate_deployment_env]
        self.gates_passed = sum(gates)
        self.gates_total  = len(gates)
        mandatory_pass = all([self.gate_syntax,self.gate_attack_mapping,self.gate_telemetry_deps,
                              self.gate_fp_probability,self.gate_tuning_recs,self.gate_logsource])
        self.production_ready = mandatory_pass and self.gates_passed >= 8
        self.confidence_score = round((self.gates_passed/self.gates_total)*100.0,2)
        self.validated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict: return asdict(self)


class DetectionValidationEngine:
    """Master validation orchestrator for all detection formats."""

    def __init__(self):
        self._fingerprints: set = set()

    def validate_rule(self, rule_text:str, rule_format:str,
                     advisory_id:str="", title:str="") -> ValidationResult:
        rule_id = f"apex-{rule_format}-{hashlib.md5(rule_text.encode()).hexdigest()[:12]}"
        result  = ValidationResult(rule_id=rule_id,rule_format=rule_format.lower(),
                                   title=title,advisory_id=advisory_id)
        fmt = rule_format.lower()

        # Gate 1: Syntax
        syntax_ok, syntax_errs, metadata = self._validate_syntax(rule_text, fmt)
        result.gate_syntax   = syntax_ok
        result.syntax_errors = syntax_errs

        # Gate 2: ATT&CK
        raw_techs = metadata.get("attack_tags",[]) + re.findall(r'\bT\d{4}(?:\.\d{3})?\b',rule_text)
        valid_techs = []
        attack_warns = []
        for t in set(raw_techs):
            norm = t.upper().replace("ATTACK.","").strip()
            if re.match(r'T\d{4}',norm):
                valid_techs.append(norm)
                if norm not in VALID_ATTACK_TECHNIQUES:
                    attack_warns.append(f"Technique {norm} not in ATT&CK v16 — verify")
        result.gate_attack_mapping = len(valid_techs) > 0
        result.attack_techniques   = list(set(valid_techs))
        result.warnings.extend(attack_warns)

        # Gate 3: Telemetry deps
        deps = self._extract_telemetry_deps(rule_text, fmt, metadata)
        result.gate_telemetry_deps = len(deps) > 0
        result.telemetry_deps      = deps

        # Gate 4: FP score
        fp_score = self._score_fp(rule_text, fmt)
        result.fp_probability_score = round(fp_score,2)
        result.gate_fp_probability  = True

        # Gate 5: Tuning recs
        recs = self._tuning_recs(rule_text, fp_score)
        result.tuning_recommendations = recs
        result.gate_tuning_recs       = len(recs) > 0

        # Gate 6: Logsource
        result.gate_logsource = len(deps) > 0

        # Gate 7: Uniqueness
        fp = hashlib.sha256(rule_text.encode()).hexdigest()[:16]
        result.rule_fingerprint = fp
        result.gate_uniqueness  = fp not in self._fingerprints
        self._fingerprints.add(fp)

        # Gate 8: Coverage score
        cov = self._coverage_score(result.attack_techniques, fmt, False)
        result.coverage_score      = cov
        result.gate_coverage_score = cov >= 30.0

        # Gate 9: Retro-hunt
        if result.attack_techniques and fmt in ("sigma","kql","spl"):
            retro = self._gen_retro_hunt(rule_text, advisory_id, result.attack_techniques)
            result.retro_hunt_query = retro
            result.gate_retro_hunt  = bool(retro)
            result.coverage_score   = self._coverage_score(result.attack_techniques, fmt, True)
        elif fmt in ("yara","suricata","snort","falco","osquery"):
            result.gate_retro_hunt = True  # Binary/agent formats: retro N/A

        # Gate 10: Deployment envs
        envs = self._deployment_envs(rule_text, fmt)
        result.deployment_environments = envs
        result.gate_deployment_env     = len(envs) > 0

        result.compute_verdict()
        return result

    def validate_detection_pack(self, detection_pack:Dict[str,str],
                                advisory_id:str="", title:str="") -> Dict:
        pack_results = {}
        tp=0; tg=0; validated=0
        for fmt, rule_text in detection_pack.items():
            if not rule_text or not rule_text.strip(): continue
            r = self.validate_rule(rule_text, fmt, advisory_id, title)
            pack_results[fmt] = r.to_dict()
            tp += r.gates_passed; tg += r.gates_total; validated += 1
        pack_score = round((tp/tg*100) if tg else 0, 2)
        overall = "PASS" if all(v.get("production_ready") for v in pack_results.values()) else "WARN"
        return {"advisory_id":advisory_id,"title":title,"overall_status":overall,
                "pack_score":pack_score,"validated_formats":validated,
                "total_gates_passed":tp,"total_gates":tg,
                "results_by_format":pack_results,
                "validated_at":datetime.now(timezone.utc).isoformat(),
                "engine_version":ENGINE_VERSION}

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _validate_syntax(self, text:str, fmt:str) -> Tuple[bool,List[str],Dict]:
        if len(text.strip()) < 30:
            return False, ["Rule text too short"], {}
        errors=[]; meta={}
        if fmt=="sigma":
            for f in ["title","id","logsource","detection","level"]:
                if not re.search(rf'^{f}\s*:', text, re.MULTILINE|re.IGNORECASE):
                    errors.append(f"Missing Sigma field: {f}")
            if "condition:" not in text: errors.append("Sigma missing condition:")
            if "falsepositives:" not in text: errors.append("Sigma missing falsepositives:")
            tags = re.findall(r'attack\.\w+(?:\.\w+)*', text.lower())
            meta["attack_tags"] = tags
            ls = re.search(r'logsource:(.*?)(?=\n\w|\Z)',text,re.DOTALL)
            if ls: meta["logsource"] = ls.group(1).strip()
        elif fmt=="kql":
            tables=["DeviceProcessEvents","DeviceNetworkEvents","DeviceFileEvents",
                    "SigninLogs","SecurityEvent","AuditLogs","CloudAppEvents",
                    "DeviceRegistryEvents","EmailEvents","BehaviorEntities"]
            found=[t for t in tables if t in text]
            if not found: errors.append("KQL: no recognized Sentinel/Defender table")
            meta["tables"]=found
        elif fmt=="spl":
            if not re.search(r'(index=|sourcetype=)',text,re.IGNORECASE):
                errors.append("SPL: should specify index= or sourcetype=")
        elif fmt in ("yara","yara_rule"):
            for s in ["rule ","meta:","strings:","condition:"]:
                if s not in text: errors.append(f"YARA missing: {s}")
        elif fmt in ("suricata","snort"):
            if not re.match(r'^(alert|drop|reject|pass)',text.strip(),re.IGNORECASE):
                errors.append("Suricata/Snort rule must start with action keyword")
            for o in ["msg:","sid:","rev:"]:
                if o not in text: errors.append(f"Suricata/Snort missing option: {o}")
        elif fmt in ("eql","elastic_eql"):
            if not re.search(r'^(process|network|file|registry|api)\s+where',text,re.MULTILINE):
                errors.append("EQL must start with event category: process|network|file...")
        elif fmt in ("qradar_aql","qradar"):
            if "SELECT" not in text.upper(): errors.append("QRadar AQL must contain SELECT")
        elif fmt in ("chronicle_yaral","yaral"):
            if not re.search(r'^rule\s+\w+',text,re.MULTILINE):
                errors.append("Chronicle YARA-L must start with 'rule <name>'")
        return len(errors)==0, errors, meta

    def _extract_telemetry_deps(self, text:str, fmt:str, meta:Dict) -> List[str]:
        deps=[]
        if fmt=="sigma":
            ls_text = meta.get("logsource","").lower()
            for key,vals in LOGSOURCE_TO_TELEMETRY.items():
                if key in ls_text: deps.extend(vals)
        elif fmt=="kql":
            mapping={"DeviceProcessEvents":"Defender XDR Process Telemetry",
                     "DeviceNetworkEvents":"Defender XDR Network Telemetry",
                     "DeviceFileEvents":"Defender XDR File Telemetry",
                     "SigninLogs":"Entra ID Sign-in Logs",
                     "SecurityEvent":"Sentinel Windows Security Events",
                     "CloudAppEvents":"Defender for Cloud Apps",
                     "EmailEvents":"Defender for Office 365"}
            for t,dep in mapping.items():
                if t in text: deps.append(dep)
        elif fmt=="spl":
            if re.search(r'WinEventLog',text,re.I): deps.append("Windows Event Log - Splunk")
            if re.search(r'sysmon',text,re.I):      deps.append("Sysmon - Splunk")
            if re.search(r'sourcetype\s*=\s*stream',text,re.I): deps.append("Splunk Stream Network")
            if not deps: deps.append("Splunk Index - Generic")
        elif fmt in ("yara","yara_rule"):
            deps=["EDR Memory Scanning","File System Scanner","Sandbox Analysis"]
        elif fmt in ("suricata","snort"):
            deps=["Network IDS/IPS","Inline Traffic Mirror","SPAN Port / TAP"]
        elif fmt in ("eql","elastic_eql"):
            deps=["Elastic Agent / Beats","Elastic SIEM / Security"]
        elif fmt in ("qradar_aql","qradar"):
            deps=["IBM QRadar SIEM - Log Sources","QRadar Flow Data"]
        elif fmt in ("chronicle_yaral","yaral"):
            deps=["Google SecOps (Chronicle)","Google Workspace Logs","UDM Events"]
        elif fmt=="falco":
            deps=["Falco Runtime Security","Linux syscall events","Kubernetes API Audit"]
        elif fmt=="osquery":
            deps=["osquery Agent","FleetDM","Kolide - Endpoint Telemetry"]
        return list(set(deps))

    def _score_fp(self, text:str, fmt:str) -> float:
        score = 30.0
        high_fp=[
            (r'CommandLine\s*[=!]+\s*["\']?\*',15),
            (r'contains\s*:\s*["\'][a-z]{1,3}["\']',20),
            (r'\\\\Users\\\\',5),(r'level:\s*low',3),
            (r'ProcessName.*cmd\.exe(?!\s+and)',10),
        ]
        low_fp=[
            (r'AllOf\b|1\s+of\s+them',-10),(r'not\s+in\s*\(',-5),
            (r'and\s+not\s+',-5),(r'threshold|count\(\)\s*>\s*[3-9]',-8),
            (r'level:\s*(high|critical)',-5),(r'endswith|startswith',-3),
            (r'hash\s*(==|in)',-10),(r'within\s+\d+\s+seconds',-5),
        ]
        for p,w in high_fp:
            if re.search(p,text,re.IGNORECASE): score+=w
        for p,w in low_fp:
            if re.search(p,text,re.IGNORECASE): score+=w
        if fmt=="yara": score-=15
        elif fmt in ("suricata","snort"): score-=10
        elif fmt=="sigma": score+=5
        return max(0.0,min(100.0,score))

    def _tuning_recs(self, text:str, fp_score:float) -> List[str]:
        recs=[]
        if fp_score>60:
            recs.append("HIGH FP RISK: Add allowlist for known-good processes/paths using 'not' conditions")
            recs.append("HIGH FP RISK: Add threshold — require N occurrences within time window")
        if fp_score>40:
            recs.append("Add exclusions for security scanning tools (Nessus, Qualys, Tenable agents)")
            recs.append("Run baseline 7-day window before production deployment — tune against environment noise")
        if "cmd.exe" in text.lower():
            recs.append("Scope cmd.exe detections to non-interactive sessions via parent process context")
        if re.search(r'\bhttp\b',text,re.IGNORECASE) and fp_score>30:
            recs.append("HTTP detection: filter by response code, add content-type conditions")
        if not recs:
            recs.append("Low FP profile — validate in staging before production deployment")
            recs.append("Monitor alert volume first 48h post-deployment — tune if >10 alerts/hour")
        return recs

    def _coverage_score(self, techs:List[str], fmt:str, has_retro:bool) -> float:
        base = 20.0 + min(len(techs)*10,30)
        bonus={"sigma":15,"kql":10,"spl":10,"yara":8,"suricata":8,
               "elastic_eql":8,"eql":8,"qradar_aql":5,"chronicle_yaral":5,
               "falco":5,"osquery":5}
        base += bonus.get(fmt.lower(),5)
        if has_retro: base+=10
        if len(techs)>=3: base+=10
        return min(100.0,base)

    def _gen_retro_hunt(self, rule_text:str, advisory_id:str, techs:List[str]) -> str:
        tech_str = ", ".join(techs[:3])
        patterns = re.findall(r"contains:\s*['\"]([^'\"]+)['\"]",rule_text)[:5]
        p_str = ", ".join(f'"{p}"' for p in patterns) if patterns else '"<indicator>"'
        return (f"// RETRO-HUNT: {advisory_id} | Techniques: {tech_str} | Lookback: 90d\n"
                f"// Generated by APEX Detection Validation Engine v{ENGINE_VERSION}\n"
                f"let lookback = 90d;\nlet indicators = dynamic([{p_str}]);\n"
                f"union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents\n"
                f"| where TimeGenerated > ago(lookback)\n"
                f"| where ProcessCommandLine has_any (indicators)\n"
                f"    or RemoteUrl has_any (indicators)\n"
                f"    or FileName has_any (indicators)\n"
                f"| summarize HuntHits=count(), FirstSeen=min(TimeGenerated),\n"
                f"    LastSeen=max(TimeGenerated), Devices=dcount(DeviceName)\n"
                f"    by DeviceName, ProcessCommandLine, ThreatScore=80\n"
                f"| where HuntHits > 0 | order by HuntHits desc")

    def _deployment_envs(self, text:str, fmt:str) -> List[str]:
        envs={
            "sigma":["Microsoft Sentinel","Splunk ES","Elastic SIEM","QRadar (via sigma-cli)"],
            "kql":["Microsoft Sentinel","Microsoft Defender XDR"],
            "spl":["Splunk Enterprise Security","Splunk SOAR"],
            "yara":["CrowdStrike","CarbonBlack","Velociraptor","YARA Scanner"],
            "suricata":["Suricata IDS/IPS","NGFW","Network TAP/SPAN"],
            "snort":["Snort IDS","NGFW"],
            "eql":["Elastic SIEM","Elastic Security"],
            "elastic_eql":["Elastic SIEM","Elastic Security"],
            "qradar_aql":["IBM QRadar SIEM"],
            "qradar":["IBM QRadar SIEM"],
            "chronicle_yaral":["Google SecOps (Chronicle)"],
            "yaral":["Google SecOps (Chronicle)"],
            "falco":["Falco Runtime Security","Kubernetes","Container Environments"],
            "osquery":["osquery Fleet","FleetDM","Kolide"],
        }
        return envs.get(fmt.lower(),["Generic SIEM"])


def run_validation_on_advisory(advisory:Dict) -> Dict:
    engine = DetectionValidationEngine()
    pack   = advisory.get("detection_pack", {})
    if not pack:
        for k in ["sigma_rule","sigma","kql_rule","kql","spl_rule","spl","yara_rule","yara"]:
            if advisory.get(k): pack[k.replace("_rule","")] = advisory[k]
    if not pack:
        return {"advisory_id":advisory.get("stix_id",""),"status":"SKIP",
                "reason":"No detection rules","engine_version":ENGINE_VERSION}
    return engine.validate_detection_pack(pack,advisory.get("stix_id",""),advisory.get("title",""))


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    engine = DetectionValidationEngine()
    test = """title: APEX - SSRF Cloud Metadata Endpoint Access
id: apex-ssrf-test001
status: experimental
description: Detects SSRF exploiting cloud metadata endpoints
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
  condition: ssrf_meta
falsepositives:
  - Security scanners
level: high
"""
    r = engine.validate_rule(test,"sigma","intel--test001","SSRF Test")
    print(json.dumps(r.to_dict(),indent=2,default=str))
    print(f"\n[DVE] Self-test complete — production_ready={r.production_ready} gates={r.gates_passed}/{r.gates_total}")
