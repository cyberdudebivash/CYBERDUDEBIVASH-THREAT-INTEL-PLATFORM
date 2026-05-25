#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/coverage_gap_analyzer.py — ATT&CK Coverage Gap Analyzer v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Analyzes current detection coverage against the full MITRE ATT&CK framework
  and identifies high-priority gaps. Generates coverage matrices, gap reports,
  and prioritized remediation recommendations.

OUTPUTS:
  - ATT&CK Coverage Matrix (per tactic/technique)
  - Gap Priority List (ranked by EPSS/KEV/actor frequency)
  - Coverage Heat Map data (for Navigator export)
  - Remediation roadmap
================================================================================
"""
from __future__ import annotations
import json,logging,os
from collections import defaultdict
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional,Set,Tuple

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-CGA"
log = logging.getLogger("apex.coverage_gap")

# ATT&CK v16 Tactic → Techniques mapping (priority subset)
ATTACK_COVERAGE_MAP: Dict[str,Dict] = {
    "TA0001": {
        "name": "Initial Access",
        "priority": 10,
        "techniques": {
            "T1190": {"name":"Exploit Public-Facing Application","priority":10,"actor_freq":9},
            "T1566": {"name":"Phishing","priority":9,"actor_freq":9},
            "T1566.001":{"name":"Phishing: Spearphishing Attachment","priority":9,"actor_freq":9},
            "T1566.002":{"name":"Phishing: Spearphishing Link","priority":8,"actor_freq":8},
            "T1133": {"name":"External Remote Services","priority":7,"actor_freq":7},
            "T1189": {"name":"Drive-by Compromise","priority":6,"actor_freq":6},
            "T1199": {"name":"Trusted Relationship","priority":7,"actor_freq":7},
            "T1195": {"name":"Supply Chain Compromise","priority":9,"actor_freq":8},
            "T1091": {"name":"Replication Through Removable Media","priority":4,"actor_freq":3},
            "T1200": {"name":"Hardware Additions","priority":3,"actor_freq":2},
        }
    },
    "TA0002": {
        "name": "Execution",
        "priority": 9,
        "techniques": {
            "T1059":     {"name":"Command and Scripting Interpreter","priority":10,"actor_freq":10},
            "T1059.001": {"name":"PowerShell","priority":10,"actor_freq":10},
            "T1059.003": {"name":"Windows Command Shell","priority":9,"actor_freq":9},
            "T1059.005": {"name":"Visual Basic","priority":7,"actor_freq":7},
            "T1059.006": {"name":"Python","priority":7,"actor_freq":6},
            "T1203":     {"name":"Exploitation for Client Execution","priority":8,"actor_freq":8},
            "T1106":     {"name":"Native API","priority":7,"actor_freq":7},
            "T1053":     {"name":"Scheduled Task/Job","priority":8,"actor_freq":8},
            "T1053.005": {"name":"Scheduled Task","priority":8,"actor_freq":8},
            "T1047":     {"name":"Windows Management Instrumentation","priority":8,"actor_freq":8},
        }
    },
    "TA0003": {
        "name": "Persistence",
        "priority": 8,
        "techniques": {
            "T1547":     {"name":"Boot or Logon Autostart Execution","priority":9,"actor_freq":8},
            "T1547.001": {"name":"Registry Run Keys/Startup Folder","priority":9,"actor_freq":9},
            "T1543":     {"name":"Create or Modify System Process","priority":8,"actor_freq":7},
            "T1543.003": {"name":"Windows Service","priority":8,"actor_freq":8},
            "T1053.005": {"name":"Scheduled Task","priority":8,"actor_freq":8},
            "T1505.003": {"name":"Web Shell","priority":9,"actor_freq":9},
            "T1136":     {"name":"Create Account","priority":7,"actor_freq":7},
            "T1098":     {"name":"Account Manipulation","priority":8,"actor_freq":8},
        }
    },
    "TA0004": {
        "name": "Privilege Escalation",
        "priority": 9,
        "techniques": {
            "T1548":     {"name":"Abuse Elevation Control Mechanism","priority":9,"actor_freq":9},
            "T1548.002": {"name":"Bypass UAC","priority":9,"actor_freq":9},
            "T1134":     {"name":"Access Token Manipulation","priority":8,"actor_freq":8},
            "T1134.001": {"name":"Token Impersonation/Theft","priority":8,"actor_freq":8},
            "T1068":     {"name":"Exploitation for Privilege Escalation","priority":10,"actor_freq":9},
            "T1055":     {"name":"Process Injection","priority":9,"actor_freq":9},
            "T1574":     {"name":"Hijack Execution Flow","priority":8,"actor_freq":7},
        }
    },
    "TA0005": {
        "name": "Defense Evasion",
        "priority": 9,
        "techniques": {
            "T1562":     {"name":"Impair Defenses","priority":10,"actor_freq":9},
            "T1562.001": {"name":"Disable or Modify Tools","priority":10,"actor_freq":9},
            "T1070":     {"name":"Indicator Removal","priority":9,"actor_freq":8},
            "T1070.001": {"name":"Clear Windows Event Logs","priority":9,"actor_freq":9},
            "T1036":     {"name":"Masquerading","priority":8,"actor_freq":8},
            "T1027":     {"name":"Obfuscated Files or Information","priority":8,"actor_freq":9},
            "T1055":     {"name":"Process Injection","priority":9,"actor_freq":9},
            "T1218":     {"name":"System Binary Proxy Execution","priority":8,"actor_freq":8},
            "T1218.011": {"name":"Rundll32","priority":8,"actor_freq":8},
        }
    },
    "TA0006": {
        "name": "Credential Access",
        "priority": 9,
        "techniques": {
            "T1110":     {"name":"Brute Force","priority":8,"actor_freq":9},
            "T1110.001": {"name":"Password Guessing","priority":8,"actor_freq":8},
            "T1110.003": {"name":"Password Spraying","priority":9,"actor_freq":9},
            "T1003":     {"name":"OS Credential Dumping","priority":10,"actor_freq":10},
            "T1003.001": {"name":"LSASS Memory","priority":10,"actor_freq":10},
            "T1555":     {"name":"Credentials from Password Stores","priority":8,"actor_freq":8},
            "T1552":     {"name":"Unsecured Credentials","priority":8,"actor_freq":8},
            "T1557":     {"name":"Adversary-in-the-Middle","priority":7,"actor_freq":7},
            "T1558":     {"name":"Steal or Forge Kerberos Tickets","priority":8,"actor_freq":8},
            "T1558.003": {"name":"Kerberoasting","priority":9,"actor_freq":9},
        }
    },
    "TA0007": {
        "name": "Discovery",
        "priority": 7,
        "techniques": {
            "T1082": {"name":"System Information Discovery","priority":7,"actor_freq":9},
            "T1083": {"name":"File and Directory Discovery","priority":7,"actor_freq":8},
            "T1046": {"name":"Network Service Discovery","priority":8,"actor_freq":8},
            "T1018": {"name":"Remote System Discovery","priority":7,"actor_freq":8},
            "T1087": {"name":"Account Discovery","priority":7,"actor_freq":8},
            "T1069": {"name":"Permission Groups Discovery","priority":7,"actor_freq":7},
            "T1057": {"name":"Process Discovery","priority":6,"actor_freq":8},
        }
    },
    "TA0008": {
        "name": "Lateral Movement",
        "priority": 9,
        "techniques": {
            "T1021":     {"name":"Remote Services","priority":9,"actor_freq":9},
            "T1021.001": {"name":"Remote Desktop Protocol","priority":9,"actor_freq":9},
            "T1021.006": {"name":"Windows Remote Management","priority":8,"actor_freq":7},
            "T1047":     {"name":"Windows Management Instrumentation","priority":8,"actor_freq":8},
            "T1570":     {"name":"Lateral Tool Transfer","priority":8,"actor_freq":7},
        }
    },
    "TA0009": {
        "name": "Collection",
        "priority": 7,
        "techniques": {
            "T1560":     {"name":"Archive Collected Data","priority":7,"actor_freq":7},
            "T1056.001": {"name":"Keylogging","priority":7,"actor_freq":7},
            "T1123":     {"name":"Audio Capture","priority":5,"actor_freq":4},
            "T1125":     {"name":"Video Capture","priority":5,"actor_freq":4},
        }
    },
    "TA0011": {
        "name": "Command and Control",
        "priority": 9,
        "techniques": {
            "T1071":     {"name":"Application Layer Protocol","priority":9,"actor_freq":9},
            "T1071.001": {"name":"Web Protocols","priority":9,"actor_freq":9},
            "T1071.004": {"name":"DNS","priority":8,"actor_freq":8},
            "T1105":     {"name":"Ingress Tool Transfer","priority":8,"actor_freq":9},
            "T1572":     {"name":"Protocol Tunneling","priority":7,"actor_freq":7},
            "T1090":     {"name":"Proxy","priority":7,"actor_freq":7},
            "T1219":     {"name":"Remote Access Software","priority":8,"actor_freq":8},
        }
    },
    "TA0010": {
        "name": "Exfiltration",
        "priority": 8,
        "techniques": {
            "T1041": {"name":"Exfiltration Over C2 Channel","priority":8,"actor_freq":8},
            "T1048": {"name":"Exfiltration Over Alternative Protocol","priority":7,"actor_freq":7},
            "T1048.002": {"name":"Exfiltration Over Asymmetric Encrypted Non-C2 Protocol","priority":7,"actor_freq":6},
        }
    },
    "TA0040": {
        "name": "Impact",
        "priority": 8,
        "techniques": {
            "T1486": {"name":"Data Encrypted for Impact","priority":10,"actor_freq":10},
            "T1489": {"name":"Service Stop","priority":8,"actor_freq":8},
            "T1490": {"name":"Inhibit System Recovery","priority":9,"actor_freq":9},
            "T1491": {"name":"Defacement","priority":6,"actor_freq":5},
            "T1499": {"name":"Endpoint Denial of Service","priority":7,"actor_freq":6},
            "T1531": {"name":"Account Access Removal","priority":7,"actor_freq":6},
        }
    },
}


@dataclass
class CoverageGap:
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    priority: int          # 1-10, detection priority
    actor_frequency: int   # How often seen in real attacks (1-10)
    gap_severity: str      # CRITICAL | HIGH | MEDIUM | LOW
    recommendation: str
    suggested_sigma_logsource: str = ""
    suggested_kql_table: str       = ""

    def to_dict(self): return asdict(self)


@dataclass
class CoverageReport:
    generated_at: str
    total_techniques_in_framework: int
    total_techniques_covered: int
    coverage_percentage: float
    tactics_coverage: Dict[str,Dict] = field(default_factory=dict)
    critical_gaps: List[CoverageGap] = field(default_factory=list)
    high_gaps: List[CoverageGap]     = field(default_factory=list)
    medium_gaps: List[CoverageGap]   = field(default_factory=list)
    covered_techniques: List[str]    = field(default_factory=list)
    uncovered_techniques: List[str]  = field(default_factory=list)
    navigator_layer: Dict            = field(default_factory=dict)
    remediation_roadmap: List[str]   = field(default_factory=list)
    engine_version: str = ENGINE_VERSION

    def to_dict(self): return asdict(self)


class CoverageGapAnalyzer:
    """Analyzes detection coverage and identifies ATT&CK gaps."""

    TACTIC_LOGSOURCE = {
        "TA0001": ("process_creation","webserver","network_connection"),
        "TA0002": ("process_creation","powershell","wmi_event"),
        "TA0003": ("registry_event","process_creation","file_event"),
        "TA0004": ("process_creation","registry_event","security"),
        "TA0005": ("process_creation","file_event","registry_event"),
        "TA0006": ("authentication","process_creation","file_event"),
        "TA0007": ("process_creation","network_connection"),
        "TA0008": ("network_connection","authentication","process_creation"),
        "TA0009": ("file_event","process_creation"),
        "TA0011": ("network_connection","dns_query","proxy"),
        "TA0010": ("network_connection","file_event"),
        "TA0040": ("file_event","process_creation","service"),
    }

    TACTIC_KQL_TABLE = {
        "TA0001": "DeviceProcessEvents, DeviceNetworkEvents",
        "TA0002": "DeviceProcessEvents",
        "TA0003": "DeviceRegistryEvents, DeviceProcessEvents",
        "TA0004": "DeviceProcessEvents, SecurityEvent",
        "TA0005": "DeviceProcessEvents, DeviceFileEvents",
        "TA0006": "SigninLogs, SecurityEvent",
        "TA0007": "DeviceProcessEvents, DeviceNetworkEvents",
        "TA0008": "DeviceNetworkEvents, SigninLogs",
        "TA0009": "DeviceFileEvents",
        "TA0011": "DeviceNetworkEvents, DnsEvents",
        "TA0010": "DeviceNetworkEvents, DeviceFileEvents",
        "TA0040": "DeviceFileEvents, DeviceProcessEvents",
    }

    def analyze(self, covered_technique_ids:List[str]) -> CoverageReport:
        """Analyze coverage and generate gap report."""
        covered_set = set(t.upper() for t in covered_technique_ids)

        total_techniques = sum(len(tactic["techniques"]) for tactic in ATTACK_COVERAGE_MAP.values())
        covered_count    = 0
        critical_gaps=[]
        high_gaps=[]
        medium_gaps=[]
        tactics_coverage={}
        uncovered=[]
        covered=[]

        for tactic_id, tactic_data in ATTACK_COVERAGE_MAP.items():
            tactic_name = tactic_data["name"]
            tactic_techniques = tactic_data["techniques"]
            tactic_covered=0
            tactic_total=len(tactic_techniques)

            logsources = self.TACTIC_LOGSOURCE.get(tactic_id,("process_creation",))
            kql_tables = self.TACTIC_KQL_TABLE.get(tactic_id,"DeviceProcessEvents")

            for tech_id, tech_data in tactic_techniques.items():
                if tech_id in covered_set:
                    tactic_covered+=1
                    covered_count+=1
                    covered.append(tech_id)
                else:
                    uncovered.append(tech_id)
                    # Determine gap severity
                    priority     = tech_data.get("priority",5)
                    actor_freq   = tech_data.get("actor_freq",5)
                    combined     = (priority*0.6 + actor_freq*0.4)
                    if combined >= 8.5:   sev="CRITICAL"
                    elif combined >= 7.0: sev="HIGH"
                    elif combined >= 5.0: sev="MEDIUM"
                    else:                 sev="LOW"

                    rec = self._build_recommendation(tech_id, tech_data["name"], tactic_name)
                    gap = CoverageGap(
                        technique_id=tech_id, technique_name=tech_data["name"],
                        tactic=tactic_name, tactic_id=tactic_id,
                        priority=priority, actor_frequency=actor_freq,
                        gap_severity=sev, recommendation=rec,
                        suggested_sigma_logsource=", ".join(logsources),
                        suggested_kql_table=kql_tables
                    )
                    if sev=="CRITICAL": critical_gaps.append(gap)
                    elif sev=="HIGH":   high_gaps.append(gap)
                    else:               medium_gaps.append(gap)

            pct = round(tactic_covered/tactic_total*100 if tactic_total>0 else 0,1)
            tactics_coverage[tactic_id] = {
                "name": tactic_name, "covered": tactic_covered,
                "total": tactic_total, "coverage_pct": pct,
                "status": "GREEN" if pct>=75 else "AMBER" if pct>=40 else "RED"
            }

        coverage_pct = round(covered_count/total_techniques*100 if total_techniques>0 else 0,2)

        # Build remediation roadmap
        roadmap = self._build_roadmap(critical_gaps, high_gaps)

        # Build Navigator layer
        navigator = self._build_navigator_layer(covered_set, critical_gaps, high_gaps)

        report = CoverageReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_techniques_in_framework=total_techniques,
            total_techniques_covered=covered_count,
            coverage_percentage=coverage_pct,
            tactics_coverage=tactics_coverage,
            critical_gaps=critical_gaps,
            high_gaps=high_gaps,
            medium_gaps=medium_gaps,
            covered_techniques=list(set(covered)),
            uncovered_techniques=list(set(uncovered)),
            navigator_layer=navigator,
            remediation_roadmap=roadmap,
        )
        return report

    def _build_recommendation(self, tech_id:str, tech_name:str, tactic:str) -> str:
        recs = {
            "T1190": "Deploy web application process spawn detection via Sigma process_creation + webserver logsource",
            "T1059.001": "Deploy PowerShell Logging (Module + ScriptBlock) + Sigma encoded command detection",
            "T1003.001": "Deploy LSASS access monitoring via Sysmon EventID 10 + Sigma lsass_access rule",
            "T1486": "Deploy ransomware behavioral detection: mass file extension changes + shadow copy deletion",
            "T1562.001": "Monitor security tool service stops and AV/EDR process terminations",
            "T1078": "Deploy authentication anomaly detection: geo-velocity, impossible travel, off-hours auth",
            "T1548.002": "Monitor UAC bypass techniques: fodhelper, eventvwr, computerdefaults registry paths",
            "T1021.001": "Monitor RDP anomalies: unusual source IPs, off-hours connections, new service accounts",
            "T1566": "Deploy email security detection: suspicious attachment types, URL detonation alerts",
            "T1195": "Monitor build pipeline integrity: unexpected dependencies, code signing verification",
        }
        if tech_id in recs:
            return recs[tech_id]
        return f"Create Sigma rule for {tech_name} ({tactic}) using process_creation or network_connection logsource. Map to ATT&CK {tech_id}."

    def _build_roadmap(self, critical:List[CoverageGap], high:List[CoverageGap]) -> List[str]:
        roadmap=[]
        if critical:
            roadmap.append(f"SPRINT 1 (Immediate): Address {len(critical)} CRITICAL gaps — highest actor frequency")
            for gap in sorted(critical, key=lambda g: g.actor_frequency, reverse=True)[:5]:
                roadmap.append(f"  → Build {gap.technique_id} ({gap.technique_name}) detection: {gap.recommendation}")
        if high:
            roadmap.append(f"SPRINT 2 (30 days): Address {len(high)} HIGH priority gaps")
            for gap in sorted(high, key=lambda g: g.priority, reverse=True)[:5]:
                roadmap.append(f"  → Build {gap.technique_id} ({gap.technique_name}) detection")
        roadmap.append("SPRINT 3 (60 days): Validate all new rules in staging, tune FP thresholds")
        roadmap.append("SPRINT 4 (90 days): Deploy to production, establish detection baselines")
        return roadmap

    def _build_navigator_layer(self, covered:Set[str], critical:List[CoverageGap],
                                high:List[CoverageGap]) -> Dict:
        techniques=[]
        for tech_id in covered:
            techniques.append({"techniqueID":tech_id,"color":"#4CAF50","score":100,"comment":"Covered by SENTINEL APEX"})
        for gap in critical:
            techniques.append({"techniqueID":gap.technique_id,"color":"#F44336","score":0,"comment":"CRITICAL GAP — no detection"})
        for gap in high:
            techniques.append({"techniqueID":gap.technique_id,"color":"#FF9800","score":0,"comment":"HIGH gap — no detection"})
        return {
            "name": f"CYBERDUDEBIVASH SENTINEL APEX Coverage — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            "versions": {"attack":"16","navigator":"4.9","layer":"4.5"},
            "domain": "enterprise-attack",
            "description": "SENTINEL APEX detection coverage layer. Green=covered, Red=critical gap, Orange=high gap.",
            "techniques": techniques,
            "gradient": {"colors":["#F44336","#4CAF50"],"minValue":0,"maxValue":100},
            "legendItems": [
                {"label":"Covered","color":"#4CAF50"},
                {"label":"Critical Gap","color":"#F44336"},
                {"label":"High Gap","color":"#FF9800"},
            ]
        }

    def save_navigator_layer(self, report:CoverageReport, output_path:str):
        """Save ATT&CK Navigator layer JSON."""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path,"w",encoding="utf-8") as f:
            json.dump(report.navigator_layer, f, indent=2)
        log.info(f"[CGA] Navigator layer saved: {output_path}")


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    analyzer = CoverageGapAnalyzer()
    # Simulate current coverage from APEX pipeline
    covered = ["T1190","T1566","T1059.001","T1059.003","T1078","T1486",
               "T1562.001","T1548.002","T1003.001","T1021.001","T1071.001"]
    report = analyzer.analyze(covered)
    print(f"[CGA] Coverage: {report.coverage_percentage:.1f}% ({report.total_techniques_covered}/{report.total_techniques_in_framework})")
    print(f"[CGA] Critical Gaps: {len(report.critical_gaps)}")
    print(f"[CGA] High Gaps: {len(report.high_gaps)}")
    print(f"[CGA] Tactic Coverage:")
    for tid,td in report.tactics_coverage.items():
        print(f"  {td['name']:30s} {td['coverage_pct']:5.1f}% [{td['status']}]")
    print("\nRemediation Roadmap:")
    for step in report.remediation_roadmap: print(f"  {step}")
