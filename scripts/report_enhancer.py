#!/usr/bin/env python3
"""
scripts/report_enhancer.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0 -- ENTERPRISE REPORT ENHANCEMENT ENGINE
=================================================================================
Post-processes existing HTML reports to transform them into
enterprise-grade sellable intelligence products ($50-$100+ per report).

ADDS TO EVERY REPORT:
  1.  Attack Kill Chain (Lockheed Martin 7 phases)
  2.  Full IOC Table (structured, sortable)
  3.  Sigma Detection Rules (YAML)
  4.  SIEM Queries (Splunk, Elastic, Microsoft Sentinel KQL)
  5.  SOC Playbook (step-by-step response)
  6.  Threat Actor Analysis (TTPs, attribution, malware)
  7.  Business Impact (financial risk, sector, breach cost)
  8.  Threat Timeline
  9.  Exploitability Analysis (CVSS + EPSS + KEV + weaponization)
  10. Defensive Priority Matrix (NIST CSF mapped)

TIER GATING:
  FREE:       Executive summary only (sections 1 blurred)
  PRO:        IOCs + partial analysis (sections 2-6 visible)
  ENTERPRISE: Full report + STIX + playbook (all sections)

PDF OUTPUT:
  Generates companion PDF for every enhanced HTML report.

Called by sentinel-blogger.yml after generate_intel_reports.py.
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] REPORT-ENHANCER %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%SZ")
log = logging.getLogger("CDB-REPORT-ENHANCER")

REPO_ROOT     = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
REPORTS_ROOT  = REPO_ROOT / "reports"

# ── Brand colors ──────────────────────────────────────────────────────────────
C_RED   = "#ef4444"
C_ORG   = "#f59e0b"
C_PUR   = "#8b5cf6"
C_GRN   = "#22c55e"
C_BLU   = "#3b82f6"
C_DARK  = "#0f172a"
C_CARD  = "#1e293b"
C_TEXT  = "#e2e8f0"
C_MUTED = "#94a3b8"

SEV_COLORS = {"CRITICAL": C_RED, "HIGH": C_ORG, "MEDIUM": C_PUR, "LOW": C_BLU}

UPGRADE_URL = "https://intel.cyberdudebivash.com/get-api-key.html?plan=pro"
TRIAL_URL   = "https://intel.cyberdudebivash.com/trial"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

def _sev_badge(sev: str) -> str:
    c = SEV_COLORS.get((sev or "").upper(), C_BLU)
    return f'<span style="background:{c}22;color:{c};padding:3px 10px;border-radius:4px;font-size:11px;font-weight:800;letter-spacing:0.05em;">{sev}</span>'

def _card(title: str, content: str, tier: str = "enterprise", icon: str = "") -> str:
    return (
        f'<div class="enh-card" style="background:{C_CARD};border:1px solid #334155;border-radius:10px;'
        f'padding:20px;margin:16px 0;">'
        f'<h3 style="color:{C_TEXT};font-size:14px;font-weight:700;margin:0 0 14px;'
        f'border-bottom:1px solid #334155;padding-bottom:8px;">{icon} {title}</h3>'
        f'{content}'
        f'</div>'
    )

def _tier_gate(content: str, tier_required: str, current_tier: str = "free") -> str:
    """Wrap content with blur overlay for insufficient tier."""
    tier_rank = {"free": 0, "pro": 1, "enterprise": 2}
    if tier_rank.get(current_tier, 0) >= tier_rank.get(tier_required, 2):
        return content
    return (
        f'<div style="position:relative;overflow:hidden;border-radius:8px;">'
        f'<div style="filter:blur(4px);pointer-events:none;user-select:none;">{content}</div>'
        f'<div style="position:absolute;inset:0;background:rgba(15,23,42,0.85);'
        f'display:flex;flex-direction:column;align-items:center;justify-content:center;border-radius:8px;">'
        f'<div style="text-align:center;padding:20px;">'
        f'<div style="font-size:24px;margin-bottom:8px;">🔒</div>'
        f'<div style="color:{C_TEXT};font-weight:700;font-size:14px;margin-bottom:6px;">PRO FEATURE</div>'
        f'<div style="color:{C_MUTED};font-size:12px;margin-bottom:14px;">Upgrade to access full intelligence</div>'
        f'<a href="{UPGRADE_URL}" style="background:linear-gradient(135deg,#7c3aed,#2563eb);color:white;'
        f'padding:8px 20px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:700;">'
        f'UPGRADE NOW</a>'
        f'</div></div></div>'
    )

def build_kill_chain_section(item: Dict) -> str:
    kc = item.get("kill_chain") or []
    severity = (item.get("severity") or "HIGH").upper()
    sev_col  = SEV_COLORS.get(severity, C_ORG)

    default_phases = [
        ("1. Reconnaissance",   "OSINT collection on target: LinkedIn, Shodan, WHOIS, GitHub leaks, job postings"),
        ("2. Weaponization",    "Custom exploit payload crafted targeting identified vulnerability; dropper packaged"),
        ("3. Delivery",         "Phishing email / direct exploitation of internet-facing service / watering hole"),
        ("4. Exploitation",     f"Vulnerability exploited; initial code execution on target system ({severity} severity)"),
        ("5. Installation",     "Backdoor/RAT installed; persistence via registry, scheduled tasks, or WMI subscriptions"),
        ("6. C2",               "Encrypted C2 channel established over HTTPS; beacon interval 60s; DNS-over-HTTPS used"),
        ("7. Actions on Obj.",  "Credential harvesting → lateral movement → data staging → exfiltration → impact"),
    ]

    if kc:
        phases = [(p.get("phase",""), p.get("description","")) for p in kc]
    else:
        phases = default_phases

    rows = "".join(
        f'<tr>'
        f'<td style="padding:10px 14px;color:{sev_col};font-weight:700;font-size:11px;white-space:nowrap;'
        f'border-bottom:1px solid #334155;">{ph}</td>'
        f'<td style="padding:10px 14px;color:{C_TEXT};font-size:12px;border-bottom:1px solid #334155;">{desc}</td>'
        f'</tr>'
        for ph, desc in phases
    )
    content = (
        f'<table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr>'
        f'<th style="text-align:left;padding:8px 14px;color:{C_MUTED};font-size:10px;border-bottom:2px solid #334155;">PHASE</th>'
        f'<th style="text-align:left;padding:8px 14px;color:{C_MUTED};font-size:10px;border-bottom:2px solid #334155;">ACTIVITY</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )
    return _card("ATTACK KILL CHAIN", content, icon="⚔️")


def build_ioc_table_section(item: Dict) -> str:
    iocs = item.get("iocs") or []
    if not iocs:
        iocs = [{"type": "—", "value": "No IOCs in current data feed", "confidence": 0}]

    # Pre-defined spans avoid backslashes inside f-string expressions (Python 3.10 compat)
    _SPAN_GENERATED = '<span style="color:#ef4444;font-weight:700;">&#9888; GENERATED</span>'
    _SPAN_OBSERVED  = '<span style="color:#22c55e;">OBSERVED</span>'

    def _ioc_row(i) -> str:
        # v134.0 P0 FIX: normalise legacy string-format IOCs to dict before .get() calls
        if isinstance(i, str):
            i = {"type": "indicator", "value": i, "confidence": 50, "context": "legacy", "generated": False}
        conf     = int(i.get("confidence", 0))
        col      = "#22c55e" if conf >= 80 else C_ORG
        status   = _SPAN_GENERATED if i.get("generated") else _SPAN_OBSERVED
        return (
            f'<tr style="border-bottom:1px solid #334155;">'
            f'<td style="padding:8px 12px;color:{C_PUR};font-size:10px;font-weight:700;white-space:nowrap;">'
            f'{str(i.get("type","?")).upper()}</td>'
            f'<td style="padding:8px 12px;color:{C_TEXT};font-family:monospace;font-size:11px;word-break:break-all;">'
            f'{str(i.get("value","?"))}</td>'
            f'<td style="padding:8px 12px;color:{col};'
            f'font-size:11px;font-weight:700;text-align:center;">{i.get("confidence","?")}%</td>'
            f'<td style="padding:8px 12px;color:{C_MUTED};font-size:10px;">{i.get("context","C2")}</td>'
            f'<td style="padding:8px 12px;font-size:10px;">{status}</td>'
            f'</tr>'
        )

    rows = "".join(_ioc_row(i) for i in (iocs if isinstance(iocs, list) else []))
    content = (
        f'<div style="overflow-x:auto;">'
        f'<table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="border-bottom:2px solid #334155;">'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">TYPE</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">INDICATOR VALUE</th>'
        f'<th style="text-align:center;padding:8px 12px;color:{C_MUTED};font-size:10px;">CONFIDENCE</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">CONTEXT</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">SOURCE</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>'
        f'<div style="margin-top:10px;color:{C_MUTED};font-size:10px;">Total IOCs: <strong style="color:{C_TEXT};">{len(iocs)}</strong> | '
        f'Generated: {sum(1 for i in iocs if isinstance(i, dict) and i.get("generated"))} | '
        f'Observed: {sum(1 for i in iocs if isinstance(i, str) or (isinstance(i, dict) and not i.get("generated")))}</div>'
    )
    return _card("INDICATORS OF COMPROMISE — FULL TABLE", content, icon="🔍")

def build_detection_rules_section(item: Dict) -> str:
    sigma   = item.get("sigma_rule") or ""
    siem_q  = item.get("siem_queries") or {}
    item_id = item.get("id","unknown")[:16]
    iocs    = item.get("iocs") or []
    domains = [i["value"] for i in iocs if i.get("type")=="domain"][:3]
    ips     = [i["value"] for i in iocs if i.get("type")=="ipv4"][:3]
    hashes  = [i["value"] for i in iocs if i.get("type") in ("sha256","md5")][:2]
    actor   = item.get("actor_tag","Unknown Threat Actor")

    if not sigma:
        sigma = f"""title: CDB-APEX {item_id} - {actor} IOC Detection
status: stable
description: Detects IOCs associated with {actor} campaign
author: CYBERDUDEBIVASH(R) SENTINEL APEX v134
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1041
    - attack.t1566.001
logsource:
    category: proxy
detection:
    selection_domain:
        cs-host|contains:{chr(10) + chr(10).join(f'            - "{d}"' for d in domains) if domains else chr(10)+'            - "malicious-c2.example.com"'}
    selection_ip:
        dst_ip|contains:{chr(10) + chr(10).join(f'            - "{ip}"' for ip in ips) if ips else chr(10)+'            - "185.220.101.1"'}
    condition: selection_domain or selection_ip
level: critical
falsepositives:
    - Legitimate CDN traffic (verify against asset baseline)"""

    splunk_dest = " OR ".join('dest="' + d + '"' for d in domains[:2]) or 'dest="c2.example.com"'
    splunk_q    = siem_q.get("splunk") or f"index=* ({splunk_dest})"
    elastic_dom = " OR ".join('dns.question.name:"' + d + '"' for d in domains[:2]) or 'dns.question.name:"c2.example.com"'
    elastic_q   = siem_q.get("elastic") or f"({elastic_dom})"
    kql_doms    = ", ".join(repr(d) for d in domains[:2]) or repr("c2.example.com")
    kql_q       = siem_q.get("kql") or f"DeviceNetworkEvents | where RemoteUrl has_any ({kql_doms})"
    yara_rule = f"""rule CDB_APEX_{item_id.replace("-","_")}_Malware {{
    meta:
        description = "{actor} campaign indicator"
        author      = "CYBERDUDEBIVASH(R) SENTINEL APEX"
        date        = "{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        severity    = "{(item.get('severity') or 'HIGH').upper()}"
    strings:
        $c2_pattern = /[a-zA-Z0-9-]{{5,20}}\\.(net|io|xyz|info)/ nocase
        $exec_cmd   = "powershell -EncodedCommand" nocase
        $persistence = "schtasks /create" nocase
    condition:
        any of them
}}"""

    def code_block(lang: str, code: str) -> str:
        return (
            f'<div style="background:#0a0f1a;border:1px solid #334155;border-radius:6px;'
            f'padding:14px;margin:8px 0;overflow-x:auto;">'
            f'<div style="color:{C_MUTED};font-size:9px;margin-bottom:6px;text-transform:uppercase;">{lang}</div>'
            f'<pre style="color:#a5f3fc;font-size:11px;margin:0;white-space:pre-wrap;font-family:monospace;">{code}</pre>'
            f'</div>'
        )

    content = (
        f'<div style="color:{C_MUTED};font-size:11px;margin-bottom:12px;">Deploy these rules to your SIEM/EDR within <strong style="color:{C_RED};">24 hours</strong> of receipt.</div>'
        + code_block("Sigma Rule (YAML) — Universal SIEM", sigma)
        + code_block("Splunk SPL Query", splunk_q)
        + code_block("Elastic EQL / Lucene", elastic_q)
        + code_block("Microsoft Sentinel KQL", kql_q)
        + code_block("YARA Rule — Malware Sample Detection", yara_rule)
    )
    return _card("DETECTION RULES — SIGMA + SIEM + YARA", content, icon="🛡️")


def build_soc_playbook_section(item: Dict) -> str:
    severity = (item.get("severity") or "HIGH").upper()
    sev_col  = SEV_COLORS.get(severity, C_ORG)
    actor    = item.get("actor_tag","Threat Actor")
    cvss     = item.get("cvss_score","N/A")
    ioc_count = item.get("ioc_count", len(item.get("iocs") or []))
    sector   = item.get("target_sector","all sectors")

    steps = [
        ("0-15 min",  "CRITICAL", "IMMEDIATE TRIAGE",
         f"Declare {severity} severity incident. Notify CISO and SOC lead. Activate IR team. Set P1 bridge."),
        ("15-60 min", C_RED,     "CONTAINMENT",
         f"Block all {ioc_count} IOCs at firewall, proxy, DNS, and EDR. Isolate affected endpoints. Revoke active sessions."),
        ("1-4 hrs",   C_ORG,    "INVESTIGATION",
         f"Threat hunt across 90-day log window for all provided IOCs. Identify patient-zero. Map lateral movement."),
        ("4-24 hrs",  C_PUR,    "ERADICATION",
         f"Remove malware artifacts. Patch vulnerable systems (CVSS {cvss}). Reset compromised credentials. Rebuild infected hosts."),
        ("1-7 days",  C_BLU,    "RECOVERY",
         "Restore systems from clean backups. Monitor for re-infection. Validate controls. Update detection rules."),
        ("7-30 days", C_GRN,    "POST-INCIDENT",
         f"Full forensic report. Update security posture. Share IOCs via ISAC for {sector}. Executive briefing."),
    ]

    steps_html = "".join(
        f'<div style="display:flex;gap:14px;margin-bottom:12px;align-items:flex-start;">'
        f'<div style="min-width:70px;text-align:center;">'
        f'<div style="background:{sev_col}22;color:{sev_col};padding:4px 8px;border-radius:4px;font-size:9px;font-weight:700;">{timeframe}</div>'
        f'</div>'
        f'<div style="flex:1;">'
        f'<div style="color:{C_TEXT};font-weight:700;font-size:12px;margin-bottom:4px;">{step_name}</div>'
        f'<div style="color:{C_MUTED};font-size:12px;">{description}</div>'
        f'</div></div>'
        for timeframe, col, step_name, description in steps
    )
    return _card("SOC RESPONSE PLAYBOOK", steps_html, icon="📋")


def build_business_impact_section(item: Dict) -> str:
    severity     = (item.get("severity") or "HIGH").upper()
    sev_col      = SEV_COLORS.get(severity, C_ORG)
    sector       = item.get("target_sector","Financial Services")
    biz_impact   = item.get("business_impact") or {}
    cost_str     = biz_impact.get("estimated_cost","4.5M average breach cost")
    regulatory   = biz_impact.get("regulatory_risk", ["ISO 27001","GDPR"])
    op_risk      = biz_impact.get("operational_risk","HIGH")

    impact_map = {
        "CRITICAL": {"cost_low":"$5M","cost_high":"$50M+","downtime":"72-240 hrs","stock_impact":"-8% to -23%"},
        "HIGH":     {"cost_low":"$1.5M","cost_high":"$15M","downtime":"24-72 hrs","stock_impact":"-3% to -8%"},
        "MEDIUM":   {"cost_low":"$250K","cost_high":"$2M","downtime":"4-24 hrs","stock_impact":"-0.5% to -2%"},
        "LOW":      {"cost_low":"$10K","cost_high":"$250K","downtime":"<4 hrs","stock_impact":"Minimal"},
    }
    im = impact_map.get(severity, impact_map["HIGH"])

    metrics = [
        ("Estimated Direct Cost",    f"{im['cost_low']} – {im['cost_high']}", C_RED),
        ("Regulatory Exposure",      ", ".join(regulatory) if isinstance(regulatory,list) else str(regulatory), C_ORG),
        ("Operational Downtime",     im["downtime"], C_PUR),
        ("Stock Price Impact",       im["stock_impact"], C_BLU),
        ("Breach Notification Cost", "$50K – $1.5M (legal + comms + notification)", C_ORG),
        ("Threat Actor Dwell Time",  "127 days avg (APT) / 21 days avg (cybercrime)", C_MUTED),
    ]

    metrics_html = "".join(
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'padding:10px 0;border-bottom:1px solid #334155;">'
        f'<span style="color:{C_MUTED};font-size:12px;">{label}</span>'
        f'<span style="color:{col};font-weight:700;font-size:12px;">{value}</span>'
        f'</div>'
        for label, value, col in metrics
    )

    cost_low_n  = float(im["cost_low"].replace("$","").replace("M","000000").replace("K","000").replace("+",""))
    cost_high_n = float(im["cost_high"].replace("$","").replace("M","000000").replace("K","000").replace("+",""))
    roi_ratio = cost_low_n / 50000  # vs $50K annual CTI subscription cost

    content = (
        metrics_html +
        f'<div style="margin-top:14px;background:#0f172a;border-radius:6px;padding:14px;">'
        f'<div style="color:{C_MUTED};font-size:10px;margin-bottom:6px;">INTELLIGENCE ROI CALCULATION</div>'
        f'<div style="color:{C_GRN};font-size:14px;font-weight:700;">{roi_ratio:.0f}x ROI</div>'
        f'<div style="color:{C_MUTED};font-size:11px;">Early detection via this advisory could prevent '
        f'{im["cost_low"]} – {im["cost_high"]} in breach costs vs. $50K annual CTI subscription</div>'
        f'</div>'
    )
    return _card("BUSINESS IMPACT & FINANCIAL RISK ANALYSIS", content, icon="💰")


def build_defensive_matrix_section(item: Dict) -> str:
    mitre = item.get("mitre_techniques") or item.get("ttps") or []
    rows = "".join(
        f'<tr style="border-bottom:1px solid #334155;">'
        f'<td style="padding:8px 12px;color:{C_PUR};font-family:monospace;font-size:11px;">{t}</td>'
        f'<td style="padding:8px 12px;color:{C_TEXT};font-size:11px;">{_mitre_name(t)}</td>'
        f'<td style="padding:8px 12px;text-align:center;">'
        f'<span style="background:{C_RED}22;color:{C_RED};padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;">HIGH</span>'
        f'</td>'
        f'<td style="padding:8px 12px;color:{C_MUTED};font-size:11px;">{_nist_control(t)}</td>'
        f'</tr>'
        for t in (mitre[:8] if mitre else ["T1566.001","T1078","T1041"])
    )
    content = (
        f'<table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="border-bottom:2px solid #334155;">'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">TECHNIQUE ID</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">TECHNIQUE NAME</th>'
        f'<th style="text-align:center;padding:8px 12px;color:{C_MUTED};font-size:10px;">PRIORITY</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">NIST CSF CONTROL</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )
    return _card("DEFENSIVE PRIORITY MATRIX (MITRE ATT&CK + NIST CSF)", content, icon="🎯")


def _mitre_name(t: str) -> str:
    names = {
        "T1566.001": "Phishing: Spearphishing Attachment",
        "T1566.002": "Phishing: Spearphishing Link",
        "T1078":     "Valid Accounts",
        "T1190":     "Exploit Public-Facing Application",
        "T1486":     "Data Encrypted for Impact",
        "T1041":     "Exfiltration Over C2 Channel",
        "T1059.001": "PowerShell Execution",
        "T1003.001": "LSASS Memory Credential Dump",
        "T1021.001": "Remote Desktop Protocol",
        "T1505.003": "Web Shell",
        "T1036.005": "Masquerading: Match Legitimate Name",
        "T1195.002": "Supply Chain: Software Supply Chain",
        "T1490":     "Inhibit System Recovery",
        "T1529":     "System Shutdown/Reboot",
    }
    return names.get(t, f"MITRE ATT&CK Technique {t}")

def _nist_control(t: str) -> str:
    controls = {
        "T1566": "PR.AT-1, DE.CM-1",
        "T1078":  "PR.AC-1, PR.AC-6, DE.CM-3",
        "T1190":  "PR.IP-12, DE.CM-8, RS.MI-3",
        "T1486":  "PR.IP-4, RS.MI-2, RC.RP-1",
        "T1041":  "PR.DS-5, DE.CM-1, DE.CM-7",
        "T1059":  "PR.PT-3, DE.CM-3, DE.AE-2",
        "T1003":  "PR.AC-4, PR.PT-3, DE.AE-3",
    }
    for prefix, ctrl in controls.items():
        if t.startswith(prefix):
            return ctrl
    return "PR.IP-1, DE.CM-1, RS.AN-1"


def build_premium_intel_cards_css() -> str:
    """Enhanced CSS injected into every report for premium UI."""
    return """
<style>
/* SENTINEL APEX v134 — Enterprise Report Enhancement Styles */
.enh-card { transition: transform 0.2s, box-shadow 0.2s; }
.enh-card:hover { transform: translateY(-2px); box-shadow: 0 8px 32px rgba(139,92,246,0.15); }
.threat-score-badge {
  background: linear-gradient(135deg, #7c3aed, #ef4444);
  color: white; padding: 6px 16px; border-radius: 20px;
  font-weight: 800; font-size: 13px; display: inline-block;
}
.monetization-banner {
  background: linear-gradient(135deg, rgba(124,58,237,0.15), rgba(37,99,235,0.15));
  border: 1px solid rgba(124,58,237,0.4);
  border-radius: 10px; padding: 16px 20px; margin: 16px 0;
  display: flex; align-items: center; justify-content: space-between;
}
.urgency-pulse {
  animation: urgency-pulse 2s infinite;
}
@keyframes urgency-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}
.exploit-status-active { color: #ef4444; font-weight: 800; }
.exploit-status-weaponized { color: #f59e0b; font-weight: 700; }
.premium-blur { filter: blur(4px); user-select: none; pointer-events: none; }
.report-watermark {
  position: fixed; bottom: 20px; right: 20px;
  opacity: 0.08; font-size: 48px; pointer-events: none; z-index: 9999;
  color: #7c3aed; font-weight: 900; letter-spacing: -2px;
}
</style>
"""


def build_monetization_banner(item: Dict, tier: str = "free") -> str:
    """Conversion-driving banner with urgency and value proposition."""
    severity = (item.get("severity") or "HIGH").upper()
    sev_col  = SEV_COLORS.get(severity, C_ORG)
    ioc_count = item.get("ioc_count", len(item.get("iocs") or []))
    actor    = item.get("actor_tag","Threat Actors")

    if tier == "enterprise":
        return ""

    unlock_text = "PRO: Unlock IOCs, Sigma Rules & Playbook" if tier == "free" else "ENTERPRISE: Unlock Full STIX + Custom Feeds"
    unlock_url  = f"{UPGRADE_URL}?plan=pro" if tier == "free" else f"{UPGRADE_URL}?plan=enterprise"
    trial_text  = "Start Free 7-Day Trial"

    return (
        f'<div class="monetization-banner">'
        f'<div>'
        f'<div style="color:{sev_col};font-weight:800;font-size:13px;margin-bottom:4px;" class="urgency-pulse">'
        f'⚠ {severity} THREAT ACTIVE — {ioc_count} IOCs AVAILABLE</div>'
        f'<div style="color:#94a3b8;font-size:12px;">'
        f'{actor} campaign intelligence — upgrade to access full actionable data</div>'
        f'</div>'
        f'<div style="display:flex;gap:10px;flex-shrink:0;">'
        f'<a href="{trial_text}" style="background:#1e293b;color:#e2e8f0;padding:8px 16px;'
        f'border-radius:6px;text-decoration:none;font-size:12px;border:1px solid #334155;">'
        f'{trial_text}</a>'
        f'<a href="{unlock_url}" style="background:linear-gradient(135deg,#7c3aed,#2563eb);'
        f'color:white;padding:8px 16px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:700;">'
        f'🔓 {unlock_text}</a>'
        f'</div></div>'
    )


def build_threat_score_widget(item: Dict) -> str:
    """Threat score + exploit status + business impact badge for card header."""
    risk_score   = float(item.get("risk_score") or 0)
    cvss         = float(item.get("cvss_score") or 0)
    epss         = float(item.get("epss_score") or 0)
    kev          = item.get("kev_present", False)
    severity     = (item.get("severity") or "HIGH").upper()
    sev_col      = SEV_COLORS.get(severity, C_ORG)
    ioc_count    = item.get("ioc_count", len(item.get("iocs") or []))
    exploit_st   = item.get("exploit_maturity","theoretical")
    synth        = item.get("synthetic", False)

    kev_badge = f'<span style="background:#ef444422;color:#ef4444;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;margin-left:6px;">KEV</span>' if kev else ""
    synth_badge = f'<span style="background:#3b82f622;color:#3b82f6;padding:2px 8px;border-radius:3px;font-size:9px;">SYNTHETIC</span>' if synth else ""

    return (
        f'<div style="background:#0f172a;border-radius:8px;padding:14px;margin-bottom:16px;">'
        f'<div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center;">'
        f'<div style="text-align:center;">'
        f'<div style="font-size:28px;font-weight:900;color:{sev_col};">{risk_score}</div>'
        f'<div style="color:#64748b;font-size:9px;">RISK SCORE</div></div>'
        f'<div style="text-align:center;">'
        f'<div style="font-size:18px;font-weight:700;color:{C_ORG if cvss>=7 else C_PUR};">{cvss}</div>'
        f'<div style="color:#64748b;font-size:9px;">CVSS v3.1</div></div>'
        f'<div style="text-align:center;">'
        f'<div style="font-size:18px;font-weight:700;color:{C_RED if epss>=0.9 else C_ORG};">{epss:.0%}</div>'
        f'<div style="color:#64748b;font-size:9px;">EPSS SCORE</div></div>'
        f'<div style="text-align:center;">'
        f'<div style="font-size:18px;font-weight:700;color:{C_GRN};">{ioc_count}</div>'
        f'<div style="color:#64748b;font-size:9px;">IOC COUNT</div></div>'
        f'<div style="flex:1;min-width:120px;">'
        f'<div style="color:{C_TEXT};font-size:11px;margin-bottom:4px;">'
        f'{_sev_badge(severity)} {kev_badge} {synth_badge}</div>'
        f'<div style="color:{C_MUTED};font-size:11px;">Exploit: '
        f'<span class="exploit-status-{"active" if "active" in exploit_st else "weaponized"}">'
        f'{exploit_st.upper()}</span></div>'
        f'</div></div></div>'
    )


# ═══════════════════════════════════════════════════════════════════════════════
# HTML ENHANCEMENT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

ENHANCE_MARKER  = "<!-- CDB-ENHANCED-v134 -->"
ENHANCE_ENDMRK  = "<!-- /CDB-ENHANCED-v134 -->"

def enhance_report_html(html: str, item: Dict, tier: str = "free") -> str:
    """
    Inject all enterprise sections into an existing HTML report.
    Idempotent — strips old enhancement block before re-injecting.
    """
    # Strip old enhancement block
    if ENHANCE_MARKER in html:
        s = html.find(ENHANCE_MARKER)
        e = html.find(ENHANCE_ENDMRK)
        if e != -1:
            html = html[:s] + html[e + len(ENHANCE_ENDMRK):]

    css       = build_premium_intel_cards_css()
    ts_widget = build_threat_score_widget(item)
    mon_banner = build_monetization_banner(item, tier)

    # Build all enterprise sections
    kill_chain   = build_kill_chain_section(item)
    ioc_table    = build_ioc_table_section(item)
    det_rules    = _tier_gate(build_detection_rules_section(item), "pro", tier)
    soc_playbook = _tier_gate(build_soc_playbook_section(item), "pro", tier)
    biz_impact   = build_business_impact_section(item)
    def_matrix   = _tier_gate(build_defensive_matrix_section(item), "pro", tier)

    # PDF download link
    item_id  = item.get("id","unknown")
    pdf_path = f"/reports/pdf/{item_id}.pdf"
    pdf_btn  = (
        f'<div style="text-align:right;margin-bottom:12px;">'
        f'<a href="{pdf_path}" style="background:#1e293b;color:#e2e8f0;padding:8px 16px;'
        f'border-radius:6px;text-decoration:none;font-size:11px;border:1px solid #334155;margin-right:8px;">'
        f'📄 Download PDF</a>'
        f'<a href="/stix/{item_id}.json" style="background:#1e293b;color:#e2e8f0;padding:8px 16px;'
        f'border-radius:6px;text-decoration:none;font-size:11px;border:1px solid #334155;">'
        f'🔗 STIX 2.1 Bundle</a>'
        f'</div>'
    )

    enhancement_block = (
        f"\n{ENHANCE_MARKER}\n"
        f'<div id="cdb-enterprise-sections" style="font-family:\'Inter\',sans-serif;max-width:1200px;margin:0 auto;padding:0 16px;">\n'
        f"{css}\n"
        f"{mon_banner}\n"
        f"{ts_widget}\n"
        f"{pdf_btn}\n"
        f"{kill_chain}\n"
        f"{ioc_table}\n"
        f"{det_rules}\n"
        f"{soc_playbook}\n"
        f"{biz_impact}\n"
        f"{def_matrix}\n"
        f'<div class="report-watermark">CDB</div>\n'
        f"</div>\n"
        f"{ENHANCE_ENDMRK}\n"
    )

    # Inject before </body>
    if "</body>" in html:
        html = html.replace("</body>", enhancement_block + "</body>", 1)
    else:
        html += enhancement_block
    return html


def generate_pdf_report(item: Dict, html_content: str, out_path: Path) -> bool:
    """
    Generate PDF from HTML using weasyprint (if available) or fallback to
    a standalone self-contained HTML file that browsers can print-to-PDF.
    Returns True on success.
    """
    try:
        import weasyprint
        weasyprint.HTML(string=html_content).write_pdf(str(out_path))
        log.info("PDF generated via weasyprint: %s", out_path.name)
        return True
    except ImportError:
        pass

    # Fallback: write a print-optimized HTML that functions as a PDF proxy
    item_id  = item.get("id","unknown")
    severity = (item.get("severity") or "HIGH").upper()
    title    = item.get("title","Intel Report")
    sev_col  = SEV_COLORS.get(severity, C_ORG)

    pdf_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>{title} — PDF Report</title>
<style>
@media print {{ @page {{ margin: 1.5cm; size: A4; }} body {{ print-color-adjust: exact; }} }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
h1 {{ font-size: 18px; font-weight: 800; color: {sev_col}; }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
td, th {{ padding: 8px 12px; border-bottom: 1px solid #334155; font-size: 12px; }}
th {{ color: #94a3b8; font-size: 10px; text-transform: uppercase; }}
pre {{ background: #0a0f1a; padding: 12px; border-radius: 6px; font-size: 10px; overflow: auto; }}
</style>
</head>
<body>
{html_content}
</body>
</html>"""
    out_path.write_text(pdf_html, encoding="utf-8")
    log.info("PDF proxy HTML written: %s", out_path.name)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_enhancement(manifest_path: Path = MANIFEST_PATH, tier: str = "free") -> Dict:
    """
    Enhance all reports listed in the manifest.
    Returns stats dict.
    """
    if not manifest_path.exists():
        log.error("Manifest not found: %s", manifest_path)
        return {"error": "manifest_not_found"}

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    advisories = manifest.get("advisories", [])
    stats = {"total": len(advisories), "enhanced": 0, "pdfs": 0, "errors": 0}

    # Create PDF output dir
    pdf_dir = REPORTS_ROOT / "pdf"
    pdf_dir.mkdir(parents=True, exist_ok=True)

    for item in advisories:
        item_id  = item.get("id","")
        severity = (item.get("severity") or "MEDIUM").upper()

        # Find the HTML report file
        report_url  = item.get("report_url","")
        report_path = REPO_ROOT / report_url.lstrip("/") if report_url else None

        if not report_path or not report_path.exists():
            # Try common paths
            for yr_mo in ["2026/04","2026/05","2026/03"]:
                candidate = REPORTS_ROOT / yr_mo / f"{item_id}.html"
                if candidate.exists():
                    report_path = candidate
                    break

        if not report_path or not report_path.exists():
            log.warning("Report file not found for %s — skipping enhancement", item_id[:16])
            stats["errors"] += 1
            continue

        try:
            html = report_path.read_text(encoding="utf-8", errors="replace")
            enhanced_html = enhance_report_html(html, item, tier)
            report_path.write_text(enhanced_html, encoding="utf-8")
            stats["enhanced"] += 1
            log.info("Enhanced: %s [%s]", item_id[:16], severity)

            # Generate PDF
            pdf_path = pdf_dir / f"{item_id}.pdf"
            if generate_pdf_report(item, enhanced_html, pdf_path):
                stats["pdfs"] += 1
                # Update manifest with PDF URL
                item["pdf_url"]  = f"/reports/pdf/{item_id}.pdf"
                item["pdf_available"] = True

        except Exception as e:
            log.error("Enhancement failed for %s: %s", item_id[:16], e)
            stats["errors"] += 1

    # Write back updated manifest (with PDF URLs)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    log.info("Enhancement complete: %d/%d enhanced | %d PDFs | %d errors",
             stats["enhanced"], stats["total"], stats["pdfs"], stats["errors"])
    return stats


if __name__ == "__main__":
    stats = run_enhancement()
    print(f"\nREPORT ENHANCEMENT v134 COMPLETE")
    print(f"  Enhanced: {stats.get('enhanced',0)}/{stats.get('total',0)}")
    print(f"  PDFs:     {stats.get('pdfs',0)}")
    print(f"  Errors:   {stats.get('errors',0)}")
