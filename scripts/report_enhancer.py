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

Called by sentinel-apex.yml after generate_intel_reports.py.
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import json
from html import escape as _html_escape
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Reuses the same eligibility test detection_bundle_injector.py already gates
# generation on (scripts/p38_shared_validators.py) -- see v134.1 fix below:
# this file used to render a fabricated Sigma/SIEM/YARA block for every item
# regardless of report type, including pure IOC/phishing-indicator items that
# were never CVE/vuln-class eligible for a detection rule in the first place.
from p38_shared_validators import is_detection_eligible
# P0 #721: evidence-integrity authority (IOC qualification, pinned ATT&CK data,
# severity basis) and the repo's EPSS scale reader -- never re-derive either.
import dossier_integrity as _di
import tlp_policy as _tlp          # fail-closed anonymous-publication authority (P0 #721)
from severity_epss_truth import epss_percent as _epss_percent

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
# DEPRECATED (P0 #721): no trial is offered -- the commercial contract's trial_policy is "No free trial"
# (owner decision 2026-09-19) and POST /api/leads/trial is 410 Gone. Kept only so external importers of
# this constant do not break; it is no longer rendered anywhere. Remove after the next major layer.
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
    """Gate content by tier.

    P0 #721: this used to wrap the full content in a CSS ``filter:blur`` and
    overlay -- the gated text remained in the served HTML (view-source / DOM /
    print / scrape bypass). Gating is now server-side: for an insufficient
    tier the content is NOT emitted at all, only a locked placeholder.
    """
    tier_rank = {"free": 0, "pro": 1, "enterprise": 2}
    if tier_rank.get(current_tier, 0) >= tier_rank.get(tier_required, 2):
        return content
    return (
        f'<div class="enh-locked" style="border:1px dashed #334155;border-radius:8px;padding:28px 20px;'
        f'text-align:center;background:rgba(15,23,42,0.85);margin:16px 0;">'
        f'<div style="font-size:24px;margin-bottom:8px;">🔒</div>'
        f'<div style="color:{C_TEXT};font-weight:700;font-size:14px;margin-bottom:6px;">'
        f'{_html_escape(tier_required.upper())} FEATURE</div>'
        f'<div style="color:{C_MUTED};font-size:12px;margin-bottom:14px;">This section is not included in the public artifact.</div>'
        f'<a href="{UPGRADE_URL}" style="background:linear-gradient(135deg,#7c3aed,#2563eb);color:white;'
        f'padding:8px 20px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:700;">'
        f'UPGRADE NOW</a>'
        f'</div>'
    )

def build_kill_chain_section(item: Dict) -> str:
    """Evidence-gated attack-chain card (P0 #721).

    This used to fall back to a fixed 7-phase template asserting implant
    installation, persistence, encrypted C2 with a 60-second beacon, DNS-over-
    HTTPS, credential harvesting and exfiltration for EVERY advisory. Phases are
    now shown only if the record itself carries them; otherwise the card states
    that no attack-chain activity was reported.
    """
    kc = item.get("kill_chain") or []
    if not isinstance(kc, list):
        kc = []
    severity = (item.get("severity") or "").upper()
    sev_col  = SEV_COLORS.get(severity, C_MUTED)

    phases = [
        (p.get("phase", "") if isinstance(p, dict) else str(p),
         p.get("description", "") if isinstance(p, dict) else "")
        for p in kc if p
    ]
    if not phases:
        content = (
            f'<div style="color:{C_TEXT};font-size:12px;line-height:1.6;">'
            f'<strong>ATTACK-CHAIN EVIDENCE: NOT PROVIDED.</strong> No report-specific attack-chain '
            f'observations are supplied in this record. This is not evidence that intrusion or '
            f'post-exploitation activity did not occur. Installation, persistence, command-and-control '
            f'and exfiltration are not asserted without corroborating evidence.</div>'
        )
        return _card("ATTACK-CHAIN EVIDENCE", content, icon="⚔️")

    rows = "".join(
        f'<tr>'
        f'<td style="padding:10px 14px;color:{sev_col};font-weight:700;font-size:11px;white-space:nowrap;'
        f'border-bottom:1px solid #334155;">{_html_escape(str(ph))}</td>'
        f'<td style="padding:10px 14px;color:{C_TEXT};font-size:12px;border-bottom:1px solid #334155;">{_html_escape(str(desc))}</td>'
        f'</tr>'
        for ph, desc in phases
    )
    content = (
        f'<div style="color:{C_MUTED};font-size:11px;margin-bottom:8px;">Phases as recorded on this advisory '
        f'(provenance not recorded; not independently verified).</div>'
        f'<table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr>'
        f'<th style="text-align:left;padding:8px 14px;color:{C_MUTED};font-size:10px;border-bottom:2px solid #334155;">PHASE</th>'
        f'<th style="text-align:left;padding:8px 14px;color:{C_MUTED};font-size:10px;border-bottom:2px solid #334155;">ACTIVITY</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )
    return _card("ATTACK-CHAIN EVIDENCE", content, icon="⚔️")


_IOC_CVE_REF_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_IOC_ADVISORY_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _is_reference_not_ioc(i) -> bool:
    """
    v186.0 P0 FIX: CVE identifiers and NVD/vendor-advisory URLs are vulnerability
    references, not network/endpoint observables -- they were being rendered in this
    table with a hardcoded "C2" context default (see _ioc_row below), which fabricates
    a specific command-and-control claim for values that were never observed as C2
    infrastructure. Mirrors the exclusion already applied in
    scripts/report_generator.py's _is_actionable_ioc.
    """
    if isinstance(i, dict):
        val, itype = str(i.get("value", "")), str(i.get("type", ""))
    else:
        val, itype = str(i), "indicator"
    val = val.strip()
    if _IOC_CVE_REF_RE.match(val) or (itype or "").lower() in ("cve", "cve_reference"):
        return True
    if _IOC_ADVISORY_URL_RE.match(val) and any(d in val.lower() for d in ("nvd.nist.gov", "cve.org", "cvefeed.io")):
        return True
    return False


_EVIDENCE_LABELS = {
    "OBSERVED":        ("OBSERVED", "#22c55e"),
    "SOURCE_REPORTED": ("SOURCE-REPORTED", "#3b82f6"),
    "SOURCE_CLAIMED":  ("SOURCE-CLAIMED (UNCORROBORATED)", "#f59e0b"),
    "UNVERIFIED":      ("UNVERIFIED", "#f59e0b"),
}


def build_ioc_table_section(item: Dict, tier: str = "enterprise") -> str:
    """IOC card.  Every number derives from ONE qualified collection (P0 #721).

    An empty collection renders NO row and a count of 0 (the old code inserted a
    "No IOCs in current data feed" placeholder row and then counted it as 1).
    Values below the Pro tier are not emitted into the page at all.
    """
    q = _di.qualify_iocs(item.get("iocs"), item)
    iocs, count, vcount = q["observables"], q["count"], q["validated_count"]
    rejected_n = len(q["rejected"]) + q["duplicates"]

    notes = []
    if rejected_n:
        notes.append(f"{rejected_n} non-indicator value(s) excluded (CVE references, advisory URLs, filenames, "
                     f"software names, malformed or duplicate entries).")
    if q["generated"]:
        notes.append(f"{len(q['generated'])} AI-derived candidate(s) withheld: not evidence-backed, not counted, "
                     f"not for blocking.")
    note_html = "".join(f'<div style="color:{C_MUTED};font-size:10px;margin-top:6px;">{_html_escape(n)}</div>' for n in notes)
    states_html = " &nbsp;|&nbsp; ".join(
        f'<span style="color:{_EVIDENCE_LABELS.get(k, (k, C_MUTED))[1]};">{_EVIDENCE_LABELS.get(k, (k, C_MUTED))[0].title()}: {v}</span>'
        for k, v in sorted(q["by_state"].items())
    )
    total_html = (
        f'<div style="margin-top:10px;color:{C_MUTED};font-size:10px;">IOC observables: '
        f'<strong style="color:{C_TEXT};">{count}</strong> &nbsp;|&nbsp; validated as malicious: '
        f'<strong style="color:{C_TEXT};">{vcount}</strong>'
        + (f' &nbsp;|&nbsp; {states_html}' if states_html else '') + '</div>'
    )

    if count == 0:
        content = (
            f'<div style="color:{C_TEXT};font-size:12px;">No IOC observables are recorded for this '
            f'advisory (count: 0). CVE identifiers and advisory URLs are references, not indicators.</div>'
            + total_html + note_html
        )
        return _card("INDICATORS OF COMPROMISE", content, icon="🔍")

    if {"free": 0, "pro": 1, "enterprise": 2}.get(tier, 0) < 1:
        content = (
            f'<div style="color:{C_TEXT};font-size:12px;">{count} IOC observable(s) recorded ({vcount} validated as malicious). Indicator values are '
            f'a Pro entitlement and are not included in this public artifact.</div>' + total_html + note_html
        )
        return _card("INDICATORS OF COMPROMISE", content, icon="🔍")

    def _ioc_row(i) -> str:
        d = i if isinstance(i, dict) else {"value": i}
        state = _di.ioc_evidence_state(i)
        label, col_s = _EVIDENCE_LABELS.get(state, (state, C_MUTED))
        conf = d.get("confidence")
        try:
            conf_txt = f"{float(conf):.0f}%"
        except (TypeError, ValueError):
            conf_txt = "n/a"          # missing stays missing (never 0%)
        return (
            f'<tr style="border-bottom:1px solid #334155;">'
            f'<td style="padding:8px 12px;color:{C_PUR};font-size:10px;font-weight:700;white-space:nowrap;">'
            f'{_html_escape(str(d.get("ioc_type") or d.get("type") or "?").upper())}</td>'
            f'<td style="padding:8px 12px;color:{C_TEXT};font-family:monospace;font-size:11px;word-break:break-all;">'
            f'{_html_escape(str(d.get("value", "")))}</td>'
            f'<td style="padding:8px 12px;color:{C_MUTED};font-size:11px;text-align:center;">{conf_txt}</td>'
            f'<td style="padding:8px 12px;color:{C_MUTED};font-size:10px;">{_html_escape(str(d.get("context") or "Unclassified"))}</td>'
            f'<td style="padding:8px 12px;font-size:10px;"><span style="color:{col_s};font-weight:700;'
            f'letter-spacing:0.5px;">{label}</span></td>'
            f'</tr>'
        )

    rows = "".join(_ioc_row(i) for i in iocs)
    content = (
        f'<div style="overflow-x:auto;">'
        f'<table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="border-bottom:2px solid #334155;">'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">TYPE</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">INDICATOR VALUE</th>'
        f'<th style="text-align:center;padding:8px 12px;color:{C_MUTED};font-size:10px;">SCORE</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">CONTEXT</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">EVIDENCE</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>'
        + total_html
        + f'<div style="margin-top:6px;color:{C_MUTED};font-size:10px;font-style:italic;">Observables are listed as extracted '
          f'from the source; syntax is not evidence of malice. Only indicators validated as malicious (corroborated source plus an '
          f'explicit malicious assertion) should drive blocking.</div>'
        + note_html
    )
    return _card("INDICATORS OF COMPROMISE", content, icon="🔍")

def build_detection_rules_section(item: Dict) -> str:
    """
    Only called for is_detection_eligible() items (gated at the call site in
    enhance_report_html()). Renders the real, generator-C-produced rule when
    present; otherwise an honest "queued" notice.

    v134.1 FIX: this function previously fabricated a full Sigma/Splunk/
    Elastic/KQL/YARA block for EVERY item whenever item["sigma_rule"] was
    empty -- including items that were never CVE/vuln-class eligible for a
    rule at all (now excluded upstream by the call-site gate) and eligible
    items generator C simply hadn't reached yet in its per-run budget
    (scripts/detection_bundle_injector.py, MAX_DETECT_ITEMS). The fabricated
    block used the item's own real IOC domains/IPs when available, else the
    literal placeholders "malicious-c2.example.com" / "185.220.101.1" --
    rendered under a "DETECTION RULES" heading indistinguishable from a real,
    generated rule. For an eligible-but-not-yet-processed item this now shows
    an honest pending notice instead of synthesizing content ahead of time.
    """
    sigma = item.get("sigma_rule") or ""
    if not sigma:
        content = (
            f'<div style="color:{C_MUTED};font-size:12px;line-height:1.6;">'
            f'This advisory is eligible for detection engineering (confirmed CVE / '
            f'vulnerability classification) and is queued for rule generation on an '
            f'upcoming intelligence refresh. Sigma, SIEM query, and YARA content will '
            f'appear here once generated — nothing is fabricated ahead of that.'
            f'</div>'
        )
        return _card("DETECTION RULES — SIGMA + SIEM + YARA", content, icon="🛡️")

    siem_q  = item.get("siem_queries") or {}
    if not isinstance(siem_q, dict):
        siem_q = {}
    iocs    = item.get("iocs") or []
    # v142.1: normalise string IOCs to dict before .get() calls (matches _ioc_row fix)
    _iocs_norm = [
        {"type": "indicator", "value": i, "confidence": 50} if isinstance(i, str) else i
        for i in (iocs if isinstance(iocs, list) else [])
        if isinstance(i, (str, dict))
    ]
    domains = [i.get("value","") for i in _iocs_norm if isinstance(i, dict) and i.get("type")=="domain"][:3]

    # AUDIT FIX (P0 evidence quality): when the item had no domain IOCs the
    # SIEM queries fell back to the literal target "c2.example.com", and the
    # YARA block was a fixed generic rule (any PowerShell -EncodedCommand /
    # schtasks string) presented as "Malware Sample Detection" for this
    # advisory. Queries are now emitted only from real domains or upstream-
    # generated queries; YARA only when upstream supplied one.
    splunk_q = siem_q.get("splunk") or (
        "index=* (" + " OR ".join('dest="' + d + '"' for d in domains[:2]) + ")" if domains else ""
    )
    elastic_q = siem_q.get("elastic") or (
        "(" + " OR ".join('dns.question.name:"' + d + '"' for d in domains[:2]) + ")" if domains else ""
    )
    kql_q = siem_q.get("kql") or (
        "DeviceNetworkEvents | where RemoteUrl has_any (" + ", ".join(repr(d) for d in domains[:2]) + ")"
        if domains else ""
    )
    # Escaped: code_block() interpolates raw into <pre>.
    yara_rule = _html_escape(item["yara_rule"]) if isinstance(item.get("yara_rule"), str) else ""

    def code_block(lang: str, code: str) -> str:
        return (
            f'<div style="background:#0a0f1a;border:1px solid #334155;border-radius:6px;'
            f'padding:14px;margin:8px 0;overflow-x:auto;">'
            f'<div style="color:{C_MUTED};font-size:9px;margin-bottom:6px;text-transform:uppercase;">{lang}</div>'
            f'<pre style="color:#a5f3fc;font-size:11px;margin:0;white-space:pre-wrap;font-family:monospace;">{code}</pre>'
            f'</div>'
        )

    content = (
        f'<div style="color:{C_MUTED};font-size:11px;margin-bottom:12px;">Validation status: <strong style="color:{C_ORG};">not validated in your environment</strong>. Syntax-check, test against your telemetry and tune before enabling; do not enable blocking actions unvalidated.</div>'
        + code_block("Sigma Rule (YAML) — Universal SIEM", sigma)
        + (code_block("Splunk SPL Query", splunk_q) if splunk_q else "")
        + (code_block("Elastic EQL / Lucene", elastic_q) if elastic_q else "")
        + (code_block("Microsoft Sentinel KQL", kql_q) if kql_q else "")
        + (code_block("YARA Rule — Malware Sample Detection", yara_rule) if yara_rule else "")
        + ("" if (splunk_q or elastic_q or kql_q) else
           f'<div style="color:{C_MUTED};font-size:11px;margin-top:8px;">No network indicators were '
           f'established for this advisory, so no IOC-based SIEM queries are generated.</div>')
    )
    return _card("DETECTION RULES — SIGMA + SIEM + YARA", content, icon="🛡️")


def build_soc_playbook_section(item: Dict) -> str:
    try:
        _cv0 = float(item.get("cvss_score")) if item.get("cvss_score") not in (None, "") else None
    except (TypeError, ValueError):
        _cv0 = None
    _sevb0 = _di.severity_basis(item, _cv0, bool(item.get("kev_present") is True or item.get("kev") is True))
    severity = _sevb0["display"].upper()
    sev_col  = SEV_COLORS.get(severity, C_ORG)
    actor    = item.get("actor_tag") or "Threat Actor"
    cvss     = item.get("cvss_score","N/A")
    _qp = _di.qualify_iocs(item.get("iocs"), item)
    ioc_count, ioc_valid = _qp["count"], _qp["validated_count"]
    sector   = item.get("target_sector","all sectors")

    # AUDIT FIX (P0 evidence quality): no "Block all 0 IOCs", no "CVSS N/A"
    # in instructions, and no unconditional incident declaration for an
    # advisory that may not affect the reader's environment.
    try:
        ioc_count = int(ioc_count or 0)
    except (TypeError, ValueError):
        ioc_count = 0
    try:
        _cvss_txt = f" (CVSS {float(cvss):.1f})" if cvss not in (None, "", "N/A") else ""
    except (TypeError, ValueError):
        _cvss_txt = ""
    if ioc_valid > 0:
        _contain = (f"{ioc_valid} indicator(s) are validated as malicious (corroborated source plus an explicit malicious "
                    "assertion): confirm against your telemetry, then block per your own review at firewall, proxy, DNS and EDR. "
                    "Isolate affected endpoints.")
        _hunt = "Threat hunt across a 90-day log window for the validated indicators and the behaviours described in this advisory."
    else:
        _contain = ((f"{ioc_count} IOC observable(s) were extracted but none is validated as malicious — hunt on them, do not block on them. "
                     if ioc_count else "No IOC observables were extracted for this advisory. ")
                    + "Contain by exposure: restrict access to affected services and apply vendor mitigations. "
                      "Isolate any endpoint showing related activity.")
        _hunt = "Threat hunt across a 90-day log window for the behaviours and techniques described in this advisory."
    steps = [
        ("0-15 min",  "CRITICAL", "IMMEDIATE TRIAGE",
         f"Determine whether affected products or assets exist in your environment. If exposure or activity "
         f"is confirmed, declare an incident per your IR policy"
         + (f" ({severity} severity)" if severity != "UNRATED" else " (severity not rated by APEX: no CVSS/KEV evidence)")
         + " and engage the IR team."),
        ("15-60 min", C_RED,     "CONTAINMENT", _contain),
        ("1-4 hrs",   C_ORG,    "INVESTIGATION", _hunt),
        ("4-24 hrs",  C_PUR,    "ERADICATION",
         f"Remove attacker artifacts. Patch vulnerable systems{_cvss_txt}. Reset compromised credentials. Rebuild infected hosts."),
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
    """AUDIT FIX (P0 evidence quality): this used to map SEVERITY alone to
    fixed "Estimated Direct Cost" ranges, "Stock Price Impact" (-8% to -23%),
    a constant "127 days / 21 days" dwell time and an "Nx ROI vs $50K CTI
    subscription" -- none derived from any evidence about the advisory or
    the reader's organisation. Now renders only facts the item carries and
    states what quantification would require."""
    _kev_flag  = bool(item.get("kev_present") is True or item.get("kev") is True)
    try:
        _cv = float(item.get("cvss_score")) if item.get("cvss_score") not in (None, "") else None
    except (TypeError, ValueError):
        _cv = None
    _sevb      = _di.severity_basis(item, _cv, _kev_flag)
    severity   = _sevb["display"].upper()
    biz_impact = item.get("business_impact") or {}
    if not isinstance(biz_impact, dict):
        biz_impact = {}
    regulatory = biz_impact.get("regulatory_risk")
    op_risk    = biz_impact.get("operational_risk")
    kev        = bool(item.get("kev_present") is True or item.get("kev") is True)
    not_est    = "Not established from available evidence"

    def _fmt(v):
        if isinstance(v, list):
            return ", ".join(str(x) for x in v) if v else not_est
        return str(v) if v not in (None, "") else not_est

    metrics = [
        ("Customer Exposure",       "UNKNOWN — no visibility into your environment", C_ORG),
        ("Severity",                severity, SEV_COLORS.get(severity, C_ORG)),
        ("CISA KEV",                "Listed — exploited in the wild" if kev else "No KEV listing found (absence does not prove no exploitation)", C_RED if kev else C_MUTED),
        ("Regulatory Exposure",     _fmt(regulatory), C_ORG),
        ("Operational Risk",        _fmt(op_risk), C_PUR),
        ("Estimated Direct Cost",   "Not computed — requires your asset, data and downtime figures", C_MUTED),
    ]
    metrics_html = "".join(
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'padding:10px 0;border-bottom:1px solid #334155;">'
        f'<span style="color:{C_MUTED};font-size:12px;">{label}</span>'
        f'<span style="color:{col};font-weight:700;font-size:12px;">{value}</span>'
        f'</div>'
        for label, value, col in metrics
    )
    content = (
        metrics_html +
        f'<div style="margin-top:14px;color:{C_MUTED};font-size:11px;line-height:1.6;">'
        f'SENTINEL APEX does not publish generic breach-cost, share-price or dwell-time figures as if they '
        f'applied to this advisory. A defensible loss estimate needs your asset values, records at risk, '
        f'downtime cost and control effectiveness (FAIR / Open Group O-RISK method).</div>'
    )
    return _card("BUSINESS IMPACT & FINANCIAL RISK ANALYSIS", content, icon="💰")


def build_defensive_matrix_section(item: Dict) -> str:
    """ATT&CK x NIST CSF card.  Only techniques whose IDs validate against the
    repo's pinned MITRE dataset are listed, with their official names (P0 #721).
    The old code defaulted to phishing / valid-accounts / exfiltration techniques
    when the record had none, labelled every row HIGH, and used non-official
    technique names."""
    mitre = item.get("mitre_techniques") or item.get("ttps") or item.get("mitre_tactics") or []
    if not isinstance(mitre, list):
        mitre = []
    valid, rejected = _di.filter_valid_techniques(mitre)
    ids = []
    for t in valid:
        tid = _di.technique_id_of(t)
        if _di.validate_technique(tid)["status"] == "VALID" and tid not in ids:
            ids.append(tid)       # names without an ID are not mappable -> omitted
    ids = ids[:8]
    if not ids:
        return _card("DEFENSIVE PRIORITY MATRIX (MITRE ATT&CK + NIST CSF)",
                     f'<div style="color:{C_TEXT};font-size:12px;">No ATT&amp;CK technique mapping with sufficient '
                     f'evidence is available for this advisory. No default techniques are substituted.</div>',
                     icon="🎯")
    rows = "".join(
        f'<tr style="border-bottom:1px solid #334155;">'
        f'<td style="padding:8px 12px;color:{C_PUR};font-family:monospace;font-size:11px;">{_html_escape(t)}</td>'
        f'<td style="padding:8px 12px;color:{C_TEXT};font-size:11px;">{_html_escape(_mitre_name(t))}</td>'
        f'<td style="padding:8px 12px;text-align:center;color:{C_MUTED};font-size:9px;font-weight:700;">ANALYST INFERENCE</td>'
        f'<td style="padding:8px 12px;color:{C_MUTED};font-size:11px;">{_nist_control(t)}</td>'
        f'</tr>'
        for t in ids
    )
    pin = _di.attack_dataset_pin()
    content = (
        f'<div style="color:{C_MUTED};font-size:10px;margin-bottom:8px;">Techniques are inferred from the advisory text '
        f'(not observed adversary activity) and validated against the pinned MITRE ATT&amp;CK dataset '
        f'(sync {_html_escape(str(pin.get("synced_at")))}, sha256 {_html_escape(str(pin.get("content_hash"))[:12])}).</div>'
        f'<table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="border-bottom:2px solid #334155;">'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">TECHNIQUE ID</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">TECHNIQUE NAME</th>'
        f'<th style="text-align:center;padding:8px 12px;color:{C_MUTED};font-size:10px;">BASIS</th>'
        f'<th style="text-align:left;padding:8px 12px;color:{C_MUTED};font-size:10px;">NIST CSF CONTROL</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )
    return _card("DEFENSIVE PRIORITY MATRIX (MITRE ATT&CK + NIST CSF)", content, icon="🎯")


def _mitre_name(t: str) -> str:
    """Official ATT&CK name from the pinned dataset (P0 #721). The previous
    hard-coded table used non-official names (e.g. 'LSASS Memory Credential
    Dump', 'PowerShell Execution') and returned a generic label for any ID."""
    return _di.technique_name(t) or f"Unvalidated technique ID ({t})"

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
    """Upgrade banner.  Contains no trial offer (contract: "No free trial") and no claim of an
    active threat; its numbers come from the same qualified collection as every other count."""
    sevb      = _di.severity_basis(item, item.get("cvss_score"), bool(item.get("kev_present") is True or item.get("kev") is True))
    severity  = sevb["display"]
    sev_col   = SEV_COLORS.get(severity, C_MUTED)
    _qb = _di.qualify_iocs(item.get("iocs"), item)
    ioc_count, ioc_valid = _qb["count"], _qb["validated_count"]

    if tier == "enterprise":
        return ""

    unlock_text = "PRO: Indicator values, rule content & playbook" if tier == "free" else "ENTERPRISE: Full STIX + custom feeds"
    # v166.3-FIX: UPGRADE_URL already contains ?plan=pro -- do NOT append ?plan=pro again (-> double param bug)
    unlock_url  = UPGRADE_URL if tier == "free" else "https://intel.cyberdudebivash.com/get-api-key.html?plan=enterprise"
    headline = (f"{severity} &middot; {ioc_count} IOC observable(s), {ioc_valid} validated as malicious" if ioc_count
                else f"{severity} &middot; no IOC observables recorded")

    return (
        f'<div class="monetization-banner">'
        f'<div>'
        f'<div style="color:{sev_col};font-weight:800;font-size:13px;margin-bottom:4px;">'
        f'{headline}</div>'
        f'<div style="color:#94a3b8;font-size:12px;">'
        f'Pro and Enterprise plans include indicator values, detection content (where available) and API access</div>'
        f'</div>'
        f'<div style="display:flex;gap:10px;flex-shrink:0;">'
        f'<a href="{unlock_url}" style="background:linear-gradient(135deg,#7c3aed,#2563eb);'
        f'color:white;padding:8px 16px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:700;">'
        f'{unlock_text}</a>'
        f'</div></div>'
    )


def build_threat_score_widget(item: Dict) -> str:
    """Score strip for the card header.  Missing data renders as n/a -- never as
    0.0 / 0% (P0 #721) -- and the IOC count is the same qualified count the IOC
    card shows."""
    def _num(v):
        try:
            return None if v is None or v == "" else float(v)
        except (TypeError, ValueError):
            return None
    risk_score = _num(item.get("risk_score"))
    cvss       = _num(item.get("cvss_score"))
    epss       = _epss_percent(item)          # percent 0-100 or None (scale proven, never guessed)
    kev        = item.get("kev_present") is True or item.get("kev") is True
    sevb       = _di.severity_basis(item, cvss, kev)
    severity   = sevb["display"]
    sev_col    = SEV_COLORS.get(severity, C_MUTED)
    _qw        = _di.qualify_iocs(item.get("iocs"), item)
    ioc_count, ioc_valid = _qw["count"], _qw["validated_count"]
    exploit_st = str(item.get("exploit_maturity") or "UNKNOWN")

    kev_badge = (f'<span style="background:#ef444422;color:#ef4444;padding:2px 8px;border-radius:3px;'
                 f'font-size:9px;font-weight:700;margin-left:6px;">KEV</span>') if kev else ""
    if item.get("synthetic"):
        kev_badge += ('<span style="background:#3b82f622;color:#3b82f6;padding:2px 8px;border-radius:3px;'
                      'font-size:9px;margin-left:6px;">SYNTHETIC</span>')
    risk_txt = f"{risk_score:.1f}" if risk_score is not None else "n/a"
    cvss_txt = f"{cvss:.1f}" if cvss is not None else "n/a"
    epss_txt = f"{_html_escape(str(round(epss, 4)))}%" if epss is not None else "n/a"
    unrated  = (f'<div style="color:{C_MUTED};font-size:10px;margin-top:4px;">{_html_escape(sevb["note"])}</div>') if sevb["note"] and (not sevb["authoritative"] or sevb["conflict"]) else ""

    return (
        f'<div style="background:#0f172a;border-radius:8px;padding:14px;margin-bottom:16px;">'
        f'<div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center;">'
        f'<div style="text-align:center;">'
        f'<div style="font-size:28px;font-weight:900;color:{sev_col};">{risk_txt}</div>'
        f'<div style="color:#64748b;font-size:9px;">APEX COMPOSITE (not CVSS)</div></div>'
        f'<div style="text-align:center;">'
        f'<div style="font-size:18px;font-weight:700;color:{C_ORG if (cvss or 0) >= 7 else C_PUR};">{cvss_txt}</div>'
        f'<div style="color:#64748b;font-size:9px;">CVSS (version not recorded)</div></div>'
        f'<div style="text-align:center;">'
        f'<div style="font-size:18px;font-weight:700;color:{C_RED if (epss or 0) >= 90 else C_ORG};">{epss_txt}</div>'
        f'<div style="color:#64748b;font-size:9px;">EPSS PERCENT</div></div>'
        f'<div style="text-align:center;">'
        f'<div style="font-size:18px;font-weight:700;color:{C_GRN};">{ioc_count}<span style="font-size:11px;color:#64748b;"> / {ioc_valid}</span></div>'
        f'<div style="color:#64748b;font-size:9px;">IOC OBSERVABLES / VALIDATED</div></div>'
        f'<div style="flex:1;min-width:120px;">'
        f'<div style="color:{C_TEXT};font-size:11px;margin-bottom:4px;">'
        f'{_sev_badge(severity)} {kev_badge}</div>'
        f'<div style="color:{C_MUTED};font-size:11px;">Exploit maturity: '
        f'<span>{_html_escape(exploit_st.upper())}</span></div>'
        f'{unrated}'
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
    _dec = _tlp.publication_decision(item)
    if not _dec["allowed"]:
        raise _tlp.PublicationDenied(_dec)       # fail closed before any bytes are produced

    # Strip old enhancement block
    if ENHANCE_MARKER in html:
        s = html.find(ENHANCE_MARKER)
        e = html.find(ENHANCE_ENDMRK)
        if e != -1:
            end = e + len(ENHANCE_ENDMRK)
            # the block is injected as "\n<MARK>...<END>\n": remove those delimiting newlines
            # too, otherwise every re-run leaves two stray newlines (non-idempotent output)
            if s > 0 and html[s - 1] == "\n":
                s -= 1
            if html[end:end + 1] == "\n":
                end += 1
            html = html[:s] + html[end:]

    css       = build_premium_intel_cards_css()
    ts_widget = build_threat_score_widget(item)
    mon_banner = build_monetization_banner(item, tier)

    # Build all enterprise sections
    kill_chain   = build_kill_chain_section(item)
    ioc_table    = build_ioc_table_section(item, tier)
    # v134.1 FIX: the detection-rules card is CVE/vuln-class-specific content
    # (Sigma host/network selectors, SIEM queries) -- it is NOT_APPLICABLE for
    # pure indicator/phishing-URL items by the same report-type contract
    # scripts/report_type_contracts.py already defines for INDICATOR_FEED.
    # Omit the card entirely for ineligible items instead of rendering it
    # (previously: build_detection_rules_section() ran unconditionally and
    # fabricated a rule for every item, eligible or not -- see that
    # function's own v134.1 fix below for the eligible-but-pending case).
    det_rules    = _tier_gate(build_detection_rules_section(item), "pro", tier) if is_detection_eligible(item) else ""
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
        # v166.3-FIX: /stix/{id}.json was a 404 path. STIX export requires Pro auth.
        # Link to get-api-key so users can unlock it.
        f'<a href="https://intel.cyberdudebivash.com/get-api-key.html?plan=pro&utm_source=report-stix-btn" style="background:#1e293b;color:#e2e8f0;padding:8px 16px;'
        f'border-radius:6px;text-decoration:none;font-size:11px;border:1px solid #334155;">'
        f'🔗 STIX 2.1 Bundle (Pro)</a>'
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
    if not _tlp.publication_decision(item)["allowed"]:
        log.warning("PDF refused for %s: TLP policy", str(item.get("id", ""))[:16])
        return False
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
            # v134.1 FIX: this was a hardcoded, point-in-time list
            # (["2026/04","2026/05","2026/03"]) that goes stale by
            # construction -- every month after May 2026 this fallback could
            # never find a report file for any item with an empty
            # report_url (100% of the live manifest window as of
            # 2026-08-31). Derive a rolling 6-month window from "now"
            # instead so it can't go stale again.
            _now = datetime.now(timezone.utc)
            _months = []
            for _back in range(6):
                _idx = _now.month - 1 - _back
                _y, _m = _now.year + _idx // 12, _idx % 12 + 1
                _months.append(f"{_y:04d}/{_m:02d}")
            for yr_mo in _months:
                candidate = REPORTS_ROOT / yr_mo / f"{item_id}.html"
                if candidate.exists():
                    report_path = candidate
                    break

        if not report_path or not report_path.exists():
            log.warning("Report file not found for %s — skipping enhancement", item_id[:16])
            stats["errors"] += 1
            continue

        # TLP gate: never append content to / produce a PDF for an artifact the policy does not allow
        # to be anonymously distributed (the enhancer is a publisher of those bytes).
        _dec = _tlp.publication_decision(item)
        if not _dec["allowed"]:
            stats["tlp_skipped"] = stats.get("tlp_skipped", 0) + 1
            log.warning("TLP skip %s: %s", item_id[:16], _dec["reason_code"])
            continue

        try:
            html = report_path.read_text(encoding="utf-8", errors="replace")
            enhanced_html = enhance_report_html(html, item, tier)
            report_path.write_text(enhanced_html, encoding="utf-8")
            stats["enhanced"] += 1
            log.info("Enhanced: %s [%s]", item_id[:16], severity)

            # Generate PDF companion
            pdf_path = pdf_dir / f"{item_id}.pdf"
            if generate_pdf_report(item, enhanced_html, pdf_path):
                stats["pdfs"] += 1
                item["pdf_url"]      = f"/reports/pdf/{item_id}.pdf"
                item["pdf_available"] = True

        except Exception as e:
            log.error("Enhancement failed for %s: %s", item_id[:16], e)
            stats["errors"] += 1

    # Write back updated manifest (PDF URLs persisted)
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
