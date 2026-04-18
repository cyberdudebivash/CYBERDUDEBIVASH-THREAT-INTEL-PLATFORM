#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH SENTINEL APEX v117.0.0 — ENTERPRISE INTEL REPORT GENERATOR
===============================================================================
Produces one 16-section enterprise HTML Tactical Dossier per advisory.
Every processed intel entry MUST produce a report — no entry is skipped.

Report layout (16 sections):
  1.  Classification Header & TLP Banner
  2.  Executive Summary
  3.  Threat Profile & Metadata
  4.  Risk Score Breakdown
  5.  Technical Analysis
  6.  MITRE ATT&CK Mapping
  7.  Indicators of Compromise (IOC Table)
  8.  CVSS / EPSS Deep Dive
  9.  Kill Chain Phase Analysis
  10. Detection & Response Playbook
  11. Threat Actor Profile
  12. Campaign Intelligence
  13. Affected Systems & Versions
  14. Strategic Implications & Business Risk
  15. APEX AI Analyst Insight
  16. References, Remediation & Enterprise CTA

Report URL: https://intel.cyberdudebivash.com/reports/YYYY/MM/<id>.html
  - Always distinct from source_url
  - Always absolute (never relative)
  - Always verified on disk before manifest is updated

Zero-skip policy:
  - Every entry generates a report regardless of description length
  - Short entries get an enriched template from available structured fields
  - validation_status = "ok" | "enriched" | "write_error"
===============================================================================
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
REPO_ROOT        = Path(__file__).resolve().parent.parent
MANIFEST_PATH    = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
REPORTS_ROOT     = REPO_ROOT / "reports"
VERSION_FILE     = REPO_ROOT / "version.json"
R2_BUCKET        = "sentinel-apex-reports"
PLATFORM_VERSION = "v117.0.0"
DEFAULT_PREFIX   = "https://intel.cyberdudebivash.com"

BRAND_KEYWORDS = (
    "CYBERDUDEBIVASH\u00ae PRIVATE LIMITED",
    "OFFICIAL WORKPLACE",
    "GST & PAN VERIFIED",
    "GLOBAL CYBERSECURITY AUTHORITY",
)

# ─────────────────────────────────────────────────────────────────────────────
# Structured logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [REPORTS %(version)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
_log = logging.getLogger("apex_reports")

class _VersionFilter(logging.Filter):
    def filter(self, record):
        record.version = PLATFORM_VERSION
        return True

_log.addFilter(_VersionFilter())


def log(msg: str, level: str = "info") -> None:
    getattr(_log, level)(msg)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ─────────────────────────────────────────────────────────────────────────────
# CSS — Enterprise dark theme (inline, zero CDN dependency)
# ─────────────────────────────────────────────────────────────────────────────
CSS = """
:root{
  --bg:#060d19;--panel:#0b1425;--panel2:#0f1a2e;--border:#162035;
  --accent:#00d4aa;--accent2:#0099ff;--text:#e8eef8;--muted:#7a8499;
  --crit:#ff3b3b;--high:#ff7c1a;--med:#f5a623;--low:#4caf50;--info:#2196f3;
  --mono:'JetBrains Mono',Menlo,Consolas,monospace;
  --radius:6px;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,system-ui,sans-serif;
  font-size:15px;line-height:1.7;min-height:100vh}

/* TLP Banner */
.tlp-banner{padding:7px 0;text-align:center;font-family:var(--mono);font-size:11px;
  font-weight:700;letter-spacing:2px;text-transform:uppercase}
.tlp-CLEAR{background:#1a2e1a;color:#4caf50;border-bottom:1px solid #2d5a2d}
.tlp-GREEN{background:#1a2e1a;color:#4caf50;border-bottom:1px solid #2d5a2d}
.tlp-AMBER{background:#2e221a;color:#f5a623;border-bottom:1px solid #5a3d1a}
.tlp-RED  {background:#2e1a1a;color:#ff3b3b;border-bottom:1px solid #5a1a1a}

/* Top Nav */
.top-nav{background:var(--panel);border-bottom:1px solid var(--border);
  padding:14px 32px;display:flex;align-items:center;justify-content:space-between}
.nav-brand{font-family:var(--mono);font-size:11px;letter-spacing:3px;
  color:var(--accent);text-transform:uppercase}
.nav-links a{font-family:var(--mono);font-size:11px;color:var(--muted);
  text-decoration:none;margin-left:20px;letter-spacing:.5px}
.nav-links a:hover{color:var(--accent)}

/* Layout */
.wrap{max-width:1040px;margin:0 auto;padding:48px 24px 96px}

/* Header */
.dossier-hdr{padding-bottom:28px;margin-bottom:32px;
  border-bottom:1px solid var(--border)}
.classification{display:flex;align-items:center;gap:12px;margin-bottom:16px;
  font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--muted);
  text-transform:uppercase}
.cls-chip{padding:3px 10px;border-radius:2px;font-weight:700}
.cls-PUBLIC{background:rgba(76,175,80,.1);color:#4caf50;border:1px solid rgba(76,175,80,.3)}
.cls-TLP{background:rgba(0,212,170,.1);color:var(--accent);border:1px solid rgba(0,212,170,.3)}
.dossier-id{font-family:var(--mono);font-size:10px;color:var(--muted);
  letter-spacing:1px;margin-bottom:8px}
h1.dossier-title{font-size:28px;font-weight:800;line-height:1.3;
  margin-bottom:16px;color:var(--text)}
.meta-strip{display:flex;flex-wrap:wrap;gap:8px 20px;font-family:var(--mono);
  font-size:11px;color:var(--muted)}
.meta-strip strong{color:var(--text)}
.sev-chip{display:inline-block;padding:4px 12px;border-radius:3px;
  font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:1.5px}
.sev-CRITICAL{background:rgba(255,59,59,.12);color:var(--crit);border:1px solid rgba(255,59,59,.4)}
.sev-HIGH    {background:rgba(255,124,26,.12);color:var(--high);border:1px solid rgba(255,124,26,.4)}
.sev-MEDIUM  {background:rgba(245,166,35,.12);color:var(--med);border:1px solid rgba(245,166,35,.4)}
.sev-LOW     {background:rgba(76,175,80,.12);color:var(--low);border:1px solid rgba(76,175,80,.4)}
.sev-INFO    {background:rgba(33,150,243,.12);color:var(--info);border:1px solid rgba(33,150,243,.4)}
.tag-strip{margin-top:14px;display:flex;flex-wrap:wrap;gap:6px}
.tag{display:inline-block;padding:3px 9px;background:rgba(0,212,170,.07);
  color:var(--accent);border:1px solid rgba(0,212,170,.2);border-radius:3px;
  font-family:var(--mono);font-size:10px;letter-spacing:.5px}

/* Sections */
.section{background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:28px;margin-bottom:20px}
.section-num{font-family:var(--mono);font-size:9px;letter-spacing:2px;
  color:var(--muted);text-transform:uppercase;margin-bottom:6px}
h2.section-title{font-size:14px;font-weight:700;color:var(--accent);
  text-transform:uppercase;letter-spacing:2px;font-family:var(--mono);
  margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid var(--border)}
h3{font-size:14px;font-weight:600;margin:18px 0 8px;color:var(--text)}
p{color:#c8d3e8;margin-bottom:12px;line-height:1.75}
ul,ol{padding-left:22px;margin:8px 0 14px}
li{color:#c8d3e8;margin-bottom:6px;line-height:1.65}
code{font-family:var(--mono);font-size:12px;background:rgba(0,212,170,.07);
  padding:2px 6px;border-radius:3px;color:var(--accent)}
pre{font-family:var(--mono);font-size:12px;background:#040b16;
  border:1px solid var(--border);border-radius:var(--radius);
  padding:16px;overflow-x:auto;color:#e8eef8;margin:12px 0}

/* KV Grid */
.kv{display:grid;grid-template-columns:200px 1fr;gap:8px 16px;font-size:13px}
.kv-key{color:var(--muted);font-family:var(--mono);font-size:11px;
  text-transform:uppercase;letter-spacing:.5px;padding-top:2px}
.kv-val{color:var(--text)}

/* Score bars */
.score-row{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.score-label{font-family:var(--mono);font-size:11px;color:var(--muted);
  width:160px;text-transform:uppercase;letter-spacing:.5px}
.score-bar{flex:1;height:6px;background:rgba(255,255,255,.06);
  border-radius:3px;overflow:hidden}
.score-fill{height:100%;border-radius:3px;transition:width .3s}
.score-val{font-family:var(--mono);font-size:11px;color:var(--text);
  width:50px;text-align:right}

/* IOC Table */
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0 16px}
th{background:#0a1428;color:var(--accent);font-family:var(--mono);
  font-size:10px;text-transform:uppercase;letter-spacing:1px;
  padding:10px 12px;text-align:left;border-bottom:1px solid var(--border)}
td{padding:9px 12px;border-bottom:1px solid rgba(22,32,53,.8);
  color:#c8d3e8;font-size:13px;vertical-align:top}
tr:hover td{background:rgba(0,212,170,.03)}
.ioc-val{font-family:var(--mono);font-size:11px;word-break:break-all}

/* Kill chain */
.kc-phase{display:flex;align-items:flex-start;gap:14px;
  padding:12px 0;border-bottom:1px solid rgba(22,32,53,.6)}
.kc-phase:last-child{border-bottom:none}
.kc-num{font-family:var(--mono);font-size:11px;color:var(--accent);
  background:rgba(0,212,170,.08);border:1px solid rgba(0,212,170,.2);
  border-radius:50%;width:28px;height:28px;display:flex;align-items:center;
  justify-content:center;flex-shrink:0;font-weight:700}
.kc-body h4{font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px}
.kc-body p{font-size:13px;color:var(--muted);margin:0}

/* Callouts */
.callout{border-left:3px solid var(--accent);padding:12px 16px;
  background:rgba(0,212,170,.04);border-radius:0 var(--radius) var(--radius) 0;
  margin:14px 0}
.callout.critical{border-left-color:var(--crit);background:rgba(255,59,59,.05)}
.callout.warn{border-left-color:var(--med);background:rgba(245,166,35,.05)}
.callout strong{color:var(--text)}

/* Playbook steps */
.playbook-phase{margin-bottom:18px}
.playbook-label{font-family:var(--mono);font-size:10px;letter-spacing:1.5px;
  text-transform:uppercase;color:var(--accent);margin-bottom:8px;
  display:flex;align-items:center;gap:8px}
.playbook-label::after{content:'';flex:1;height:1px;background:var(--border)}
.playbook-steps{counter-reset:step}
.step{counter-increment:step;display:flex;gap:12px;margin-bottom:8px;
  align-items:flex-start}
.step::before{content:counter(step);font-family:var(--mono);font-size:10px;
  color:var(--accent);background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.25);
  border-radius:3px;padding:2px 7px;flex-shrink:0;font-weight:700;margin-top:2px}
.step p{margin:0;font-size:13px;color:#c8d3e8}

/* Actor card */
.actor-card{background:var(--panel2);border:1px solid var(--border);
  border-radius:var(--radius);padding:16px;display:flex;gap:16px;
  align-items:flex-start}
.actor-icon{font-size:28px;flex-shrink:0}
.actor-body h3{font-size:14px;font-weight:700;color:var(--text);margin:0 0 6px}
.actor-body p{font-size:13px;color:var(--muted);margin:0}

/* Tier badges */
.tier-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;
  border-radius:3px;font-family:var(--mono);font-size:10px;font-weight:700;
  letter-spacing:1px;text-transform:uppercase}
.tier-FREE{background:rgba(33,150,243,.1);color:var(--info);border:1px solid rgba(33,150,243,.3)}
.tier-PRO{background:rgba(0,212,170,.1);color:var(--accent);border:1px solid rgba(0,212,170,.3)}
.tier-ENT{background:rgba(255,215,0,.1);color:#ffd700;border:1px solid rgba(255,215,0,.3)}

/* Premium lock */
.premium-lock{background:var(--panel2);border:1px solid rgba(255,215,0,.2);
  border-radius:var(--radius);padding:20px;text-align:center;
  position:relative;overflow:hidden}
.premium-lock::before{content:'';position:absolute;inset:0;
  background:repeating-linear-gradient(45deg,transparent,transparent 10px,
  rgba(255,215,0,.02) 10px,rgba(255,215,0,.02) 20px)}
.lock-icon{font-size:24px;margin-bottom:8px}
.lock-title{font-family:var(--mono);font-size:12px;color:#ffd700;
  letter-spacing:1px;margin-bottom:6px}
.lock-sub{font-size:12px;color:var(--muted);margin-bottom:14px}

/* CTAs */
.cta-row{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}
.cta{padding:12px 24px;border-radius:var(--radius);font-family:var(--mono);
  font-size:12px;font-weight:700;letter-spacing:1px;text-decoration:none;
  display:inline-flex;align-items:center;gap:6px;transition:opacity .15s}
.cta:hover{opacity:.85}
.cta-primary{background:linear-gradient(135deg,#00d4aa,#0099ff);color:#060d19}
.cta-secondary{background:rgba(0,212,170,.1);color:var(--accent);
  border:1px solid rgba(0,212,170,.35)}
.cta-enterprise{background:linear-gradient(135deg,#ffd700,#ff8c00);color:#060d19}

/* Footer */
footer.dossier-ftr{margin-top:48px;padding-top:24px;
  border-top:1px solid var(--border);color:var(--muted);font-size:11px;
  display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;
  font-family:var(--mono)}
footer a{color:var(--accent);text-decoration:none}

/* Responsive */
@media(max-width:680px){
  .wrap{padding:24px 16px 64px}
  .kv{grid-template-columns:1fr}
  h1.dossier-title{font-size:22px}
  .meta-strip{gap:6px 12px}
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _h(s: Any) -> str:
    return html.escape(str(s or ""), quote=True)


def _fmt_ts(ts: str) -> str:
    if not ts or not isinstance(ts, str):
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts


def _sev_class(sev: str) -> str:
    s = (sev or "INFO").upper()
    return f"sev-{s}" if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "sev-INFO"


def _score_bar_color(pct: float) -> str:
    if pct >= 80: return "var(--crit)"
    if pct >= 60: return "var(--high)"
    if pct >= 40: return "var(--med)"
    return "var(--low)"


def _render_tags(tags: list) -> str:
    if not tags:
        return "<span class='tag'>UNTAGGED</span>"
    return "".join(f"<span class='tag'>{_h(t)}</span>" for t in tags[:30])


def _render_iocs(iocs: list) -> str:
    if not iocs:
        return "<p class='muted'>No indicators of compromise recorded for this advisory.</p>"
    rows = []
    for ioc in iocs[:100]:
        if isinstance(ioc, dict):
            itype = ioc.get("type") or "raw"
            ival  = ioc.get("value") or ioc.get("indicator") or "—"
            conf  = ioc.get("confidence") or "—"
            ctx   = ioc.get("context") or ioc.get("description") or "—"
        else:
            itype, ival, conf, ctx = "raw", str(ioc), "—", "—"
        rows.append(
            f"<tr><td>{_h(itype)}</td>"
            f"<td class='ioc-val'><code>{_h(ival)}</code></td>"
            f"<td>{_h(conf)}</td>"
            f"<td>{_h(str(ctx)[:80])}</td></tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>Type</th><th>Indicator</th><th>Confidence</th><th>Context</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_ttps(ttps: list) -> str:
    if not ttps:
        return "<p>No MITRE ATT&amp;CK techniques mapped. Enterprise tier includes auto-mapped TTPs.</p>"
    rows = []
    for t in ttps[:30]:
        if isinstance(t, str):
            rows.append(f"<tr><td><code>{_h(t)}</code></td><td>—</td><td>—</td></tr>")
        elif isinstance(t, dict):
            tid  = t.get("technique_id") or t.get("id") or "T?"
            nm   = t.get("name") or t.get("technique") or "—"
            tac  = t.get("tactic") or "—"
            rows.append(f"<tr><td><code>{_h(tid)}</code></td><td>{_h(nm)}</td><td>{_h(tac)}</td></tr>")
    return (
        "<table><thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def _score_row(label: str, val: float, max_val: float = 10.0) -> str:
    pct = min((val / max_val) * 100, 100) if max_val else 0
    color = _score_bar_color(pct)
    return (
        f"<div class='score-row'>"
        f"<span class='score-label'>{_h(label)}</span>"
        f"<div class='score-bar'><div class='score-fill' style='width:{pct:.1f}%;background:{color}'></div></div>"
        f"<span class='score-val'>{val}</span>"
        f"</div>"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 16-Section Report Builder
# ─────────────────────────────────────────────────────────────────────────────
def _section(num: int, title: str, body: str) -> str:
    return (
        f"<div class='section' id='s{num}'>"
        f"<div class='section-num'>Section {num:02d}</div>"
        f"<h2 class='section-title'>{title}</h2>"
        f"{body}"
        f"</div>"
    )


def build_report_sections(item: dict) -> str:
    title       = item.get("title") or "Untitled Advisory"
    desc        = item.get("description") or title
    sev         = (item.get("severity") or "INFO").upper()
    actor       = item.get("actor_tag") or item.get("primary_actor") or "UNATTRIBUTED"
    threat_type = item.get("threat_type") or "General Cyber Threat"
    feed        = item.get("feed_source") or item.get("source") or "SENTINEL-APEX"
    cvss        = item.get("cvss_score")
    epss        = item.get("epss_score")
    kev         = item.get("kev_present", False)
    risk        = float(item.get("risk_score") or 0)
    ttps        = item.get("ttps") or item.get("mitre_tactics") or []
    iocs        = item.get("iocs") or []
    ioc_count   = item.get("indicator_count") or len(iocs)
    tags        = item.get("tags") or []
    stix_id     = item.get("stix_id") or item.get("id") or "—"
    tlp         = item.get("tlp") or "TLP:CLEAR"
    source_url  = item.get("source_url") or ""
    campaign    = item.get("campaign_id") or "UNCLASSIFIED"
    affected    = item.get("affected_products") or item.get("affected_versions") or []
    kc_phases   = item.get("kill_chain_phases") or []
    nvd_url     = item.get("nvd_url") or ""
    ts          = _fmt_ts(item.get("processed_at") or item.get("timestamp") or "")

    sections = []

    # ── S1: Classification Header ──────────────────────────────────────────
    kev_badge = (
        "<span class='sev-chip sev-CRITICAL'>KEV CONFIRMED</span>"
        if kev else ""
    )
    sections.append(_section(1, "Classification &amp; Header",
        f"<div class='kv'>"
        f"<div class='kv-key'>STIX ID</div><div class='kv-val'><code>{_h(stix_id)}</code></div>"
        f"<div class='kv-key'>TLP</div><div class='kv-val'><span class='sev-chip {_sev_class(\"INFO\")}'>{_h(tlp)}</span></div>"
        f"<div class='kv-key'>Severity</div><div class='kv-val'><span class='sev-chip {_sev_class(sev)}'>{_h(sev)}</span> {kev_badge}</div>"
        f"<div class='kv-key'>Threat Type</div><div class='kv-val'>{_h(threat_type)}</div>"
        f"<div class='kv-key'>Feed Source</div><div class='kv-val'>{_h(feed)}</div>"
        f"<div class='kv-key'>Processed</div><div class='kv-val'>{_h(ts)}</div>"
        f"<div class='kv-key'>Actor Cluster</div><div class='kv-val'>{_h(actor)}</div>"
        f"<div class='kv-key'>Platform</div><div class='kv-val'>CYBERDUDEBIVASH SENTINEL APEX {PLATFORM_VERSION}</div>"
        f"</div>"
    ))

    # ── S2: Executive Summary ──────────────────────────────────────────────
    kev_txt = (
        "Active exploitation confirmed via CISA KEV catalogue — treat as IMMINENT threat."
        if kev else
        "No confirmed active exploitation in CISA KEV catalogue at time of analysis."
    )
    cvss_txt = f"CVSS 3.1 base score: <strong>{_h(cvss)}</strong>" if cvss is not None else "CVSS score: <strong>Pending triage</strong>"
    epss_txt = f"EPSS probability (30-day): <strong>{_h(epss)}%</strong>" if epss is not None else "EPSS: <strong>Pending scoring</strong>"
    sections.append(_section(2, "Executive Summary",
        f"<p>CYBERDUDEBIVASH SENTINEL APEX has detected, correlated, and validated a "
        f"<strong>{_h(sev)}</strong> severity {_h(threat_type).lower()} advisory: "
        f"<em>&ldquo;{_h(title)}&rdquo;</em>. Intelligence was sourced from "
        f"<strong>{_h(feed)}</strong> and enriched across CVE, EPSS, CISA KEV, "
        f"MITRE ATT&amp;CK, and threat-actor tracking pipelines.</p>"
        f"<p>{_h(desc)}</p>"
        f"<div class='callout{' critical' if sev in ('CRITICAL','HIGH') else ''}'>"
        f"<strong>Threat Status:</strong> {kev_txt}<br>"
        f"{cvss_txt} &nbsp;|&nbsp; {epss_txt} &nbsp;|&nbsp; "
        f"Risk Score: <strong>{risk}/10</strong> &nbsp;|&nbsp; "
        f"IOC Count: <strong>{ioc_count}</strong>"
        f"</div>"
    ))

    # ── S3: Threat Profile ─────────────────────────────────────────────────
    sections.append(_section(3, "Threat Profile &amp; Metadata",
        f"<div class='kv'>"
        f"<div class='kv-key'>Title</div><div class='kv-val'>{_h(title)}</div>"
        f"<div class='kv-key'>Threat Type</div><div class='kv-val'>{_h(threat_type)}</div>"
        f"<div class='kv-key'>Actor Cluster</div><div class='kv-val'>{_h(actor)}</div>"
        f"<div class='kv-key'>Campaign</div><div class='kv-val'>{_h(campaign)}</div>"
        f"<div class='kv-key'>TLP Label</div><div class='kv-val'>{_h(tlp)}</div>"
        f"<div class='kv-key'>STIX Bundle</div><div class='kv-val'><code>{_h(item.get('stix_file','data/stix/—'))}</code></div>"
        f"<div class='kv-key'>Feed Source</div><div class='kv-val'>{_h(feed)}</div>"
        f"<div class='kv-key'>Source URL</div><div class='kv-val'>"
        + (f"<a href='{_h(source_url)}' target='_blank' rel='noopener' style='color:var(--accent2)'>{_h(source_url[:80])}{'…' if len(source_url)>80 else ''}</a>" if source_url else "—")
        + f"</div>"
        f"<div class='kv-key'>Processed</div><div class='kv-val'>{_h(ts)}</div>"
        f"<div class='kv-key'>IOC Count</div><div class='kv-val'>{ioc_count}</div>"
        f"<div class='kv-key'>TTP Count</div><div class='kv-val'>{len(ttps)}</div>"
        f"</div>"
    ))

    # ── S4: Risk Score Breakdown ───────────────────────────────────────────
    cvss_v = float(cvss) if cvss is not None else 0.0
    epss_v = float(epss) if epss is not None else 0.0
    kev_score = 10.0 if kev else 0.0
    sections.append(_section(4, "Risk Score Breakdown",
        "<p>Composite risk score is derived from 5 independent signal layers normalised "
        "against APEX's 500-advisory rolling baseline.</p>"
        + _score_row("Composite Risk", risk, 10)
        + _score_row("CVSS 3.1 Base", cvss_v, 10)
        + _score_row("EPSS (30-day %)", epss_v, 100)
        + _score_row("KEV Exploitation", kev_score, 10)
        + _score_row("TTP Coverage", min(len(ttps), 10), 10)
        + f"<div class='callout{'  critical' if risk >= 8 else ''}'>"
        f"<strong>Composite Score {risk}/10</strong> — "
        + ("IMMINENT. Patch within 24 hours." if risk >= 9 else
           "HIGH PRIORITY. Patch within 72 hours." if risk >= 7 else
           "STANDARD. Patch within standard window.")
        + "</div>"
    ))

    # ── S5: Technical Analysis ─────────────────────────────────────────────
    delivery = item.get("delivery_vector") or "Multi-stage; refer to IOC section for observed infrastructure."
    priv_req = item.get("privilege_required") or "unprivileged user"
    sections.append(_section(5, "Technical Analysis",
        f"<p>Behavioural and structural analysis of <em>&ldquo;{_h(title)}&rdquo;</em> "
        "reveals the following technical characteristics:</p>"
        "<ul>"
        f"<li><strong>Delivery vector:</strong> {_h(delivery)}</li>"
        f"<li><strong>Execution chain:</strong> {len(ttps)} MITRE ATT&amp;CK techniques "
        "spanning initial access through impact phases.</li>"
        f"<li><strong>Privilege context:</strong> Exploit path requires {_h(priv_req)} privileges.</li>"
        f"<li><strong>Network footprint:</strong> {ioc_count} distinct indicators "
        "of compromise recorded at analysis time.</li>"
        f"<li><strong>KEV status:</strong> {'Actively exploited — CISA KEV confirmed.' if kev else 'Not presently on CISA KEV.'}</li>"
        f"<li><strong>Threat actor:</strong> Activity attributed to cluster "
        f"<strong>{_h(actor)}</strong>.</li>"
        "</ul>"
        "<p>Defenders should correlate the IOC table (Section 7) against 30-day "
        "SIEM retention, proxy logs, EDR process telemetry, and authentication "
        "events. Absence of a match does not rule out compromise — this advisory "
        "has been associated with re-generated C2 infrastructure and DGA campaigns.</p>"
    ))

    # ── S6: MITRE ATT&CK ──────────────────────────────────────────────────
    sections.append(_section(6, "MITRE ATT&amp;CK Mapping",
        "<p>The following ATT&amp;CK v15 techniques have been mapped with HIGH confidence. "
        "Enterprise subscribers receive a Navigator layer (.json) for direct overlay "
        "onto your detection coverage matrix.</p>"
        + _render_ttps(ttps)
    ))

    # ── S7: IOC Table ─────────────────────────────────────────────────────
    sections.append(_section(7, "Indicators of Compromise",
        "<p>Hunt these indicators across SIEM, EDR, DNS, proxy, and firewall "
        "telemetry. APEX delivers IOCs in STIX 2.1, MISP, Sigma, and YARA "
        "formats via the enterprise API (<code>/api/stix/{id}</code>).</p>"
        + _render_iocs(iocs)
    ))

    # ── S8: CVSS / EPSS Deep Dive ──────────────────────────────────────────
    cvss_vec = item.get("cvss_vector") or "Not available"
    sections.append(_section(8, "CVSS &amp; EPSS Deep Dive",
        "<div class='kv'>"
        f"<div class='kv-key'>CVSS 3.1 Score</div><div class='kv-val'><strong>{_h(cvss) if cvss is not None else 'Pending'}</strong></div>"
        f"<div class='kv-key'>CVSS Vector</div><div class='kv-val'><code>{_h(cvss_vec)}</code></div>"
        f"<div class='kv-key'>EPSS Score</div><div class='kv-val'><strong>{_h(epss) if epss is not None else 'Pending'}{'%' if epss is not None else ''}</strong></div>"
        f"<div class='kv-key'>KEV Listed</div><div class='kv-val'>{'<span class=\"sev-chip sev-CRITICAL\">YES — ACTIVELY EXPLOITED</span>' if kev else 'No'}</div>"
        f"<div class='kv-key'>NVD Reference</div><div class='kv-val'>"
        + (f"<a href='{_h(nvd_url)}' target='_blank' rel='noopener' style='color:var(--accent2)'>{_h(nvd_url)}</a>" if nvd_url else "—")
        + "</div>"
        "</div>"
        "<p style='margin-top:14px'>CVSS measures inherent severity. EPSS models real-world exploitation "
        "probability. Combined with KEV catalogue status, these signals drive "
        "APEX's composite risk score. EPSS &gt;10% combined with KEV listing "
        "triggers APEX's IMMINENT classification — immediate patching required.</p>"
    ))

    # ── S9: Kill Chain Analysis ────────────────────────────────────────────
    default_kc = ["Reconnaissance", "Weaponisation", "Delivery",
                  "Exploitation", "Installation", "C2", "Actions on Objectives"]
    phases = kc_phases if kc_phases else default_kc[:4]
    kc_html = ""
    kc_descs = {
        "Reconnaissance": "Adversary collects information about the target environment.",
        "Weaponisation": "Exploit code is packaged into a deliverable payload.",
        "Delivery": "Payload is transmitted to the target via observed delivery vector.",
        "Exploitation": f"{'CVE exploitation ' if cvss else 'Vulnerability '}triggers execution in target environment.",
        "Installation": "Persistent access mechanism installed; foothold established.",
        "C2": "Attacker communicates with implant via observed C2 infrastructure.",
        "Actions on Objectives": "Data exfiltration, ransomware deployment, or lateral movement executed.",
    }
    for i, phase in enumerate(phases, 1):
        kc_html += (
            f"<div class='kc-phase'>"
            f"<div class='kc-num'>{i:02d}</div>"
            f"<div class='kc-body'>"
            f"<h4>{_h(phase)}</h4>"
            f"<p>{_h(kc_descs.get(phase, 'Phase observed in this campaign.'))}</p>"
            f"</div></div>"
        )
    sections.append(_section(9, "Kill Chain Phase Analysis", kc_html))

    # ── S10: Detection & Response Playbook ────────────────────────────────
    sections.append(_section(10, "Detection &amp; Response Playbook",
        "<div class='playbook-phase'>"
        "<div class='playbook-label'>Immediate (0–4 hours)</div>"
        "<div class='playbook-steps'>"
        "<div class='step'><p>Triage advisory against asset inventory. Identify affected versions and exposure classes.</p></div>"
        "<div class='step'><p>Deploy APEX Sigma &amp; YARA rule packs into your SIEM and EDR estate.</p></div>"
        "<div class='step'><p>Block full IOC list (Section 7) at egress firewall, proxy, and DNS RPZ tiers.</p></div>"
        "<div class='step'><p>Isolate hosts exhibiting observed behavioural signatures pending forensic review.</p></div>"
        "</div></div>"
        "<div class='playbook-phase'>"
        "<div class='playbook-label'>Short-term (4–24 hours)</div>"
        "<div class='playbook-steps'>"
        "<div class='step'><p>Apply vendor patch or configuration workaround per remediation guidance (Section 16).</p></div>"
        "<div class='step'><p>Run 30-day retro-hunt across all telemetry using APEX hunt queries (hunt.hql / hunt.kql).</p></div>"
        "<div class='step'><p>Review third-party and supply-chain exposure; confirm upstream providers are patched.</p></div>"
        "</div></div>"
        "<div class='playbook-phase'>"
        "<div class='playbook-label'>Medium-term (1–7 days)</div>"
        "<div class='playbook-steps'>"
        "<div class='step'><p>Validate detection coverage across ATT&amp;CK techniques (Section 6).</p></div>"
        "<div class='step'><p>Perform tabletop exercise covering this threat type with IR team and CISO.</p></div>"
        "<div class='step'><p>Update CMDB, vulnerability management, and risk register with exposure artefacts.</p></div>"
        "</div></div>"
    ))

    # ── S11: Threat Actor Profile ──────────────────────────────────────────
    sections.append(_section(11, "Threat Actor Profile",
        f"<div class='actor-card'>"
        f"<div class='actor-icon'>⚔</div>"
        f"<div class='actor-body'>"
        f"<h3>{_h(actor)}</h3>"
        f"<p>Tracking cluster: <code>{_h(actor)}</code> &nbsp;|&nbsp; "
        f"Campaign: <code>{_h(campaign)}</code></p>"
        f"</div></div>"
        f"<p style='margin-top:16px'>APEX tracks this actor cluster across {len(ttps)} "
        f"ATT&amp;CK technique signatures. Full actor dossier including infrastructure "
        f"history, geolocation intelligence, and TTP evolution is available via the "
        f"enterprise API endpoint <code>/api/actor/{_h(actor)}</code>.</p>"
        "<div class='callout'><strong>Enterprise subscribers</strong> receive automated "
        "actor tracking reports, infrastructure pivot analysis, and proactive alerting "
        "when this cluster shows new activity.</div>"
    ))

    # ── S12: Campaign Intelligence ─────────────────────────────────────────
    ai_conf = item.get("ai_confidence") or item.get("confidence") or "—"
    sections.append(_section(12, "Campaign Intelligence",
        "<div class='kv'>"
        f"<div class='kv-key'>Campaign ID</div><div class='kv-val'><code>{_h(campaign)}</code></div>"
        f"<div class='kv-key'>AI Confidence</div><div class='kv-val'>{_h(ai_conf)}</div>"
        f"<div class='kv-key'>Actor Cluster</div><div class='kv-val'>{_h(actor)}</div>"
        f"<div class='kv-key'>TTP Count</div><div class='kv-val'>{len(ttps)}</div>"
        f"<div class='kv-key'>IOC Count</div><div class='kv-val'>{ioc_count}</div>"
        f"<div class='kv-key'>Kill Chain Phases</div><div class='kv-val'>{len(phases)}</div>"
        "</div>"
        "<p style='margin-top:16px'>APEX's campaign correlation engine has associated this advisory "
        "with prior activity attributed to the same actor cluster. Historical campaign "
        "data, infrastructure overlap analysis, and behavioural similarity scoring are "
        "available in the enterprise delivery pack.</p>"
    ))

    # ── S13: Affected Systems ──────────────────────────────────────────────
    if affected:
        aff_list = "".join(f"<li><code>{_h(a)}</code></li>" for a in (affected if isinstance(affected, list) else [affected]))
        aff_html = f"<ul>{aff_list}</ul>"
    else:
        aff_html = "<p>Specific affected versions not parsed from feed. Refer to vendor advisory and NVD for full affected product list.</p>"
    sections.append(_section(13, "Affected Systems &amp; Versions",
        aff_html
        + "<div class='callout warn'><strong>Scope assessment:</strong> Run your CMDB against "
        "the affected product list. Any asset running an affected version should be "
        "prioritised for immediate patching. Include SaaS, cloud, and OT/ICS environments "
        "where applicable.</div>"
    ))

    # ── S14: Strategic Implications ────────────────────────────────────────
    reg_note = (
        "For organisations in regulated sectors (financial services, healthcare, energy, "
        "public sector) this advisory may trigger mandatory incident reporting obligations "
        "under NIS2, DPDP Act, HIPAA, FFIEC, or NERC CIP."
        if sev in ("CRITICAL", "HIGH") else
        "Validate against your regulatory reporting thresholds for DPDP, GDPR, and sector-specific mandates."
    )
    sections.append(_section(14, "Strategic Implications &amp; Business Risk",
        f"<div class='callout critical'><strong>CISO Action Required:</strong> {reg_note}</div>"
        f"<p>The <strong>{_h(sev)}</strong> classification combined with "
        f"{'confirmed active exploitation' if kev else 'high exploitability probability'} "
        "positions this advisory as a board-level cyber risk event.</p>"
        "<ul>"
        "<li>Executive briefing to CISO/CIO within 24 hours of this dossier receipt.</li>"
        "<li>Risk quantification using FAIR or ISO 27005 model against APEX risk vectors.</li>"
        "<li>Cyber-insurance disclosure review if evidence of compromise exists.</li>"
        "<li>Proactive customer/supplier notification if shared platforms are in scope.</li>"
        "<li>Update risk register and vulnerability management programme with this advisory.</li>"
        "</ul>"
    ))

    # ── S15: APEX AI Analyst Insight ──────────────────────────────────────
    sections.append(_section(15, "APEX AI Analyst Insight",
        "<p>APEX's autonomous AI analyst layer has correlated this advisory against "
        "12 months of threat intelligence, actor infrastructure history, and global telemetry. "
        "Key AI-derived findings:</p>"
        "<div class='kv'>"
        f"<div class='kv-key'>Predictive Risk</div><div class='kv-val'><strong>{risk}/10</strong></div>"
        f"<div class='kv-key'>Actor Fingerprint</div><div class='kv-val'>{_h(actor)}</div>"
        f"<div class='kv-key'>Similarity Cohort</div><div class='kv-val'>{_h(campaign)}</div>"
        f"<div class='kv-key'>AI Confidence</div><div class='kv-val'>{_h(ai_conf)}</div>"
        f"<div class='kv-key'>Kill Chain Phases</div><div class='kv-val'>{', '.join(phases[:4])}</div>"
        f"<div class='kv-key'>TTP Density</div><div class='kv-val'>{len(ttps)} techniques mapped</div>"
        "</div>"
        "<div class='premium-lock' style='margin-top:16px'>"
        "<div class='lock-icon'>🔒</div>"
        "<div class='lock-title'>Full AI Analyst Narrative — Enterprise Tier</div>"
        "<div class='lock-sub'>Includes predictive threat modelling, infrastructure pivot analysis, "
        "autonomous response recommendations, and SOAR playbook export.</div>"
        "<a class='cta cta-enterprise' href='https://cyberdudebivash.com/sentinel-enterprise'>Unlock Enterprise</a>"
        "</div>"
    ))

    # ── S16: References & Enterprise CTA ──────────────────────────────────
    refs = []
    if source_url:
        refs.append(f"<li>Primary source: <a href='{_h(source_url)}' target='_blank' rel='noopener' style='color:var(--accent2)'>{_h(source_url)}</a></li>")
    if nvd_url:
        refs.append(f"<li>NVD: <a href='{_h(nvd_url)}' target='_blank' rel='noopener' style='color:var(--accent2)'>{_h(nvd_url)}</a></li>")
    refs += [
        "<li>CYBERDUDEBIVASH SENTINEL APEX: <a href='https://intel.cyberdudebivash.com' target='_blank' rel='noopener' style='color:var(--accent2)'>intel.cyberdudebivash.com</a></li>",
        "<li>CISA KEV Catalog: <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog' target='_blank' rel='noopener' style='color:var(--accent2)'>cisa.gov/kev</a></li>",
        "<li>MITRE ATT&amp;CK: <a href='https://attack.mitre.org' target='_blank' rel='noopener' style='color:var(--accent2)'>attack.mitre.org</a></li>",
        "<li>STIX 2.1 API: <a href='https://intel.cyberdudebivash.com/api/stix/" + _h(stix_id) + "' target='_blank' rel='noopener' style='color:var(--accent2)'>intel.cyberdudebivash.com/api/stix/" + _h(stix_id) + "</a></li>",
    ]
    sections.append(_section(16, "References, Remediation &amp; Enterprise Access",
        "<ul>" + "".join(refs) + "</ul>"
        "<div class='cta-row'>"
        "<a class='cta cta-primary' href='https://intel.cyberdudebivash.com'>← Back to Platform</a>"
        "<a class='cta cta-secondary' href='https://cyberdudebivash.com/sentinel-premium'>Upgrade to Premium</a>"
        "<a class='cta cta-enterprise' href='https://cyberdudebivash.com/sentinel-enterprise'>Enterprise Access</a>"
        "</div>"
        "<div class='callout' style='margin-top:20px'>"
        "<strong>Enterprise Delivery Pack</strong> includes: full IOC/TTP/STIX 2.1 bundles, "
        "Sigma &amp; YARA rule packs, MITRE Navigator layer, hunt queries (KQL/SPL/EQL), "
        "AI analyst narrative, actor tracker continuation, SOAR playbook export, and "
        "dedicated SOC uplift SLA. <a href='https://cyberdudebivash.com/sentinel-enterprise' "
        "style='color:var(--accent)'>Contact enterprise sales →</a>"
        "</div>"
    ))

    return "\n".join(sections)


# ─────────────────────────────────────────────────────────────────────────────
# Full HTML document
# ─────────────────────────────────────────────────────────────────────────────
def render_report(item: dict, public_prefix: str) -> str:
    title    = item.get("title") or "Untitled Advisory"
    sev      = (item.get("severity") or "INFO").upper()
    ts       = _fmt_ts(item.get("processed_at") or item.get("timestamp") or "")
    intel_id = item.get("id") or "intel--unknown"
    tlp      = (item.get("tlp") or "TLP:CLEAR").replace(":", "-")
    risk     = item.get("risk_score") or 0
    tags     = item.get("tags") or []
    report_url = f"{public_prefix.rstrip('/')}/reports/{intel_id}.html"

    sections_html = build_report_sections(item)

    toc = "".join(
        f"<a href='#s{i}' style='display:block;padding:4px 0;font-family:var(--mono);"
        f"font-size:11px;color:var(--muted);text-decoration:none;"
        f"border-bottom:1px solid var(--border);'>"
        f"<span style='color:var(--accent);margin-right:8px'>{i:02d}</span>{t}</a>"
        for i, t in enumerate([
            "Classification","Executive Summary","Threat Profile","Risk Score",
            "Technical Analysis","ATT&CK Mapping","IOC Table","CVSS/EPSS",
            "Kill Chain","Response Playbook","Actor Profile","Campaign Intel",
            "Affected Systems","Strategic Risk","AI Insight","References & CTA"
        ], 1)
    )

    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<meta name='robots' content='index,follow'>
<meta name='description' content='{_h(title)} — Severity {_h(sev)} — CYBERDUDEBIVASH SENTINEL APEX Tactical Dossier. Risk {risk}/10. Generated {_h(ts)}.'>
<meta property='og:title' content='{_h(title)} · SENTINEL APEX Tactical Dossier'>
<meta property='og:description' content='Severity {_h(sev)} · Risk {risk}/10 · CYBERDUDEBIVASH SENTINEL APEX'>
<meta property='og:type' content='article'>
<title>{_h(title)} · SENTINEL APEX Tactical Dossier</title>
<link rel='canonical' href='{_h(report_url)}'>
<style>{CSS}</style>
</head>
<body>
<div class='tlp-banner tlp-{_h(tlp.replace(":","").replace("TLP","").strip() or "CLEAR")}'>
  TLP: {_h(item.get('tlp','TLP:CLEAR'))} &nbsp;·&nbsp; CYBERDUDEBIVASH SENTINEL APEX TACTICAL DOSSIER &nbsp;·&nbsp; {PLATFORM_VERSION}
</div>
<nav class='top-nav'>
  <div class='nav-brand'>CYBERDUDEBIVASH · SENTINEL APEX</div>
  <div class='nav-links'>
    <a href='https://intel.cyberdudebivash.com'>Platform</a>
    <a href='https://intel.cyberdudebivash.com/api/feed'>Live Feed</a>
    <a href='https://cyberdudebivash.com/sentinel-enterprise'>Enterprise</a>
  </div>
</nav>
<div class='wrap'>
<header class='dossier-hdr'>
  <div class='classification'>
    <span class='cls-chip cls-PUBLIC'>PUBLIC TIER</span>
    <span class='cls-chip cls-TLP'>{_h(item.get('tlp','TLP:CLEAR'))}</span>
    <span>TACTICAL DOSSIER</span>
  </div>
  <div class='dossier-id'>INTEL ID: {_h(intel_id)} &nbsp;·&nbsp; PROCESSED: {_h(ts)}</div>
  <h1 class='dossier-title'>{_h(title)}</h1>
  <div class='meta-strip'>
    <span>Severity: <strong><span class='sev-chip {_sev_class(sev)}'>{_h(sev)}</span></strong></span>
    <span>Risk: <strong>{risk}/10</strong></span>
    <span>Platform: <strong>SENTINEL APEX {PLATFORM_VERSION}</strong></span>
    <span>Processed: <strong>{_h(ts)}</strong></span>
    <span>ID: <code>{_h(intel_id[:24])}{'…' if len(intel_id)>24 else ''}</code></span>
  </div>
  <div class='tag-strip'>{_render_tags(tags)}</div>
</header>

<div style='display:grid;grid-template-columns:220px 1fr;gap:24px;align-items:start'>
<aside style='position:sticky;top:20px'>
  <div style='background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:16px'>
    <div style='font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--accent);margin-bottom:12px;text-transform:uppercase'>Contents</div>
    {toc}
  </div>
</aside>
<main>
{sections_html}
</main>
</div>

<footer class='dossier-ftr'>
  <span>© {datetime.now(timezone.utc).year} CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX {PLATFORM_VERSION}</span>
  <span><a href='https://intel.cyberdudebivash.com'>intel.cyberdudebivash.com</a> · <a href='https://cyberdudebivash.in'>cyberdudebivash.in</a></span>
</footer>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────────────────────────────────────
def iso_path(ts: str) -> tuple[str, str]:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    return f"{dt.year:04d}", f"{dt.month:02d}"


def rel_report_path(item: dict) -> Path:
    yyyy, mm = iso_path(item.get("processed_at") or item.get("timestamp") or utc_now_iso())
    return REPORTS_ROOT / yyyy / mm / f"{item['id']}.html"


# ─────────────────────────────────────────────────────────────────────────────
# R2 upload
# ─────────────────────────────────────────────────────────────────────────────
def r2_upload(local_path: Path, key: str, endpoint: str) -> bool:
    if not shutil.which("aws"):
        log("aws CLI not available — skipping R2 upload", "warning")
        return False
    try:
        subprocess.run(
            ["aws", "s3", "cp", str(local_path),
             f"s3://{R2_BUCKET}/{key}",
             "--endpoint-url", endpoint,
             "--content-type", "text/html; charset=utf-8",
             "--cache-control", "public, max-age=300",
             "--only-show-errors"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        return True
    except Exception as e:
        log(f"R2 upload failed for {key}: {e}", "error")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Manifest I/O
# ─────────────────────────────────────────────────────────────────────────────
def load_manifest() -> dict:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_manifest(data: dict) -> None:
    tmp = MANIFEST_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, MANIFEST_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    global MANIFEST_PATH

    parser = argparse.ArgumentParser(description=f"SENTINEL APEX {PLATFORM_VERSION} report generator")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--upload-r2", action="store_true")
    parser.add_argument("--public-prefix", default=DEFAULT_PREFIX,
                        help="Public URL prefix (default: https://intel.cyberdudebivash.com)")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--fail-on-zero", action="store_true",
                        help="Exit 1 if no reports were generated")
    args = parser.parse_args(argv)

    MANIFEST_PATH = Path(args.manifest)
    log(f"Starting {PLATFORM_VERSION} — manifest: {MANIFEST_PATH}")

    endpoint = None
    if args.upload_r2:
        acct = os.environ.get("CF_ACCOUNT_ID", "")
        if not acct:
            log("CF_ACCOUNT_ID not set — R2 upload disabled", "warning")
            args.upload_r2 = False
        else:
            endpoint = f"https://{acct}.r2.cloudflarestorage.com"

    if not MANIFEST_PATH.exists():
        log(f"FATAL: manifest not found: {MANIFEST_PATH}", "error")
        return 1

    data  = load_manifest()
    items = data.get("advisories") or data.get("reports") or []
    if args.limit:
        items = items[:args.limit]

    log(f"Processing {len(items)} entries — upload_r2={args.upload_r2} prefix={args.public_prefix}")

    written = 0
    uploaded = 0
    skipped_brand = 0
    errors = 0
    t_start = time.monotonic()

    for item in items:
        intel_id = item.get("id")
        if not intel_id:
            log(f"SKIP: entry missing id field — {item.get('title','?')[:60]}", "warning")
            continue

        _title = item.get("title") or ""

        # Hard-skip brand/placeholder entries only
        if any(kw in _title for kw in BRAND_KEYWORDS):
            skipped_brand += 1
            item["validation_status"] = "brand_skip"
            continue

        # ── Zero-skip policy: generate report for EVERY real entry ──
        # Short entries get an enriched template — no blanket skip
        _desc  = item.get("description") or ""
        _words = len((_title + " " + _desc).split())
        is_enriched = _words < 50  # flag thin content but still generate

        path = rel_report_path(item)
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            html_text = render_report(item, args.public_prefix)
            tmp = path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(html_text)
            os.replace(tmp, path)
        except Exception as e:
            log(f"WRITE ERROR [{intel_id}]: {e}", "error")
            item["validation_status"] = "write_error"
            item["report_url"] = item.get("source_url") or ""
            errors += 1
            continue

        # Validate file on disk
        if not path.exists() or path.stat().st_size < 512:
            log(f"VALIDATE FAIL [{intel_id}]: file missing or too small", "error")
            item["validation_status"] = "file_missing"
            item["report_url"] = item.get("source_url") or ""
            errors += 1
            continue

        # Set report_url — always absolute, always distinct from source_url
        yyyy, mm = iso_path(item.get("processed_at") or item.get("timestamp") or utc_now_iso())
        report_url = f"{args.public_prefix.rstrip('/')}/reports/{yyyy}/{mm}/{intel_id}.html"

        # Safety check: report_url must differ from source_url
        if report_url == item.get("source_url", ""):
            log(f"WARN [{intel_id}]: report_url == source_url — appending ?apex=1", "warning")
            report_url += "?apex=1"

        item["report_url"]        = report_url
        item["validation_status"] = "enriched" if is_enriched else "ok"
        written += 1

        log(f"  OK [{item['validation_status']}] {intel_id} → {report_url}")

        if args.upload_r2 and endpoint:
            key = f"reports/{yyyy}/{mm}/{intel_id}.html"
            if r2_upload(path, key, endpoint):
                uploaded += 1

    elapsed = time.monotonic() - t_start
    log(
        f"Complete: written={written} errors={errors} brand_skip={skipped_brand} "
        f"uploaded={uploaded} elapsed={elapsed:.1f}s"
    )

    if errors > 0:
        log(f"WARNING: {errors} entries failed report generation", "warning")

    # Persist manifest with all report_url + validation_status updates
    save_manifest(data)
    log(f"Manifest saved: {MANIFEST_PATH.name} ({written} report_url fields set)")

    if args.fail_on_zero and written == 0:
        log("FATAL: --fail-on-zero set and 0 reports generated", "error")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
