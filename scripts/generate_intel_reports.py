#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH SENTINEL APEX v134.0.0 – ENTERPRISE INTEL REPORT GENERATOR
===============================================================================
Produces one 16-section enterprise HTML Tactical Dossier per advisory.
Every processed intel entry MUST produce a report – no entry is skipped.

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

import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import argparse
import hashlib
import html
import json
import logging
import os
import re
import shutil
import subprocess
# P0 v134.0: IOC enforcement imports
try:
    from core.intelligence.ioc_enforcer import IOCEnforcer as _IOCEnforcer
    from core.intelligence.ioc_confidence import IOCConfidenceEngine as _IOCConfEngine
    _ioc_enforcer = _IOCEnforcer(auto_generate_fallback=True)
    _ioc_confidence = _IOCConfEngine()
    _IOC_ENFORCE_AVAILABLE = True
except ImportError:
    _IOC_ENFORCE_AVAILABLE = False
    _ioc_enforcer = None
    _ioc_confidence = None
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# v134: Global schema enforcement — enforce_schema() applied at every write boundary
_ENFORCE_SCHEMA_AVAILABLE = False
_enforce_schema = None
try:
    import sys as _sys
    _scripts_dir = str(Path(__file__).resolve().parent)
    if _scripts_dir not in _sys.path:
        _sys.path.insert(0, _scripts_dir)
    from safe_io import enforce_schema as _enforce_schema_fn
    _enforce_schema = _enforce_schema_fn
    _ENFORCE_SCHEMA_AVAILABLE = True
except ImportError:
    pass

# ── v148.1.0: APEX Intelligence Upgrade Engine — premium CTI enrichment ─────
_APEX_UPGRADE_AVAILABLE = False
try:
    import sys as _apex_sys
    _repo_root = str(Path(__file__).resolve().parent.parent)
    if _repo_root not in _apex_sys.path:
        _apex_sys.path.insert(0, _repo_root)
    from agent.apex_intelligence_upgrade import (
        generate_technical_narrative   as _apex_technical_narrative,
        render_ttps_premium            as _apex_render_ttps,
        generate_actor_intelligence    as _apex_actor_intel,
        generate_campaign_intelligence as _apex_campaign_intel,
        generate_ai_insight_premium    as _apex_ai_insight,
        generate_kill_chain_html       as _apex_kill_chain,
        generate_enhanced_sigma        as _apex_sigma,
        enrich_advisory                as _apex_enrich,
        filter_operational_iocs        as _apex_filter_iocs,
    )
    _APEX_UPGRADE_AVAILABLE = True
except Exception as _apex_import_err:
    _APEX_UPGRADE_AVAILABLE = False
    import logging as _apex_log_mod
    _apex_log_mod.getLogger("sentinel.report_gen").warning(
        "APEX upgrade engine unavailable (non-fatal): %s", _apex_import_err
    )


def _safe_enforce_schema(item: dict) -> dict:
    """
    Apply global schema enforcement at the write boundary.
    If safe_io is unavailable, falls back to inline critical fixes only.
    Never raises — returns corrected copy.
    """
    if _ENFORCE_SCHEMA_AVAILABLE and _enforce_schema is not None:
        try:
            return _enforce_schema(item)
        except Exception as _schema_exc:
            # v134.1 HARDENING: log schema enforcement failure — never silent
            _log.warning(
                "SCHEMA ENFORCE WARN [%s]: %s: %s — applying inline fallback",
                item.get("id", "UNKNOWN"),
                type(_schema_exc).__name__,
                _schema_exc,
            )
    # Inline fallback: fix the critical P0 regression (published=bool → ISO string)
    item = dict(item)
    if isinstance(item.get("published"), bool):
        item["published"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Coerce severity to string (prevents AttributeError on .upper() in render)
    for _f in ("severity", "threat_type", "actor_tag", "tlp", "feed_source"):
        v = item.get(_f)
        if v is not None and not isinstance(v, str):
            item[_f] = str(v)
    # ioc_count == len(iocs) invariant
    iocs = item.get("iocs")
    if isinstance(iocs, list):
        item["ioc_count"] = len(iocs)
    return item


# ─── Version loader (reads from config/version.json — single source of truth) ───
def _load_platform_version() -> str:
    """Load version from config/version.json. Falls back to hardcoded if missing."""
    try:
        vf = REPO_ROOT / "config" / "version.json"
        if vf.exists():
            import json as _json
            data = _json.loads(vf.read_text(encoding="utf-8"))
            return "v" + data.get("platform", data.get("version", "134.0.0"))
    except Exception:
        pass
    return "v134.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
REPO_ROOT        = Path(__file__).resolve().parent.parent
MANIFEST_PATH    = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
REPORTS_ROOT     = REPO_ROOT / "reports"
VERSION_FILE     = REPO_ROOT / "version.json"
R2_BUCKET        = "sentinel-apex-reports"
PLATFORM_VERSION = _load_platform_version()
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
# Apply filter to ALL root-logger handlers so every logger in this process
# (including CDB-IOC-ENFORCER, CDB-*, etc.) has record.version set before
# the %(version)s formatter is applied.  Without this, any child logger that
# propagates to root crashes with KeyError: 'version'.
_version_filter_instance = _VersionFilter()
for _root_handler in logging.root.handlers:
    _root_handler.addFilter(_version_filter_instance)


def log(msg: str, level: str = "info") -> None:
    getattr(_log, level)(msg)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ─────────────────────────────────────────────────────────────────────────────
# CSS – Enterprise dark theme (inline, zero CDN dependency)
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
  rgba(255,215,0,.02) 10px,rgba(255,215,0,.02) 20px);
  pointer-events:none}
.lock-icon{font-size:24px;margin-bottom:8px}
.lock-title{font-family:var(--mono);font-size:12px;color:#ffd700;
  letter-spacing:1px;margin-bottom:6px}
.lock-sub{font-size:12px;color:var(--muted);margin-bottom:14px}

/* CTAs */
.cta-row{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}
.cta{padding:12px 24px;border-radius:var(--radius);font-family:var(--mono);
  font-size:12px;font-weight:700;letter-spacing:1px;text-decoration:none;
  display:inline-flex;align-items:center;gap:6px;transition:opacity .15s;
  position:relative;z-index:2}
.cta:hover{opacity:.85;transform:translateY(-1px)}
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

/* Financial Impact */
.fin-table{width:100%;border-collapse:collapse;font-size:12px;margin:12px 0}
.fin-table th{background:#060d19;color:var(--accent);font-family:var(--mono);font-size:10px;
  text-transform:uppercase;letter-spacing:1px;padding:8px 12px;text-align:left;
  border-bottom:1px solid var(--border)}
.fin-table td{padding:7px 12px;border-bottom:1px solid rgba(22,32,53,.7);vertical-align:middle}
.fin-table td:first-child{font-family:var(--mono);font-size:11px;color:var(--muted)}
.fin-table .cost{color:var(--crit);font-weight:700;font-family:var(--mono)}
.fin-table .sector-match{background:rgba(0,212,170,.05)}
.bis-ring{display:flex;align-items:center;gap:24px;padding:16px 0}
.bis-circle{width:80px;height:80px;border-radius:50%;display:flex;flex-direction:column;
  align-items:center;justify-content:center;flex-shrink:0;border-width:3px;border-style:solid}
.bis-num{font-family:var(--mono);font-size:22px;font-weight:900}
.bis-label{font-family:var(--mono);font-size:8px;letter-spacing:1px;color:var(--muted)}

/* APEX Intelligence Upgrade v148.1 — Premium CTI Styles */
.apex-narrative{line-height:1.7}
.apex-intel-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin:16px 0}
.apex-intel-item{background:var(--panel2);border:1px solid var(--border);border-radius:6px;padding:12px 14px}
.apex-label{display:block;font-size:0.75em;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.apex-value{display:block;font-size:0.9em;color:var(--text);font-weight:500}
.apex-conf-high{display:inline-block;background:rgba(0,212,170,.12);color:var(--accent);border:1px solid rgba(0,212,170,.3);border-radius:3px;padding:1px 7px;font-size:0.8em;font-weight:700}
.apex-conf-med{display:inline-block;background:rgba(245,166,35,.1);color:var(--med);border:1px solid rgba(245,166,35,.3);border-radius:3px;padding:1px 7px;font-size:0.8em;font-weight:700}
.apex-ai-insight{border:1px solid rgba(0,212,170,.2);border-radius:8px;padding:20px;background:rgba(0,212,170,.03)}
.apex-kev{color:#ff3b3b;display:inline-block;margin-top:4px}

/* Detection Engineering */
.rule-block{background:#020810;border:1px solid rgba(0,212,170,.15);border-left:3px solid var(--accent);
  border-radius:4px;padding:14px 16px;margin:12px 0;overflow-x:auto}
.rule-block pre{margin:0;font-family:var(--mono);font-size:11px;color:#8be9fd;line-height:1.6}
.rule-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.rule-badge{font-family:var(--mono);font-size:9px;letter-spacing:1.5px;padding:2px 8px;
  border-radius:2px;font-weight:700}
.rule-sigma{background:rgba(0,153,255,.15);color:var(--accent2);border:1px solid rgba(0,153,255,.3)}
.rule-yara{background:rgba(255,124,26,.12);color:var(--high);border:1px solid rgba(255,124,26,.3)}
.rule-kql{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.3)}
.rule-spl{background:rgba(255,215,0,.1);color:#ffd700;border:1px solid rgba(255,215,0,.25)}
.copy-hint{font-family:var(--mono);font-size:9px;color:var(--muted);letter-spacing:.5px}

/* Regulatory Matrix */
.reg-matrix{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin:12px 0}
.reg-card{background:var(--panel2);border:1px solid var(--border);border-radius:var(--radius);padding:14px}
.reg-name{font-family:var(--mono);font-size:10px;color:var(--accent);letter-spacing:1.5px;
  font-weight:700;margin-bottom:6px;text-transform:uppercase}
.reg-trigger{font-size:12px;color:#c8d3e8;margin-bottom:4px}
.reg-deadline{font-family:var(--mono);font-size:10px;color:var(--med);margin-top:6px}
.reg-penalty{font-family:var(--mono);font-size:10px;color:var(--crit)}

/* Navigator Download */
.nav-download{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;
  background:rgba(0,212,170,.08);border:1px solid rgba(0,212,170,.3);border-radius:4px;
  font-family:var(--mono);font-size:11px;color:var(--accent);text-decoration:none;
  margin-top:12px;transition:background .15s}
.nav-download:hover{background:rgba(0,212,170,.14)}

/* ── EXECUTIVE INTELLIGENCE CARD ─────────────────────────────────────── */
.exec-card{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;
  margin:24px 0;padding:0}
.exec-tile{background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:16px 14px;text-align:center;
  transition:border-color .15s}
.exec-tile:hover{border-color:var(--accent)}
.exec-tile-label{font-family:var(--mono);font-size:9px;letter-spacing:2px;
  color:var(--muted);text-transform:uppercase;margin-bottom:6px}
.exec-tile-val{font-size:22px;font-weight:900;font-family:var(--mono);
  line-height:1}
.exec-tile-sub{font-family:var(--mono);font-size:9px;color:var(--muted);
  margin-top:4px}
.exec-tile.crit .exec-tile-val{color:var(--crit)}
.exec-tile.high .exec-tile-val{color:var(--high)}
.exec-tile.med  .exec-tile-val{color:var(--med)}
.exec-tile.low  .exec-tile-val{color:var(--low)}
.exec-tile.info .exec-tile-val{color:var(--info)}
.exec-tile.neutral .exec-tile-val{color:var(--accent)}

/* ── SEVERITY BANNER ──────────────────────────────────────────────────── */
.sev-banner{padding:10px 32px;font-family:var(--mono);font-size:11px;
  font-weight:700;letter-spacing:1.5px;display:flex;align-items:center;
  justify-content:center;gap:16px}
.sev-banner.CRITICAL{background:linear-gradient(90deg,rgba(255,59,59,.18),rgba(255,59,59,.06));
  border-bottom:1px solid rgba(255,59,59,.35);color:var(--crit)}
.sev-banner.HIGH{background:linear-gradient(90deg,rgba(255,124,26,.15),rgba(255,124,26,.04));
  border-bottom:1px solid rgba(255,124,26,.3);color:var(--high)}
.sev-banner.MEDIUM{background:linear-gradient(90deg,rgba(245,166,35,.12),rgba(245,166,35,.03));
  border-bottom:1px solid rgba(245,166,35,.25);color:var(--med)}
.sev-banner.LOW{background:rgba(76,175,80,.06);
  border-bottom:1px solid rgba(76,175,80,.2);color:var(--low)}
.sev-banner.INFO{background:rgba(33,150,243,.05);
  border-bottom:1px solid rgba(33,150,243,.2);color:var(--info)}
.sev-pulse{display:inline-block;width:8px;height:8px;border-radius:50%;
  animation:pulse 1.4s infinite}
.sev-banner.CRITICAL .sev-pulse,.sev-banner.HIGH .sev-pulse{background:currentColor}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}

/* ── ACTION BUTTONS (nav) ────────────────────────────────────────────── */
.nav-actions{display:flex;align-items:center;gap:8px}
.nav-btn{font-family:var(--mono);font-size:10px;letter-spacing:1px;
  padding:5px 12px;border-radius:3px;cursor:pointer;text-decoration:none;
  display:inline-flex;align-items:center;gap:5px;border:1px solid;
  transition:opacity .15s;background:none;font-weight:600}
.nav-btn:hover{opacity:.75}
.nav-btn-print{color:var(--muted);border-color:var(--border)}
.nav-btn-stix{color:var(--accent);border-color:rgba(0,212,170,.35)}
.nav-btn-upgrade{color:#ffd700;border-color:rgba(255,215,0,.35);
  background:rgba(255,215,0,.06)}

/* ── CONFIDENCE INDICATOR ─────────────────────────────────────────────── */
.confidence-strip{display:flex;align-items:center;gap:10px;
  margin-top:12px;padding:8px 12px;background:rgba(0,212,170,.04);
  border-radius:var(--radius);border:1px solid rgba(0,212,170,.12)}
.conf-label{font-family:var(--mono);font-size:10px;color:var(--muted);
  letter-spacing:1px;text-transform:uppercase;white-space:nowrap}
.conf-bar{flex:1;height:4px;background:rgba(255,255,255,.06);border-radius:2px}
.conf-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.conf-val{font-family:var(--mono);font-size:11px;color:var(--accent);
  white-space:nowrap;font-weight:700}

/* ── ENHANCED PREMIUM LOCK ────────────────────────────────────────────── */
.premium-lock-v2{background:linear-gradient(135deg,var(--panel2),rgba(15,26,46,.9));
  border:1px solid rgba(255,215,0,.25);border-radius:var(--radius);
  padding:24px;position:relative;overflow:hidden}
.premium-lock-v2::before{content:'';position:absolute;top:0;right:0;
  width:160px;height:160px;border-radius:50%;
  background:radial-gradient(circle,rgba(255,215,0,.07),transparent 70%);
  pointer-events:none}
.plv2-header{display:flex;align-items:center;gap:14px;margin-bottom:16px}
.plv2-icon{font-size:28px}
.plv2-title{font-family:var(--mono);font-size:13px;color:#ffd700;
  letter-spacing:1px;font-weight:700;margin-bottom:3px}
.plv2-sub{font-size:12px;color:var(--muted)}
.plv2-features{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:16px 0}
.plv2-feat{display:flex;align-items:center;gap:7px;font-size:12px;color:#c8d3e8}
.plv2-feat::before{content:'✓';color:var(--accent);font-family:var(--mono);
  font-size:11px;font-weight:700;flex-shrink:0}
.plv2-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}

/* ── WATERMARK / BRAND OVERLAY ─────────────────────────────────────────── */
.report-watermark{position:fixed;bottom:20px;right:20px;
  font-family:var(--mono);font-size:9px;letter-spacing:2px;
  color:rgba(0,212,170,.25);text-transform:uppercase;
  pointer-events:none;z-index:999}

/* ── ACTION URGENCY BADGE ─────────────────────────────────────────────── */
.urgency-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;
  border-radius:3px;font-family:var(--mono);font-size:11px;font-weight:700;
  letter-spacing:1px;text-transform:uppercase}
.urgency-IMMEDIATE{background:rgba(255,59,59,.15);color:var(--crit);
  border:1px solid rgba(255,59,59,.4)}
.urgency-HIGH{background:rgba(255,124,26,.12);color:var(--high);
  border:1px solid rgba(255,124,26,.35)}
.urgency-STANDARD{background:rgba(76,175,80,.1);color:var(--low);
  border:1px solid rgba(76,175,80,.3)}
.urgency-MONITOR{background:rgba(33,150,243,.1);color:var(--info);
  border:1px solid rgba(33,150,243,.3)}

/* ── STIX EXPORT BUTTON ───────────────────────────────────────────────── */
.stix-export{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;
  background:linear-gradient(135deg,rgba(0,212,170,.12),rgba(0,153,255,.08));
  border:1px solid rgba(0,212,170,.3);border-radius:var(--radius);
  font-family:var(--mono);font-size:11px;color:var(--accent);
  text-decoration:none;transition:all .15s;font-weight:600}
.stix-export:hover{background:rgba(0,212,170,.18);border-color:var(--accent)}

/* ── SHARE ROW ────────────────────────────────────────────────────────── */
.share-row{display:flex;align-items:center;gap:10px;padding:10px 14px;
  background:rgba(0,212,170,.03);border:1px solid var(--border);
  border-radius:var(--radius);font-size:12px;color:var(--muted);margin-top:16px}
.share-row code{flex:1;font-size:11px;color:var(--accent2);overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.share-copy{font-family:var(--mono);font-size:10px;padding:4px 10px;
  background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.3);
  border-radius:3px;color:var(--accent);cursor:pointer;white-space:nowrap;
  transition:opacity .15s}
.share-copy:hover{opacity:.75}

/* ── PRINT STYLES ─────────────────────────────────────────────────────── */
@media print{
  body{background:#fff!important;color:#111!important;font-size:12px}
  .top-nav,.tlp-banner,.sev-banner,.report-watermark{display:none!important}
  .wrap{max-width:none;padding:16px}
  .section{break-inside:avoid;border:1px solid #ddd!important;
    background:#f8f8f8!important;margin-bottom:10px}
  h2.section-title{color:#111!important}
  .aside,.toc-aside{display:none!important}
  .exec-card{display:none!important}
  a{color:#0066cc!important}
  pre{background:#f0f0f0!important;color:#111!important;border:1px solid #ccc!important}
  .premium-lock,.premium-lock-v2{display:none!important}
  @page{margin:15mm}
}

/* ── RESPONSIVE ───────────────────────────────────────────────────────── */
@media(max-width:900px){
  .exec-card{grid-template-columns:repeat(3,1fr)}
}
@media(max-width:680px){
  .wrap{padding:24px 16px 64px}
  .kv{grid-template-columns:1fr}
  h1.dossier-title{font-size:22px}
  .meta-strip{gap:6px 12px}
  .reg-matrix{grid-template-columns:1fr}
  .exec-card{grid-template-columns:repeat(2,1fr)}
  .plv2-features{grid-template-columns:1fr}
  .nav-actions .nav-btn-stix,.nav-actions .nav-btn-upgrade{display:none}
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
# v134: Every free-text field is sanitized through the encoding repair
# layer BEFORE HTML-escape. Guarantees no mojibake ever reaches disk.
try:
    import sys as _sys_enc
    _core_dir = str(Path(__file__).resolve().parent.parent)
    if _core_dir not in _sys_enc.path:
        _sys_enc.path.insert(0, _core_dir)
    from core.utils.encoding_utils import sanitize_field as _sanitize_field
except Exception:  # pragma: no cover
    def _sanitize_field(x):  # type: ignore[no-redef]
        return x


def _h(s: Any) -> str:
    """HTML-escape after mojibake repair. Every string that reaches HTML
    passes through this single chokepoint — the v134 encoding guarantee."""
    if s is None:
        return ""
    s = _sanitize_field(s) if isinstance(s, str) else s
    return html.escape(str(s), quote=True)


def _fmt_ts(ts: str) -> str:
    if not ts or not isinstance(ts, str):
        return "–"
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
            ival  = ioc.get("value") or ioc.get("indicator") or "–"
            conf  = ioc.get("confidence") or "–"
            ctx   = ioc.get("context") or ioc.get("description") or "–"
        else:
            itype, ival, conf, ctx = "raw", str(ioc), "–", "–"
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
            rows.append(f"<tr><td><code>{_h(t)}</code></td><td>–</td><td>–</td></tr>")
        elif isinstance(t, dict):
            tid  = t.get("technique_id") or t.get("id") or "T?"
            nm   = t.get("name") or t.get("technique") or "–"
            tac  = t.get("tactic") or "–"
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
# Premium Enterprise Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

# IBM Cost of a Data Breach 2024 / Ponemon Institute sector benchmarks
_BREACH_COSTS: list[tuple[str, str, str, str]] = [
    # (sector, avg_cost_usd, avg_days_to_contain, risk_multiplier)
    ("Healthcare",           "$9.77M",  "236 days", "3.4×"),
    ("Financial Services",   "$6.08M",  "175 days", "2.1×"),
    ("Energy & Utilities",   "$5.29M",  "189 days", "1.8×"),
    ("Technology",           "$4.97M",  "204 days", "1.7×"),
    ("Industrial / ICS",     "$4.65M",  "210 days", "1.6×"),
    ("Education",            "$3.99M",  "242 days", "1.4×"),
    ("Retail & eCommerce",   "$3.48M",  "198 days", "1.2×"),
    ("Government / Public",  "$2.60M",  "261 days", "0.9×"),
    ("Cross-Sector Average", "$4.88M",  "204 days", "1.0×"),
]


def _render_financial_impact(sev: str, risk: float, sectors: list) -> str:
    """Render IBM/Ponemon-based financial impact table with sector analysis."""
    match_sectors = {s.lower() for s in (sectors or [])}
    rows = []
    for sector, cost, days, mult in _BREACH_COSTS:
        is_match = any(kw in sector.lower() for kw in match_sectors) if match_sectors else False
        row_class = " class='sector-match'" if is_match else ""
        rows.append(
            f"<tr{row_class}><td>{_h(sector)}</td>"
            f"<td class='cost'>{_h(cost)}</td>"
            f"<td>{_h(days)}</td>"
            f"<td>{_h(mult)}</td>"
            f"</tr>"
        )
    # Exposure multiplier from risk score
    risk_mult = max(0.3, min(risk / 5.0, 2.0))
    fair_low  = f"${4_880_000 * 0.15 * risk_mult:,.0f}"
    fair_mid  = f"${4_880_000 * 0.60 * risk_mult:,.0f}"
    fair_high = f"${4_880_000 * 1.20 * risk_mult:,.0f}"
    return (
        "<p>Breach cost projections derived from <strong>IBM Cost of a Data Breach Report 2024</strong> "
        "and <strong>Ponemon Institute benchmarks</strong>, adjusted for observed severity and exploit maturity. "
        "Figures represent industry median for organisations of 1,000—10,000 employees.</p>"
        "<table class='fin-table'>"
        "<thead><tr><th>Sector</th><th>Avg Breach Cost</th><th>Avg Contain Time</th><th>Risk Multiplier</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        "<h3 style='margin-top:20px'>FAIR Model Exposure Estimate – This Advisory</h3>"
        "<div class='kv'>"
        f"<div class='kv-key'>Risk Input</div><div class='kv-val'>{risk}/10 composite APEX score</div>"
        f"<div class='kv-key'>Loss Range (Low)</div><div class='kv-val'><strong style='color:var(--low)'>{_h(fair_low)}</strong></div>"
        f"<div class='kv-key'>Loss Range (Most Likely)</div><div class='kv-val'><strong style='color:var(--med)'>{_h(fair_mid)}</strong></div>"
        f"<div class='kv-key'>Loss Range (High)</div><div class='kv-val'><strong style='color:var(--crit)'>{_h(fair_high)}</strong></div>"
        "<div class='kv-key'>Methodology</div><div class='kv-val'>FAIR ISO/IEC 27005 + NIST SP 800-30</div>"
        "</div>"
        "<div class='callout warn'><strong>Cyber-Insurance Disclosure:</strong> Losses in the Most Likely range "
        "typically trigger notification obligations under your cyber-insurance policy. Engage your broker within "
        "72 hours of confirmed compromise.</div>"
    )


def _render_sigma_rule(title: str, ttps: list, iocs: list) -> str:
    """Generate a Sigma detection rule template from advisory data."""
    safe_title = re.sub(r"[^a-zA-Z0-9_]", "_", (title or "advisory"))[:40]
    ttp_ids = [
        (t.get("technique_id") or t.get("id") or t) if isinstance(t, dict) else str(t)
        for t in (ttps or [])[:5]
    ]
    ioc_vals = []
    for ioc in (iocs or [])[:6]:
        if isinstance(ioc, dict):
            v = ioc.get("value") or ioc.get("indicator") or ""
        else:
            v = str(ioc)
        if v and len(v) > 3:
            ioc_vals.append(v[:60])

    ttp_comment = "  # " + ", ".join(str(t) for t in ttp_ids) if ttp_ids else "  # TTPs: enrich via APEX Enterprise"
    # Build SIGMA detection block — always start with process Image filter
    # CommandLine|contains (if IOCs present) is a SIBLING of Image|endswith,
    # both at 4-space indent (children of 'selection' which sits at 2 spaces).
    ioc_section = ""
    if ioc_vals:
        # 6 spaces for list items under 4-space CommandLine|contains key
        ioc_list = "\n".join(f"      - '{_h(v)}'" for v in ioc_vals)
        ioc_section = f"\n    CommandLine|contains:\n{ioc_list}"

    rule = f"""title: APEX_{_h(safe_title)}
id: apex-{safe_title[:8].lower()}-detect-001
status: experimental
description: >
  APEX-generated Sigma rule for: {_h(title[:80])}
  Generated by CYBERDUDEBIVASH SENTINEL APEX {PLATFORM_VERSION}
references:
  - https://intel.cyberdudebivash.com
author: CYBERDUDEBIVASH SENTINEL APEX
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
tags:
{ttp_comment}
  # Source: APEX advisory - replace with confirmed technique IDs
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\\\cmd.exe'
      - '\\\\powershell.exe'
      - '\\\\wscript.exe'{ioc_section}
  condition: selection
falsepositives:
  - Legitimate administrative tooling
level: {'high' if len(ttp_ids) >= 3 else 'medium'}
"""
    return rule


def _is_reference_url(v: str) -> bool:
    """Return True if a string is a feed/reference URL, not a threat indicator."""
    _REF_DOMAINS = (
        "vulners.com", "cvefeed.io", "nvd.nist.gov", "cve.mitre.org",
        "github.com/advisories", "nvd.nist.gov/vuln/detail", "cve.org",
        "intel.cyberdudebivash.com", "cyberdudebivash.in", "attack.mitre.org",
        "cisa.gov", "msrc.microsoft.com", "packetstormsecurity.com",
    )
    if not v or not v.startswith(("http://", "https://")):
        return False
    v_lower = v.lower()
    return any(d in v_lower for d in _REF_DOMAINS)


def _filter_yara_iocs(iocs: list) -> list:
    """Return only operationally huntable IOC values — no source/reference URLs."""
    result = []
    for ioc in (iocs or []):
        if isinstance(ioc, dict):
            v = ioc.get("value") or ioc.get("indicator") or ""
            itype = str(ioc.get("type") or "").lower()
        else:
            v, itype = str(ioc), "raw"
        if not v:
            continue
        # Skip reference/source URLs
        if _is_reference_url(v):
            continue
        # Skip bare CVE IDs as YARA strings (too generic, high false-positive)
        if re.match(r'^CVE-\d{4}-\d+$', v.strip(), re.IGNORECASE):
            continue
        if 4 <= len(v) <= 120:
            result.append(v)
    return result


def _render_yara_rule(title: str, iocs: list, actor: str) -> str:
    """Generate a YARA signature with operationally huntable IOC strings."""
    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", (title or "Advisory"))[:32]
    safe_actor = re.sub(r"[^a-zA-Z0-9_]", "_", (actor or "UNKNOWN"))[:16]
    # Use only operational IOCs — no source URLs, no bare CVE IDs
    op_ioc_vals = _filter_yara_iocs(iocs)
    str_defs = []
    for i, v in enumerate(op_ioc_vals[:8]):
        if v and not any(c in v for c in ['"', '\\']):
            str_defs.append(f'    $ioc_{i} = "{v}" ascii wide nocase')
    if not str_defs:
        # Generate behavioural strings from vulnerability class
        cve_match = re.search(r'CVE-\d{4}-\d+', title or "", re.IGNORECASE)
        cve_id = cve_match.group(0) if cve_match else ""
        vuln_lower = (title or "").lower()
        if "sql" in vuln_lower and "inject" in vuln_lower:
            str_defs = [
                '    $sqli_1 = "UNION SELECT" ascii wide nocase',
                '    $sqli_2 = "OR 1=1" ascii wide nocase',
                '    $sqli_3 = "xp_cmdshell" ascii wide nocase',
            ]
        elif "ssrf" in vuln_lower:
            str_defs = [
                '    $ssrf_1 = "169.254.169.254" ascii wide',
                '    $ssrf_2 = "metadata.google.internal" ascii wide',
                '    $ssrf_3 = "file://" ascii wide nocase',
            ]
        elif "path traversal" in vuln_lower or "directory traversal" in vuln_lower:
            str_defs = [
                '    $pt_1 = "../../../" ascii wide',
                '    $pt_2 = "..%2F..%2F" ascii wide nocase',
                '    $pt_3 = "/etc/passwd" ascii wide',
            ]
        elif "rce" in vuln_lower or "remote code" in vuln_lower or "command injection" in vuln_lower:
            str_defs = [
                '    $rce_1 = "/bin/bash" ascii wide',
                '    $rce_2 = "cmd.exe" ascii wide nocase',
                '    $rce_3 = "whoami" ascii wide nocase',
            ]
        elif cve_id:
            str_defs = [f'    $cve_ref = "{cve_id}" ascii wide nocase  // narrow with observed payload strings']
        else:
            str_defs = [f'    $title_kw = "{title[:30]}" ascii nocase  // refine with observed strings']

    rule = f"""rule APEX_{safe_name}__{safe_actor} {{
    meta:
        description = "APEX detection: {title[:60]}"
        author      = "CYBERDUDEBIVASH SENTINEL APEX {PLATFORM_VERSION}"
        date        = "{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        reference   = "https://intel.cyberdudebivash.com"
        severity    = "high"
    strings:
{chr(10).join(str_defs)}
    condition:
        any of ($ioc_*) or
        (uint16(0) == 0x5A4D and any of ($ioc_*))
}}
"""
    return rule


def _render_hunt_queries(title: str, ttps: list, iocs: list) -> str:
    """Generate KQL (Sentinel/Defender) and SPL (Splunk) hunt queries.
    Strips source/reference URLs from IOC list — only operational indicators used.
    """
    kw = re.sub(r"[^a-zA-Z0-9 ]", " ", title or "advisory").split()[0:3]
    kw_str = " or ".join(f'"{w}"' for w in kw if len(w) > 3) or '"advisory"'
    # Only use operational IOC values — no source URLs
    ioc_vals = []
    for ioc in (iocs or [])[:6]:
        if isinstance(ioc, dict):
            v = ioc.get("value") or ioc.get("indicator") or ""
        else:
            v = str(ioc)
        if v and len(v) > 3 and not _is_reference_url(v):
            ioc_vals.append(v[:80])
    # Build keyword fallback from title if no operational IOCs
    if not ioc_vals:
        title_kws = [w for w in re.sub(r"[^a-zA-Z0-9 ]", " ", title or "").split() if len(w) > 4][:3]
        ioc_vals = title_kws or ["<replace-with-observed-ioc>"]
    # Raw strings for code — NO _h() escaping inside code blocks
    ioc_kql_list = ", ".join(f'"{v}"' for v in ioc_vals)
    ioc_spl_list = " OR ".join(f'"{v}"' for v in ioc_vals)
    ioc_spl_re = "|".join(re.escape(v) for v in ioc_vals)

    kql = f"""// KQL – Microsoft Sentinel / Defender XDR
// APEX Advisory Hunt: {title[:60]}
// Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}

let lookback = 30d;
let apex_iocs = dynamic([{ioc_kql_list}]);

// IOC match across network events
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has_any (apex_iocs) or RemoteIP has_any (apex_iocs)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by Timestamp desc;

// Process execution anomaly — keyword hunt
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any ({kw_str})
| summarize count() by DeviceName, ProcessCommandLine, bin(Timestamp, 1h)
| where count_ > 3
| order by count_ desc;

// Authentication anomaly correlated with advisory window
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != 0
| where UserPrincipalName has_any (apex_iocs) or IPAddress has_any (apex_iocs)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultDescription
| order by TimeGenerated desc;"""

    spl = f"""// SPL – Splunk Enterprise Security
// APEX Advisory Hunt: {title[:60]}
// Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}

index=* sourcetype=zeek* OR sourcetype=suricata* OR sourcetype=wineventlog*
({ioc_spl_list})
| eval hunt_match=if(match(_raw, "({ioc_spl_re})" ), "IOC_HIT", "NONE")
| stats count by src_ip, dest_ip, dest_port, hunt_match, _time
| where hunt_match="IOC_HIT"
| sort - _time

| eval risk_score=case(
    match(hunt_match, "IOC_HIT"), 95,
    match(sourcetype, "suricata"), 80,
    true(), 50)
| table _time, src_ip, dest_ip, dest_port, risk_score, hunt_match

// Retro-hunt: network telemetry correlated with advisory IOCs
index=network sourcetype=proxy OR sourcetype=firewall
({ioc_spl_list})
| stats count by src_ip, dest_host, url, _time
| sort - count"""

    return kql, spl


def _render_regulatory_matrix(sev: str, kev: bool, sectors: list) -> str:
    """Render multi-framework regulatory compliance impact matrix."""
    regs = [
        {
            "name": "GDPR",
            "trigger": f"{'Mandatory' if sev in ('CRITICAL','HIGH') else 'Conditional'} – personal data at risk",
            "deadline": "72-hour notification to supervisory authority",
            "penalty": "Up to €20M or 4% global turnover",
            "active": True,
        },
        {
            "name": "DPDP ACT (India)",
            "trigger": f"{'High-priority' if sev in ('CRITICAL','HIGH') else 'Standard'} – Indian resident data",
            "deadline": "72 hours to Data Protection Board",
            "penalty": "Up to ₹250 crore (~$30M)",
            "active": True,
        },
        {
            "name": "HIPAA",
            "trigger": "PHI breach – 500+ records triggers HHS notification",
            "deadline": "60 days post-discovery; media notification if 500+ in state",
            "penalty": "Up to $1.9M per violation category per year",
            "active": any("health" in str(s).lower() for s in (sectors or [])),
        },
        {
            "name": "PCI-DSS v4",
            "trigger": "Cardholder data environment (CDE) in scope",
            "deadline": "Immediate card scheme notification; forensic investigation mandatory",
            "penalty": "$5K—$100K/month until compliant; card acceptance revocation",
            "active": any("fin" in str(s).lower() or "retail" in str(s).lower() for s in (sectors or [])),
        },
        {
            "name": "NIS2 (EU)",
            "trigger": f"{'Significant impact on essential services' if sev in ('CRITICAL','HIGH') else 'Standard incident'} classification",
            "deadline": "Early warning: 24h; Notification: 72h; Final report: 1 month",
            "penalty": "Essential entities: up to €10M or 2% global turnover",
            "active": True,
        },
        {
            "name": "SEC Cybersecurity Rules",
            "trigger": "Material incident – publicly traded entities",
            "deadline": "Form 8-K filing within 4 business days of materiality determination",
            "penalty": "Enforcement action; restatement risk",
            "active": False,
        },
    ]
    _applies_badge = "&nbsp;<span style='color:var(--accent);font-size:8px'>&#x25CF; APPLIES</span>"
    cards = []
    for reg in regs:
        active_style = "" if reg["active"] else "opacity:.55;"
        applies_html = _applies_badge if reg["active"] else ""
        cards.append(
            f"<div class='reg-card' style='{active_style}'>"
            f"<div class='reg-name'>{_h(reg['name'])}{applies_html}</div>"
            f"<div class='reg-trigger'>{_h(reg['trigger'])}</div>"
            f"<div class='reg-deadline'>&#x23F1; {_h(reg['deadline'])}</div>"
            f"<div class='reg-penalty'>&#x26A0; {_h(reg['penalty'])}</div>"
            f"</div>"
        )
    kev_note = (
        "<div class='callout critical'><strong>KEV CONFIRMED:</strong> CISA KEV listing creates mandatory remediation "
        "timelines for US Federal civilian agencies (FCEB) – 3—14 days depending on severity. "
        "US critical infrastructure operators should treat as equivalent obligation.</div>"
        if kev else ""
    )
    return (
        "<p>Regulatory obligations triggered by this advisory depend on your sector, data classification, "
        "and jurisdiction. APEX compliance mapping covers the frameworks below – engage your DPO/GC immediately "
        "on any <strong>CRITICAL</strong> or <strong>HIGH</strong> advisory with personal data in scope.</p>"
        f"<div class='reg-matrix'>{''.join(cards)}</div>"
        f"{kev_note}"
    )


def _compute_bis(risk: float, cvss: Any, epss: Any, kev: bool, ioc_count: int, ttp_count: int) -> dict:
    """Compute Business Impact Score (BIS/10) – FAIR-aligned composite metric."""
    base  = float(risk or 0) * 0.35
    c_v   = (float(cvss or 0) / 10.0) * 2.5
    e_v   = min(float(epss or 0) / 100.0, 1.0) * 2.0
    kev_v = 2.0 if kev else 0.0
    ioc_v = min(ioc_count / 10.0, 1.0) * 1.5
    ttp_v = min(ttp_count / 10.0, 1.0) * 1.5  # up to 1.5
    bis   = round(min(base + c_v + e_v + kev_v + ioc_v + ttp_v, 10.0), 1)

    if bis >= 8.5:
        label, color = "CRITICAL BUSINESS RISK", "var(--crit)"
    elif bis >= 6.5:
        label, color = "HIGH BUSINESS RISK", "var(--high)"
    elif bis >= 4.5:
        label, color = "MEDIUM BUSINESS RISK", "var(--med)"
    else:
        label, color = "LOW BUSINESS RISK", "var(--low)"

    return {"score": bis, "label": label, "color": color}


# ─────────────────────────────────────────────────────────────────────────────
# 16-Section Report Builder (+ 4 Premium Enterprise Sections)
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
    # RENDER LAYER SAFETY: NEVER assume data types — all fields coerced before use
    title       = str(item.get("title") or "Untitled Advisory")
    desc        = str(item.get("description") or title)
    sev         = str(item.get("severity") or "UNKNOWN").upper()
    actor       = str(item.get("actor_tag") or item.get("primary_actor") or "UNATTRIBUTED")
    threat_type = str(item.get("threat_type") or "General Cyber Threat")
    feed        = str(item.get("feed_source") or item.get("source") or "SENTINEL-APEX")
    cvss        = item.get("cvss_score")
    epss        = item.get("epss_score")
    kev         = bool(item.get("kev_present", False))
    risk        = float(item.get("risk_score") or 0)
    ttps        = item.get("ttps") or item.get("mitre_tactics") or []
    iocs        = item.get("iocs") or []
    # P0 FIX v134.0: IOC enforcement + confidence scoring pipeline
    iocs = list(iocs)  # ensure list

    # Step 1: Score IOC confidence (no IOC ships at 0%)
    if _IOC_ENFORCE_AVAILABLE and _ioc_confidence and iocs:
        iocs = _ioc_confidence.score_batch(iocs)
        iocs = _ioc_confidence.ensure_minimum_confidence(iocs)

    # Step 2: Enforce IOC count for HIGH/CRITICAL (auto-generate fallback IOCs)
    if _IOC_ENFORCE_AVAILABLE and _ioc_enforcer:
        severity_val = (item.get("severity") or "").upper()
        if severity_val in ("HIGH", "CRITICAL") and len(iocs) == 0:
            item["iocs"] = iocs
            result = _ioc_enforcer.enforce(item)
            if not result.blocked:
                iocs = result.item.get("iocs", iocs)
                _item_id = item.get('id', '?')
                log(f"IOC fallback: {result.fallback_added} IOCs generated for {_item_id[:16]} [{severity_val}]", "warning")
            else:
                log(f"IOC BLOCK: {result.reason}", "error")

    # P0 INTEGRITY: ioc_count MUST equal len(iocs)
    ioc_count   = len(iocs)
    item["ioc_count"]        = ioc_count
    item["indicator_count"]  = ioc_count
    item["iocs"]             = iocs
    tags        = item.get("tags") or []
    stix_id     = item.get("stix_id") or item.get("id") or "–"
    tlp         = item.get("tlp") or "TLP:CLEAR"
    source_url  = item.get("source_url") or ""
    campaign    = item.get("campaign_id") or "UNCLASSIFIED"
    affected    = item.get("affected_products") or item.get("affected_versions") or []
    kc_phases   = item.get("kill_chain_phases") or []
    nvd_url     = item.get("nvd_url") or ""
    ts          = _fmt_ts(item.get("processed_at") or item.get("timestamp") or "")

    # ── v148.1.0: APEX Intelligence Upgrade — enrich advisory before rendering ──
    if _APEX_UPGRADE_AVAILABLE:
        try:
            item = _apex_enrich(item)
            # Re-read enriched TTPs
            ttps = item.get("ttps") or item.get("mitre_tactics") or []
        except Exception as _enrich_exc:
            log(f"APEX enrich warn (non-fatal): {_enrich_exc}", "warning")

    # Re-bind actor after enrichment (may have been updated)
    actor       = str(item.get("actor_cluster") or item.get("actor_tag") or item.get("primary_actor") or "UNATTRIBUTED")
    campaign    = item.get("campaign_id") or item.get("campaign") or "UNCLASSIFIED"

    sections = []

    # ── S1: Classification Header ──────────────────────────────────────────
    kev_badge = (
        "<span class='sev-chip sev-CRITICAL'>KEV CONFIRMED</span>"
        if kev else ""
    )
    _tlp_class = _sev_class("INFO")   # pre-computed – no backslash inside f-string
    sections.append(_section(1, "Classification &amp; Header",
        f"<div class='kv'>"
        f"<div class='kv-key'>STIX ID</div><div class='kv-val'><code>{_h(stix_id)}</code></div>"
        f"<div class='kv-key'>TLP</div><div class='kv-val'><span class='sev-chip {_tlp_class}'>{_h(tlp)}</span></div>"
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
        "Active exploitation confirmed via CISA KEV catalogue – treat as IMMINENT threat."
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
        f"<div class='kv-key'>STIX Bundle</div><div class='kv-val'><code>{_h(item.get('stix_file','data/stix/–'))}</code></div>"
        f"<div class='kv-key'>Feed Source</div><div class='kv-val'>{_h(feed)}</div>"
        f"<div class='kv-key'>Source URL</div><div class='kv-val'>"
        + (f"<a href='{_h(source_url)}' target='_blank' rel='noopener' style='color:var(--accent2)'>{_h(source_url[:80])}{'…' if len(source_url)>80 else ''}</a>" if source_url else "–")
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
        f"<strong>Composite Score {risk}/10</strong> – "
        + ("IMMINENT. Patch within 24 hours." if risk >= 9 else
           "HIGH PRIORITY. Patch within 72 hours." if risk >= 7 else
           "STANDARD. Patch within standard window.")
        + "</div>"
    ))

    # ── S5: Technical Analysis — APEX Intelligence Upgrade v148.1 ─────────
    if _APEX_UPGRADE_AVAILABLE:
        _s5_body = _apex_technical_narrative(item)
    else:
        delivery = item.get("delivery_vector") or "Multi-stage; refer to IOC section for observed infrastructure."
        priv_req = item.get("privilege_required") or "unprivileged user"
        _s5_body = (
            f"<p>Behavioural and structural analysis of <em>&ldquo;{_h(title)}&rdquo;</em> "
            "reveals the following technical characteristics:</p>"
            "<ul>"
            f"<li><strong>Delivery vector:</strong> {_h(delivery)}</li>"
            f"<li><strong>Execution chain:</strong> {len(ttps)} MITRE ATT&amp;CK techniques "
            "spanning initial access through impact phases.</li>"
            f"<li><strong>Privilege context:</strong> Exploit path requires {_h(priv_req)} privileges.</li>"
            f"<li><strong>Network footprint:</strong> {ioc_count} distinct indicators "
            "of compromise recorded at analysis time.</li>"
            f"<li><strong>KEV status:</strong> {'Actively exploited – CISA KEV confirmed.' if kev else 'Not presently on CISA KEV.'}</li>"
            f"<li><strong>Threat actor:</strong> Activity attributed to cluster "
            f"<strong>{_h(actor)}</strong>.</li>"
            "</ul>"
            "<p>Defenders should correlate the IOC table (Section 7) against 30-day "
            "SIEM retention, proxy logs, EDR process telemetry, and authentication "
            "events. Absence of a match does not rule out compromise – this advisory "
            "has been associated with re-generated C2 infrastructure and DGA campaigns.</p>"
        )
    sections.append(_section(5, "Technical Analysis", _s5_body))

    # ── S6: MITRE ATT&CK — APEX Premium ATT&CK Engine v148.1 ─────────────
    if _APEX_UPGRADE_AVAILABLE:
        _s6_body = _apex_render_ttps(ttps, item)
    else:
        _s6_body = (
            "<p>The following ATT&amp;CK v15 techniques have been mapped with HIGH confidence. "
            "Enterprise subscribers receive a Navigator layer (.json) for direct overlay "
            "onto your detection coverage matrix.</p>"
            + _render_ttps(ttps)
        )
    sections.append(_section(6, "MITRE ATT&amp;CK Mapping", _s6_body))

    # ── S7: IOC Table — APEX IOC Intelligence Engine v148.1 ───────────────
    # Filter source reference URLs; keep only operational threat indicators
    _operational_iocs = iocs
    if _APEX_UPGRADE_AVAILABLE:
        try:
            _operational_iocs, _suppressed_iocs = _apex_filter_iocs(iocs)
            if not _operational_iocs and iocs:
                # All were reference URLs — still show them but mark as reference
                _operational_iocs = iocs
        except Exception as _ioc_filter_exc:
            log(f"IOC filter warn (non-fatal): {_ioc_filter_exc}", "warning")
    sections.append(_section(7, "Indicators of Compromise",
        "<p>Hunt these indicators across SIEM, EDR, DNS, proxy, and firewall "
        "telemetry. APEX delivers IOCs in STIX 2.1, MISP, Sigma, and YARA "
        "formats via the enterprise API (<code>/api/stix/{id}</code>).</p>"
        + _render_iocs(_operational_iocs)
    ))

    # ── S8: CVSS / EPSS Deep Dive ──────────────────────────────────────────
    cvss_vec = item.get("cvss_vector") or "Not available"
    # pre-computed – no backslash inside f-string (Python <3.12 restriction)
    _kev_chip = "<span class='sev-chip sev-CRITICAL'>YES &mdash; ACTIVELY EXPLOITED</span>" if kev else "No"
    sections.append(_section(8, "CVSS &amp; EPSS Deep Dive",
        "<div class='kv'>"
        f"<div class='kv-key'>CVSS 3.1 Score</div><div class='kv-val'><strong>{_h(cvss) if cvss is not None else 'Pending'}</strong></div>"
        f"<div class='kv-key'>CVSS Vector</div><div class='kv-val'><code>{_h(cvss_vec)}</code></div>"
        f"<div class='kv-key'>EPSS Score</div><div class='kv-val'><strong>{_h(epss) if epss is not None else 'Pending'}{'%' if epss is not None else ''}</strong></div>"
        f"<div class='kv-key'>KEV Listed</div><div class='kv-val'>{_kev_chip}</div>"
        f"<div class='kv-key'>NVD Reference</div><div class='kv-val'>"
        + (f"<a href='{_h(nvd_url)}' target='_blank' rel='noopener' style='color:var(--accent2)'>{_h(nvd_url)}</a>" if nvd_url else "–")
        + "</div>"
        "</div>"
        "<p style='margin-top:14px'>CVSS measures inherent severity. EPSS models real-world exploitation "
        "probability. Combined with KEV catalogue status, these signals drive "
        "APEX's composite risk score. EPSS &gt;10% combined with KEV listing "
        "triggers APEX's IMMINENT classification – immediate patching required.</p>"
    ))

    # ── S9: Kill Chain Analysis — APEX Threat-Specific Engine v148.1 ────────
    if _APEX_UPGRADE_AVAILABLE:
        kc_html = _apex_kill_chain(item, kc_phases)
        if not kc_html:
            # fallback to original if upgrade returns empty
            default_kc = ["Reconnaissance", "Weaponisation", "Delivery", "Exploitation"]
            kc_html = "".join(
                f"<div class='kc-phase'><div class='kc-num'>{i:02d}</div>"
                f"<div class='kc-body'><h4>{p}</h4></div></div>"
                for i, p in enumerate(default_kc, 1)
            )
    else:
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
        "<div class='playbook-label'>Immediate (0—4 hours)</div>"
        "<div class='playbook-steps'>"
        "<div class='step'><p>Triage advisory against asset inventory. Identify affected versions and exposure classes.</p></div>"
        "<div class='step'><p>Deploy APEX Sigma &amp; YARA rule packs into your SIEM and EDR estate.</p></div>"
        "<div class='step'><p>Block full IOC list (Section 7) at egress firewall, proxy, and DNS RPZ tiers.</p></div>"
        "<div class='step'><p>Isolate hosts exhibiting observed behavioural signatures pending forensic review.</p></div>"
        "</div></div>"
        "<div class='playbook-phase'>"
        "<div class='playbook-label'>Short-term (4—24 hours)</div>"
        "<div class='playbook-steps'>"
        "<div class='step'><p>Apply vendor patch or configuration workaround per remediation guidance (Section 16).</p></div>"
        "<div class='step'><p>Run 30-day retro-hunt across all telemetry using APEX hunt queries (hunt.hql / hunt.kql).</p></div>"
        "<div class='step'><p>Review third-party and supply-chain exposure; confirm upstream providers are patched.</p></div>"
        "</div></div>"
        "<div class='playbook-phase'>"
        "<div class='playbook-label'>Medium-term (1—7 days)</div>"
        "<div class='playbook-steps'>"
        "<div class='step'><p>Validate detection coverage across ATT&amp;CK techniques (Section 6).</p></div>"
        "<div class='step'><p>Perform tabletop exercise covering this threat type with IR team and CISO.</p></div>"
        "<div class='step'><p>Update CMDB, vulnerability management, and risk register with exposure artefacts.</p></div>"
        "</div></div>"
    ))

    # ── S11: Threat Actor Profile — APEX Adversary Intelligence v148.1 ─────
    if _APEX_UPGRADE_AVAILABLE:
        _s11_body = _apex_actor_intel(actor, item)
    else:
        _s11_body = (
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
        )
    sections.append(_section(11, "Threat Actor Profile", _s11_body))

    # ── S12: Campaign Intelligence — APEX Campaign Correlation v148.1 ───────
    ai_conf = item.get("ai_confidence") or item.get("confidence") or "–"
    if _APEX_UPGRADE_AVAILABLE:
        _s12_body = _apex_campaign_intel(item)
    else:
        _s12_body = (
            "<div class='kv'>"
            f"<div class='kv-key'>Campaign ID</div><div class='kv-val'><code>{_h(campaign)}</code></div>"
            f"<div class='kv-key'>AI Confidence</div><div class='kv-val'>{_h(ai_conf)}</div>"
            f"<div class='kv-key'>Actor Cluster</div><div class='kv-val'>{_h(actor)}</div>"
            f"<div class='kv-key'>TTP Count</div><div class='kv-val'>{len(ttps)}</div>"
            f"<div class='kv-key'>IOC Count</div><div class='kv-val'>{ioc_count}</div>"
            "</div>"
            "<p style='margin-top:16px'>APEX's campaign correlation engine has associated this advisory "
            "with prior activity attributed to the same actor cluster. Historical campaign "
            "data, infrastructure overlap analysis, and behavioural similarity scoring are "
            "available in the enterprise delivery pack.</p>"
        )
    sections.append(_section(12, "Campaign Intelligence", _s12_body))

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

    # ── S15: APEX AI Analyst Insight — APEX AI Brain v148.1 ─────────────────
    if _APEX_UPGRADE_AVAILABLE:
        _s15_body = _apex_ai_insight(item)
        # Append enterprise upsell after real AI content
        _s15_body += (
            "<div class=’premium-lock-v2’ style=’margin-top:20px’>"
            "<div class=’plv2-header’>"
            "<div class=’plv2-icon’>&#x1F916;</div>"
            "<div><div class=’plv2-title’>APEX ENTERPRISE — ADVANCED AI INTELLIGENCE</div>"
            "<div class=’plv2-sub’>Unlock full 30-day predictive modelling, SOAR playbook export &amp; dedicated SOC uplift</div></div>"
            "</div>"
            "<div class=’plv2-actions’>"
            f"<a class=’cta cta-enterprise’ href=’https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise&utm_source=report-ai&utm_medium=unlock-btn’ target=’_blank’ rel=’noopener’>&#9733; Unlock Enterprise &rarr;</a>"
            "<a class=’cta cta-secondary’ href=’https://intel.cyberdudebivash.com/upgrade.html?plan=pro&utm_source=report-ai&utm_medium=unlock-btn’ target=’_blank’ rel=’noopener’>Try Pro &rarr;</a>"
            "</div>"
            "</div>"
        )
    else:
        _s15_body = (
            "<p>APEX’s autonomous AI analyst layer has correlated this advisory against "
            "12 months of threat intelligence, actor infrastructure history, and global telemetry. "
            "Key AI-derived findings:</p>"
            "<div class=’kv’>"
            f"<div class=’kv-key’>Predictive Risk</div><div class=’kv-val’><strong>{risk}/10</strong></div>"
            f"<div class=’kv-key’>Actor Fingerprint</div><div class=’kv-val’>{_h(actor)}</div>"
            f"<div class=’kv-key’>AI Confidence</div><div class=’kv-val’>{_h(ai_conf)}</div>"
            f"<div class=’kv-key’>TTP Density</div><div class=’kv-val’>{len(ttps)} techniques mapped</div>"
            "</div>"
            "<div class=’premium-lock-v2’ style=’margin-top:16px’>"
            "<div class=’plv2-header’>"
            "<div class=’plv2-icon’>&#x1F916;</div>"
            "<div><div class=’plv2-title’>APEX AI ANALYST NARRATIVE &mdash; ENTERPRISE</div>"
            "<div class=’plv2-sub’>Full narrative unlocked for Enterprise &amp; MSSP subscribers</div></div>"
            "</div>"
            "<div class=’plv2-actions’>"
            f"<a class=’cta cta-enterprise’ href=’https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise&utm_source=report-ai-lock&utm_medium=unlock-btn’ target=’_blank’ rel=’noopener’>&#9733; Unlock Enterprise &rarr;</a>"
            "<a class=’cta cta-secondary’ href=’https://intel.cyberdudebivash.com/upgrade.html?plan=pro&utm_source=report-ai-lock&utm_medium=unlock-btn’ target=’_blank’ rel=’noopener’>Try Pro &rarr;</a>"
            "</div>"
            "</div>"
        )
    sections.append(_section(15, "APEX AI Analyst Insight", _s15_body))

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
        "<a class='cta cta-primary' href='https://intel.cyberdudebivash.com'>â† Back to Platform</a>"
        "<a class='cta cta-secondary' href='https://intel.cyberdudebivash.com/upgrade.html?plan=pro&utm_source=report-s16&utm_medium=cta'>&#9650; Upgrade to Pro</a>"
        "<a class='cta cta-enterprise' href='https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise&utm_source=report-s16&utm_medium=cta'>&#9733; Enterprise Access</a>"
        "</div>"
        "<div class='callout' style='margin-top:20px'>"
        "<strong>Enterprise Delivery Pack</strong> includes: full IOC/TTP/STIX 2.1 bundles, "
        "Sigma &amp; YARA rule packs, MITRE Navigator layer, hunt queries (KQL/SPL/EQL), "
        "AI analyst narrative, actor tracker continuation, SOAR playbook export, and "
        "dedicated SOC uplift SLA. <a href='https://intel.cyberdudebivash.com/get-api-key.html?plan=enterprise' "
        "style='color:var(--accent)'>Contact enterprise sales →</a>"
        "</div>"
    ))

    # ── S17: Financial Impact Quantification ──────────────────────────────
    sectors_tagged = [t for t in tags if any(
        k in str(t).lower() for k in ["health","finance","energy","tech","gov","retail","edu","ics"]
    )]
    sections.append(_section(17, "Financial Impact Quantification",
        _render_financial_impact(sev, risk, sectors_tagged)
    ))

    # ── S18: Detection Engineering Pack — APEX Enhanced Detection v148.1 ───
    # Use _operational_iocs (already filtered) for all detection artefacts
    _det_iocs = _operational_iocs if "_operational_iocs" in dir() else iocs
    if _APEX_UPGRADE_AVAILABLE:
        sigma_rule = _apex_sigma(title, ttps, _det_iocs, item)
    else:
        sigma_rule = _render_sigma_rule(title, ttps, _det_iocs)
    yara_rule  = _render_yara_rule(title, _det_iocs, actor)
    kql_q, spl_q = _render_hunt_queries(title, ttps, _det_iocs)

    sections.append(_section(18, "Detection Engineering Pack",
        "<p>Production-grade detection artefacts generated by SENTINEL APEX's rule synthesis engine. "
        "Rules are pre-mapped to this advisory's IOCs and ATT&amp;CK techniques. "
        "<strong>Enterprise subscribers</strong> receive validated, tuned rule packs with "
        "false-positive rates below 0.1% against the APEX telemetry corpus.</p>"

        # Sigma
        "<div class='rule-block'>"
        "<div class='rule-header'>"
        "<span class='rule-badge rule-sigma'>SIGMA – SIEM/EDR Universal</span>"
        "<span class='copy-hint'>Compatible: Splunk · Elastic · QRadar · Sentinel · Chronicle</span>"
        "</div>"
        f"<pre>{_h(sigma_rule)}</pre>"
        "</div>"

        # YARA
        "<div class='rule-block'>"
        "<div class='rule-header'>"
        "<span class='rule-badge rule-yara'>YARA – Memory &amp; File Scanning</span>"
        "<span class='copy-hint'>Deploy via: CrowdStrike · Carbon Black · Velociraptor · CAPE</span>"
        "</div>"
        f"<pre>{_h(yara_rule)}</pre>"
        "</div>"

        # KQL
        "<div class='rule-block'>"
        "<div class='rule-header'>"
        "<span class='rule-badge rule-kql'>KQL – Microsoft Sentinel / Defender XDR</span>"
        "<span class='copy-hint'>Retro-hunt: last 30 days</span>"
        "</div>"
        f"<pre>{_h(kql_q)}</pre>"
        "</div>"

        # SPL
        "<div class='rule-block'>"
        "<div class='rule-header'>"
        "<span class='rule-badge rule-spl'>SPL – Splunk Enterprise Security</span>"
        "<span class='copy-hint'>ES correlation search ready</span>"
        "</div>"
        f"<pre>{_h(spl_q)}</pre>"
        "</div>"

        "<div class='callout'><strong>Enterprise Delivery:</strong> Full validated rule packs (Sigma, YARA, KQL, SPL, EQL, LEEF) "
        "with ATT&amp;CK Navigator overlay and SOC deployment guide available via "
        "<a href='https://intel.cyberdudebivash.com/api/stix/" + _h(stix_id) + "' style='color:var(--accent)'>APEX Enterprise API</a>.</div>"
    ))

    # ── S19: Regulatory Compliance Impact ─────────────────────────────────
    sections.append(_section(19, "Regulatory Compliance Impact",
        _render_regulatory_matrix(sev, kev, sectors_tagged)
    ))

    # ── S20: Business Impact Score & MITRE Navigator Layer ─────────────
    bis = _compute_bis(risk, cvss, epss, kev, ioc_count, len(ttps))
    bis_score  = bis["score"]
    bis_label  = bis["label"]
    bis_color  = bis["color"]

    # Build MITRE Navigator layer JSON (inline data URI download)
    nav_techniques = []
    for t in ttps[:20]:
        if isinstance(t, str):
            nav_techniques.append({"techniqueID": t, "color": "#ff3b3b", "comment": f"Mapped by APEX: {title[:60]}", "enabled": True})
        elif isinstance(t, dict):
            tid = t.get("technique_id") or t.get("id") or ""
            if tid:
                nav_techniques.append({"techniqueID": tid, "color": "#ff3b3b", "comment": f"Mapped by APEX: {title[:60]}", "enabled": True})

    nav_layer = json.dumps({
        "name": f"APEX – {title[:60]}",
        "versions": {"attack": "15", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"CYBERDUDEBIVASH SENTINEL APEX {PLATFORM_VERSION} – {title[:80]}",
        "techniques": nav_techniques,
        "gradient": {"colors": ["#ffffff","#ff3b3b"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "APEX Mapped Technique", "color": "#ff3b3b"}],
        "metadata": [{"name": "apex_id", "value": stix_id}, {"name": "risk", "value": str(risk)}],
    }, separators=(",", ":"))
    import urllib.parse as _ul
    nav_href = "data:application/json;charset=utf-8," + _ul.quote(nav_layer)

    sections.append(_section(20, "Business Impact Score &amp; MITRE Navigator Layer",
        "<h3>Business Impact Score (BIS)</h3>"
        "<p>BIS is a FAIR-aligned composite metric combining CVSS severity, EPSS exploitation probability, "
        "CISA KEV status, IOC density, and TTP coverage into a single board-reportable risk number.</p>"
        "<div class='bis-ring'>"
        f"<div class='bis-circle' style='border-color:{_h(bis_color)};background:rgba(0,0,0,.3)'>"
        f"<span class='bis-num' style='color:{_h(bis_color)}'>{bis_score}</span>"
        f"<span class='bis-label'>/10 BIS</span>"
        f"</div>"
        "<div>"
        f"<div style='font-family:var(--mono);font-size:14px;font-weight:700;color:{_h(bis_color)};margin-bottom:6px'>{_h(bis_label)}</div>"
        f"<div class='kv' style='grid-template-columns:160px 1fr;font-size:12px'>"
        f"<div class='kv-key'>APEX Risk Input</div><div class='kv-val'>{risk}/10</div>"
        f"<div class='kv-key'>CVSS 3.1</div><div class='kv-val'>{cvss if cvss is not None else 'Pending'}</div>"
        f"<div class='kv-key'>EPSS (30d %)</div><div class='kv-val'>{epss if epss is not None else 'Pending'}</div>"
        f"<div class='kv-key'>KEV Status</div><div class='kv-val'>{'CONFIRMED' if kev else 'Not listed'}</div>"
        f"<div class='kv-key'>IOC Density</div><div class='kv-val'>{ioc_count} indicators</div>"
        f"<div class='kv-key'>TTP Coverage</div><div class='kv-val'>{len(ttps)} techniques</div>"
        f"</div>"
        "</div>"
        "</div>"

        "<h3 style='margin-top:24px'>MITRE ATT&amp;CK Navigator Layer</h3>"
        "<p>Download the pre-built Navigator layer to overlay this advisory's techniques onto your "
        "existing detection coverage matrix. Identifies gaps and maps directly into ATT&amp;CK Workbench.</p>"
        + (
            f"<a class='nav-download' href='{_h(nav_href)}' download='APEX_{_h(stix_id[:16])}_navigator.json'>"
            "⬇ Download Navigator Layer (.json)"
            "</a>"
            if nav_techniques else
            "<div class='callout'>No TTPs mapped – Navigator layer requires confirmed technique IDs. "
            "Enterprise tier auto-maps via APEX AI inference engine.</div>"
        )
        + "<div class='callout' style='margin-top:16px'>"
        "<strong>Board Reporting:</strong> BIS score is designed for executive dashboards and cyber-insurance "
        "disclosure. Include BIS alongside CVSS in your risk register and monthly CISO report. "
        "APEX Enterprise provides automated board-level PDF briefing generation on every advisory.</div>"
    ))

    return "\n".join(sections)


# ─────────────────────────────────────────────────────────────────────────────
# Full HTML document
# ─────────────────────────────────────────────────────────────────────────────
def render_report(item: dict, public_prefix: str) -> str:
    # RENDER LAYER SAFETY: all field access uses str() — never assume data types
    title    = str(item.get("title") or "Untitled Advisory")
    sev      = str(item.get("severity") or "UNKNOWN").upper()
    # published: explicitly cast to str — P0 regression guard (run #805: published=True bool)
    published = str(item.get("published") or "")
    ts       = _fmt_ts(str(item.get("processed_at") or item.get("timestamp") or ""))
    intel_id = str(item.get("id") or "intel--unknown")
    tlp      = str(item.get("tlp") or "TLP:CLEAR").replace(":", "-")
    risk     = item.get("risk_score") or 0
    tags     = item.get("tags") or []
    report_url = f"{public_prefix.rstrip('/')}/reports/{intel_id}.html"

    sections_html = build_report_sections(item)

    # ── Pre-computed display variables for god-mode template (no backslash in f-string) ──
    _ioc_conf    = min(int(item.get("ioc_confidence") or 75), 100)
    _ioc_list    = item.get("iocs") or []
    _ttp_list    = (item.get("apex_ai") or {}).get("ttps") or item.get("ttps") or []
    _cvss_disp   = str(item["cvss_score"]) if item.get("cvss_score") is not None else "Pending"
    _epss_disp   = str(item["epss_score"]) if item.get("epss_score") is not None else "Pending"
    _epss_pct    = "%" if item.get("epss_score") is not None else ""
    _kev         = bool(item.get("kev_present"))
    _kev_disp    = "YES &#x26A0;" if _kev else "No"
    _feed_src    = str(item.get("feed_source") or item.get("source") or "SENTINEL APEX")[:40]
    _urgency_cls = ("IMMEDIATE" if sev in ("CRITICAL", "HIGH") else
                    "HIGH" if sev == "MEDIUM" else "MONITOR")
    _urgency_txt = ("PATCH IMMEDIATELY" if sev == "CRITICAL" else
                    "HIGH PRIORITY"    if sev == "HIGH"     else
                    "PATCH STANDARD"   if sev == "MEDIUM"   else "MONITOR")
    _sev_tile    = ("crit" if sev == "CRITICAL" else "high" if sev == "HIGH" else
                    "med"  if sev == "MEDIUM"   else "low"  if sev == "LOW"  else "neutral")
    _risk_tile   = ("crit" if risk >= 9 else "high" if risk >= 7 else
                    "med"  if risk >= 5 else "low")
    _cvss_f      = float(item.get("cvss_score") or 0)
    _cvss_tile   = ("crit" if _cvss_f >= 9 else "high" if _cvss_f >= 7 else
                    "med"  if _cvss_f >= 4 else "neutral")
    _epss_f      = float(item.get("epss_score") or 0)
    _epss_tile   = ("crit" if _epss_f >= 50 else "high" if _epss_f >= 20 else "neutral")
    _conf_strip  = (
        "<div class='confidence-strip'>"
        "<span class='conf-label'>Intel Confidence</span>"
        "<div class='conf-bar'>"
        f"<div class='conf-fill' style='width:{_ioc_conf}%'></div>"
        "</div>"
        f"<span class='conf-val'>{_ioc_conf}%</span>"
        "<span style='font-family:var(--mono);font-size:9px;color:var(--muted);"
        "margin-left:8px'>APEX ML ENRICHED</span>"
        "</div>"
    )

    toc = "".join(
        f"<a href='#s{i}' style='display:block;padding:4px 0;font-family:var(--mono);"
        f"font-size:11px;color:var(--muted);text-decoration:none;"
        f"border-bottom:1px solid var(--border);'>"
        f"<span style='color:var(--accent);margin-right:8px'>{i:02d}</span>{t}</a>"
        for i, t in enumerate([
            "Classification","Executive Summary","Threat Profile","Risk Score",
            "Technical Analysis","ATT&CK Mapping","IOC Table","CVSS/EPSS",
            "Kill Chain","Response Playbook","Actor Profile","Campaign Intel",
            "Affected Systems","Strategic Risk","AI Insight","References & CTA",
            "Financial Impact","Detection Eng. Pack","Regulatory Compliance","BIS & Navigator",
        ], 1)
    )

    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta http-equiv='Content-Type' content='text/html; charset=utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<meta name='robots' content='index,follow'>
<meta name='description' content='{_h(title)} – Severity {_h(sev)} – CYBERDUDEBIVASH SENTINEL APEX Tactical Dossier. Risk {risk}/10. Generated {_h(ts)}.'>
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
  <div>
    <div class='nav-brand'>CYBERDUDEBIVASH &middot; SENTINEL APEX</div>
    <div style='font-family:var(--mono);font-size:9px;color:var(--muted);margin-top:3px;letter-spacing:1px'>TACTICAL INTELLIGENCE DOSSIER &middot; {PLATFORM_VERSION}</div>
  </div>
  <div class='nav-actions'>
    <button class='nav-btn nav-btn-print' onclick='window.print()' title='Print report'>&#128438; Print</button>
    <a class='nav-btn nav-btn-stix' href='https://intel.cyberdudebivash.com/api/stix?id={_h(intel_id)}' target='_blank' rel='noopener' title='Download STIX 2.1 bundle'>&#8659; STIX 2.1</a>
    <a class='nav-btn nav-btn-upgrade' href='https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise&utm_source=report-nav&utm_medium=report&utm_content={_h(intel_id)}' target='_blank' rel='noopener'>&#9733; Enterprise</a>
    <div class='nav-links' style='margin-left:8px;border-left:1px solid var(--border);padding-left:16px'>
      <a href='https://intel.cyberdudebivash.com'>Platform</a>
      <a href='https://intel.cyberdudebivash.com/api/feed'>Live Feed</a>
    </div>
  </div>
</nav>
<div class='report-watermark'>CYBERDUDEBIVASH · SENTINEL APEX · {PLATFORM_VERSION}</div>
<div class='wrap'>
<header class='dossier-hdr'>
  <div class='classification'>
    <span class='cls-chip cls-PUBLIC'>PUBLIC TIER</span>
    <span class='cls-chip cls-TLP'>{_h(item.get('tlp','TLP:CLEAR'))}</span>
    <span>TACTICAL DOSSIER</span>
    &nbsp;&middot;&nbsp;
    <span class='urgency-badge urgency-{_urgency_cls}'><span class='sev-pulse'></span>{_urgency_txt}</span>
  </div>
  <div class='dossier-id'>INTEL ID: {_h(intel_id)} &nbsp;·&nbsp; PROCESSED: {_h(ts)} &nbsp;·&nbsp; SOURCE: {_h(_feed_src)}</div>
  <h1 class='dossier-title'>{_h(title)}</h1>
  <div class='meta-strip'>
    <span>Severity: <strong><span class='sev-chip {_sev_class(sev)}'>{_h(sev)}</span></strong></span>
    <span>Risk: <strong>{risk}/10</strong></span>
    <span>CVSS: <strong>{_cvss_disp}</strong></span>
    <span>EPSS: <strong>{_epss_disp}{_epss_pct}</strong></span>
    <span>IOCs: <strong>{len(_ioc_list)}</strong></span>
    <span>TTPs: <strong>{len(_ttp_list)}</strong></span>
    <span>KEV: <strong>{_kev_disp}</strong></span>
  </div>
  {_conf_strip}
  <div class='tag-strip'>{_render_tags(tags)}</div>
</header>

<!-- Executive Intelligence Card -->
<div class='exec-card'>
  <div class='exec-tile {_sev_tile}'>
    <div class='exec-tile-label'>Severity</div>
    <div class='exec-tile-val'>{_h(sev[:4])}</div>
    <div class='exec-tile-sub'>Classification</div>
  </div>
  <div class='exec-tile {_risk_tile}'>
    <div class='exec-tile-label'>Risk Score</div>
    <div class='exec-tile-val'>{risk}<span style='font-size:13px;font-weight:400'>/10</span></div>
    <div class='exec-tile-sub'>Composite APEX</div>
  </div>
  <div class='exec-tile {_cvss_tile}'>
    <div class='exec-tile-label'>CVSS 3.1</div>
    <div class='exec-tile-val'>{_cvss_disp}</div>
    <div class='exec-tile-sub'>Base Score</div>
  </div>
  <div class='exec-tile {_epss_tile}'>
    <div class='exec-tile-label'>EPSS 30d</div>
    <div class='exec-tile-val'>{_epss_disp}<span style='font-size:12px;font-weight:400'>{_epss_pct}</span></div>
    <div class='exec-tile-sub'>Exploit Probability</div>
  </div>
  <div class='exec-tile {"crit" if _kev else "neutral"}'>
    <div class='exec-tile-label'>IOCs / KEV</div>
    <div class='exec-tile-val'>{len(_ioc_list)}</div>
    <div class='exec-tile-sub'>{"KEV CONFIRMED" if _kev else "No KEV entry"}</div>
  </div>
</div>

<div style='display:grid;grid-template-columns:220px 1fr;gap:24px;align-items:start'>
<aside class='toc-aside' style='position:sticky;top:20px'>
  <div style='background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:16px'>
    <div style='font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--accent);margin-bottom:12px;text-transform:uppercase'>Contents</div>
    {toc}
  </div>
  <!-- Sidebar CTA -->
  <div style='margin-top:14px;background:linear-gradient(135deg,rgba(15,26,46,.9),rgba(15,26,46,.7));border:1px solid rgba(255,215,0,.2);border-radius:var(--radius);padding:16px;text-align:center'>
    <div style='font-family:var(--mono);font-size:9px;letter-spacing:2px;color:#ffd700;text-transform:uppercase;margin-bottom:8px'>Enterprise Intel</div>
    <div style='font-size:12px;color:var(--muted);margin-bottom:12px;line-height:1.5'>Full STIX export, API access &amp; automated briefings</div>
    <a href='https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise&utm_source=report-sidebar' target='_blank' rel='noopener' style='display:block;padding:8px;background:linear-gradient(135deg,#ffd700,#ff8c00);color:#060d19;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:1px;border-radius:3px;text-decoration:none'>UPGRADE &#8594;</a>
  </div>
  <!-- Share -->
  <div style='margin-top:10px;padding:12px;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius)'>
    <div style='font-family:var(--mono);font-size:9px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:8px'>Share Report</div>
    <div style='font-family:var(--mono);font-size:10px;color:var(--accent2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:8px'>{_h(report_url[:50])}...</div>
    <button class='nav-btn nav-btn-print' onclick='navigator.clipboard&&navigator.clipboard.writeText("{_h(report_url)}").then(()=>this.textContent="Copied!")' style='width:100%;justify-content:center;font-size:10px'>&#128203; Copy Link</button>
  </div>
</aside>
<main>
{sections_html}
</main>
</div>

<footer class='dossier-ftr' style='margin-top:48px;padding-top:24px'>
  <div style='width:100%;border-top:1px solid var(--border);padding-top:16px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px'>
    <div>
      <div style='font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:700;letter-spacing:2px'>CYBERDUDEBIVASH SENTINEL APEX</div>
      <div style='font-family:var(--mono);font-size:9px;color:var(--muted);margin-top:3px;letter-spacing:1px'>PROFESSIONAL THREAT INTELLIGENCE PLATFORM &middot; {PLATFORM_VERSION}</div>
    </div>
    <div style='display:flex;gap:12px;align-items:center'>
      <a href='https://intel.cyberdudebivash.com/upgrade.html?plan=pro&utm_source=report-footer' target='_blank' rel='noopener' style='font-family:var(--mono);font-size:10px;color:#ffd700;text-decoration:none;border:1px solid rgba(255,215,0,.3);padding:5px 12px;border-radius:3px'>&#9733; Get Pro Access</a>
      <a href='https://intel.cyberdudebivash.com/api/stix?id={_h(intel_id)}' target='_blank' rel='noopener' style='font-family:var(--mono);font-size:10px;color:var(--accent);text-decoration:none'>&#8659; STIX Export</a>
    </div>
  </div>
  <div style='display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-family:var(--mono);font-size:10px;color:var(--muted)'>
    <span>&copy; {datetime.now(timezone.utc).year} CyberDudeBivash Pvt. Ltd. GSTIN: 21ARKPN8270G1ZP &middot; Odisha, India</span>
    <span>
      <a href='https://intel.cyberdudebivash.com' style='color:var(--accent);text-decoration:none'>intel.cyberdudebivash.com</a>
      &nbsp;&middot;&nbsp;
      <a href='https://cyberdudebivash.in' style='color:var(--accent);text-decoration:none'>cyberdudebivash.in</a>
      &nbsp;&middot;&nbsp;
      <a href='mailto:bivashnayak.ai007@gmail.com' style='color:var(--muted);text-decoration:none'>Contact</a>
    </span>
  </div>
  <div style='width:100%;margin-top:10px;padding:8px 12px;background:rgba(0,212,170,.03);border:1px solid var(--border);border-radius:3px;font-family:var(--mono);font-size:9px;color:var(--muted);line-height:1.5'>
    <strong style='color:var(--muted)'>CLASSIFICATION NOTICE:</strong> This tactical dossier is generated by CYBERDUDEBIVASH SENTINEL APEX automated intelligence pipeline. Intelligence is sourced from public threat feeds, CVE databases, and APEX enrichment engines. This document is provided for informational and defensive security purposes only. Report ID: {_h(intel_id)}
  </div>
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
        log("aws CLI not available – skipping R2 upload", "warning")
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
    """
    v134: Hardened manifest save — FileLock (120s) + 5-attempt retry + JSON verify.
    Falls back to direct write if atomic replace fails.
    """
    try:
        from scripts.safe_io import atomic_json_write, acquire_lock, retry_write, _store_write_failure
        def _do_save() -> None:
            atomic_json_write(MANIFEST_PATH, data, indent=2, ensure_ascii=False, verify=True, locked=True)
        retry_write(
            _do_save,
            attempts=5,
            base_delay=0.5,
            path=MANIFEST_PATH,
            payload=data,
        )
        return
    except ImportError:
        pass  # safe_io not available, fall through to legacy path
    except Exception as e:
        log(f"save_manifest: retry_write failed ({e}) — attempting legacy save", "warning")
    # Legacy fallback (no lock, no retry — last resort)
    tmp = MANIFEST_PATH.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        if not tmp.exists():
            raise OSError(f"tmp vanished before replace: {tmp}")
        os.replace(tmp, MANIFEST_PATH)
    except Exception as fallback_err:
        log(f"save_manifest: LEGACY FALLBACK FAILED: {fallback_err}", "error")
        # Last resort: direct write to avoid total data loss
        try:
            MANIFEST_PATH.write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as direct_err:
            log(f"save_manifest: DIRECT WRITE FAILED: {direct_err}", "error")
            raise


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
    log(f"Starting {PLATFORM_VERSION} – manifest: {MANIFEST_PATH}")

    endpoint = None
    if args.upload_r2:
        acct = os.environ.get("CF_ACCOUNT_ID", "")
        if not acct:
            log("CF_ACCOUNT_ID not set – R2 upload disabled", "warning")
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

    log(f"Processing {len(items)} entries – upload_r2={args.upload_r2} prefix={args.public_prefix}")

    written = 0
    uploaded = 0
    skipped_brand = 0
    errors = 0
    t_start = time.monotonic()

    for item in items:
        intel_id = item.get("id")
        if not intel_id:
            log(f"SKIP: entry missing id field – {item.get('title','?')[:60]}", "warning")
            continue

        _title = item.get("title") or ""

        # Hard-skip brand/placeholder entries only
        if any(kw in _title for kw in BRAND_KEYWORDS):
            skipped_brand += 1
            item["validation_status"] = "brand_skip"
            continue

        # ── Zero-skip policy: generate report for EVERY real entry ──
        # Short entries get an enriched template – no blanket skip
        _desc  = item.get("description") or ""
        _words = len((_title + " " + _desc).split())
        is_enriched = _words < 50  # flag thin content but still generate

        # ── SCHEMA ENFORCEMENT (MANDATORY — at write boundary, before render) ──
        item = _safe_enforce_schema(item)

        path = rel_report_path(item)
        path.parent.mkdir(parents=True, exist_ok=True)

        # ── RENDER PHASE (separate from write — never tag render failures as write_error) ──
        html_text: Optional[str] = None
        try:
            html_text = render_report(item, args.public_prefix)
        except Exception as render_exc:
            log(f"RENDER ERROR [{intel_id}]: {type(render_exc).__name__}: {render_exc}", "error")
            item["validation_status"] = "render_error"
            item["report_url"] = item.get("source_url") or ""
            errors += 1
            # Store in fail-safe buffer for post-mortem analysis
            try:
                from scripts.safe_io import _store_write_failure
                _store_write_failure(path, render_exc, payload=item)
            except Exception as _rbuf_exc:
                # v134.1: log — diagnostics path must not silently swallow errors
                _log.debug("RENDER FAIL BUFFER [%s]: could not store render failure: %s", intel_id, _rbuf_exc)
            continue

        # ── WRITE PHASE (retry with backoff — genuine I/O failures) ──
        def _write_report_atomic(html: str, dest: Path) -> None:
            tmp = dest.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(html)
            # Safety: verify tmp exists before replace
            if not tmp.exists():
                raise OSError(f"tmp vanished before replace: {tmp}")
            try:
                os.replace(tmp, dest)
            except OSError as replace_err:
                log(f"os.replace failed for {dest.name}: {replace_err} — falling back to direct write", "warning")
                dest.write_text(html, encoding="utf-8")
                try:
                    tmp.unlink(missing_ok=True)
                except Exception:
                    pass

        write_succeeded = False
        write_exc_final: Optional[Exception] = None
        _attempts = 5
        _base_delay = 0.5
        for _attempt in range(_attempts):
            try:
                _write_report_atomic(html_text, path)
                write_succeeded = True
                break
            except Exception as write_exc:
                write_exc_final = write_exc
                _delay = _base_delay * (_attempt + 1)
                log(
                    f"WRITE RETRY [{intel_id}] attempt {_attempt + 1}/{_attempts}: "
                    f"{type(write_exc).__name__}: {write_exc} (retry in {_delay:.1f}s)",
                    "warning",
                )
                import time as _time
                _time.sleep(_delay)

        if not write_succeeded:
            log(f"WRITE HARD FAIL [{intel_id}]: all {_attempts} attempts failed: {write_exc_final}", "error")
            item["validation_status"] = "write_error"
            item["report_url"] = item.get("source_url") or ""
            errors += 1
            # Fail-safe buffer — preserve HTML payload
            try:
                from scripts.safe_io import _store_write_failure
                _store_write_failure(path, write_exc_final, payload={"html_len": len(html_text), "id": intel_id})
            except Exception as _buf_exc:
                # v134.1: log secondary failure — diagnostics path must not silently swallow errors
                _log.debug("WRITE FAIL BUFFER [%s]: could not store write failure: %s", intel_id, _buf_exc)
            continue

        # ── FAIL-FAST VALIDATION (v134.1 HARDENING) ──────────────────────────
        # RULE: Report MUST exist on disk with valid size and valid HTML header.
        # Any failure here is a HARD STOP for this entry — logged + errors counted.
        _MIN_REPORT_BYTES = 1024  # 1 KB minimum (raised from 512 per v134.1)
        _HTML_SIGS = (b"<!doctype html", b"<!DOCTYPE html", b"<html")
        _file_valid = False
        if not path.exists():
            log(f"VALIDATE FAIL [{intel_id}]: report file does not exist on disk: {path}", "error")
        elif path.stat().st_size < _MIN_REPORT_BYTES:
            log(
                f"VALIDATE FAIL [{intel_id}]: report too small "
                f"({path.stat().st_size} bytes < {_MIN_REPORT_BYTES} minimum): {path}",
                "error",
            )
        else:
            # Check first 64 bytes for valid HTML signature
            try:
                with open(path, "rb") as _fh:
                    _head = _fh.read(64).lower()
                if not any(_head.startswith(sig.lower()) for sig in _HTML_SIGS):
                    log(
                        f"VALIDATE FAIL [{intel_id}]: report does not begin with valid HTML "
                        f"(got: {_head[:32]!r}): {path}",
                        "error",
                    )
                else:
                    _file_valid = True
            except Exception as _val_exc:
                log(f"VALIDATE WARN [{intel_id}]: HTML check failed (non-fatal): {_val_exc}", "warning")
                _file_valid = True