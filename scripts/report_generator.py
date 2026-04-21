#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Internal Report Generator
===========================================================
Version : v134.0
Purpose : Generate a self-contained HTML Tactical Dossier for every intel entry
          BEFORE the manifest entry is written. This ensures report_url always
          points to a physical file that exists on disk.

Contract:
  - generate_report(entry, stix_bundle_path) -> (success: bool, path_or_error: str)
  - Output: reports/{YYYY}/{MM}/{intel_id}.html
  - Never raises — all exceptions are caught, logged, and returned as (False, msg)
  - Called from export_stix._update_manifest pipeline and from standalone CLI

Zero-skip policy: every entry must attempt report generation. If it fails, the
pipeline logs the error and CONTINUES (does NOT abort). The entry is still
written to the manifest with the internal report_url so the URL is consistent.

Standalone usage:
  python3 scripts/report_generator.py --manifest data/stix/feed_manifest.json
  python3 scripts/report_generator.py --entry '{"id":"intel--abc","title":"Test"}'
"""
from __future__ import annotations

import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import html as _html
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("CDB-REPORT-GEN")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)

# ── Constants ──────────────────────────────────────────────────────────────────

REPORTS_BASE = Path("reports")
PLATFORM_NAME = "CyberDudeBivash SENTINEL APEX"
PLATFORM_URL  = "https://intel.cyberdudebivash.com"
GUMROAD_URL   = "https://cyberdudebivash.gumroad.com/?utm_source=report&utm_medium=cta"

_SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#22c55e",
    "INFO":     "#3b82f6",
    "UNKNOWN":  "#6b7280",
}


# ── Core Generator ────────────────────────────────────────────────────────────

def generate_report(
    entry: Dict[str, Any],
    stix_bundle_path: Optional[str] = None,
    reports_base: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Generate an HTML Tactical Dossier for the given intel entry.

    Args:
        entry: Advisory dict (must have at minimum 'id' and 'title').
        stix_bundle_path: Optional path to the STIX bundle JSON file.
        reports_base: Override the base reports directory (default: 'reports').

    Returns:
        (True, output_path) on success.
        (False, error_message) on failure — never raises.
    """
    try:
        return _generate_internal(entry, stix_bundle_path, reports_base)
    except Exception as exc:
        msg = f"report_generator: unhandled exception for '{entry.get('id','?')}': {exc}"
        logger.error(msg)
        return False, msg


def _generate_internal(
    entry: Dict[str, Any],
    stix_bundle_path: Optional[str],
    reports_base: Optional[str],
) -> Tuple[bool, str]:
    """Internal — may raise; wrapped by generate_report()."""

    intel_id = (entry.get("id") or entry.get("stix_id") or "").strip()
    if not intel_id:
        return False, "entry has no 'id' or 'stix_id' field"

    title = (entry.get("title") or "Intel Advisory").strip()

    # Determine output path from report_url or construct it
    report_url = (entry.get("internal_report_url") or entry.get("report_url") or "").strip()
    if report_url.startswith("/"):
        # Strip leading slash → relative path under cwd
        rel_path = report_url.lstrip("/")
        out_path = Path(rel_path)
    else:
        # Construct canonical path: reports/YYYY/MM/{intel_id}.html
        now = datetime.now(timezone.utc)
        base = Path(reports_base) if reports_base else REPORTS_BASE
        out_path = base / str(now.year) / f"{now.month:02d}" / f"{intel_id}.html"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Build HTML
    html_content = _build_html(entry, stix_bundle_path, out_path)

    # Atomic write
    tmp_path = out_path.with_suffix(".tmp")
    try:
        tmp_path.write_text(html_content, encoding="utf-8")
        tmp_path.replace(out_path)
    except Exception as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return False, f"write error for {out_path}: {exc}"

    logger.info("Report written: %s (%d bytes)", out_path, out_path.stat().st_size)
    return True, str(out_path)


def _esc(s: Any) -> str:
    """HTML-escape a value safely."""
    return _html.escape(str(s or ""), quote=True)


def _build_html(
    entry: Dict[str, Any],
    stix_bundle_path: Optional[str],
    out_path: Path,
) -> str:
    """Build the full HTML dossier string."""

    intel_id    = _esc(entry.get("id") or entry.get("stix_id") or "")
    title       = _esc(entry.get("title") or "Intel Advisory")
    severity    = str(entry.get("severity") or "UNKNOWN").upper()
    risk_score  = entry.get("risk_score") or 0.0
    sev_color   = _SEV_COLOR.get(severity, "#6b7280")
    tlp         = _esc(entry.get("tlp") or entry.get("tlp_label") or "TLP:CLEAR")
    description = _esc(entry.get("description") or entry.get("summary") or
                       "Threat intelligence advisory generated by SENTINEL APEX.")
    actor_tag   = _esc(entry.get("actor_tag") or "UNC")
    feed_source = _esc(entry.get("feed_source") or PLATFORM_NAME)
    source_url  = entry.get("source_url") or ""
    processed   = _esc(entry.get("processed_at") or entry.get("timestamp") or
                       datetime.now(timezone.utc).isoformat())
    confidence  = float(entry.get("confidence") or entry.get("confidence_score") or 0.0)
    cvss        = entry.get("cvss_score")
    epss        = entry.get("epss_score")
    kev         = bool(entry.get("kev_present"))

    # MITRE tactics
    mitre = entry.get("mitre_tactics") or entry.get("ttps") or []
    mitre_html = "".join(
        f'<span class="badge">{_esc(t)}</span>' for t in mitre[:10]
    ) or "<span style='color:#5a6578;font-size:11px;'>No MITRE tactics mapped</span>"

    # IOCs
    iocs_raw = entry.get("iocs") or []
    # Support both flat list of strings and list of dicts
    ioc_rows = ""
    for ioc in iocs_raw[:50]:
        if isinstance(ioc, dict):
            ioc_type  = _esc(ioc.get("type", "unknown"))
            ioc_val   = _esc(ioc.get("value", ""))
            ioc_conf  = ioc.get("confidence", "—")
            ioc_ctx   = _esc(ioc.get("context", ""))
        else:
            ioc_type  = "indicator"
            ioc_val   = _esc(str(ioc))
            ioc_conf  = "—"
            ioc_ctx   = ""
        ioc_rows += (
            f"<tr><td>{ioc_type}</td><td style='font-family:monospace;word-break:break-all;'>"
            f"{ioc_val}</td><td>{ioc_conf}</td><td>{ioc_ctx}</td></tr>"
        )
    ioc_table = (
        f"""<table class="ioc-table">
        <thead><tr>
          <th>Type</th><th>Indicator</th><th>Confidence</th><th>Context</th>
        </tr></thead>
        <tbody>{ioc_rows}</tbody></table>"""
        if ioc_rows
        else "<p style='color:#5a6578;'>No IOCs extracted for this advisory.</p>"
    )

    # STIX bundle link
    stix_link = ""
    stix_bundle_url = entry.get("stix_bundle_url") or ""
    if stix_bundle_url:
        stix_link = (
            f'<a href="{_esc(stix_bundle_url)}" target="_blank" class="btn-secondary">'
            f"⬇ Download STIX Bundle</a>"
        )
    elif stix_bundle_path and os.path.exists(stix_bundle_path):
        stix_fname = Path(stix_bundle_path).name
        stix_link = (
            f'<span style="font-family:monospace;color:#00d4aa;">STIX: {_esc(stix_fname)}</span>'
        )

    # Source reference
    source_link = (
        f'<a href="{_esc(source_url)}" target="_blank" rel="noopener" '
        f'style="color:#5a6578;font-size:11px;">Source Article ↗</a>'
        if source_url else ""
    )

    # Risk bar width
    risk_pct = min(100, max(0, float(risk_score) * 10))

    # CVSS / EPSS rows
    score_rows = ""
    if cvss is not None:
        score_rows += f"<tr><td>CVSS v3</td><td>{float(cvss):.1f}/10.0</td></tr>"
    if epss is not None:
        score_rows += f"<tr><td>EPSS</td><td>{float(epss):.2f}%</td></tr>"
    if kev:
        score_rows += "<tr><td>KEV</td><td>⚠ In CISA KEV catalogue</td></tr>"
    scores_html = (
        f"<table class='score-table'><tbody>{score_rows}</tbody></table>"
        if score_rows
        else "<p style='color:#5a6578;'>No CVE/EPSS data available.</p>"
    )

    canonical_url = f"{PLATFORM_URL}/reports/{out_path.parent.name}/{out_path.name}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>{title} — {PLATFORM_NAME}</title>
  <meta name="description" content="Threat intelligence dossier: {title}"/>
  <link rel="canonical" href="{_esc(canonical_url)}"/>
  <style>
    :root {{
      --bg: #0d1117; --card: #161b22; --border: #21262d;
      --accent: #00d4aa; --text: #e6edf3; --muted: #8b949e;
      --critical: #dc2626; --high: #ea580c; --medium: #f59e0b;
      --low: #22c55e; --font-mono: 'Courier New',monospace;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; font-size: 14px; line-height: 1.6; }}
    .tlp-banner {{ background:{sev_color}22; border-bottom:2px solid {sev_color}; padding:6px 24px; text-align:center; font-family:var(--font-mono); font-size:11px; font-weight:800; color:{sev_color}; letter-spacing:2px; }}
    .header {{ background:var(--card); border-bottom:1px solid var(--border); padding:24px 32px; }}
    .header-meta {{ display:flex; align-items:center; gap:16px; margin-bottom:12px; flex-wrap:wrap; }}
    .badge {{ background:{sev_color}22; border:1px solid {sev_color}66; color:{sev_color}; font-family:var(--font-mono); font-size:10px; font-weight:800; padding:2px 10px; border-radius:3px; letter-spacing:1px; }}
    .badge-tlp {{ background:rgba(0,212,170,0.08); border:1px solid rgba(0,212,170,0.3); color:var(--accent); }}
    h1 {{ font-size:22px; font-weight:700; color:var(--text); margin-bottom:8px; }}
    .intel-id {{ font-family:var(--font-mono); font-size:10px; color:var(--muted); }}
    .container {{ max-width:960px; margin:0 auto; padding:32px 24px; }}
    .section {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:24px; margin-bottom:20px; }}
    .section-title {{ font-family:var(--font-mono); font-size:11px; font-weight:800; color:var(--accent); letter-spacing:2px; text-transform:uppercase; margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border); }}
    .risk-bar-wrap {{ background:rgba(255,255,255,0.06); border-radius:4px; height:8px; margin:8px 0; }}
    .risk-bar {{ height:8px; border-radius:4px; background:linear-gradient(90deg,{sev_color},{sev_color}88); transition:width 0.6s; }}
    .risk-val {{ font-family:var(--font-mono); font-size:28px; font-weight:900; color:{sev_color}; }}
    .ioc-table {{ width:100%; border-collapse:collapse; font-size:12px; }}
    .ioc-table th {{ background:rgba(255,255,255,0.04); color:var(--accent); font-family:var(--font-mono); font-size:10px; font-weight:700; padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); }}
    .ioc-table td {{ padding:7px 12px; border-bottom:1px solid rgba(255,255,255,0.04); color:var(--text); vertical-align:top; }}
    .ioc-table tr:hover td {{ background:rgba(255,255,255,0.02); }}
    .score-table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    .score-table td {{ padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04); }}
    .score-table td:first-child {{ color:var(--muted); width:120px; font-family:var(--font-mono); font-size:11px; }}
    .mitre-wrap {{ display:flex; flex-wrap:wrap; gap:8px; }}
    .mitre-wrap .badge {{ background:rgba(59,130,246,0.1); border-color:rgba(59,130,246,0.3); color:#60a5fa; }}
    .cta {{ background:linear-gradient(135deg,rgba(0,212,170,0.08),rgba(0,212,170,0.02)); border:1px solid rgba(0,212,170,0.25); border-radius:8px; padding:24px; text-align:center; }}
    .cta h3 {{ color:var(--accent); font-size:16px; margin-bottom:8px; }}
    .cta p {{ color:var(--muted); font-size:12px; margin-bottom:16px; }}
    .btn {{ display:inline-block; padding:10px 24px; border-radius:6px; font-family:var(--font-mono); font-size:12px; font-weight:700; letter-spacing:0.5px; text-decoration:none; cursor:pointer; }}
    .btn-primary {{ background:var(--accent); color:#0d1117; }}
    .btn-secondary {{ background:transparent; color:var(--accent); border:1px solid rgba(0,212,170,0.4); margin-left:12px; }}
    .footer {{ text-align:center; padding:32px 24px; color:var(--muted); font-size:11px; font-family:var(--font-mono); border-top:1px solid var(--border); margin-top:16px; }}
    .grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
    .meta-row {{ display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04); font-size:12px; }}
    .meta-row span:first-child {{ color:var(--muted); font-family:var(--font-mono); font-size:10px; }}
    @media(max-width:640px){{ .grid-2{{grid-template-columns:1fr;}} h1{{font-size:18px;}} }}
  </style>
</head>
<body>

<!-- TLP Banner -->
<div class="tlp-banner">⚠ {_esc(tlp)} — CYBERDUDEBIVASH SENTINEL APEX — INTERNAL INTELLIGENCE REPORT ⚠</div>

<!-- Header -->
<div class="header">
  <div class="header-meta">
    <span class="badge">{_esc(severity)}</span>
    <span class="badge badge-tlp">{_esc(tlp)}</span>
    {"<span class='badge' style='color:#ef4444;border-color:#ef444466;background:#ef444411;'>⚠ KEV</span>" if kev else ""}
  </div>
  <h1>{title}</h1>
  <div class="intel-id">INTEL ID: {intel_id} · PROCESSED: {_esc(processed[:19])} UTC · SOURCE: {_esc(feed_source)}</div>
</div>

<div class="container">

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title">01 — Executive Summary</div>
    <p style="color:var(--text);font-size:14px;line-height:1.8;">{description}</p>
    {"<p style='margin-top:12px;'>" + source_link + "</p>" if source_url else ""}
  </div>

  <!-- Risk Assessment -->
  <div class="section">
    <div class="section-title">02 — Risk Score &amp; Severity</div>
    <div class="grid-2">
      <div>
        <div class="risk-val">{float(risk_score):.1f}<span style="font-size:16px;color:var(--muted);">/10</span></div>
        <div style="color:var(--muted);font-size:11px;margin-bottom:8px;font-family:var(--font-mono);">COMPOSITE RISK SCORE</div>
        <div class="risk-bar-wrap"><div class="risk-bar" style="width:{risk_pct:.1f}%;"></div></div>
        <div style="margin-top:8px;"><span class="badge">{_esc(severity)}</span></div>
      </div>
      <div>
        <div class="meta-row"><span>CONFIDENCE</span><span style="color:var(--accent);">{confidence:.0f}%</span></div>
        <div class="meta-row"><span>THREAT ACTOR</span><span>{_esc(actor_tag)}</span></div>
        <div class="meta-row"><span>TLP</span><span>{_esc(tlp)}</span></div>
        <div class="meta-row"><span>INTEL ID</span><span style="font-family:var(--font-mono);font-size:10px;">{intel_id[:24]}</span></div>
      </div>
    </div>
  </div>

  <!-- CVE / EPSS / KEV -->
  <div class="section">
    <div class="section-title">03 — CVE / EPSS / KEV Analysis</div>
    {scores_html}
  </div>

  <!-- MITRE ATT&CK -->
  <div class="section">
    <div class="section-title">04 — MITRE ATT&CK Mapping</div>
    <div class="mitre-wrap">{mitre_html}</div>
  </div>

  <!-- IOC Table -->
  <div class="section">
    <div class="section-title">05 — Indicators of Compromise</div>
    {ioc_table}
  </div>

  <!-- STIX Bundle -->
  <div class="section">
    <div class="section-title">06 — STIX 2.1 Intelligence Bundle</div>
    <p style="color:var(--muted);font-size:12px;margin-bottom:12px;">Structured threat intelligence in STIX 2.1 format for SIEM/SOAR ingestion.</p>
    {stix_link if stix_link else "<p style='color:#5a6578;font-size:12px;'>STIX bundle not yet available for this advisory.</p>"}
  </div>

  <!-- CTA -->
  <div class="cta">
    <h3>🔐 Unlock Full Intelligence Package</h3>
    <p>Get complete IOC lists, YARA rules, Sigma detections, and enterprise STIX bundles.</p>
    <a href="{_esc(GUMROAD_URL)}" target="_blank" rel="noopener" class="btn btn-primary">⚡ Get Premium Intel</a>
    {stix_link}
  </div>

</div><!-- /container -->

<div class="footer">
  {_esc(PLATFORM_NAME)} · {_esc(canonical_url)}<br/>
  Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")} UTC ·
  <a href="{_esc(PLATFORM_URL)}" style="color:var(--accent);">{_esc(PLATFORM_URL)}</a>
</div>

</body>
</html>"""


# ── Manifest Batch Generator ───────────────────────────────────────────────────

def generate_reports_from_manifest(
    manifest_path: str = "data/stix/feed_manifest.json",
    reports_base: str = "reports",
    skip_existing: bool = True,
) -> Dict[str, Any]:
    """
    Generate HTML reports for ALL advisories in the manifest.
    Safe to call standalone (CLI) or from pipeline.

    Returns:
        {"success": int, "skipped": int, "failed": int, "errors": [str]}
    """
    results = {"success": 0, "skipped": 0, "failed": 0, "errors": []}

    if not os.path.exists(manifest_path):
        msg = f"Manifest not found: {manifest_path}"
        logger.error(msg)
        results["errors"].append(msg)
        return results

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        msg = f"Failed to load manifest: {exc}"
        logger.error(msg)
        results["errors"].append(msg)
        return results

    advisories = data if isinstance(data, list) else data.get(
        "advisories", data.get("entries", [])
    )
    logger.info("Generating reports for %d advisories ...", len(advisories))

    for entry in advisories:
        intel_id = entry.get("id") or entry.get("stix_id") or ""
        if not intel_id:
            results["skipped"] += 1
            continue

        # Determine expected output path
        report_url = (entry.get("internal_report_url") or entry.get("report_url") or "").strip()
        if report_url.startswith("/"):
            expected_path = Path(report_url.lstrip("/"))
        else:
            ts = entry.get("processed_at") or entry.get("timestamp") or ""
            yyyy = ts[:4] if len(ts) >= 4 else datetime.now().strftime("%Y")
            mm   = ts[5:7] if len(ts) >= 7 else datetime.now().strftime("%m")
            expected_path = Path(reports_base) / yyyy / mm / f"{intel_id}.html"

        if skip_existing and expected_path.exists() and expected_path.stat().st_size > 500:
            # v134.0 P0 FIX: Verify the file is actually valid HTML, not a JSON stub.
            # Prior pipeline runs may have written manifest-entry JSON to the .html path.
            # If the file starts with '{' (JSON) or lacks an HTML doctype signature,
            # fall through and regenerate it — do NOT skip.
            try:
                _head = expected_path.read_text(encoding="utf-8", errors="replace")[:512].lower()
                _is_html = any(sig in _head for sig in ("<!doctype html", "<html"))
            except Exception:
                _is_html = False
            if _is_html:
                results["skipped"] += 1
                continue
            # File exists but is not valid HTML — will regenerate

        stix_bundle = entry.get("stix_bundle") or entry.get("stix_file") or None
        ok, path_or_err = generate_report(entry, stix_bundle, reports_base)
        if ok:
            results["success"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(f"{intel_id}: {path_or_err}")
            logger.warning("Report generation failed for %s: %s", intel_id, path_or_err)

    logger.info(
        "Report generation complete — success=%d skipped=%d failed=%d",
        results["success"], results["skipped"], results["failed"],
    )
    return results


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Report Generator — generate HTML dossiers from manifest"
    )
    parser.add_argument("--manifest", default="data/stix/feed_manifest.json")
    parser.add_argument("--reports-base", default="reports")
    parser.add_argument("--force", action="store_true",
                        help="Re-generate even if report already exists")
    parser.add_argument("--entry", default="",
                        help="JSON string of a single entry to generate")
    args = parser.parse_args()

    if args.entry:
        try:
            entry = json.loads(args.entry)
        except json.JSONDecodeError as e:
            print(f"ERROR: invalid JSON in --entry: {e}", file=sys.stderr)
            return 1
        ok, result = generate_report(entry, None, args.reports_base)
        if ok:
            print(f"✔ Report generated: {result}")
            return 0
        else:
            print(f"✗ Report generation failed: {result}", file=sys.stderr)
            return 1

    results = generate_reports_from_manifest(
        manifest_path=args.manifest,
        reports_base=args.reports_base,
        skip_existing=not args.force,
    )
    print(f"\n{'='*60}")
    print(f"  Reports: success={results['success']}  skipped={results['skipped']}  failed={results['failed']}")
    if results["errors"]:
        print(f"  Errors ({len(results['errors'])}):")
        for e in results["errors"][:20]:
            print(f"    - {e}")
    print(f"{'='*60}")
    return 1 if results["failed"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
