#!/usr/bin/env python3
"""
scripts/daily_brief_generator.py
CYBERDUDEBIVASH(R) SENTINEL APEX v148.0.0 -- Daily Executive Threat Brief Generator
=====================================================================================
Reads api/v1/intel/ai_summary.json + api/feed.json and generates a professional
single-page executive PDF threat brief.

Output:
  data/reports/daily_brief_<YYYY-MM-DD>.pdf   -- archived by date
  api/v1/intel/daily_brief_latest.pdf         -- always current (published to R2)

Designed to be listed as a Gumroad product ($9.99/month subscription):
  https://cyberdudebivash.gumroad.com/l/sentinel-apex-daily-brief

Usage:
  python3 scripts/daily_brief_generator.py [--date YYYY-MM-DD] [--dry-run] [--upload]

  --date     Override report date (default: today UTC)
  --dry-run  Generate PDF but skip R2 upload
  --upload   Upload to Cloudflare R2 via wrangler (requires CLOUDFLARE_API_TOKEN)

(c) 2026 CYBERDUDEBIVASH PRIVATE LIMITED. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# ReportLab imports
# ---------------------------------------------------------------------------
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.platypus.flowables import KeepTogether
except ImportError:
    print("[FATAL] reportlab not installed. Run: pip install reportlab --break-system-packages")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT     = pathlib.Path(__file__).resolve().parent.parent
AI_SUMMARY    = REPO_ROOT / "api" / "v1" / "intel" / "ai_summary.json"
FEED_JSON     = REPO_ROOT / "api" / "feed.json"
REPORTS_DIR   = REPO_ROOT / "data" / "reports"
API_DEST      = REPO_ROOT / "api" / "v1" / "intel" / "daily_brief_latest.pdf"
R2_KEY        = "api/v1/intel/daily_brief_latest.pdf"

# ---------------------------------------------------------------------------
# Brand colours  (SENTINEL APEX dark theme)
# ---------------------------------------------------------------------------
C_BG          = colors.HexColor("#0a0e1a")
C_CARD        = colors.HexColor("#111827")
C_ACCENT      = colors.HexColor("#00d4ff")
C_PURPLE      = colors.HexColor("#9900ff")
C_RED         = colors.HexColor("#ef4444")
C_ORANGE      = colors.HexColor("#f97316")
C_YELLOW      = colors.HexColor("#eab308")
C_GREEN       = colors.HexColor("#22c55e")
C_TEXT        = colors.HexColor("#e2e8f0")
C_MUTED       = colors.HexColor("#64748b")
C_WHITE       = colors.white
C_BLACK       = colors.black
C_BORDER      = colors.HexColor("#1e293b")

SEV_COLOUR = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_GREEN,
    "INFO":     C_MUTED,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sev_colour(sev: str) -> Any:
    return SEV_COLOUR.get((sev or "").upper(), C_MUTED)


def _risk_colour(score: float) -> Any:
    if score >= 9.0: return C_RED
    if score >= 7.0: return C_ORANGE
    if score >= 5.0: return C_YELLOW
    return C_GREEN


def _load_json(path: pathlib.Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Cannot load {path.name}: {e}")
        return default if default is not None else {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_label(dt_str: str) -> str:
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y")
    except Exception:
        return dt_str[:10] if dt_str else "Unknown"


# ---------------------------------------------------------------------------
# Style sheet
# ---------------------------------------------------------------------------

def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles: dict[str, ParagraphStyle] = {}

    def _s(name, **kw) -> ParagraphStyle:
        s = ParagraphStyle(name, **kw)
        styles[name] = s
        return s

    _s("Cover",         fontSize=26, leading=32, textColor=C_ACCENT,      alignment=TA_CENTER, fontName="Helvetica-Bold")
    _s("CoverSub",      fontSize=12, leading=16, textColor=C_TEXT,         alignment=TA_CENTER, fontName="Helvetica")
    _s("CoverDate",     fontSize=10, leading=13, textColor=C_MUTED,        alignment=TA_CENTER, fontName="Helvetica")
    _s("SectionHead",   fontSize=13, leading=18, textColor=C_ACCENT,       alignment=TA_LEFT,  fontName="Helvetica-Bold",
       spaceAfter=4, spaceBefore=14, borderPad=0)
    _s("SubHead",       fontSize=10, leading=14, textColor=C_TEXT,         alignment=TA_LEFT,  fontName="Helvetica-Bold", spaceBefore=8)
    _s("Body",          fontSize=8,  leading=12, textColor=C_TEXT,         alignment=TA_LEFT,  fontName="Helvetica")
    _s("BodyMuted",     fontSize=7,  leading=11, textColor=C_MUTED,        alignment=TA_LEFT,  fontName="Helvetica")
    _s("TableHead",     fontSize=7,  leading=10, textColor=C_MUTED,        alignment=TA_LEFT,  fontName="Helvetica-Bold")
    _s("TableCell",     fontSize=7,  leading=10, textColor=C_TEXT,         alignment=TA_LEFT,  fontName="Helvetica")
    _s("Verdict",       fontSize=9,  leading=13, textColor=C_TEXT,         alignment=TA_LEFT,  fontName="Helvetica",
       leftIndent=8, backColor=C_CARD, borderPad=6)
    _s("Footer",        fontSize=6,  leading=8,  textColor=C_MUTED,        alignment=TA_CENTER, fontName="Helvetica")
    _s("Watermark",     fontSize=7,  leading=9,  textColor=C_MUTED,        alignment=TA_RIGHT, fontName="Helvetica")
    return styles


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_hr(colour=C_ACCENT, width=1) -> HRFlowable:
    return HRFlowable(width="100%", thickness=width, color=colour, spaceAfter=6, spaceBefore=2)


def build_cover(styles, report_date: str, advisory_count: int, gri: float) -> list:
    elems = []
    elems.append(Spacer(1, 1.2*cm))
    elems.append(Paragraph("SENTINEL APEX", styles["Cover"]))
    elems.append(Paragraph("DAILY EXECUTIVE THREAT INTELLIGENCE BRIEF", styles["CoverSub"]))
    elems.append(Spacer(1, 0.3*cm))
    elems.append(_section_hr(C_PURPLE, 2))
    elems.append(Spacer(1, 0.2*cm))
    elems.append(Paragraph(f"Report Date: {report_date}  |  {advisory_count} Advisories Analysed  |  GRI: {gri:.1f}/10", styles["CoverDate"]))
    elems.append(Paragraph("Classification: TLP:WHITE — Unrestricted Distribution", styles["CoverDate"]))
    elems.append(Spacer(1, 0.4*cm))
    return elems


def build_apex_summary(styles, apex_summary: str, gri: float, advisory_count: int) -> list:
    elems = []
    elems.append(Paragraph("APEX AI CORTEX — EXECUTIVE VERDICT", styles["SectionHead"]))
    elems.append(_section_hr())
    gri_colour = _risk_colour(gri)
    verdict_html = (
        f'<font color="#{gri_colour.hexval()[2:]}"><b>Global Risk Index: {gri:.1f}/10</b></font>  |  '
        f'<font color="#64748b">{advisory_count} threat advisories</font><br/><br/>'
        f'{apex_summary}'
    )
    elems.append(Paragraph(verdict_html, styles["Verdict"]))
    elems.append(Spacer(1, 0.3*cm))
    return elems


def build_top_threats(styles, feed_items: list) -> list:
    elems = []
    elems.append(Paragraph("TOP 10 CRITICAL THREATS", styles["SectionHead"]))
    elems.append(_section_hr())

    # Sort by risk_score desc, take top 10
    ranked = sorted(
        [i for i in feed_items if isinstance(i, dict)],
        key=lambda x: float(x.get("risk_score", 0) or 0),
        reverse=True,
    )[:10]

    col_widths = [0.6*cm, 7.2*cm, 1.4*cm, 1.4*cm, 2.2*cm, 2.4*cm]
    header_row = [
        Paragraph("#", styles["TableHead"]),
        Paragraph("Title", styles["TableHead"]),
        Paragraph("Severity", styles["TableHead"]),
        Paragraph("Risk", styles["TableHead"]),
        Paragraph("CVE / KEV", styles["TableHead"]),
        Paragraph("Source", styles["TableHead"]),
    ]
    table_data = [header_row]

    for idx, item in enumerate(ranked, 1):
        sev   = (item.get("severity") or "").upper()
        risk  = float(item.get("risk_score", 0) or 0)
        cve   = item.get("cve_id") or (item.get("cve_ids") or [""])[0] if item.get("cve_ids") else ""
        kev   = item.get("kev_present") or item.get("kev", False)
        src   = str(item.get("source", "Unknown"))[:30]
        title = str(item.get("title", "Unknown"))[:80]
        cve_kev = f'{cve[:12] or "-"}' + (" [KEV]" if kev else "")

        sev_colour = _sev_colour(sev)
        risk_colour = _risk_colour(risk)
        table_data.append([
            Paragraph(str(idx), styles["TableCell"]),
            Paragraph(title, styles["TableCell"]),
            Paragraph(f'<font color="#{sev_colour.hexval()[2:]}">{sev[:4]}</font>', styles["TableCell"]),
            Paragraph(f'<font color="#{risk_colour.hexval()[2:]}"><b>{risk:.1f}</b></font>', styles["TableCell"]),
            Paragraph(cve_kev, styles["TableCell"]),
            Paragraph(src, styles["TableCell"]),
        ])

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  C_CARD),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  C_MUTED),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, C_CARD]),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 0.3*cm))
    return elems


def build_campaigns(styles, campaigns: list) -> list:
    elems = []
    elems.append(Paragraph("ACTIVE THREAT CAMPAIGNS", styles["SectionHead"]))
    elems.append(_section_hr())

    top_camps = sorted(campaigns, key=lambda x: float(x.get("max_risk", 0) or 0), reverse=True)[:8]
    col_widths = [3.8*cm, 1.5*cm, 1.3*cm, 1.4*cm, 7.2*cm]
    header_row = [
        Paragraph("Actor / Campaign", styles["TableHead"]),
        Paragraph("Severity", styles["TableHead"]),
        Paragraph("Max Risk", styles["TableHead"]),
        Paragraph("Count", styles["TableHead"]),
        Paragraph("Threat Types", styles["TableHead"]),
    ]
    table_data = [header_row]
    for c in top_camps:
        sev    = (c.get("severity") or "").upper()
        risk   = float(c.get("max_risk", 0) or 0)
        count  = c.get("count", 0)
        name   = str(c.get("display_name") or c.get("actor", "Unknown"))[:35]
        ttypes = ", ".join(str(t) for t in (c.get("threat_types") or [])[:3])
        sc     = _sev_colour(sev)
        rc     = _risk_colour(risk)
        table_data.append([
            Paragraph(name, styles["TableCell"]),
            Paragraph(f'<font color="#{sc.hexval()[2:]}">{sev[:4]}</font>', styles["TableCell"]),
            Paragraph(f'<font color="#{rc.hexval()[2:]}"><b>{risk:.1f}</b></font>', styles["TableCell"]),
            Paragraph(str(count), styles["TableCell"]),
            Paragraph(ttypes[:60], styles["TableCell"]),
        ])
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_CARD),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, C_CARD]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 0.3*cm))
    return elems


def build_sector_forecasts(styles, forecasts: list) -> list:
    elems = []
    elems.append(Paragraph("7-DAY SECTOR RISK FORECAST", styles["SectionHead"]))
    elems.append(_section_hr())

    top_f = sorted(forecasts, key=lambda x: float(x.get("current_risk", 0) or 0), reverse=True)[:6]
    col_widths = [4.2*cm, 1.6*cm, 1.6*cm, 1.4*cm, 1.8*cm, 4.6*cm]
    header_row = [
        Paragraph("Sector", styles["TableHead"]),
        Paragraph("Current Risk", styles["TableHead"]),
        Paragraph("Peak (7d)", styles["TableHead"]),
        Paragraph("Prob %", styles["TableHead"]),
        Paragraph("Trend", styles["TableHead"]),
        Paragraph("Attack Vector", styles["TableHead"]),
    ]
    table_data = [header_row]
    for f in top_f:
        cur  = float(f.get("current_risk", 0) or 0)
        peak = float(f.get("peak_risk", 0) or 0)
        prob = f.get("prob", 0)
        trend= str(f.get("trend", "STABLE"))
        sect = str(f.get("sector", "Unknown"))[:30]
        vec  = str(f.get("vector", "Unknown"))[:45]
        rc   = _risk_colour(cur)
        pc   = _risk_colour(peak)
        tc   = C_RED if trend == "ESCALATING" else (C_GREEN if trend == "DECLINING" else C_YELLOW)
        table_data.append([
            Paragraph(sect, styles["TableCell"]),
            Paragraph(f'<font color="#{rc.hexval()[2:]}"><b>{cur:.2f}</b></font>', styles["TableCell"]),
            Paragraph(f'<font color="#{pc.hexval()[2:]}">{peak:.2f}</font>', styles["TableCell"]),
            Paragraph(f"{prob}%", styles["TableCell"]),
            Paragraph(f'<font color="#{tc.hexval()[2:]}">{trend}</font>', styles["TableCell"]),
            Paragraph(vec, styles["TableCell"]),
        ])
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_CARD),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, C_CARD]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 0.3*cm))
    return elems


def build_anomalies(styles, anomalies: list) -> list:
    elems = []
    elems.append(Paragraph("SOC PRIORITY ANOMALIES & ZERO-DAY CANDIDATES", styles["SectionHead"]))
    elems.append(_section_hr())

    top_a = sorted(anomalies, key=lambda x: float(x.get("anomaly_score", 0) or 0), reverse=True)[:6]
    col_widths = [5.8*cm, 1.4*cm, 1.3*cm, 1.4*cm, 1.5*cm, 3.8*cm]
    header_row = [
        Paragraph("Threat", styles["TableHead"]),
        Paragraph("Severity", styles["TableHead"]),
        Paragraph("Risk", styles["TableHead"]),
        Paragraph("SOC Pri", styles["TableHead"]),
        Paragraph("0-Day?", styles["TableHead"]),
        Paragraph("Sector", styles["TableHead"]),
    ]
    table_data = [header_row]
    for a in top_a:
        sev   = (a.get("severity") or "").upper()
        risk  = float(a.get("risk_score", 0) or 0)
        title = str(a.get("title", "Unknown"))[:55]
        pri   = str(a.get("soc_priority", "-"))
        zday  = "YES" if a.get("is_zero_day_candidate") else "no"
        sect  = str(a.get("sector", "-"))[:30]
        sc    = _sev_colour(sev)
        rc    = _risk_colour(risk)
        zc    = C_RED if zday == "YES" else C_MUTED
        table_data.append([
            Paragraph(title, styles["TableCell"]),
            Paragraph(f'<font color="#{sc.hexval()[2:]}">{sev[:4]}</font>', styles["TableCell"]),
            Paragraph(f'<font color="#{rc.hexval()[2:]}"><b>{risk:.1f}</b></font>', styles["TableCell"]),
            Paragraph(pri, styles["TableCell"]),
            Paragraph(f'<font color="#{zc.hexval()[2:]}"><b>{zday}</b></font>', styles["TableCell"]),
            Paragraph(sect, styles["TableCell"]),
        ])
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_CARD),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, C_CARD]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 0.3*cm))
    return elems


def build_kev_digest(styles, feed_items: list) -> list:
    """CISA KEV items from the feed."""
    kev_items = [
        i for i in feed_items
        if isinstance(i, dict) and (i.get("kev_present") or i.get("kev"))
    ][:8]
    if not kev_items:
        return []

    elems = []
    elems.append(Paragraph(f"CISA KEV DIGEST — {len(kev_items)} KNOWN EXPLOITED VULNERABILITIES", styles["SectionHead"]))
    elems.append(_section_hr(C_RED))

    col_widths = [5.0*cm, 2.2*cm, 1.5*cm, 1.5*cm, 5.0*cm]
    header_row = [
        Paragraph("Vulnerability", styles["TableHead"]),
        Paragraph("CVE ID", styles["TableHead"]),
        Paragraph("CVSS", styles["TableHead"]),
        Paragraph("EPSS", styles["TableHead"]),
        Paragraph("Source", styles["TableHead"]),
    ]
    table_data = [header_row]
    for item in kev_items:
        title = str(item.get("title", "Unknown"))[:55]
        cve   = item.get("cve_id") or "-"
        cvss  = item.get("cvss_score") or item.get("cvss")
        epss  = item.get("epss_score") or item.get("epss")
        src   = str(item.get("source", "-"))[:40]
        cvss_str = f"{float(cvss):.1f}" if cvss else "-"
        epss_str = f"{float(epss):.3f}" if epss else "-"
        table_data.append([
            Paragraph(title, styles["TableCell"]),
            Paragraph(str(cve)[:18], styles["TableCell"]),
            Paragraph(cvss_str, styles["TableCell"]),
            Paragraph(epss_str, styles["TableCell"]),
            Paragraph(src, styles["TableCell"]),
        ])
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_CARD),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, C_CARD]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 0.3*cm))
    return elems


def build_footer(styles, report_date: str, generated_at: str) -> list:
    elems = []
    elems.append(_section_hr(C_BORDER))
    footer_text = (
        f"SENTINEL APEX Daily Brief  |  {report_date}  |  Generated: {generated_at}  |  "
        f"intel.cyberdudebivash.com  |  TLP:WHITE  |  GSTIN: 21ARKPN8270G1ZP  |  "
        f"Subscribe: cyberdudebivash.gumroad.com/l/sentinel-apex-daily-brief"
    )
    elems.append(Paragraph(footer_text, styles["Footer"]))
    return elems


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------

def generate_brief(output_path: pathlib.Path, report_date: str) -> None:
    # Load data
    ai   = _load_json(AI_SUMMARY, {})
    feed = _load_json(FEED_JSON, [])
    items = feed if isinstance(feed, list) else feed.get("items", [])

    advisory_count = ai.get("advisory_count", len(items))
    apex_summary   = ai.get("apex_summary", "Threat intelligence analysis unavailable.")
    campaigns      = ai.get("campaigns", [])
    anomalies      = ai.get("anomalies", [])
    forecasts      = ai.get("forecasts", [])
    generated_at   = _utc_now()

    # Compute GRI from top items
    risks = [float(i.get("risk_score", 0) or 0) for i in items if isinstance(i, dict)]
    gri = round(sum(risks) / len(risks), 2) if risks else 0.0

    styles = _build_styles()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=1.5*cm, leftMargin=1.5*cm,
        topMargin=1.2*cm,   bottomMargin=1.2*cm,
        title=f"SENTINEL APEX Daily Brief {report_date}",
        author="CYBERDUDEBIVASH SENTINEL APEX",
        subject="Executive Threat Intelligence Brief",
        creator="SENTINEL APEX v148.0.0",
    )

    date_label = _date_label(report_date) if report_date else "Today"
    story = []
    story += build_cover(styles, date_label, advisory_count, gri)
    story += build_apex_summary(styles, apex_summary, gri, advisory_count)
    story += build_top_threats(styles, items)
    story += build_campaigns(styles, campaigns)
    story += build_anomalies(styles, anomalies)
    story += build_sector_forecasts(styles, forecasts)
    story += build_kev_digest(styles, items)
    story += build_footer(styles, date_label, generated_at)

    doc.build(story)
    size_kb = output_path.stat().st_size // 1024
    print(f"[OK] PDF generated: {output_path} ({size_kb} KB)")


# ---------------------------------------------------------------------------
# R2 upload via wrangler
# ---------------------------------------------------------------------------

def upload_to_r2(pdf_path: pathlib.Path) -> bool:
    """Upload daily brief to Cloudflare R2 using wrangler CLI."""
    import subprocess
    bucket = "sentinel-apex-data"
    cmd = [
        "npx", "wrangler", "r2", "object", "put",
        f"{bucket}/{R2_KEY}",
        "--file", str(pdf_path),
        "--content-type", "application/pdf",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(REPO_ROOT))
        if result.returncode == 0:
            print(f"[OK] Uploaded to R2: r2://{bucket}/{R2_KEY}")
            return True
        else:
            print(f"[WARN] R2 upload failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"[WARN] R2 upload skipped: {e}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Daily Threat Brief Generator v148.0.0")
    parser.add_argument("--date",    default="", help="Report date YYYY-MM-DD (default: today UTC)")
    parser.add_argument("--dry-run", action="store_true", help="Generate PDF but skip R2 upload")
    parser.add_argument("--upload",  action="store_true", help="Upload to Cloudflare R2 after generating")
    args = parser.parse_args()

    report_date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    print("=" * 65)
    print(f"  SENTINEL APEX DAILY BRIEF GENERATOR v148.0.0")
    print(f"  Date: {report_date}")
    print("=" * 65)

    # 1. Generate dated archive copy
    archive_path = REPORTS_DIR / f"daily_brief_{report_date}.pdf"
    generate_brief(archive_path, report_date)

    # 2. Copy to API latest path
    API_DEST.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(archive_path, API_DEST)
    print(f"[OK] Latest brief: {API_DEST}")

    # 3. Write metadata sidecar
    meta_path = REPO_ROOT / "api" / "v1" / "intel" / "daily_brief_meta.json"
    meta = {
        "report_date":   report_date,
        "generated_at":  _utc_now(),
        "version":       "148.0.0",
        "size_bytes":    API_DEST.stat().st_size,
        "download_url":  f"https://intel.cyberdudebivash.com/{R2_KEY}",
        "subscribe_url": "https://cyberdudebivash.gumroad.com/l/sentinel-apex-daily-brief",
        "price_monthly": 9.99,
        "currency":      "USD",
        "description":   "Daily AI-powered executive threat intelligence brief. Includes top 10 threats, active campaigns, zero-day anomalies, CISA KEV digest, and 7-day sector risk forecast.",
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[OK] Metadata: {meta_path}")

    # 4. Optional R2 upload
    if args.upload and not args.dry_run:
        upload_to_r2(API_DEST)
    elif args.dry_run:
        print("[INFO] Dry run — R2 upload skipped")

    print("=" * 65)
    print(f"  COMPLETE — {API_DEST.stat().st_size // 1024} KB brief ready")
    print(f"  Subscribe: cyberdudebivash.gumroad.com/l/sentinel-apex-daily-brief")
    print("=" * 65)


if __name__ == "__main__":
    main()
