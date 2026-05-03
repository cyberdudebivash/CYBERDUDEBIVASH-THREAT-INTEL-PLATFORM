#!/usr/bin/env python3
"""
generate_premium_pdf.py — CYBERDUDEBIVASH SENTINEL APEX v143.0.0
Premium Threat Intelligence PDF Report Generator

Produces a high-fidelity, watermark-branded PDF report suitable for the
$49/report sellable asset. Callable standalone (CLI) or imported as a module
by premium-reports.js via a Python subprocess.

Usage (CLI):
    python3 generate_premium_pdf.py --report-json /path/to/report.json \
                                     --output /path/to/output.pdf

Usage (module):
    from generate_premium_pdf import generate_pdf
    pdf_bytes = generate_pdf(report_dict)
    with open('output.pdf', 'wb') as f:
        f.write(pdf_bytes)

Required secret:  None (self-contained)
Optional env var: SENTINEL_LOGO_PATH — path to a PNG logo (falls back to text)

Report JSON schema (produced by premium-reports.js / handlePremiumReport):
    {
      "report_id":      "rpt_...",
      "type":           "weekly|monthly|custom|cve_focused|actor_focused",
      "title":          "...",
      "generated_at":   "ISO-8601",
      "period":         { "from": "ISO-8601", "to": "ISO-8601" },
      "executive_summary": "...",
      "threat_landscape": { "total_advisories": N, "critical": N, ... },
      "top_threats":    [ { "id": "...", "title": "...", "severity": "...",
                            "cvss": N, "actor": "...", "apex_ai": {...} } ],
      "mitre_coverage": { "techniques": [...], "tactics": [...], "density": N },
      "actor_intel":    [ { "actor": "...", "count": N, "top_cves": [...] } ],
      "iocs":           [ { "type": "...", "value": "...", "confidence": N } ],
      "recommendations":[ "..." ],
      "tier":           "pro|enterprise|mssp",
      "customer_email": "...",   # optional
    }
"""

import argparse
import io
import json
import math
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── ReportLab imports ─────────────────────────────────────────────────────────
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, Image, KeepTogether,
    PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

# ── Brand palette ─────────────────────────────────────────────────────────────
class Brand:
    BG          = colors.HexColor("#0a0f1e")
    PANEL       = colors.HexColor("#0f1729")
    BORDER      = colors.HexColor("#1a2540")
    ACCENT_BLUE = colors.HexColor("#00d4ff")
    ACCENT_GRN  = colors.HexColor("#10b981")
    ACCENT_RED  = colors.HexColor("#ef4444")
    ACCENT_YLW  = colors.HexColor("#f59e0b")
    ACCENT_PRP  = colors.HexColor("#7c3aed")
    TEXT_MAIN   = colors.HexColor("#e2e8f0")
    TEXT_DIM    = colors.HexColor("#64748b")
    TEXT_HEAD   = colors.HexColor("#f8fafc")
    WHITE       = colors.white
    BLACK       = colors.black

    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#ef4444"),
        "HIGH":     colors.HexColor("#f97316"),
        "MEDIUM":   colors.HexColor("#f59e0b"),
        "LOW":      colors.HexColor("#3b82f6"),
        "INFO":     colors.HexColor("#64748b"),
    }

    @staticmethod
    def sev_color(sev: str):
        return Brand.SEV_COLORS.get((sev or "").upper(), Brand.TEXT_DIM)


# ── Watermark / background canvas callbacks ───────────────────────────────────
WATERMARK_TEXT  = "CYBERDUDEBIVASH® SENTINEL APEX"
WATERMARK_TEXT2 = "CONFIDENTIAL — FOR AUTHORIZED USE ONLY"
FOOTER_TEXT     = "cyberdudebivash.com  |  intel.cyberdudebivash.com  |  GSTIN: 21ARKPN8270G1ZP"

def _draw_page(c: canvas.Canvas, doc, report: Dict, page_num: int, total_pages: int):
    """Called by PageTemplate onPage — draws background, watermark, header, footer."""
    W, H = A4

    # ── Dark background
    c.saveState()
    c.setFillColor(Brand.BG)
    c.rect(0, 0, W, H, fill=1, stroke=0)

    # ── Diagonal watermark (semi-transparent simulation via grey on dark bg)
    c.setFillColor(colors.HexColor("#1a2540"))
    c.setFont("Helvetica-Bold", 38)
    c.saveState()
    c.translate(W / 2, H / 2)
    c.rotate(35)
    c.drawCentredString(0, 0, WATERMARK_TEXT)
    c.setFont("Helvetica", 16)
    c.drawCentredString(0, -44, WATERMARK_TEXT2)
    c.restoreState()

    # ── Top header bar
    c.setFillColor(Brand.PANEL)
    c.rect(0, H - 36*mm, W, 36*mm, fill=1, stroke=0)
    # Header accent line
    c.setFillColor(Brand.ACCENT_BLUE)
    c.rect(0, H - 36*mm, W, 1.2*mm, fill=1, stroke=0)

    # Brand name in header
    c.setFillColor(Brand.ACCENT_BLUE)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(16*mm, H - 14*mm, "CYBERDUDEBIVASH®")
    c.setFillColor(Brand.TEXT_DIM)
    c.setFont("Helvetica", 9)
    c.drawString(16*mm, H - 21*mm, "SENTINEL APEX  |  THREAT INTELLIGENCE PLATFORM  |  v143.0.0")

    # TLP badge in header
    tier  = (report.get("tier") or "pro").upper()
    tlp   = "TLP:GREEN" if tier in ("PRO", "PREMIUM") else "TLP:AMBER" if tier == "ENTERPRISE" else "TLP:RED"
    tlp_c = Brand.ACCENT_GRN if tlp == "TLP:GREEN" else Brand.ACCENT_YLW if tlp == "TLP:AMBER" else Brand.ACCENT_RED
    c.setFillColor(tlp_c)
    c.roundRect(W - 52*mm, H - 20*mm, 36*mm, 9*mm, 2*mm, fill=1, stroke=0)
    c.setFillColor(Brand.WHITE)
    c.setFont("Helvetica-Bold", 8)
    c.drawCentredString(W - 34*mm, H - 16*mm, tlp)

    # Report ID in header (right side)
    rid = report.get("report_id", "rpt_unknown")
    c.setFillColor(Brand.TEXT_DIM)
    c.setFont("Helvetica", 7)
    c.drawRightString(W - 16*mm, H - 24*mm, f"ID: {rid}")

    # ── Bottom footer bar
    c.setFillColor(Brand.PANEL)
    c.rect(0, 0, W, 16*mm, fill=1, stroke=0)
    c.setFillColor(Brand.ACCENT_BLUE)
    c.rect(0, 16*mm - 0.8*mm, W, 0.8*mm, fill=1, stroke=0)

    c.setFillColor(Brand.TEXT_DIM)
    c.setFont("Helvetica", 7)
    c.drawString(16*mm, 6*mm, FOOTER_TEXT)
    c.setFont("Helvetica-Bold", 7)
    c.drawRightString(W - 16*mm, 6*mm, f"Page {page_num} of {total_pages}")

    c.restoreState()


# ── Style helpers ─────────────────────────────────────────────────────────────
def _styles():
    s = getSampleStyleSheet()
    base = dict(fontName="Helvetica", textColor=Brand.TEXT_MAIN, backColor=None)
    defs = {
        "Title": ParagraphStyle("Title", fontName="Helvetica-Bold", fontSize=22,
                                 textColor=Brand.ACCENT_BLUE, spaceAfter=4*mm,
                                 spaceBefore=6*mm, alignment=TA_LEFT, leading=26),
        "Subtitle": ParagraphStyle("Subtitle", fontName="Helvetica", fontSize=11,
                                    textColor=Brand.TEXT_DIM, spaceAfter=8*mm, leading=14),
        "SectionHead": ParagraphStyle("SectionHead", fontName="Helvetica-Bold", fontSize=13,
                                       textColor=Brand.ACCENT_BLUE, spaceBefore=8*mm,
                                       spaceAfter=3*mm, leading=16),
        "SubHead": ParagraphStyle("SubHead", fontName="Helvetica-Bold", fontSize=10,
                                   textColor=Brand.TEXT_HEAD, spaceBefore=4*mm, spaceAfter=2*mm),
        "Body": ParagraphStyle("Body", fontName="Helvetica", fontSize=9,
                                textColor=Brand.TEXT_MAIN, leading=14, spaceAfter=3*mm,
                                alignment=TA_JUSTIFY),
        "Mono": ParagraphStyle("Mono", fontName="Courier", fontSize=8,
                                textColor=Brand.ACCENT_GRN, leading=12),
        "Label": ParagraphStyle("Label", fontName="Helvetica-Bold", fontSize=8,
                                  textColor=Brand.ACCENT_BLUE, leading=10),
        "Small": ParagraphStyle("Small", fontName="Helvetica", fontSize=7,
                                  textColor=Brand.TEXT_DIM, leading=10),
        "BulletBody": ParagraphStyle("BulletBody", fontName="Helvetica", fontSize=9,
                                      textColor=Brand.TEXT_MAIN, leading=13,
                                      leftIndent=8*mm, bulletIndent=2*mm,
                                      spaceAfter=1.5*mm),
    }
    return defs


def _hr():
    return HRFlowable(width="100%", thickness=0.5, color=Brand.BORDER,
                      spaceAfter=3*mm, spaceBefore=3*mm)


def _spacer(h_mm=4):
    return Spacer(1, h_mm * mm)


# ── Table style factory ───────────────────────────────────────────────────────
def _table_style(col_widths=None):
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1,  0),   Brand.PANEL),
        ("TEXTCOLOR",    (0, 0), (-1,  0),   Brand.ACCENT_BLUE),
        ("FONTNAME",     (0, 0), (-1,  0),   "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1,  0),   8),
        ("BOTTOMPADDING",(0, 0), (-1,  0),   4*mm),
        ("TOPPADDING",   (0, 0), (-1,  0),   3*mm),
        ("BACKGROUND",   (0, 1), (-1, -1),   Brand.BG),
        ("TEXTCOLOR",    (0, 1), (-1, -1),   Brand.TEXT_MAIN),
        ("FONTNAME",     (0, 1), (-1, -1),   "Helvetica"),
        ("FONTSIZE",     (0, 1), (-1, -1),   8),
        ("ROWBACKGROUNDS",(0,1), (-1, -1),   [Brand.BG, colors.HexColor("#0c1322")]),
        ("BOTTOMPADDING",(0, 1), (-1, -1),   3*mm),
        ("TOPPADDING",   (0, 1), (-1, -1),   2.5*mm),
        ("GRID",         (0, 0), (-1, -1),   0.3, Brand.BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1),   3*mm),
        ("RIGHTPADDING", (0, 0), (-1, -1),   3*mm),
        ("VALIGN",       (0, 0), (-1, -1),   "MIDDLE"),
        ("WORDWRAP",     (0, 0), (-1, -1),   True),
    ])


# ── Section builders ──────────────────────────────────────────────────────────
def _section_cover(report: Dict, st: Dict) -> List:
    """Cover page content (flows after header)."""
    elems = []
    W, _ = A4
    usable = W - 32*mm

    # Title block
    title = report.get("title") or "Sentinel APEX Intelligence Report"
    elems.append(_spacer(18))
    elems.append(Paragraph(title, st["Title"]))

    rtype   = (report.get("type") or "weekly").replace("_", " ").title()
    gen_at  = report.get("generated_at", datetime.now(timezone.utc).isoformat())
    try:
        gen_dt = datetime.fromisoformat(gen_at.replace("Z", "+00:00"))
        gen_str = gen_dt.strftime("%B %d, %Y  %H:%M UTC")
    except Exception:
        gen_str = gen_at

    period = report.get("period") or {}
    period_str = ""
    if period.get("from") and period.get("to"):
        try:
            pf = datetime.fromisoformat(period["from"].replace("Z", "+00:00"))
            pt = datetime.fromisoformat(period["to"].replace("Z",  "+00:00"))
            period_str = f"  ·  Coverage: {pf.strftime('%b %d')} – {pt.strftime('%b %d, %Y')}"
        except Exception:
            pass

    elems.append(Paragraph(f"Report Type: {rtype}  ·  Generated: {gen_str}{period_str}", st["Subtitle"]))
    elems.append(_hr())

    # Threat landscape summary boxes (4-up stat table)
    tl = report.get("threat_landscape") or {}
    stats = [
        ("Total Advisories", str(tl.get("total_advisories", 0)), Brand.ACCENT_BLUE),
        ("Critical",         str(tl.get("critical", 0)),         Brand.ACCENT_RED),
        ("High",             str(tl.get("high", 0)),             colors.HexColor("#f97316")),
        ("Medium",           str(tl.get("medium", 0)),           Brand.ACCENT_YLW),
    ]
    col_w = usable / 4
    stat_data = [[Paragraph(f'<font color="#00d4ff"><b>{v}</b></font><br/><font size="7" color="#64748b">{k}</font>', st["Body"])
                  for k, v, _ in stats]]
    tbl = Table(stat_data, colWidths=[col_w] * 4)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), Brand.PANEL),
        ("BOX",           (0,0),(-1,-1), 0.5, Brand.BORDER),
        ("INNERGRID",     (0,0),(-1,-1), 0.3, Brand.BORDER),
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0),(-1,-1), 4*mm),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4*mm),
    ]))
    elems.append(tbl)
    elems.append(_spacer(6))

    # Executive Summary
    exec_sum = report.get("executive_summary") or "No executive summary provided."
    elems.append(Paragraph("Executive Summary", st["SectionHead"]))
    elems.append(Paragraph(exec_sum, st["Body"]))
    elems.append(_hr())

    # Confidentiality notice
    tier = (report.get("tier") or "pro").upper()
    elems.append(Paragraph(
        f"<b>CONFIDENTIALITY NOTICE:</b> This report is classified {tier} tier and intended exclusively "
        "for the named recipient. Redistribution, resale, or disclosure to unauthorized parties is "
        "strictly prohibited. © 2026 CYBERDUDEBIVASH SENTINEL APEX. All rights reserved.",
        st["Small"]))

    return elems


def _section_top_threats(report: Dict, st: Dict) -> List:
    elems = []
    threats = report.get("top_threats") or []
    if not threats:
        return elems

    elems.append(Paragraph("Top Threat Advisories", st["SectionHead"]))
    elems.append(Paragraph(
        "High-priority advisories ranked by CVSS score, exploitability, and actor attribution.",
        st["Body"]))

    W, _ = A4
    usable = W - 32*mm
    col_widths = [usable * 0.36, usable * 0.10, usable * 0.08, usable * 0.10, usable * 0.36]
    headers = ["Advisory Title", "Severity", "CVSS", "EPSS", "AI Summary"]

    rows = [headers]
    for t in threats[:20]:
        sev     = (t.get("severity") or "MEDIUM").upper()
        apex    = t.get("apex_ai") or {}
        summary = apex.get("ai_summary") or apex.get("summary") or "—"
        if len(summary) > 120:
            summary = summary[:117] + "…"
        title = (t.get("title") or t.get("id") or "")[:72]
        cvss  = f'{t.get("cvss") or "—"}'
        epss_raw = t.get("epss")
        epss  = f'{float(epss_raw)*100:.1f}%' if epss_raw is not None else "—"
        rows.append([title, sev, cvss, epss, summary])

    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    ts  = _table_style()
    # Colour-code severity column
    for i, t in enumerate(threats[:20], start=1):
        sev = (t.get("severity") or "MEDIUM").upper()
        sc  = Brand.sev_color(sev)
        ts.add("TEXTCOLOR", (1, i), (1, i), sc)
        ts.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")
    tbl.setStyle(ts)
    elems.append(tbl)
    elems.append(_spacer(4))
    return elems


def _section_mitre(report: Dict, st: Dict) -> List:
    elems = []
    mc = report.get("mitre_coverage") or {}
    techniques = mc.get("techniques") or []
    tactics    = mc.get("tactics") or []
    density    = mc.get("density") or 0

    elems.append(Paragraph("MITRE ATT&CK® Coverage", st["SectionHead"]))
    elems.append(Paragraph(
        f"ATT&CK technique density score: <b><font color='#00d4ff'>{density:.1f}</font></b>  ·  "
        f"Techniques observed: <b>{len(techniques)}</b>  ·  "
        f"Tactics covered: <b>{len(tactics)}</b>",
        st["Body"]))

    if tactics:
        W, _ = A4
        usable = W - 32*mm
        cols = min(len(tactics), 4)
        col_w = usable / cols
        rows_data = []
        for i in range(0, len(tactics), cols):
            chunk = tactics[i:i+cols]
            while len(chunk) < cols:
                chunk.append({"tactic": "", "count": ""})
            rows_data.append([
                Paragraph(
                    f'<font color="#00d4ff"><b>{c.get("tactic","")}</b></font>'
                    f'<br/><font size="7" color="#64748b">{c.get("count","")} techniques</font>',
                    st["Body"]
                ) if c.get("tactic") else "" for c in chunk
            ])
        tbl = Table(rows_data, colWidths=[col_w] * cols)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), Brand.PANEL),
            ("BOX",           (0,0),(-1,-1), 0.5, Brand.BORDER),
            ("INNERGRID",     (0,0),(-1,-1), 0.3, Brand.BORDER),
            ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0),(-1,-1), 3*mm),
            ("BOTTOMPADDING", (0,0),(-1,-1), 3*mm),
        ]))
        elems.append(tbl)

    if techniques:
        elems.append(_spacer(3))
        elems.append(Paragraph("Observed ATT&CK Techniques", st["SubHead"]))
        W, _ = A4
        usable = W - 32*mm
        col_widths = [usable * 0.20, usable * 0.45, usable * 0.20, usable * 0.15]
        headers = ["Technique ID", "Name", "Tactic", "Count"]
        rows = [headers]
        for t in techniques[:30]:
            rows.append([
                t.get("id") or "—",
                (t.get("name") or "")[:55],
                (t.get("tactic") or "—")[:22],
                str(t.get("count") or "—"),
            ])
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(_table_style())
        elems.append(tbl)

    elems.append(_spacer(4))
    return elems


def _section_actor_intel(report: Dict, st: Dict) -> List:
    elems = []
    actors = report.get("actor_intel") or []
    if not actors:
        return elems

    elems.append(Paragraph("Threat Actor Intelligence", st["SectionHead"]))
    elems.append(Paragraph(
        "Attribution analysis across advisories in this report period.", st["Body"]))

    W, _ = A4
    usable = W - 32*mm
    col_widths = [usable * 0.28, usable * 0.10, usable * 0.62]
    headers = ["Threat Actor", "Advisory Count", "Associated CVEs / Indicators"]
    rows = [headers]
    for a in actors[:25]:
        cves = ", ".join((a.get("top_cves") or [])[:5])
        if len(cves) > 80:
            cves = cves[:77] + "…"
        rows.append([
            (a.get("actor") or "Unknown")[:30],
            str(a.get("count") or "—"),
            cves or "—",
        ])
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(_table_style())
    elems.append(tbl)
    elems.append(_spacer(4))
    return elems


def _section_iocs(report: Dict, st: Dict) -> List:
    elems = []
    iocs = report.get("iocs") or []
    if not iocs:
        return elems

    elems.append(Paragraph("Indicators of Compromise (IOCs)", st["SectionHead"]))
    elems.append(Paragraph(
        f"{len(iocs)} indicators extracted from advisories in this report period. "
        "Ingest directly into your SIEM / EDR / firewall deny-list.", st["Body"]))

    W, _ = A4
    usable = W - 32*mm
    col_widths = [usable * 0.18, usable * 0.52, usable * 0.15, usable * 0.15]
    headers = ["Type", "Indicator Value", "Confidence", "First Seen"]
    rows = [headers]
    for ioc in iocs[:60]:
        conf   = ioc.get("confidence")
        conf_s = f'{int(conf*100)}%' if conf is not None else "—"
        seen   = (ioc.get("first_seen") or "")[:10]
        rows.append([
            (ioc.get("type") or "unknown").upper()[:16],
            (ioc.get("value") or "")[:55],
            conf_s,
            seen or "—",
        ])
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(_table_style())
    elems.append(tbl)

    if len(iocs) > 60:
        elems.append(Paragraph(
            f"… and {len(iocs)-60} additional IOCs. Full list available via API: "
            "GET /api/feed?ioc_only=true", st["Small"]))

    elems.append(_spacer(4))
    return elems


def _section_recommendations(report: Dict, st: Dict) -> List:
    elems = []
    recs = report.get("recommendations") or []
    if not recs:
        return elems

    elems.append(Paragraph("Actionable Recommendations", st["SectionHead"]))
    elems.append(Paragraph(
        "Prioritized defensive actions based on this period's intelligence.", st["Body"]))

    for i, rec in enumerate(recs[:15], start=1):
        elems.append(Paragraph(f"<b>{i}.</b>  {rec}", st["BulletBody"]))

    elems.append(_spacer(4))
    return elems


def _section_appendix(report: Dict, st: Dict) -> List:
    elems = []
    elems.append(PageBreak())
    elems.append(Paragraph("Appendix — Report Metadata & Legal", st["SectionHead"]))
    elems.append(_hr())

    meta = [
        ("Report ID",      report.get("report_id", "—")),
        ("Report Type",    (report.get("type") or "—").replace("_", " ").title()),
        ("Platform",       "CYBERDUDEBIVASH SENTINEL APEX v143.0.0 GOD-MODE"),
        ("Generated At",   report.get("generated_at", "—")),
        ("Customer Tier",  (report.get("tier") or "—").upper()),
        ("Customer Email", report.get("customer_email") or "—"),
        ("TLP",            report.get("tlp") or "TLP:GREEN"),
        ("STIX Version",   "2.1"),
        ("ATT&CK Version", "v15"),
    ]
    W, _ = A4
    usable = W - 32*mm
    col_widths = [usable * 0.30, usable * 0.70]
    rows = [["Field", "Value"]] + list(meta)
    tbl = Table(rows, colWidths=col_widths)
    tbl.setStyle(_table_style())
    elems.append(tbl)

    elems.append(_spacer(6))
    elems.append(Paragraph("Legal & Usage Notice", st["SubHead"]))
    legal = (
        "This threat intelligence report is produced by CYBERDUDEBIVASH SENTINEL APEX, "
        "operated by Bivash Nath (GSTIN: 21ARKPN8270G1ZP). All intelligence is aggregated "
        "from public vulnerability databases (NVD, CVSS), threat feeds, and proprietary AI "
        "enrichment pipelines. This report is provided AS-IS for informational and defensive "
        "security purposes only. CYBERDUDEBIVASH accepts no liability for actions taken based "
        "on this intelligence. Redistribution, resale, or disclosure to unauthorized parties "
        "is strictly prohibited without written consent. For licensing inquiries contact "
        "bivash@cyberdudebivash.com."
    )
    elems.append(Paragraph(legal, st["Body"]))
    return elems


# ── Main PDF generator ────────────────────────────────────────────────────────
def _build_story(report: Dict, st: Dict) -> List:
    """Build a fresh story list from report data. Called twice for two-pass PDF generation."""
    story = []
    story.extend(_section_cover(report, st))
    story.append(PageBreak())
    story.extend(_section_top_threats(report, st))
    story.extend(_section_mitre(report, st))
    story.extend(_section_actor_intel(report, st))
    elems_ioc = _section_iocs(report, st)
    if elems_ioc:
        story.append(PageBreak())
        story.extend(elems_ioc)
    story.extend(_section_recommendations(report, st))
    story.extend(_section_appendix(report, st))
    return story


def _make_doc(buf: io.BytesIO, report: Dict, on_page_cb) -> BaseDocTemplate:
    """Construct a BaseDocTemplate with standard margins and page template."""
    W, H = A4
    frame = Frame(
        16*mm, 16*mm,       # x, y (sits above footer)
        W - 32*mm,          # width
        H - 56*mm,          # height (clears header + footer)
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )
    tpl = PageTemplate(id="main", frames=[frame], onPage=on_page_cb)
    return BaseDocTemplate(
        buf, pagesize=A4, pageTemplates=[tpl],
        title=report.get("title", "Sentinel APEX Intelligence Report"),
        author="CYBERDUDEBIVASH SENTINEL APEX",
        subject="Threat Intelligence Report",
        creator="SENTINEL APEX v143.0.0 GOD-MODE",
        leftMargin=16*mm, rightMargin=16*mm,
        topMargin=38*mm, bottomMargin=18*mm,
    )


def generate_pdf(report: Dict) -> bytes:
    """
    Generate a branded PDF from a report dict.
    Uses a two-pass build: first pass counts pages, second pass renders
    accurate 'Page N of M' footers. Story is rebuilt fresh each pass
    because ReportLab platypus flowables are stateful after build().
    Returns raw PDF bytes.
    """
    st = _styles()

    # ── Pass 1: count total pages ─────────────────────────────────────────────
    buf1     = io.BytesIO()
    tracker1 = {"pages": 0}

    def on_page1(c, doc):
        tracker1["pages"] += 1
        _draw_page(c, doc, report, tracker1["pages"], 999)  # placeholder total

    doc1 = _make_doc(buf1, report, on_page1)
    doc1.build(_build_story(report, st))
    total_pages = tracker1["pages"]

    # ── Pass 2: render with correct total ─────────────────────────────────────
    buf2     = io.BytesIO()
    tracker2 = {"pages": 0}

    def on_page2(c, doc):
        tracker2["pages"] += 1
        _draw_page(c, doc, report, tracker2["pages"], total_pages)

    doc2 = _make_doc(buf2, report, on_page2)
    doc2.build(_build_story(report, st))

    return buf2.getvalue()


# ── Demo report (used for testing / CLI with no --report-json) ────────────────
DEMO_REPORT = {
    "report_id":       "rpt_demo0000000001",
    "type":            "weekly",
    "title":           "SENTINEL APEX Weekly Threat Intelligence Brief — 2026-W18",
    "generated_at":    "2026-05-03T00:00:00Z",
    "period":          {"from": "2026-04-27T00:00:00Z", "to": "2026-05-03T23:59:59Z"},
    "tier":            "pro",
    "customer_email":  "client@example.com",
    "tlp":             "TLP:GREEN",
    "executive_summary": (
        "This week's intelligence cycle identified 47 new critical advisories, 3 active APT "
        "campaigns targeting financial and healthcare sectors, and 12 previously unknown zero-day "
        "indicators surfaced through SENTINEL APEX's Isolation Forest anomaly pipeline. "
        "CVE-2026-6481 (Apache HTTP Server RCE) remains the highest-priority advisory with a CVSS "
        "score of 9.8 and confirmed exploitation in the wild. Immediate patching is advised for all "
        "organizations running Apache 2.4.x. Actor CDB-APT-01 has been observed pivoting to supply-"
        "chain attack vectors — defenders should review third-party code dependencies."
    ),
    "threat_landscape": {"total_advisories": 3312, "critical": 47, "high": 218, "medium": 1104, "low": 1943},
    "top_threats": [
        {"id": "CVE-2026-6481", "title": "Apache HTTP Server Remote Code Execution", "severity": "CRITICAL",
         "cvss": 9.8, "epss": 0.92, "actor": "CDB-APT-01",
         "apex_ai": {"ai_summary": "Unauthenticated RCE via mod_proxy buffer overflow. Active exploitation confirmed in 14 countries."}},
        {"id": "CVE-2026-7672", "title": "youlai-boot SQL Injection via getUserList", "severity": "LOW",
         "cvss": 3.7, "epss": 0.21, "actor": "CDB-CVE-GEN",
         "apex_ai": {"ai_summary": "SQL injection in Users endpoint. Low exploitability; local access required."}},
        {"id": "CVE-2026-7670", "title": "Jinher OA UserSel.aspx SQL Injection", "severity": "MEDIUM",
         "cvss": 4.3, "epss": 0.21, "actor": "CDB-CVE-GEN",
         "apex_ai": {"ai_summary": "SQL injection vulnerability in enterprise OA product widely deployed in APAC."}},
    ],
    "mitre_coverage": {
        "density": 4.2,
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",    "count": 47},
            {"id": "T1059", "name": "Command and Scripting Interpreter",  "tactic": "Execution",        "count": 31},
            {"id": "T1078", "name": "Valid Accounts",                    "tactic": "Persistence",       "count": 19},
            {"id": "T1055", "name": "Process Injection",                  "tactic": "Defense Evasion",  "count": 14},
            {"id": "T1041", "name": "Exfiltration over C2 Channel",       "tactic": "Exfiltration",     "count": 9},
        ],
        "tactics": [
            {"tactic": "Initial Access", "count": 47},
            {"tactic": "Execution",      "count": 31},
            {"tactic": "Persistence",    "count": 19},
            {"tactic": "Exfiltration",   "count": 9},
        ],
    },
    "actor_intel": [
        {"actor": "CDB-CVE-GEN",  "count": 3200, "top_cves": ["CVE-2026-7672", "CVE-2026-7671", "CVE-2026-7670"]},
        {"actor": "CDB-APT-01",   "count": 87,   "top_cves": ["CVE-2026-6481"]},
        {"actor": "CDB-RU-01",    "count": 12,   "top_cves": ["Trellix Source Code Breach"]},
    ],
    "iocs": [
        {"type": "ipv4",   "value": "198.51.100.42",               "confidence": 0.94, "first_seen": "2026-05-01"},
        {"type": "domain", "value": "malicious-c2.example.evil",   "confidence": 0.88, "first_seen": "2026-04-29"},
        {"type": "sha256", "value": "e3b0c44298fc1c149afb4c8996fb924", "confidence": 0.79, "first_seen": "2026-04-28"},
        {"type": "url",    "value": "http://198.51.100.42/payload.exe", "confidence": 0.91, "first_seen": "2026-05-02"},
    ],
    "recommendations": [
        "Immediately apply CVE-2026-6481 patches for Apache HTTP Server 2.4.x — exploitation is confirmed in the wild.",
        "Block C2 IP range 198.51.100.0/24 at perimeter firewall and SIEM alert on outbound connections.",
        "Review all SQL-injectable OA / ERP endpoints exposed to the internet; enforce parameterized queries.",
        "Audit third-party supply-chain dependencies following CDB-APT-01 pivot to supply-chain attack vectors.",
        "Deploy SENTINEL APEX SIEM webhook integration to receive real-time IOC push updates.",
        "Enable multi-factor authentication on all admin panels and VPN endpoints.",
        "Run dark web leak check via /api/leak-check to assess if organizational credentials are exposed.",
    ],
}


# ── CLI entry point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH SENTINEL APEX — Premium PDF Report Generator v143.0.0"
    )
    parser.add_argument("--report-json", "-r",
                        help="Path to report JSON file (default: use built-in demo report)")
    parser.add_argument("--output", "-o", default="sentinel_apex_report.pdf",
                        help="Output PDF path (default: sentinel_apex_report.pdf)")
    parser.add_argument("--demo", action="store_true",
                        help="Generate demo report using built-in sample data")
    args = parser.parse_args()

    if args.report_json and not args.demo:
        with open(args.report_json, "r", encoding="utf-8") as f:
            report = json.load(f)
    else:
        report = DEMO_REPORT
        if not args.demo and not args.report_json:
            print("[INFO] No --report-json provided — using demo report.", file=sys.stderr)

    print(f"[SENTINEL APEX] Generating PDF for report: {report.get('report_id', 'unknown')}",
          file=sys.stderr)
    pdf_bytes = generate_pdf(report)

    with open(args.output, "wb") as f:
        f.write(pdf_bytes)

    size_kb = len(pdf_bytes) / 1024
    print(f"[SENTINEL APEX] PDF written → {args.output}  ({size_kb:.1f} KB, "
          f"{len(pdf_bytes)} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
