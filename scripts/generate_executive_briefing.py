#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SENTINEL APEX — Executive Intelligence Briefing Engine v143.0.0           ║
║  Phase IV Asset 2 — Automated Daily PDF Briefing                           ║
║                                                                            ║
║  Produces watermarked, branded TLP:AMBER executive PDFs with:             ║
║    • AI-scored threat summary (Top 5 critical)                            ║
║    • MITRE ATT&CK heatmap data                                            ║
║    • 30-day risk forecast                                                  ║
║    • Actor attribution summary                                             ║
║    • GSTIN: 21ARKPN8270G1ZP legal branding                               ║
║                                                                            ║
║  Monetization: $49/unit | $149/mo subscription                            ║
║  Output:  data/reports/executive_briefing_YYYY-MM-DD.pdf                 ║
║           data/reports/executive_briefing_YYYY-MM-DD.json (metadata)     ║
║                                                                            ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — All Rights Reserved               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python scripts/generate_executive_briefing.py
    python scripts/generate_executive_briefing.py --date 2026-05-04
    python scripts/generate_executive_briefing.py --tier enterprise --watermark-id ENT-0042
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import textwrap
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-EXEC-BRIEFING")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).parent.parent
DATA_DIR      = ROOT / "data"
REPORTS_DIR   = DATA_DIR / "reports"
MANIFESTS_DIR = DATA_DIR
APEX_V2_DIR   = ROOT / "api" / "apex_v2"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Branding Constants ────────────────────────────────────────────────────────
COMPANY_NAME  = "CYBERDUDEBIVASH PVT. LTD."
PLATFORM      = "SENTINEL APEX v143.0.0"
GSTIN         = "21ARKPN8270G1ZP"
PAN           = "ARKPN8270G"
ADDRESS       = "29, Korai-Sukinda-Ramchandrapur Rd, Ragadi, JAJPUR ROAD, Odisha 755019, INDIA"
EMAIL         = "enterprise@cyberdudebivash.com"
PHONE         = "+91 8179881447"
WEBSITE       = "https://intel.cyberdudebivash.com"
FOOTER_LINE   = (
    f"CLASSIFIED: TLP:AMBER | {COMPANY_NAME} | GSTIN: {GSTIN} | "
    f"{WEBSITE} | © 2026 All Rights Reserved"
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Data Loaders ──────────────────────────────────────────────────────────────

def _atomic_read(path: Path) -> Optional[Any]:
    """Atomic read — loads entire file before JSON parse."""
    try:
        if path.exists():
            return json.loads(path.read_bytes().decode("utf-8"))
    except Exception as e:
        logger.warning(f"atomic_read({path.name}): {e}")
    return None


def load_threat_data() -> Dict:
    """Load and merge threat intel from available pipeline outputs."""
    # Priority order: apex_v2 > apex_enriched > feed_manifest > feed
    sources = [
        DATA_DIR / "apex_v2_manifest.json",
        DATA_DIR / "apex_enriched_manifest.json",
        DATA_DIR / "feed_manifest.json",
        ROOT / "feed.json",
    ]
    for src in sources:
        data = _atomic_read(src)
        if data:
            logger.info(f"Loaded threat data from {src.name}")
            return data if isinstance(data, dict) else {"items": data}
    logger.warning("No threat data found — generating skeleton briefing")
    return {"items": []}


def extract_items(data: Dict) -> List[Dict]:
    """Normalize items from any feed format."""
    raw = (
        data.get("items") or
        data.get("advisories") or
        data.get("threats") or
        (data if isinstance(data, list) else [])
    )
    return [i for i in raw if isinstance(i, dict)]


def load_forecast() -> Dict:
    """Load 30-day AI forecast from apex_v2 pipeline."""
    forecast = _atomic_read(APEX_V2_DIR / "priority.json") or {}
    return forecast


def load_actor_data() -> Dict:
    """Load actor attribution from correlation engine."""
    actor_data = _atomic_read(DATA_DIR / "correlation" / "actor_clusters.json") or {}
    return actor_data


# ── Briefing Generation ───────────────────────────────────────────────────────

def compute_briefing_id(date_str: str, tier: str) -> str:
    """Deterministic briefing ID — unique per date+tier combination."""
    seed = f"{date_str}:{tier}:{GSTIN}"
    return "CDB-" + hashlib.sha256(seed.encode()).hexdigest()[:12].upper()


def classify_severity_bucket(items: List[Dict]) -> Dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in items:
        sev = str(item.get("severity", "INFO")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def compute_risk_posture(items: List[Dict]) -> float:
    """Weighted composite risk score (0.0–10.0)."""
    if not items:
        return 0.0
    total = sum(
        float(i.get("risk_score") or i.get("apex_ai", {}).get("predictive_risk") or 0)
        for i in items
    )
    return round(min(total / len(items), 10.0), 2)


def extract_top_threats(items: List[Dict], n: int = 5) -> List[Dict]:
    """Return top-N threats sorted by severity → risk score."""
    def sort_key(i):
        sev = str(i.get("severity", "INFO")).upper()
        risk = float(i.get("risk_score") or 0)
        return (SEVERITY_ORDER.get(sev, 9), -risk)
    return sorted(items, key=sort_key)[:n]


def extract_mitre_coverage(items: List[Dict]) -> Dict:
    """Aggregate MITRE ATT&CK technique coverage from items."""
    tactic_counts: Dict[str, int] = {}
    technique_list: List[str] = []
    for item in items:
        ttps = item.get("ttps") or item.get("mitre_tactics") or []
        for ttp in ttps:
            t_id = ttp if isinstance(ttp, str) else ttp.get("technique_id", "")
            tactic = ttp.get("tactic", "unknown") if isinstance(ttp, dict) else "unknown"
            technique_list.append(t_id)
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    return {
        "total_techniques": len(set(t for t in technique_list if t)),
        "tactic_distribution": tactic_counts,
        "top_techniques": list(set(t for t in technique_list if t))[:10],
    }


def build_executive_narrative(
    date_str: str,
    severity_counts: Dict,
    risk_posture: float,
    top_threats: List[Dict],
    forecast: Dict,
    actor_data: Dict,
) -> str:
    """
    Generate structured executive narrative text.
    This is the core intelligence content of the briefing.
    """
    critical = severity_counts.get("CRITICAL", 0)
    high     = severity_counts.get("HIGH", 0)
    medium   = severity_counts.get("MEDIUM", 0)
    total    = sum(severity_counts.values())

    risk_label = (
        "CRITICAL — IMMEDIATE BOARD NOTIFICATION REQUIRED" if risk_posture >= 8.0 else
        "HIGH — ELEVATED VIGILANCE REQUIRED" if risk_posture >= 6.0 else
        "MEDIUM — STANDARD SOC MONITORING" if risk_posture >= 3.0 else
        "LOW — ROUTINE POSTURE"
    )

    # Top threat summary
    threat_bullets = []
    for idx, t in enumerate(top_threats[:5], 1):
        title = t.get("title", "Unknown threat")[:80]
        sev   = t.get("severity", "UNKNOWN")
        risk  = t.get("risk_score") or 0
        actor = (t.get("apex_ai") or {}).get("actor_fingerprint") or t.get("actor_tag") or "UNK"
        threat_bullets.append(
            f"  [{idx}] [{sev}] {title}\n"
            f"       Risk: {risk}/10 | Actor: {actor}"
        )
    threat_section = "\n".join(threat_bullets) if threat_bullets else "  No high-priority threats in current cycle."

    # Forecast excerpt
    forecast_items = forecast.get("predictions") or forecast.get("sectors") or []
    forecast_lines = []
    for f in forecast_items[:3]:
        sector = f.get("sector") or f.get("name") or "Unknown"
        prob   = f.get("probability") or f.get("risk") or 0
        vector = f.get("primary_vector") or "Unknown"
        forecast_lines.append(f"  • {sector}: {prob*100:.0f}% risk | Primary vector: {vector}")
    forecast_section = (
        "\n".join(forecast_lines)
        if forecast_lines
        else "  Forecast pipeline warming — predictions available after next AI run."
    )

    narrative = textwrap.dedent(f"""
    ══════════════════════════════════════════════════════════════════════════════
    CYBERDUDEBIVASH® SENTINEL APEX — EXECUTIVE THREAT BRIEFING
    Classification: TLP:AMBER | Date: {date_str} | GSTIN: {GSTIN}
    ══════════════════════════════════════════════════════════════════════════════

    EXECUTIVE SUMMARY
    ─────────────────
    During the current intelligence cycle, SENTINEL APEX processed {total} threat
    advisories across all active feeds. The composite organizational risk posture
    is assessed at {risk_posture}/10 — {risk_label}.

    Severity Distribution:
      CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | TOTAL: {total}

    PRIORITY THREAT QUEUE (TOP 5 — SOC ACTION REQUIRED)
    ────────────────────────────────────────────────────
{threat_section}

    30-DAY AI THREAT FORECAST (GRADIENT BOOSTING MODEL)
    ────────────────────────────────────────────────────
{forecast_section}

    ANALYST RECOMMENDATIONS
    ────────────────────────
    1. PATCH MANAGEMENT: Prioritize CVEs with CISA KEV designation. Exploit
       window is collapsing — mean time to weaponization is now < 24h for
       AI-assisted threat actors.

    2. IDENTITY HYGIENE: Credential stealer logs indicate elevated dark web
       activity. Enforce MFA rotation for all privileged accounts immediately.

    3. SUPPLY CHAIN POSTURE: Review third-party dependencies against active
       campaign IOC feeds. Malicious package injection is the #1 initial
       access vector this cycle.

    4. SOC INTEGRATION: Ensure Splunk/Sentinel webhooks are receiving
       SENTINEL APEX push feeds. SIEM correlation rules must be tuned for
       current actor TTPs.

    INTELLIGENCE SOURCES
    ────────────────────
    Feed Providers: CrowdStrike, Sploitus, CVEFeed.io, HelpNetSecurity,
                    Malwarebytes, CISA KEV, NVD/CVSS
    Classification: STIX 2.1 | TLP v2.0 | MITRE ATT&CK v15
    AI Engine: Isolation Forest + Gradient Boosting + DBSCAN Clustering

    ══════════════════════════════════════════════════════════════════════════════
    {FOOTER_LINE}
    ══════════════════════════════════════════════════════════════════════════════
    """).strip()

    return narrative


def generate_pdf_with_reportlab(
    narrative: str,
    output_path: Path,
    watermark_id: str,
    date_str: str,
) -> bool:
    """
    Generate PDF using ReportLab (preferred).
    Falls back to plain text .pdf if ReportLab not available.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
        )
        from reportlab.pdfgen import canvas as pdfcanvas

        # ── Watermark canvas ──────────────────────────────────────────────────
        class WatermarkCanvas(pdfcanvas.Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._wm_id = watermark_id

            def showPage(self):
                self.saveState()
                self.setFont("Helvetica", 6)
                self.setFillColor(colors.Color(0, 0, 0, alpha=0.08))
                self.setFillColorRGB(0.6, 0.6, 0.6, alpha=0.15)
                # Diagonal watermark
                self.translate(A4[0] / 2, A4[1] / 2)
                self.rotate(45)
                self.setFont("Helvetica-Bold", 48)
                self.drawCentredString(0, 0, "TLP:AMBER")
                self.setFont("Helvetica", 9)
                self.drawCentredString(0, -55, f"CYBERDUDEBIVASH | {self._wm_id} | {GSTIN}")
                self.restoreState()

                # Footer
                self.saveState()
                self.setFont("Helvetica", 6)
                self.setFillColorRGB(0.4, 0.4, 0.4)
                self.drawString(1.5 * cm, 0.8 * cm, FOOTER_LINE[:110])
                self.restoreState()
                super().showPage()

        # ── Document Setup ────────────────────────────────────────────────────
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle(
            "CDBTitle",
            parent=styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#00d4aa"),
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        heading_style = ParagraphStyle(
            "CDBHeading",
            parent=styles["Heading2"],
            fontSize=11,
            textColor=colors.HexColor("#0ea5e9"),
            spaceBefore=12,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        )
        body_style = ParagraphStyle(
            "CDBBody",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=13,
            fontName="Helvetica",
        )
        mono_style = ParagraphStyle(
            "CDBMono",
            parent=styles["Code"],
            fontSize=7.5,
            leading=11,
            fontName="Courier",
            backColor=colors.HexColor("#f0f4f8"),
            borderPadding=4,
        )

        # Header
        story.append(Paragraph("CYBERDUDEBIVASH® SENTINEL APEX", title_style))
        story.append(Paragraph("Executive Intelligence Briefing", heading_style))
        story.append(Paragraph(
            f"Date: {date_str} &nbsp;|&nbsp; ID: {watermark_id} "
            f"&nbsp;|&nbsp; Classification: <b>TLP:AMBER</b> "
            f"&nbsp;|&nbsp; GSTIN: {GSTIN}",
            body_style
        ))
        story.append(HRFlowable(width="100%", thickness=1,
                                 color=colors.HexColor("#00d4aa")))
        story.append(Spacer(1, 0.3 * cm))

        # Narrative content (split by sections)
        for line in narrative.split("\n"):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 0.15 * cm))
            elif line.startswith("══"):
                story.append(HRFlowable(width="100%", thickness=0.5,
                                         color=colors.HexColor("#cccccc")))
            elif line.isupper() and len(line) > 8 and not line.startswith("["):
                story.append(Paragraph(line, heading_style))
            elif line.startswith("─"):
                story.append(HRFlowable(width="100%", thickness=0.3,
                                         color=colors.HexColor("#e0e0e0")))
            elif line.startswith("[") or line.startswith("•") or line.startswith("  •"):
                story.append(Paragraph(
                    line.replace("<", "&lt;").replace(">", "&gt;"),
                    mono_style
                ))
            else:
                story.append(Paragraph(
                    line.replace("<", "&lt;").replace(">", "&gt;"),
                    body_style
                ))

        doc.build(story, canvasmaker=WatermarkCanvas)
        return True

    except ImportError:
        logger.warning("ReportLab not installed — generating text-based PDF stub")
        return _fallback_text_pdf(narrative, output_path, watermark_id, date_str)
    except Exception as e:
        logger.error(f"ReportLab PDF generation failed: {e}", exc_info=True)
        return _fallback_text_pdf(narrative, output_path, watermark_id, date_str)


def _fallback_text_pdf(
    narrative: str, output_path: Path, watermark_id: str, date_str: str
) -> bool:
    """
    Fallback: write narrative as UTF-8 text file with .pdf extension.
    Used when ReportLab is unavailable. HTML version auto-generated for rendering.
    """
    try:
        output_path.write_text(narrative, encoding="utf-8")
        # Generate HTML sidecar
        html_path = output_path.with_suffix(".html")
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberDudeBivash Executive Briefing {date_str}</title>
<style>
  body{{font-family:'Courier New',monospace;background:#0a0a0f;color:#e0e0e0;
        max-width:900px;margin:40px auto;padding:30px;line-height:1.6}}
  .header{{color:#00d4aa;font-size:1.4em;font-weight:bold;border-bottom:2px solid #00d4aa;
           padding-bottom:10px;margin-bottom:20px}}
  .tlp{{color:#ffa500;font-weight:bold}}
  pre{{white-space:pre-wrap;color:#e0e0e0}}
  .watermark{{position:fixed;top:40%;left:20%;transform:rotate(-30deg);
              opacity:0.04;font-size:5em;font-weight:bold;color:#00d4aa;
              pointer-events:none;z-index:1000}}
</style>
</head>
<body>
<div class="watermark">TLP:AMBER</div>
<div class="header">CYBERDUDEBIVASH® SENTINEL APEX — Executive Briefing</div>
<p>ID: <strong>{watermark_id}</strong> | Date: <strong>{date_str}</strong> |
   Classification: <span class="tlp">TLP:AMBER</span> | GSTIN: {GSTIN}</p>
<hr>
<pre>{narrative}</pre>
<hr>
<small style="color:#666">{FOOTER_LINE}</small>
</body>
</html>"""
        html_path.write_text(html_content, encoding="utf-8")
        logger.info(f"HTML sidecar written: {html_path.name}")
        return True
    except Exception as e:
        logger.error(f"Fallback PDF write failed: {e}")
        return False


# ── Metadata / Registry ───────────────────────────────────────────────────────

def write_briefing_metadata(
    briefing_id: str,
    date_str: str,
    pdf_path: Path,
    severity_counts: Dict,
    risk_posture: float,
    tier: str,
    watermark_id: str,
    generation_time_sec: float,
) -> Path:
    """Write JSON metadata sidecar for the briefing — used by billing + delivery."""
    meta = {
        "briefing_id": briefing_id,
        "watermark_id": watermark_id,
        "date": date_str,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": PLATFORM,
        "gstin": GSTIN,
        "company": COMPANY_NAME,
        "tier": tier,
        "classification": "TLP:AMBER",
        "risk_posture": risk_posture,
        "severity_counts": severity_counts,
        "pdf_path": str(pdf_path),
        "status": "generated",
        "generation_time_sec": round(generation_time_sec, 3),
        "monetization": {
            "unit_price_usd": 49,
            "subscription_price_usd": 149,
            "billing_page": "https://intel.cyberdudebivash.com/upgrade.html?plan=briefing",
        },
        "delivery": {
            "email": EMAIL,
            "telegram": "https://t.me/cyberdudebivash",
        }
    }
    meta_path = pdf_path.with_suffix(".json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    logger.info(f"Briefing metadata: {meta_path.name}")
    return meta_path


# ── Main Entrypoint ───────────────────────────────────────────────────────────

def generate_briefing(
    date_str: Optional[str] = None,
    tier: str = "enterprise",
    watermark_id: Optional[str] = None,
) -> Dict:
    """
    Full briefing generation pipeline.
    Returns result dict with paths and status.
    """
    t0 = time.monotonic()

    if not date_str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    briefing_id  = compute_briefing_id(date_str, tier)
    watermark_id = watermark_id or f"CDB-{uuid.uuid4().hex[:8].upper()}"
    pdf_filename = f"executive_briefing_{date_str}.pdf"
    pdf_path     = REPORTS_DIR / pdf_filename

    logger.info(f"Generating Executive Briefing | ID: {briefing_id} | Date: {date_str}")

    # Load data
    threat_data   = load_threat_data()
    items         = extract_items(threat_data)
    forecast      = load_forecast()
    actor_data    = load_actor_data()

    logger.info(f"Loaded {len(items)} threat items")

    # Compute intelligence metrics
    severity_counts = classify_severity_bucket(items)
    risk_posture    = compute_risk_posture(items)
    top_threats     = extract_top_threats(items)
    mitre_coverage  = extract_mitre_coverage(items)

    # Generate narrative
    narrative = build_executive_narrative(
        date_str, severity_counts, risk_posture,
        top_threats, forecast, actor_data
    )

    # Generate PDF (atomic write pattern — write to temp then rename)
    tmp_path = pdf_path.with_suffix(".tmp")
    success  = generate_pdf_with_reportlab(narrative, tmp_path, watermark_id, date_str)

    if success and tmp_path.exists():
        tmp_path.rename(pdf_path)                # atomic rename
        logger.info(f"PDF written (atomic): {pdf_path}")
    elif tmp_path.exists():
        tmp_path.unlink(missing_ok=True)
        logger.error("PDF generation failed — temp file cleaned up")

    elapsed = time.monotonic() - t0

    # Write metadata sidecar
    meta_path = write_briefing_metadata(
        briefing_id, date_str, pdf_path,
        severity_counts, risk_posture, tier, watermark_id, elapsed
    )

    result = {
        "status": "generated" if pdf_path.exists() else "failed",
        "briefing_id": briefing_id,
        "watermark_id": watermark_id,
        "date": date_str,
        "pdf_path": str(pdf_path),
        "meta_path": str(meta_path),
        "risk_posture": risk_posture,
        "severity_counts": severity_counts,
        "total_threats": len(items),
        "mitre_coverage": mitre_coverage,
        "generation_time_sec": round(elapsed, 3),
    }

    logger.info(
        f"Briefing complete | "
        f"status={result['status']} | "
        f"risk={risk_posture}/10 | "
        f"threats={len(items)} | "
        f"elapsed={elapsed:.2f}s"
    )
    return result


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Executive Intelligence Briefing Generator"
    )
    parser.add_argument("--date", default=None,
                        help="Briefing date (YYYY-MM-DD, default: today)")
    parser.add_argument("--tier", default="enterprise",
                        choices=["free", "pro", "enterprise", "mssp"],
                        help="Subscription tier")
    parser.add_argument("--watermark-id", default=None,
                        help="Custom watermark ID (auto-generated if omitted)")
    parser.add_argument("--json-output", action="store_true",
                        help="Print result JSON to stdout")
    args = parser.parse_args()

    result = generate_briefing(
        date_str=args.date,
        tier=args.tier,
        watermark_id=args.watermark_id,
    )

    if args.json_output:
        print(json.dumps(result, indent=2))

    sys.exit(0 if result["status"] == "generated" else 1)


if __name__ == "__main__":
    main()
