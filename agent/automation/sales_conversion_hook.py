#!/usr/bin/env python3
"""
sales_conversion_hook.py — CYBERDUDEBIVASH® SENTINEL APEX v55.0
AUTONOMOUS LEAD CONVERSION PIPELINE

Links ReasoningOrchestrator / BugHunter CRITICAL findings directly to
automated sales funnel:

  1. Finding ingestion → severity triage
  2. CRITICAL findings trigger executive_risk_engine for ALE/ROSI
  3. Auto-generate branded "Risk Mitigation Advisory" PDF
  4. Dispatch to client via email or webhook
  5. Track conversion pipeline metrics

Integration:
    from agent.automation.sales_conversion_hook import conversion_pipeline
    conversion_pipeline.process_finding(finding, client_context)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
Founder & CEO — Bivash Kumar Nayak
"""

import os
import json
import uuid
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
from enum import Enum

logger = logging.getLogger("CDB-SALES-CONVERSION")

# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "bivash@cyberdudebivash.com")
SENDER_NAME = os.environ.get("SENDER_NAME", "CyberDudeBivash SENTINEL APEX")

PLATFORM_URL = "https://intel.cyberdudebivash.com"
PRICING_URL = f"{PLATFORM_URL}/pricing"
ENTERPRISE_EMAIL = "enterprise@cyberdudebivash.com"
WHATSAPP_URL = "https://wa.me/918179881447"
STORE_URL = "https://cyberdudebivash.gumroad.com"

DATA_DIR = Path("data/sales_conversion")
ADVISORIES_DIR = DATA_DIR / "advisories"
PIPELINE_LOG = DATA_DIR / "pipeline_log.json"
METRICS_FILE = DATA_DIR / "conversion_metrics.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
ADVISORIES_DIR.mkdir(parents=True, exist_ok=True)

# Severity threshold for auto-conversion trigger
AUTO_TRIGGER_SEVERITIES = {"CRITICAL", "HIGH"}
# CRITICAL findings trigger immediate advisory; HIGH triggers batched (daily digest)
IMMEDIATE_TRIGGER_SEVERITIES = {"CRITICAL"}


# ═══════════════════════════════════════════════════════════
# PIPELINE STAGES
# ═══════════════════════════════════════════════════════════

class PipelineStage(str, Enum):
    INGESTED = "INGESTED"
    RISK_QUANTIFIED = "RISK_QUANTIFIED"
    ADVISORY_GENERATED = "ADVISORY_GENERATED"
    ADVISORY_DISPATCHED = "ADVISORY_DISPATCHED"
    LEAD_CREATED = "LEAD_CREATED"
    FOLLOW_UP_SCHEDULED = "FOLLOW_UP_SCHEDULED"
    CONVERTED = "CONVERTED"
    CLOSED_LOST = "CLOSED_LOST"


class ClientContext:
    """Client/prospect context for personalized advisory generation."""

    def __init__(
        self,
        org_id: str = "",
        org_name: str = "",
        contact_email: str = "",
        contact_name: str = "",
        region: str = "GLOBAL",
        sector: str = "DEFAULT",
        annual_revenue_usd: float = 10_000_000,
        current_tier: str = "FREE",
        existing_tools: Optional[List[str]] = None,
    ):
        self.org_id = org_id
        self.org_name = org_name or f"ORG-{org_id[:8]}"
        self.contact_email = contact_email
        self.contact_name = contact_name
        self.region = region
        self.sector = sector
        self.annual_revenue_usd = annual_revenue_usd
        self.current_tier = current_tier
        self.existing_tools = existing_tools or []


# ═══════════════════════════════════════════════════════════
# PDF ADVISORY GENERATOR
# ═══════════════════════════════════════════════════════════

class AdvisoryPDFGenerator:
    """
    Generates branded Risk Mitigation Advisory PDFs using fpdf2.
    Falls back to JSON advisory if fpdf2 is unavailable.
    """

    # CDB Brand Colors
    BG_COLOR = (6, 8, 13)         # Deep dark
    ACCENT_COLOR = (0, 212, 170)  # Neon teal
    TEXT_COLOR = (255, 255, 255)
    MUTED_COLOR = (148, 163, 184)
    DANGER_COLOR = (239, 68, 68)
    WARNING_COLOR = (234, 179, 8)

    def generate(
        self,
        risk_report: Dict,
        client: ClientContext,
        findings: List[Dict],
    ) -> Optional[str]:
        """
        Generate branded advisory PDF.
        
        Returns:
            File path to generated PDF, or None on failure.
        """
        try:
            from fpdf import FPDF
        except ImportError:
            logger.warning("fpdf2 not installed — generating JSON advisory instead")
            return self._generate_json_fallback(risk_report, client, findings)

        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=20)

            # ── Page 1: Cover ──
            pdf.add_page()
            self._draw_background(pdf)

            # Header
            pdf.set_font("Arial", "B", 24)
            pdf.set_text_color(*self.ACCENT_COLOR)
            pdf.cell(0, 12, "RISK MITIGATION ADVISORY", ln=True, align="C")
            pdf.ln(3)

            pdf.set_font("Arial", "", 10)
            pdf.set_text_color(*self.MUTED_COLOR)
            pdf.cell(0, 6, "CYBERDUDEBIVASH SENTINEL APEX | CONFIDENTIAL", ln=True, align="C")
            pdf.ln(5)

            # Client info
            pdf.set_font("Arial", "B", 11)
            pdf.set_text_color(*self.TEXT_COLOR)
            pdf.cell(0, 8, f"Prepared for: {client.org_name}", ln=True)
            pdf.set_font("Arial", "", 9)
            pdf.cell(0, 6, f"Region: {client.region} | Sector: {client.sector}", ln=True)
            report_id = risk_report.get("report_id", "N/A")
            pdf.cell(0, 6, f"Report ID: {report_id}", ln=True)
            pdf.cell(0, 6, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", ln=True)
            pdf.ln(8)

            # ── Executive Summary Box ──
            summary = risk_report.get("executive_summary", {})
            pdf.set_font("Arial", "B", 13)
            pdf.set_text_color(*self.ACCENT_COLOR)
            pdf.cell(0, 10, "[#] EXECUTIVE RISK SUMMARY", ln=True)
            pdf.ln(3)

            self._metric_line(pdf, "Total Risk Exposure",
                              f"${summary.get('total_risk_exposure_usd', 0):,.2f}")
            self._metric_line(pdf, "Annualized Loss Exposure (ALE)",
                              f"${summary.get('annualized_loss_exposure_usd', 0):,.2f}")
            self._metric_line(pdf, "Max Regulatory Fine Exposure",
                              f"${summary.get('max_regulatory_fine_usd', 0):,.2f}")
            self._metric_line(pdf, "3-Year Cost of Inaction",
                              f"${summary.get('cost_of_inaction_3yr_usd', 0):,.2f}")
            self._metric_line(pdf, "CDB Platform ROSI",
                              f"{summary.get('rosi_percentage', 0):.1f}%")
            self._metric_line(pdf, "Risk Rating",
                              summary.get("risk_rating", "N/A"))
            pdf.ln(8)

            # ── Regulatory Exposure ──
            reg_exposure = risk_report.get("regulatory_exposure", {})
            if reg_exposure:
                pdf.set_font("Arial", "B", 13)
                pdf.set_text_color(*self.ACCENT_COLOR)
                pdf.cell(0, 10, "[#] REGULATORY FINE EXPOSURE", ln=True)
                pdf.ln(3)

                for reg, info in reg_exposure.items():
                    fine = info.get("projected_fine_usd", 0)
                    pdf.set_font("Arial", "B", 10)
                    color = self.DANGER_COLOR if fine > 1_000_000 else self.WARNING_COLOR
                    pdf.set_text_color(*color)
                    pdf.cell(50, 7, f"  {reg}:")
                    pdf.set_text_color(*self.TEXT_COLOR)
                    pdf.set_font("Arial", "", 10)
                    pdf.cell(0, 7, f"${fine:,.2f}", ln=True)

                pdf.ln(5)

            # ── Critical Findings ──
            pdf.set_font("Arial", "B", 13)
            pdf.set_text_color(*self.ACCENT_COLOR)
            pdf.cell(0, 10, "[#] CRITICAL FINDINGS REQUIRING IMMEDIATE ACTION", ln=True)
            pdf.ln(3)

            for i, f in enumerate(findings[:10], 1):  # Top 10 findings
                severity = f.get("severity", "MEDIUM")
                pdf.set_font("Arial", "B", 10)
                if severity == "CRITICAL":
                    pdf.set_text_color(*self.DANGER_COLOR)
                elif severity == "HIGH":
                    pdf.set_text_color(*self.WARNING_COLOR)
                else:
                    pdf.set_text_color(*self.TEXT_COLOR)

                title = f.get("title", f.get("description", "Finding"))[:80]
                pdf.cell(0, 7, f"  {i}. [{severity}] {title}", ln=True)

                pdf.set_font("Arial", "", 9)
                pdf.set_text_color(*self.MUTED_COLOR)
                f_type = f.get("type", "Unknown")
                ale = f.get("ale_usd", 0)
                pdf.cell(0, 6, f"     Type: {f_type} | ALE: ${ale:,.0f}", ln=True)

            pdf.ln(8)

            # ── Recommendations ──
            recs = risk_report.get("recommendations", [])
            if recs:
                pdf.add_page()
                self._draw_background(pdf)

                pdf.set_font("Arial", "B", 13)
                pdf.set_text_color(*self.ACCENT_COLOR)
                pdf.cell(0, 10, "[#] REMEDIATION RECOMMENDATIONS", ln=True)
                pdf.ln(3)

                for rec in recs:
                    pdf.set_font("Arial", "B", 10)
                    pdf.set_text_color(*self.TEXT_COLOR)
                    priority = rec.get("priority", "P2")
                    action = rec.get("action", "")
                    pdf.cell(0, 7, f"  [{priority}] {action}", ln=True)

                    pdf.set_font("Arial", "", 9)
                    pdf.set_text_color(*self.MUTED_COLOR)
                    impact = rec.get("impact", "")
                    pdf.cell(0, 6, f"     Impact: {impact}", ln=True)
                    pdf.ln(2)

            # ── CTA Section ──
            pdf.ln(10)
            pdf.set_font("Arial", "B", 14)
            pdf.set_text_color(*self.ACCENT_COLOR)
            pdf.cell(0, 10, "PROTECT YOUR ORGANIZATION NOW", ln=True, align="C")
            pdf.ln(3)

            pdf.set_font("Arial", "", 10)
            pdf.set_text_color(*self.TEXT_COLOR)
            mitigated = summary.get("mitigated_value_usd", 0)
            pdf.multi_cell(
                0, 6,
                f"CDB SENTINEL APEX can mitigate ${mitigated:,.0f} in projected losses "
                f"with a {summary.get('rosi_percentage', 0):.0f}% return on security investment.\n\n"
                f"Enterprise Platform: {PLATFORM_URL}\n"
                f"Pricing: {PRICING_URL}\n"
                f"Enterprise Sales: {ENTERPRISE_EMAIL}\n"
                f"WhatsApp: {WHATSAPP_URL}",
                align="C",
            )

            # ── Footer ──
            pdf.ln(15)
            pdf.set_font("Arial", "", 7)
            pdf.set_text_color(*self.MUTED_COLOR)
            pdf.cell(
                0, 5,
                f"(c) 2026 CyberDudeBivash Pvt. Ltd. | {PLATFORM_URL} | "
                "This advisory is auto-generated by SENTINEL APEX AI.",
                ln=True, align="C",
            )

            # Save
            filename = f"CDB_Advisory_{report_id}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
            filepath = ADVISORIES_DIR / filename
            pdf.output(str(filepath))

            logger.info(f"Advisory PDF generated: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return self._generate_json_fallback(risk_report, client, findings)

    def _draw_background(self, pdf):
        """Draw dark background."""
        pdf.set_fill_color(*self.BG_COLOR)
        pdf.rect(0, 0, 210, 297, "F")

    def _metric_line(self, pdf, label: str, value: str):
        """Render a metric line in the executive summary."""
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(*self.MUTED_COLOR)
        pdf.cell(90, 7, f"  {label}:")
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(*self.TEXT_COLOR)
        pdf.cell(0, 7, value, ln=True)

    def _generate_json_fallback(
        self, risk_report: Dict, client: ClientContext, findings: List[Dict]
    ) -> str:
        """Generate JSON advisory when PDF library unavailable."""
        advisory = {
            "type": "CDB_RISK_MITIGATION_ADVISORY",
            "report_id": risk_report.get("report_id"),
            "client": {
                "org_name": client.org_name,
                "region": client.region,
                "sector": client.sector,
            },
            "executive_summary": risk_report.get("executive_summary"),
            "regulatory_exposure": risk_report.get("regulatory_exposure"),
            "top_findings": [
                {
                    "severity": f.get("severity"),
                    "title": f.get("title", "")[:100],
                    "ale_usd": f.get("ale_usd", 0),
                }
                for f in findings[:10]
            ],
            "recommendations": risk_report.get("recommendations"),
            "cta": {
                "platform": PLATFORM_URL,
                "pricing": PRICING_URL,
                "enterprise_sales": ENTERPRISE_EMAIL,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        filename = f"CDB_Advisory_{risk_report.get('report_id', 'N-A')}.json"
        filepath = ADVISORIES_DIR / filename
        with open(filepath, "w") as f:
            json.dump(advisory, f, indent=2, default=str)
        return str(filepath)


# ═══════════════════════════════════════════════════════════
# EMAIL DISPATCHER
# ═══════════════════════════════════════════════════════════

class AdvisoryDispatcher:
    """Dispatches advisories via email (SendGrid) or webhook."""

    def dispatch_email(
        self,
        to_email: str,
        to_name: str,
        subject: str,
        html_body: str,
        pdf_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send advisory email with optional PDF attachment."""
        if not SENDGRID_API_KEY:
            logger.warning("SendGrid API key not configured — email skipped")
            return {"status": "SKIPPED", "reason": "NO_SENDGRID_KEY"}

        try:
            import base64
            import json as json_mod
            import urllib.request

            message = {
                "personalizations": [{"to": [{"email": to_email, "name": to_name}]}],
                "from": {"email": SENDER_EMAIL, "name": SENDER_NAME},
                "subject": subject,
                "content": [{"type": "text/html", "value": html_body}],
            }

            # Attach PDF
            if pdf_path and os.path.exists(pdf_path):
                with open(pdf_path, "rb") as f:
                    pdf_data = base64.b64encode(f.read()).decode()
                message["attachments"] = [{
                    "content": pdf_data,
                    "type": "application/pdf",
                    "filename": os.path.basename(pdf_path),
                    "disposition": "attachment",
                }]

            req = urllib.request.Request(
                "https://api.sendgrid.com/v3/mail/send",
                data=json_mod.dumps(message).encode(),
                headers={
                    "Authorization": f"Bearer {SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=15) as resp:
                return {
                    "status": "SENT",
                    "status_code": resp.status,
                    "to": to_email,
                }

        except Exception as e:
            logger.error(f"Email dispatch failed: {e}")
            return {"status": "FAILED", "error": str(e)}

    def build_advisory_email_html(
        self,
        client: ClientContext,
        risk_report: Dict,
    ) -> str:
        """Build branded HTML email body for advisory."""
        summary = risk_report.get("executive_summary", {})
        ale = summary.get("annualized_loss_exposure_usd", 0)
        rosi = summary.get("rosi_percentage", 0)
        rating = summary.get("risk_rating", "N/A")
        inaction = summary.get("cost_of_inaction_3yr_usd", 0)

        return f"""
<div style="background:#06080d; color:#94a3b8; font-family:'Segoe UI',Arial,sans-serif;
            padding:32px; border:1px solid #1e293b; max-width:620px; margin:auto;
            border-top:4px solid #00d4aa;">

    <div style="margin-bottom:24px;">
        <h1 style="color:#ffffff; font-size:20px; margin:0; letter-spacing:1px;">
            RISK MITIGATION ADVISORY
        </h1>
        <p style="color:#00d4aa; font-size:11px; letter-spacing:2px; margin:4px 0;">
            CYBERDUDEBIVASH SENTINEL APEX | AUTOMATED INTELLIGENCE
        </p>
    </div>

    <p>Dear {client.contact_name or 'Security Leader'},</p>

    <p>Our autonomous threat intelligence platform has identified
    <strong style="color:#ef4444;">CRITICAL</strong> security findings
    affecting <strong style="color:#fff;">{client.org_name}</strong>.</p>

    <div style="background:#0f1218; border:1px solid #1e293b; border-radius:8px;
                padding:20px; margin:20px 0;">
        <h3 style="color:#00d4aa; margin-top:0;">FINANCIAL IMPACT ASSESSMENT</h3>
        <table style="width:100%; color:#e2e8f0; font-size:14px;">
            <tr>
                <td style="padding:6px 0; color:#94a3b8;">Annualized Loss Exposure:</td>
                <td style="text-align:right; font-weight:bold; color:#ef4444;">${ale:,.0f}</td>
            </tr>
            <tr>
                <td style="padding:6px 0; color:#94a3b8;">3-Year Cost of Inaction:</td>
                <td style="text-align:right; font-weight:bold; color:#f59e0b;">${inaction:,.0f}</td>
            </tr>
            <tr>
                <td style="padding:6px 0; color:#94a3b8;">Risk Rating:</td>
                <td style="text-align:right; font-weight:bold; color:#ef4444;">{rating}</td>
            </tr>
            <tr>
                <td style="padding:6px 0; color:#94a3b8;">CDB Platform ROSI:</td>
                <td style="text-align:right; font-weight:bold; color:#00d4aa;">{rosi:.0f}%</td>
            </tr>
        </table>
    </div>

    <p>The attached PDF contains the full advisory with regulatory fine projections,
    per-finding ALE breakdown, and prioritized remediation roadmap.</p>

    <div style="text-align:center; margin:28px 0;">
        <a href="{PRICING_URL}" style="background:#00d4aa; color:#06080d; padding:12px 32px;
           text-decoration:none; font-weight:bold; border-radius:6px; display:inline-block;">
            ACTIVATE ENTERPRISE PROTECTION
        </a>
    </div>

    <p style="font-size:12px; color:#64748b;">
        Enterprise Sales: <a href="mailto:{ENTERPRISE_EMAIL}" style="color:#00d4aa;">{ENTERPRISE_EMAIL}</a><br>
        Platform: <a href="{PLATFORM_URL}" style="color:#00d4aa;">{PLATFORM_URL}</a><br>
        WhatsApp: <a href="{WHATSAPP_URL}" style="color:#00d4aa;">+91 81798 81447</a>
    </p>

    <hr style="border:none; border-top:1px solid #1e293b; margin:20px 0;">
    <p style="font-size:10px; color:#475569; text-align:center;">
        (c) 2026 CyberDudeBivash Pvt. Ltd. | This advisory was auto-generated by SENTINEL APEX AI.
    </p>
</div>
"""


# ═══════════════════════════════════════════════════════════
# CONVERSION PIPELINE (Main Orchestrator)
# ═══════════════════════════════════════════════════════════

class ConversionPipeline:
    """
    End-to-end autonomous sales conversion pipeline.
    
    Flow:
      Finding → Severity Triage → Risk Quantification →
      PDF Advisory → Email/Webhook Dispatch → Lead Tracking
    """

    def __init__(self):
        self._pdf_gen = AdvisoryPDFGenerator()
        self._dispatcher = AdvisoryDispatcher()
        self._pipeline_log: List[Dict] = []
        self._metrics = {
            "total_findings_processed": 0,
            "critical_findings": 0,
            "advisories_generated": 0,
            "advisories_dispatched": 0,
            "leads_created": 0,
            "conversions": 0,
        }
        self._load_metrics()

    def process_finding(
        self,
        finding: Dict,
        client: Optional[ClientContext] = None,
        auto_dispatch: bool = True,
    ) -> Dict[str, Any]:
        """
        Process a single finding through the conversion pipeline.
        
        Triggers advisory generation for CRITICAL findings.
        Batches HIGH findings for daily digest.
        
        Args:
            finding: Technical finding from BugHunter/ReasoningOrchestrator
            client: Client context for personalization
            auto_dispatch: Whether to auto-send advisory email
            
        Returns:
            Pipeline result with stage, advisory path, dispatch status
        """
        self._metrics["total_findings_processed"] += 1
        severity = finding.get("severity", "MEDIUM").upper()

        pipeline_entry = {
            "pipeline_id": f"pipe_{uuid.uuid4().hex[:12]}",
            "finding_type": finding.get("type", "UNKNOWN"),
            "severity": severity,
            "stage": PipelineStage.INGESTED,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # ── Severity Triage ──
        if severity not in AUTO_TRIGGER_SEVERITIES:
            pipeline_entry["stage"] = PipelineStage.INGESTED
            pipeline_entry["note"] = f"Severity {severity} below auto-trigger threshold"
            self._log_pipeline(pipeline_entry)
            return pipeline_entry

        if severity == "CRITICAL":
            self._metrics["critical_findings"] += 1

        # ── Build client context ──
        if not client:
            client = ClientContext(
                org_id=finding.get("org_id", finding.get("target", "unknown")),
                org_name=finding.get("org_name", finding.get("target", "Organization")),
                contact_email=finding.get("contact_email", ""),
                region=finding.get("region", "GLOBAL"),
                sector=finding.get("sector", "DEFAULT"),
            )

        # ── Risk Quantification via Executive Risk Engine ──
        try:
            from agent.analytics.executive_risk_engine import executive_risk_engine
            risk_report = executive_risk_engine.quantify(
                findings=[finding],
                region=client.region,
                sector=client.sector,
                annual_revenue_usd=client.annual_revenue_usd,
            )
            pipeline_entry["stage"] = PipelineStage.RISK_QUANTIFIED
            pipeline_entry["ale_usd"] = risk_report.get("executive_summary", {}).get(
                "annualized_loss_exposure_usd", 0
            )
        except Exception as e:
            logger.error(f"Risk quantification failed: {e}")
            # Continue with basic report
            risk_report = self._basic_risk_report(finding)
            pipeline_entry["stage"] = PipelineStage.RISK_QUANTIFIED
            pipeline_entry["note"] = "Used basic risk estimation"

        # ── Generate Advisory PDF ──
        if severity in IMMEDIATE_TRIGGER_SEVERITIES:
            pdf_path = self._pdf_gen.generate(
                risk_report=risk_report,
                client=client,
                findings=[finding],
            )

            if pdf_path:
                pipeline_entry["stage"] = PipelineStage.ADVISORY_GENERATED
                pipeline_entry["advisory_path"] = pdf_path
                self._metrics["advisories_generated"] += 1

                # ── Auto-dispatch ──
                if auto_dispatch and client.contact_email:
                    dispatch_result = self._dispatch_advisory(
                        client=client,
                        risk_report=risk_report,
                        pdf_path=pdf_path,
                    )
                    pipeline_entry["dispatch"] = dispatch_result

                    if dispatch_result.get("status") == "SENT":
                        pipeline_entry["stage"] = PipelineStage.ADVISORY_DISPATCHED
                        self._metrics["advisories_dispatched"] += 1

                # ── Create lead ──
                lead = self._create_lead(client, risk_report, pipeline_entry)
                pipeline_entry["lead"] = lead
                pipeline_entry["stage"] = PipelineStage.LEAD_CREATED
                self._metrics["leads_created"] += 1

        self._log_pipeline(pipeline_entry)
        self._save_metrics()

        return pipeline_entry

    def process_batch(
        self,
        findings: List[Dict],
        client: Optional[ClientContext] = None,
        auto_dispatch: bool = True,
    ) -> Dict[str, Any]:
        """
        Process multiple findings as a batch.
        Generates a single consolidated advisory for all CRITICAL/HIGH findings.
        """
        if not findings:
            return {"status": "NO_FINDINGS"}

        # Filter actionable findings
        actionable = [f for f in findings if f.get("severity", "").upper() in AUTO_TRIGGER_SEVERITIES]
        if not actionable:
            return {"status": "NO_ACTIONABLE_FINDINGS", "total": len(findings)}

        # Build client context
        if not client:
            first = actionable[0]
            client = ClientContext(
                org_id=first.get("org_id", "batch"),
                org_name=first.get("org_name", "Organization"),
                contact_email=first.get("contact_email", ""),
                region=first.get("region", "GLOBAL"),
                sector=first.get("sector", "DEFAULT"),
            )

        # Quantify all findings together
        try:
            from agent.analytics.executive_risk_engine import executive_risk_engine
            risk_report = executive_risk_engine.quantify(
                findings=actionable,
                region=client.region,
                sector=client.sector,
                annual_revenue_usd=client.annual_revenue_usd,
            )
        except Exception:
            risk_report = self._basic_risk_report_batch(actionable)

        # Generate consolidated PDF
        pdf_path = self._pdf_gen.generate(risk_report, client, actionable)

        result = {
            "findings_total": len(findings),
            "findings_actionable": len(actionable),
            "risk_report_id": risk_report.get("report_id"),
            "advisory_path": pdf_path,
            "ale_usd": risk_report.get("executive_summary", {}).get("annualized_loss_exposure_usd", 0),
        }

        # Dispatch
        if auto_dispatch and client.contact_email and pdf_path:
            dispatch_result = self._dispatch_advisory(client, risk_report, pdf_path)
            result["dispatch"] = dispatch_result

        return result

    def get_metrics(self) -> Dict:
        """Return pipeline conversion metrics."""
        return {
            **self._metrics,
            "conversion_rate": (
                round(self._metrics["conversions"] / max(self._metrics["leads_created"], 1) * 100, 1)
            ),
            "advisory_dispatch_rate": (
                round(self._metrics["advisories_dispatched"] / max(self._metrics["advisories_generated"], 1) * 100, 1)
            ),
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Internal Methods ──

    def _dispatch_advisory(
        self, client: ClientContext, risk_report: Dict, pdf_path: str
    ) -> Dict:
        """Dispatch advisory to client."""
        summary = risk_report.get("executive_summary", {})
        ale = summary.get("annualized_loss_exposure_usd", 0)
        rating = summary.get("risk_rating", "CRITICAL")

        subject = (
            f"[{rating}] Risk Mitigation Advisory — "
            f"${ale:,.0f} Projected Exposure | {client.org_name}"
        )

        html_body = self._dispatcher.build_advisory_email_html(client, risk_report)

        return self._dispatcher.dispatch_email(
            to_email=client.contact_email,
            to_name=client.contact_name or client.org_name,
            subject=subject,
            html_body=html_body,
            pdf_path=pdf_path,
        )

    def _create_lead(
        self, client: ClientContext, risk_report: Dict, pipeline_entry: Dict
    ) -> Dict:
        """Create a lead record for CRM tracking."""
        summary = risk_report.get("executive_summary", {})
        lead = {
            "lead_id": f"lead_{uuid.uuid4().hex[:12]}",
            "org_id": client.org_id,
            "org_name": client.org_name,
            "contact_email": client.contact_email,
            "contact_name": client.contact_name,
            "current_tier": client.current_tier,
            "target_tier": "ENTERPRISE" if summary.get("annualized_loss_exposure_usd", 0) > 500_000 else "PRO",
            "ale_usd": summary.get("annualized_loss_exposure_usd", 0),
            "rosi_pct": summary.get("rosi_percentage", 0),
            "region": client.region,
            "sector": client.sector,
            "pipeline_id": pipeline_entry.get("pipeline_id"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "NEW",
            "follow_up_date": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
            "source": "AUTO_CONVERSION_PIPELINE",
        }

        # Persist lead
        try:
            leads_file = DATA_DIR / "leads.jsonl"
            with open(leads_file, "a") as f:
                f.write(json.dumps(lead, default=str) + "\n")
        except Exception as e:
            logger.error(f"Lead persistence failed: {e}")

        return lead

    def _basic_risk_report(self, finding: Dict) -> Dict:
        """Fallback basic risk estimation when executive engine unavailable."""
        severity = finding.get("severity", "MEDIUM").upper()
        base_ale = {"CRITICAL": 1_000_000, "HIGH": 400_000, "MEDIUM": 100_000}.get(severity, 50_000)

        return {
            "report_id": f"CDB-BASIC-{uuid.uuid4().hex[:8]}",
            "executive_summary": {
                "total_risk_exposure_usd": base_ale * 1.5,
                "annualized_loss_exposure_usd": base_ale,
                "max_regulatory_fine_usd": base_ale * 2,
                "mitigated_value_usd": base_ale * 0.95,
                "rosi_percentage": (base_ale * 0.95 / 50_000) * 100,
                "rosi_ratio": base_ale * 0.95 / 50_000,
                "cost_of_inaction_3yr_usd": base_ale * 3.5,
                "risk_rating": severity,
            },
            "regulatory_exposure": {},
            "recommendations": [{
                "priority": "P0",
                "action": "Deploy CDB SENTINEL APEX for continuous monitoring",
                "impact": f"Mitigate ${base_ale * 0.95:,.0f} in projected losses",
            }],
        }

    def _basic_risk_report_batch(self, findings: List[Dict]) -> Dict:
        """Batch fallback."""
        total_ale = sum(
            {"CRITICAL": 1_000_000, "HIGH": 400_000, "MEDIUM": 100_000}.get(
                f.get("severity", "MEDIUM").upper(), 50_000
            ) for f in findings
        )
        return {
            "report_id": f"CDB-BATCH-{uuid.uuid4().hex[:8]}",
            "executive_summary": {
                "total_risk_exposure_usd": total_ale * 1.5,
                "annualized_loss_exposure_usd": total_ale,
                "max_regulatory_fine_usd": total_ale * 2,
                "mitigated_value_usd": total_ale * 0.95,
                "rosi_percentage": (total_ale * 0.95 / 50_000) * 100,
                "rosi_ratio": total_ale * 0.95 / 50_000,
                "cost_of_inaction_3yr_usd": total_ale * 3.5,
                "risk_rating": "CRITICAL" if total_ale > 2_000_000 else "HIGH",
            },
            "regulatory_exposure": {},
            "recommendations": [],
        }

    def _log_pipeline(self, entry: Dict):
        """Log pipeline event."""
        self._pipeline_log.append(entry)
        try:
            with open(PIPELINE_LOG, "w") as f:
                json.dump(self._pipeline_log[-1000:], f, indent=2, default=str)
        except Exception:
            pass

    def _save_metrics(self):
        try:
            with open(METRICS_FILE, "w") as f:
                json.dump(self._metrics, f, indent=2)
        except Exception:
            pass

    def _load_metrics(self):
        if METRICS_FILE.exists():
            try:
                with open(METRICS_FILE, "r") as f:
                    self._metrics.update(json.load(f))
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

conversion_pipeline = ConversionPipeline()
