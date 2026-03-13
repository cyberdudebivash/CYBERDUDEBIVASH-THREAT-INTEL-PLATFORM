"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Bug Hunter Report Generator
===================================================================
Generates branded PDF security audit reports with risk scoring,
financial impact metrics, and remediation strategies.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-BH-REPORT")

_REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "bughunter", "reports")


class ReportGenerator:
    """Generates structured audit reports from scan results."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or _REPORTS_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    def calculate_risk_score(self, findings: List[Dict]) -> int:
        """Proprietary risk scoring algorithm."""
        if not findings:
            return 0

        score = 0
        for f in findings:
            f_type = f.get("type", "").upper()
            severity = f.get("severity", "MEDIUM").upper()

            type_weights = {
                "BOLA": 40, "CLOUD_LEAK": 35, "SUBDOMAIN_TAKEOVER": 30,
                "SECRET_LEAK": 45, "OPEN_PORT": 15,
            }
            score += type_weights.get(f_type, 10)

            if severity == "CRITICAL":
                score += 10
            elif severity == "HIGH":
                score += 5

        return min(score, 100)

    def generate_text_report(self, scan_data: Dict) -> str:
        """Generate a structured text report (PDF generation requires fpdf)."""
        domain = scan_data.get("domain", "unknown")
        findings = scan_data.get("findings", [])
        roi = scan_data.get("roi_metrics", {})
        risk_score = self.calculate_risk_score(findings)

        lines = [
            "=" * 70,
            "CYBERDUDEBIVASH® BUG HUNTER — SECURITY AUDIT REPORT",
            "=" * 70,
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Target: {domain}",
            f"CyberDudeBivash Risk Score: {risk_score}/100",
            "",
            "─" * 70,
            "1. EXECUTIVE RISK ASSESSMENT",
            "─" * 70,
            f"Total findings: {len(findings)}",
            f"Critical: {sum(1 for f in findings if f.get('severity') == 'CRITICAL')}",
            f"High: {sum(1 for f in findings if f.get('severity') == 'HIGH')}",
            f"Medium: {sum(1 for f in findings if f.get('severity') == 'MEDIUM')}",
            "",
        ]

        if roi:
            lines.extend([
                "─" * 70,
                "2. FINANCIAL IMPACT ANALYSIS",
                "─" * 70,
                f"Total Risk Exposure: ${roi.get('total_risk_exposure', 0):,.2f}",
                f"Mitigated Value: ${roi.get('mitigated_value', 0):,.2f}",
                f"Platform ROSI: {roi.get('rosi_percentage', 0):.1f}%",
                "",
            ])

        lines.extend([
            "─" * 70,
            "3. TECHNICAL FINDINGS",
            "─" * 70,
        ])

        if not findings:
            lines.append("No critical vulnerabilities identified during this cycle.")
        else:
            for i, f in enumerate(findings, 1):
                lines.extend([
                    f"  [{i}] {f.get('type', 'UNKNOWN')} — {f.get('severity', 'N/A')}",
                    f"      Target: {f.get('url') or f.get('host') or f.get('bucket', 'N/A')}",
                    f"      Evidence: {f.get('evidence', 'See technical details')}",
                    "",
                ])

        lines.extend([
            "─" * 70,
            "4. REMEDIATION STRATEGY",
            "─" * 70,
            "  1. Enforce BOLA validation on all user-specific API endpoints.",
            "  2. Audit cloud storage bucket policies for public access.",
            "  3. Remove hardcoded secrets from client-side JavaScript.",
            "  4. Implement CNAME lifecycle management to prevent takeovers.",
            "  5. Restrict exposed ports to required services only.",
            "",
            "─" * 70,
            f"Confidential — CyberDudeBivash Pvt. Ltd.",
            f"Official Authority: Bivash Kumar, Founder & CEO",
            "=" * 70,
        ])

        return "\n".join(lines)

    def save_report(self, scan_data: Dict) -> Optional[str]:
        """Save report to file and return path."""
        domain = scan_data.get("domain", "unknown")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"CDB_BugHunter_Audit_{domain}_{timestamp}.txt"
        filepath = os.path.join(self.output_dir, filename)

        try:
            report_text = self.generate_text_report(scan_data)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_text)
            logger.info(f"[REPORT] Saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"[REPORT] Failed to save: {e}")
            return None

    def generate_pdf_report(self, scan_data: Dict) -> Optional[str]:
        """Generate PDF report using fpdf2 (if installed)."""
        try:
            from fpdf import FPDF
        except ImportError:
            logger.warning("[REPORT] fpdf not installed — falling back to text report")
            return self.save_report(scan_data)

        domain = scan_data.get("domain", "unknown")
        findings = scan_data.get("findings", [])
        roi = scan_data.get("roi_metrics", {})
        risk_score = self.calculate_risk_score(findings)

        pdf = FPDF()
        pdf.add_page()

        # Header
        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(220, 20, 60)
        pdf.cell(0, 12, "CYBERDUDEBIVASH BUG HUNTER", 0, 1, "C")
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "SECURITY AUDIT REPORT", 0, 1, "C")
        pdf.set_font("Arial", "I", 9)
        pdf.set_text_color(100)
        pdf.cell(0, 6, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC", 0, 1, "C")
        pdf.ln(8)

        # Risk Score
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(0)
        pdf.cell(0, 8, f"Target: {domain}", 0, 1)
        pdf.cell(0, 8, f"Risk Score: {risk_score}/100", 0, 1)

        # Risk bar
        color = (220, 20, 60) if risk_score >= 70 else (255, 165, 0) if risk_score >= 40 else (34, 139, 34)
        pdf.set_fill_color(*color)
        pdf.rect(10, pdf.get_y(), risk_score * 1.8, 5, "F")
        pdf.ln(10)

        # Findings
        pdf.set_font("Arial", "B", 11)
        pdf.cell(0, 8, "VULNERABILITY FINDINGS", 0, 1)
        pdf.set_font("Arial", "", 9)

        for f in findings:
            pdf.set_text_color(220, 20, 60)
            pdf.cell(0, 6, f"[{f.get('severity', 'N/A')}] {f.get('type', 'UNKNOWN')}", 0, 1)
            pdf.set_text_color(0)
            pdf.cell(0, 5, f"  Target: {f.get('url') or f.get('host', 'N/A')}", 0, 1)
            pdf.ln(2)

        # Financial
        if roi:
            pdf.ln(4)
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 8, "FINANCIAL IMPACT", 0, 1)
            pdf.set_font("Arial", "", 9)
            pdf.cell(0, 6, f"Risk Exposure: ${roi.get('total_risk_exposure', 0):,.2f}", 0, 1)
            pdf.cell(0, 6, f"Mitigated: ${roi.get('mitigated_value', 0):,.2f}", 0, 1)
            pdf.cell(0, 6, f"ROSI: {roi.get('rosi_percentage', 0):.1f}%", 0, 1)

        # Footer
        pdf.set_y(-20)
        pdf.set_font("Arial", "I", 8)
        pdf.set_text_color(128)
        pdf.cell(0, 6, "Confidential - CyberDudeBivash Pvt. Ltd.", 0, 0, "C")

        # Save
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"CDB_BugHunter_Audit_{domain}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        try:
            pdf.output(filepath)
            logger.info(f"[REPORT] PDF saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"[REPORT] PDF generation failed: {e}")
            return self.save_report(scan_data)
