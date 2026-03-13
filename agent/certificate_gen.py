#!/usr/bin/env python3
"""
certificate_gen.py — CYBERDUDEBIVASH® SENTINEL APEX
INSTITUTIONAL SECURITY CERTIFICATE GENERATOR
Mandate: Automatic Brand Authority & Forensic Verification.
"""

import os
import qrcode
import logging
from fpdf import FPDF
from datetime import datetime
from agent.sovereignty_engine import sovereign_engine

logger = logging.getLogger("CDB-CERT-GEN")

class CertificateGenerator:
    def __init__(self, output_dir="data/certificates"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.verification_url = "https://www.cyberdudebivash.com/verify"

    def generate_cert(self, intel_data, signature):
        """Generates a professional PDF certificate with embedded QR code."""
        cert_id = f"CDB-CERT-{int(datetime.now().timestamp())}"
        pdf = FPDF(orientation='L', unit='mm', format='A4')
        pdf.add_page()
        
        # 1. Institutional Branding & Borders
        pdf.set_draw_color(0, 212, 170) # CDB Emerald
        pdf.set_line_width(2)
        pdf.rect(5, 5, 287, 200)
        
        # 2. Header Area
        pdf.set_font("Helvetica", 'B', 24)
        pdf.set_text_color(21, 26, 36) # Dark Navy
        pdf.cell(0, 30, "CYBERDUDEBIVASH® SENTINEL APEX", ln=True, align='C')
        pdf.set_font("Helvetica", '', 16)
        pdf.cell(0, 10, "OFFICIAL CERTIFICATE OF AUTHENTICITY", ln=True, align='C')
        
        # 3. Intelligence Details
        pdf.ln(15)
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(0, 10, f"Threat ID: {intel_data.get('threat_id', 'N/A')}", ln=True)
        pdf.cell(0, 10, f"Asset Name: {intel_data['title']}", ln=True)
        pdf.cell(0, 10, f"Issue Date: {datetime.now().strftime('%B %d, 2026')}", ln=True)
        pdf.cell(0, 10, f"Certificate ID: {cert_id}", ln=True)

        # 4. QR Code Generation for Instant Verification
        qr_data = f"{self.verification_url}?sig={signature}&id={cert_id}"
        qr = qrcode.make(qr_data)
        qr_path = os.path.join(self.output_dir, f"qr_{cert_id}.png")
        qr.save(qr_path)
        pdf.image(qr_path, x=230, y=140, w=40)
        
        # 5. Technical Signature Block
        pdf.set_y(150)
        pdf.set_font("Courier", 'I', 8)
        pdf.multi_cell(180, 5, f"TECHNICAL SIGNATURE (RSA-2048):\n{signature}")
        
        # Final Output
        file_path = os.path.join(self.output_dir, f"CERT_{cert_id}.pdf")
        pdf.output(file_path)
        logger.info(f"✅ CERTIFICATE GENERATED: {file_path}")
        return file_path

# Initialize for use in Asset Factory
certificate_engine = CertificateGenerator()
