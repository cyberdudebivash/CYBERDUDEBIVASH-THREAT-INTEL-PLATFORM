#!/usr/bin/env python3
"""
pdf_generator.py — CyberDudeBivash v7.2
Automated Enterprise Whitepaper Generator.
"""
import os
from fpdf import FPDF # Requires: pip install fpdf2

class CDBWhitepaper(FPDF):
    def header(self):
        self.set_fill_color(5, 5, 5) # Deep Dark Background
        self.rect(0, 0, 210, 297, 'F')
        self.set_font('Arial', 'B', 20)
        self.set_text_color(0, 212, 170) # Neon Teal
        self.cell(0, 10, 'CDB SENTINEL APEX', ln=True, align='L')
        self.set_font('Arial', '', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, 'CYBERDUDEBIVASH PVT. LTD. | ENTERPRISE ADVISORY', ln=True, align='L')
        self.ln(10)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_text_color(0, 212, 170)
        self.cell(0, 10, f"[#] {title}", ln=True)
        self.ln(5)

    def create_report(self, headline, risk_score, iocs, mitre_data, filename):
        self.add_page()
        self.set_text_color(255, 255, 255)
        
        # BLUF
        self.chapter_title("EXECUTIVE SUMMARY (BLUF)")
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, f"THREAT: {headline}\nRISK SCORE: {risk_score}/10\nSTATUS: ACTIVE EXPLOITATION DETECTED")
        self.ln(10)

        # MITRE Mapping
        if mitre_data:
            self.chapter_title("TACTICAL ATTRIBUTION (MITRE ATT&CK)")
            for tech in mitre_data:
                self.set_font('Arial', 'B', 9)
                self.cell(0, 5, f"- {tech['id']}: {tech['tactic']}", ln=True)
        
        # Save PDF
        output_path = f"data/whitepapers/{filename}"
        os.makedirs("data/whitepapers", exist_ok=True)
        self.output(output_path)
        return output_path

pdf_engine = CDBWhitepaper()
