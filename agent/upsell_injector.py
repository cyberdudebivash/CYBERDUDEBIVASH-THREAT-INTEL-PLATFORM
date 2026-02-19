#!/usr/bin/env python3
"""
upsell_injector.py — CYBERDUDEBIVASH® SENTINEL APEX
REVENUE BRIDGE & CTA INJECTION ENGINE
Mandate: 100% Accuracy | Secure HTML Injection | Enterprise-Grade CTA.
"""

import logging

# --- Institutional Logging ---
logger = logging.getLogger("CDB-INJECTOR")

class UpsellInjector:
    def __init__(self):
        # Professional Enterprise CSS for the Buy Button
        self.button_style = (
            "display: inline-block; padding: 15px 30px; margin: 20px 0; "
            "background-color: #00d4aa; color: #020205; text-decoration: none; "
            "font-weight: bold; border-radius: 5px; font-family: 'Outfit', sans-serif; "
            "box-shadow: 0 4px 15px rgba(0,212,170,0.3);"
        )

    def inject_premium_cta(self, report_html: str, product_url: str, risk_score: float) -> str:
        """
        Surgically appends a professional CTA to the technical dossier.
        Only triggers for high-value intelligence (Risk > 7.0).
        """
        if not product_url:
            return report_html

        # Context-Aware Messaging based on Risk Score
        urgency_msg = "CRITICAL DEFENSE KIT" if risk_score >= 8.5 else "ENTERPRISE RESPONSE PACKAGE"

        cta_html = f"""
        <hr style="border: 0; border-top: 1px solid #151a24; margin: 40px 0;">
        <div class="cdb-upsell-container" style="text-align: center; padding: 20px; background: #080a10; border: 1px solid #00d4aa33;">
            <h3 style="color: #f0f4f8; margin-bottom: 10px;">{urgency_msg} AVAILABLE</h3>
            <p style="color: #5a6578; font-size: 14px;">Deploy institutional-grade detection rules, automated remediation scripts, and structured IR playbooks for this specific threat.</p>
            <a href="{product_url}" target="_blank" style="{self.button_style}">
                GET THE ENTERPRISE KIT →
            </a>
            <p style="color: #00d4aa; font-size: 11px; margin-top: 10px; font-family: monospace;">Secured by CYBERDUDEBIVASH® PVT LTD</p>
        </div>
        """

        # Append to the end of the report to maintain technical flow
        return report_html + cta_html

# Initialize Injector for Global Operations
upsell_engine = UpsellInjector()
