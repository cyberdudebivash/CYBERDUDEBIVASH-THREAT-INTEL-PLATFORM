#!/usr/bin/env python3
"""
premium_report_generator.py — CyberDudeBivash v16.4
The "Intelligence Architect": Generates premium signed reports.
"""
import logging
from typing import Dict
from agent.enricher import enricher
from agent.risk_engine import risk_engine

logger = logging.getLogger("CDB-GENERATOR")

class PremiumReportGenerator:
    def __init__(self):
        self.target_word_count = 2500

    def prepare_report(self, entry: Dict) -> Dict:
        """Synthesizes raw feed data into an enriched intelligence object."""
        logger.info(f"🏗️ ARCHITECT: Preparing data for: {entry['title'][:50]}")
        
        # v16.4 Handshake with v11.0 Enricher
        enriched_content = enricher.enrich(entry['link'])
        
        try:
            score_data = risk_engine.analyze(enriched_content)
        except Exception:
            score_data = {"score": 8.0, "severity": "HIGH"}

        return {
            "headline": entry['title'],
            "link": entry['link'],
            "content_raw": enriched_content,
            "technical_dive": enriched_content[:2000],
            "risk_score": score_data.get('score', 8.0),
            "severity": score_data.get('severity', 'HIGH')
        }

    def generate_html(self, data: Dict) -> str:
        """Renders the final Sovereign Intelligence HTML template."""
        signature = data.get('signature', 'VERIFICATION_FAILED')
        return f"""
        <div style="font-family: sans-serif; border: 2px solid #1a1a1a; padding: 20px;">
            <h1 style="color: #d32f2f;">🚨 THREAT ADVISORY: {data['headline']}</h1>
            <p><strong>Risk Score:</strong> {data['risk_score']}/10</p>
            <div style="background: #f9f9f9; padding: 10px; border-left: 5px solid #d32f2f;">
                {data['technical_dive']}
            </div>
            <p style="font-size: 0.8em; margin-top: 20px;">Signature: {signature}</p>
        </div>
        """

# MANDATORY: Explicitly create and export the instance for sentinel_blogger.py
premium_report_gen = PremiumReportGenerator()
