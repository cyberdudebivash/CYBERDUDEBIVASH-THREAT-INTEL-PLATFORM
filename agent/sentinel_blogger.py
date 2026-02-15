#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.2 (BEAST MODE)
Full Integration: Ingestion -> MITRE -> Enrichment -> PDF Gen -> Dispatch.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone

import feedparser
from fpdf import FPDF  # Requires: pip install fpdf2

# Path resolution for Enterprise Environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Platform Module Imports
from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY
)
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

# --- BEAST MODE MODULES ---
class MITREMapper:
    def __init__(self):
        self.mapping_db = {
            "phishing": {"id": "T1566", "tactic": "Initial Access"},
            "credential": {"id": "T1556", "tactic": "Credential Access"},
            "c2": {"id": "T1071", "tactic": "Command and Control"},
            "beacon": {"id": "T1071.004", "tactic": "Command and Control"},
            "ransomware": {"id": "T1486", "tactic": "Impact"}
        }

    def map_threat(self, corpus: str) -> list:
        matches = []
        corpus_lower = corpus.lower()
        for keyword, meta in self.mapping_db.items():
            if keyword in corpus_lower:
                matches.append(meta)
        return [dict(t) for t in {tuple(d.items()) for d in matches}]

class CDBWhitepaper(FPDF):
    def header(self):
        self.set_fill_color(10, 10, 10)
        self.rect(0, 0, 210, 297, 'F')
        self.set_font('Arial', 'B', 20)
        self.set_text_color(0, 212, 170)
        self.cell(0, 15, 'CDB SENTINEL APEX v7.2', ln=True, align='L')
        self.ln(10)

    def create_report(self, headline, risk, iocs, mitre, filename):
        self.add_page()
        self.set_font('Arial', 'B', 14)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, f"Advisory: {headline}", ln=True)
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, f"Risk Score: {risk}/10\nMITRE Techniques: {len(mitre)}")
        
        output_dir = "data/whitepapers"
        os.makedirs(output_dir, exist_ok=True)
        self.output(os.path.join(output_dir, filename))

# --- CORE ORCHESTRATION ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-APEX] %(message)s")
logger = logging.getLogger("CDB-MAIN")
mitre_engine = MITREMapper()
pdf_engine = CDBWhitepaper()

def _calculate_cdb_risk_score(headline: str, corpus: str, iocs: dict, mitre_context: list) -> float:
    score = 6.5
    if len(mitre_context) > 0: score += 1.0
    if len(iocs.get('ipv4', [])) > 5: score += 1.5
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nCYBERDUDEBIVASH SENTINEL APEX v7.2 — PRODUCTION ACTIVE\n" + "="*60)

    try:
        # 1. Ingestion Cycle
        processed = set()
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                processed = set(json.load(f)[-MAX_STATE_SIZE:])

        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid", entry.link)
                if guid not in processed:
                    intel_items.append({"title": entry.title, "link": entry.link, "summary": entry.get("summary", "")})
                    processed.add(guid)
        
        if not intel_items:
            logger.info("No new threat vectors. Updating manifest for stability.")
            stix_exporter.update_manifest()
            return

        # 2. Intelligence Enrichment
        corpus = " ".join([i['summary'] for i in intel_items])
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {v: {**enricher_pro.get_ip_context(v), "reputation": vt_lookup.get_reputation(v, "ipv4")} for v in extracted_iocs.get('ipv4', [])}
        
        # 3. Report Triage
        headline = generate_headline(intel_items)
        risk_score = _calculate_cdb_risk_score(headline, corpus, extracted_iocs, mitre_context)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # Fixed call signature to match blog_post_generator.py
        full_html = generate_full_post_content(
            intel_items, extracted_iocs, enriched_metadata, 
            visualizer.generate_heat_map(enriched_metadata), 
            stix_id, mitre_data=mitre_context
        )
        
        # 4. Global Dispatch
        service = get_blogger_service()
        post = service.posts().insert(blogId=os.environ.get('BLOG_ID'), body={
            "title": f"[v7.2] {headline} (Score: {risk_score}/10)",
            "content": full_html,
            "labels": ["Sentinel-Apex", "MITRE", "Enterprise-Advisory"]
        }).execute()

        if post.get("url"):
            logger.info(f"✓ Report Live: {post['url']}")
            with open(STATE_FILE, "w") as f: json.dump(list(processed), f)
            
            # v7.2 Actions: PDF and STIX
            if risk_score >= 7.0:
                pdf_engine.create_report(headline, risk_score, extracted_iocs, mitre_context, f"{stix_id}.pdf")
            
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata, mitre_data=mitre_context)
            send_sentinel_alert(headline, risk_score, post['url'])

    except Exception as e:
        logger.critical(f"APEX FAILURE: {e}")
        raise

if __name__ == "__main__":
    main()
