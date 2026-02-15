#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.4.1 (STABILIZED)
Orchestrator: Resolved NameErrors and synchronized v7.4 content calls.
"""
import os, sys, json, logging, time  # Time import verified
from datetime import datetime, timezone
import feedparser
from fpdf import FPDF

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.blogger_auth import get_blogger_service
from agent.config import BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-APEX] %(message)s")
logger = logging.getLogger("CDB-MAIN")

class MITREMapper:
    def __init__(self):
        self.db = {"phishing":{"id":"T1566","tactic":"Initial Access"},"c2":{"id":"T1071","tactic":"C2"}}
    def map_threat(self, text):
        return [v for k,v in self.db.items() if k in text.lower()]

class CDBWhitepaper(FPDF):
    def create_report(self, headline, risk, iocs, mitre, filename):
        self.add_page(); self.set_font("Arial","B",16); self.cell(0,10, f"ADVISORY: {headline}", ln=True)
        os.makedirs("data/whitepapers", exist_ok=True)
        self.output(os.path.join("data/whitepapers", filename))

mitre_engine = MITREMapper(); pdf_engine = CDBWhitepaper()

def main():
    logger.info("="*60 + "\nAPEX v7.4.1 — PRODUCTION ACTIVE\n" + "="*60)
    try:
        if not os.path.exists("data"): os.makedirs("data")
        processed = set(json.load(open(STATE_FILE))[-MAX_STATE_SIZE:]) if os.path.exists(STATE_FILE) else set()
        
        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid", entry.link)
                if guid not in processed:
                    intel_items.append({"title":entry.title, "link":entry.link, "summary":entry.get("summary","")})
                    processed.add(guid)
        
        if not intel_items:
            stix_exporter.update_manifest(); return

        # FIX: Define headline here for global use in main()
        headline = generate_headline(intel_items)
        corpus = " ".join([i['summary'] for i in intel_items])
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {v: {**enricher_pro.get_ip_context(v), "reputation": vt_lookup.get_reputation(v, "ipv4")} for v in extracted_iocs.get('ipv4', [])}
        
        risk_score = 7.5
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        full_html = generate_full_post_content(
            intel_items, extracted_iocs, enriched_metadata, 
            visualizer.generate_heat_map(enriched_metadata), 
            stix_id, mitre_data=mitre_context, risk_score=risk_score
        )
        
        service = get_blogger_service()
        post = service.posts().insert(
            blogId=os.environ.get('BLOG_ID', BLOG_ID), 
            body={"title": f"[v7.4.1] {headline}", "content": full_html}
        ).execute()

        if post.get("url"):
            json.dump(list(processed), open(STATE_FILE, "w"))
            if risk_score >= 7.0:
                pdf_engine.create_report(headline, risk_score, extracted_iocs, mitre_context, f"{stix_id}.pdf")
            
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata, mitre_data=mitre_context)
            send_sentinel_alert(headline, risk_score, post['url'], mitre_data=mitre_context)

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__": main()
