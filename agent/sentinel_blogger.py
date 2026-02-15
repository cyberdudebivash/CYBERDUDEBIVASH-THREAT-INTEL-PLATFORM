#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.4.1 (STABILIZED BEAST MODE)
Orchestrator: Ingestion -> MITRE -> Enrichment -> PDF -> TLP -> Alerts.
"""
import os, sys, json, logging, time
from datetime import datetime, timezone
import feedparser
from fpdf import FPDF

# System Path Alignment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Platform Imports
from agent.blogger_auth import get_blogger_service
from agent.config import BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

# Global Logging
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

def _calculate_cdb_risk_score(headline, corpus, iocs, mitre_context):
    """Dynamic risk calculation for TLP marking."""
    score = 6.5
    if len(mitre_context) > 0: score += 1.5
    if len(iocs.get('ipv4', [])) > 5: score += 1.0
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nAPEX v7.4.1 — PRODUCTION ACTIVE (STABILIZED)\n" + "="*60)
    try:
        # 1. State/Ingestion Logic
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
            logger.info("No new items found. Syncing manifest only.")
            stix_exporter.update_manifest(); return

        # 2. Intelligence Triage (Scope: Global to main())
        # FIX: Define 'headline' here to prevent NameError in post call
        headline = generate_headline(intel_items)
        corpus = " ".join([i['summary'] for i in intel_items])
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {v: {**enricher_pro.get_ip_context(v), "reputation": vt_lookup.get_reputation(v, "ipv4")} for v in extracted_iocs.get('ipv4', [])}
        
        risk_score = _calculate_cdb_risk_score(headline, corpus, extracted_iocs, mitre_context)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 3. Content Synthesis (TLP Awareness)
        full_html = generate_full_post_content(
            intel_items, extracted_iocs, enriched_metadata, 
            visualizer.generate_heat_map(enriched_metadata), 
            stix_id, mitre_data=mitre_context, risk_score=risk_score
        )
        
        # 4. Authenticated Dispatch
        service = get_blogger_service()
        # Ensure BLOG_ID is pulled from env if possible
        post = service.posts().insert(
            blogId=os.environ.get('BLOG_ID', BLOG_ID), 
            body={"title": f"[v7.4.1] {headline}", "content": full_html}
        ).execute()

        if post.get("url"):
            # Persistence Logic
            json.dump(list(processed), open(STATE_FILE, "w"))
            
            # 5. Asset Generation & Alerts
            if risk_score >= 7.0:
                pdf_engine.create_report(headline, risk_score, extracted_iocs, mitre_context, f"{stix_id}.pdf")
            
            # Synchronized STIX/Alert calls
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata, mitre_data=mitre_context)
            send_sentinel_alert(headline, risk_score, post['url'], mitre_data=mitre_context)
            logger.info(f"✓ ENTERPRISE ADVISORY DISPATCHED: {post['url']}")

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__": main()
