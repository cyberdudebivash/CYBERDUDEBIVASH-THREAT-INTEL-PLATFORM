#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.2.1
Synchronized Core: Ingestion -> MITRE -> Enrichment -> PDF Gen -> Blogger.
"""
import os, sys, json, logging, time
from datetime import datetime, timezone
import feedparser
from fpdf import FPDF # v7.2 Asset Generation

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.blogger_auth import get_blogger_service
from agent.config import RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter

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
    logger.info("="*60 + "\nCYBERDUDEBIVASH SENTINEL APEX v7.2.1 — BEAST MODE RUN\n" + "="*60)
    try:
        # 1. State/Ingestion
        processed = set(json.load(open(STATE_FILE))[-MAX_STATE_SIZE:]) if os.path.exists(STATE_FILE) else set()
        intel_items = []
        for url in RSS_FEEDS:
            for entry in feedparser.parse(url).entries[:MAX_PER_FEED]:
                guid = entry.get("guid", entry.link)
                if guid not in processed:
                    intel_items.append({"title":entry.title, "link":entry.link, "summary":entry.get("summary","")})
                    processed.add(guid)
        
        if not intel_items:
            stix_exporter.update_manifest(); return

        # 2. Intelligence Cycle
        corpus = " ".join([i['summary'] for i in intel_items])
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {v: {**enricher_pro.get_ip_context(v), "reputation": vt_lookup.get_reputation(v, "ipv4")} for v in extracted_iocs.get('ipv4', [])}
        
        # 3. Report Assembly
        headline = generate_headline(intel_items)
        stix_id = f"CDB-APEX-{int(time.time())}"
        full_html = generate_full_post_content(
            intel_items, extracted_iocs, enriched_metadata, 
            visualizer.generate_heat_map(enriched_metadata), 
            stix_id, mitre_data=mitre_context # Fixed TypeError
        )
        
        # 4. Authenticated Dispatch
        service = get_blogger_service()
        post = service.posts().insert(blogId=os.environ.get('BLOG_ID'), body={
            "title": f"[v7.2.1] {headline}",
            "content": full_html,
            "labels": ["Sentinel-Apex", "MITRE", "Enterprise-Advisory"]
        }).execute()

        if post.get("url"):
            json.dump(list(processed), open(STATE_FILE, "w"))
            pdf_engine.create_report(headline, 7.5, extracted_iocs, mitre_context, f"{stix_id}.pdf")
            stix_exporter.create_bundle(headline, extracted_iocs, 7.5, enriched_metadata, mitre_data=mitre_context)
            logger.info(f"✓ REPORT PUBLISHED: {post['url']}")

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}")
        raise

if __name__ == "__main__": main()
