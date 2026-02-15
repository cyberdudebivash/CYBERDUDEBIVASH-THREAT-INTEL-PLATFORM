#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v10.1 (APEX ELITE)
Orchestrator: Focus Purity, GOC Branding, and Manifest Sync
"""
import os, sys, json, logging, time, re
import feedparser

# System Path Alignment for GitHub Actions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.blogger_auth import get_blogger_service
from agent.config import BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.enricher import enricher
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

# GOC Branding Initialization
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-GOC] %(message)s")
logger = logging.getLogger("CDB-MAIN")

def main():
    logger.info("="*60 + "\nAPEX v10.1 — GOC AUTHORITY ACTIVATED\n" + "="*60)
    try:
        # 1. Manifest Initialization
        if not os.path.exists("data"): os.makedirs("data")
        processed = set(json.load(open(STATE_FILE))) if os.path.exists(STATE_FILE) else set()
        
        # 2. Focus Purity: Single-Campaign Isolation
        # Ingest the latest tactical entry only to ensure content depth
        feed = feedparser.parse(RSS_FEEDS[0])
        if not feed.entries: return
        
        entry = feed.entries[0]
        if entry.id in processed:
            logger.info("GOC Neural Manifest up-to-date. Syncing..."); return
            
        primary_threat = [{"title": entry.title, "summary": entry.summary, "link": entry.link}]
        
        # 3. Multi-Pillar Analysis
        extracted_iocs = enricher.extract_iocs(entry.summary)
        headline = generate_headline(primary_threat)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 4. Apex Elite Dossier Generation
        full_html = generate_full_post_content(
            primary_threat, extracted_iocs, {}, "", stix_id, risk_score=9.3
        )
        
        # 5. Institutional Publishing
        service = get_blogger_service()
        service.posts().insert(
            blogId=os.environ.get('BLOG_ID', BLOG_ID), 
            body={"title": headline, "content": full_html}
        ).execute()
        
        # 6. Global Sync (STIX 2.1 & Dashboard)
        processed.add(entry.id)
        with open(STATE_FILE, "w") as f: json.dump(list(processed), f)
        stix_exporter.create_bundle(headline, extracted_iocs, 9.3, {"blog_url": entry.link})
        
        logger.info(f"✓ GOC ELITE ADVISORY LIVE: {headline}")

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__": main()
