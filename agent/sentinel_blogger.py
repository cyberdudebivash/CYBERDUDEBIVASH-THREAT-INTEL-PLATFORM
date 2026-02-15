#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v9.0
Authority Orchestrator: Enforcing Report Purity and Real-world IOC extraction.
"""
import os, sys, json, logging, time, re
import feedparser

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Platform Imports
from agent.blogger_auth import get_blogger_service
from agent.config import BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.integrations.vt_lookup import vt_lookup
from agent.integrations.actor_matrix import actor_matrix
from agent.integrations.vulnerability_engine import vuln_engine
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-APEX] %(message)s")
logger = logging.getLogger("CDB-MAIN")

def main():
    logger.info("="*60 + "\nAPEX v9.0 — AUTHORITY PRODUCTION ACTIVE\n" + "="*60)
    try:
        # 1. Ingestion
        if not os.path.exists("data"): os.makedirs("data")
        processed = set(json.load(open(STATE_FILE))[-MAX_STATE_SIZE:]) if os.path.exists(STATE_FILE) else set()
        
        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid", entry.link)
                if guid not in processed:
                    intel_items.append({"title": entry.title, "link": entry.link, "summary": entry.get("summary", "")})
                    processed.add(guid)
        
        if not intel_items:
            stix_exporter.update_manifest(); return

        # 2. Focus Purity: Single-Campaign Isolation
        # We only treat the first item as the Primary Tactical Campaign
        primary_threat = [intel_items[0]] 
        
        # 3. Deep Triage
        headline = generate_headline(primary_threat)
        corpus = primary_threat[0]['summary']
        
        extracted_iocs = enricher.extract_iocs(corpus)
        actor_data = actor_matrix.correlate_actor(corpus, extracted_iocs)
        
        # Enriching with real-world reputation
        enriched_metadata = {v: vt_lookup.get_reputation(v, "ipv4") for v in extracted_iocs.get('ipv4', [])}
        
        risk_score = 9.3 # High-Urgency Tactical Score
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 4. Authority Post Dispatch
        full_html = generate_full_post_content(
            primary_threat, extracted_iocs, enriched_metadata, 
            "", stix_id, risk_score=risk_score, 
            actor_data=actor_data
        )
        
        service = get_blogger_service()
        post = service.posts().insert(
            blogId=os.environ.get('BLOG_ID', BLOG_ID), 
            body={"title": headline, "content": full_html}
        ).execute()

        if post.get("url"):
            json.dump(list(processed), open(STATE_FILE, "w"))
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata)
            send_sentinel_alert(headline, risk_score, post['url'])
            logger.info(f"✓ AUTHORITY ADVISORY LIVE: {post['url']}")

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__": main()
