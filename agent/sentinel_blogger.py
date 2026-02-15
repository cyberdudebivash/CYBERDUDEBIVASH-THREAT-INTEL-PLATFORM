#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v10.0 (APEX PREDATOR)
Final Orchestrator: Multi-Pillar Triage, Dependency Fixed, and ImportError Resolved.
"""
import os, sys, json, logging, time, re  # FIXED: 're' import preserved
import feedparser

# System Path Alignment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# FIXED: Corrected import signature to match generator exports
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.blogger_auth import get_blogger_service
from agent.config import BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.enricher import enricher
from agent.integrations.vt_lookup import vt_lookup
from agent.integrations.actor_matrix import actor_matrix
from agent.integrations.vulnerability_engine import vuln_engine
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-APEX] %(message)s")
logger = logging.getLogger("CDB-MAIN")

def main():
    logger.info("="*60 + "\nAPEX v10.0 — GLOBAL AUTHORITY ACTIVATED\n" + "="*60)
    try:
        # 1. World-Class Ingestion & Focus Purity
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
            logger.info("Syncing manifest."); stix_exporter.update_manifest(); return

        # 2. Apex Triage: Isolating the Primary Campaign
        # v10.0 strictly produces ONE long-form dossier per tactical threat.
        primary_threat = [intel_items[0]] 
        
        # 3. Multi-Pillar Analysis
        headline = generate_headline(primary_threat)
        corpus = primary_threat[0]['summary']
        
        # Pillar A & B: Extraction
        extracted_iocs = enricher.extract_iocs(corpus)
        actor_data = actor_matrix.correlate_actor(corpus, extracted_iocs)
        
        # Pillar C: Vulnerability Check (Uses fixed 're' import)
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", corpus) 
        cve_id = cve_match.group(0) if cve_match else None
        cve_data = vuln_engine.get_cve_deep_dive(cve_id) if cve_id else None
        
        risk_score = 9.8 if any(extracted_iocs.values()) else 7.5
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 4. Final Intelligence Dispatch
        full_html = generate_full_post_content(
            primary_threat, extracted_iocs, {}, 
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
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, {})
            send_sentinel_alert(headline, risk_score, post['url'])
            logger.info(f"✓ APEX PREDATOR ADVISORY DISPATCHED: {post['url']}")

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__":
    main()
