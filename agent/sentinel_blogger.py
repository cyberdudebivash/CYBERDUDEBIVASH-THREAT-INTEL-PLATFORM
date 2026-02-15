#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v8.2
Final Unified Orchestrator: All Enterprise Pillars (A, B, C) Integrated.
"""
import os, sys, json, logging, time
from datetime import datetime, timezone
import feedparser

# System Path Alignment
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
    logger.info("="*60 + "\nAPEX v8.2 — ELITE PRODUCTION ACTIVE\n" + "="*60)
    try:
        if not os.path.exists("data"): os.makedirs("data")
        processed = set(json.load(open(STATE_FILE))[-MAX_STATE_SIZE:]) if os.path.exists(STATE_FILE) else set()
        
        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid", entry.link)
                if guid not in processed:
                    intel_items.append({
                        "title": entry.title, 
                        "link": entry.link, 
                        "summary": entry.get("summary", entry.get("description", ""))
                    })
                    processed.add(guid)
        
        if not intel_items:
            stix_exporter.update_manifest(); return

        # 2. Strategic Triage
        headline = generate_headline(intel_items)
        corpus = " ".join([i['summary'] for i in intel_items])
        
        # Pillar A: Attribution
        extracted_iocs = enricher.extract_iocs(corpus)
        actor_data = actor_matrix.correlate_actor(corpus, extracted_iocs)
        
        # Pillar B: Vulnerability Deep-Dive
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", corpus)
        cve_id = cve_match.group(0) if cve_match else None
        cve_data = vuln_engine.get_cve_deep_dive(cve_id) if cve_id else None
        
        enriched_metadata = {v: vt_lookup.get_reputation(v, "ipv4") for v in extracted_iocs.get('ipv4', [])}
        risk_score = 7.5
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 3. Content Dispatch
        full_html = generate_full_post_content(
            intel_items, extracted_iocs, enriched_metadata, 
            "", stix_id, risk_score=risk_score, 
            actor_data=actor_data, cve_data=cve_data
        )
        
        service = get_blogger_service()
        post = service.posts().insert(
            blogId=os.environ.get('BLOG_ID', BLOG_ID), 
            body={"title": f"[v8.2 Advisory] {headline}", "content": full_html}
        ).execute()

        if post.get("url"):
            json.dump(list(processed), open(STATE_FILE, "w"))
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata)
            send_sentinel_alert(headline, risk_score, post['url'])

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__": main()
