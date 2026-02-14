#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v5.4 APEX
Final Production: Forensic + Geo + VT Reputation Orchestrator.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone

import feedparser
from googleapiclient.errors import HttpError

# Path resolution for GitHub Actions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY, VT_API_KEY
)
from agent.content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("="*60 + "\nCDB-SENTINEL v5.4 APEX — Reputation Pipeline Active\n" + "="*60)
    try:
        # 1. State Management
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        with open(STATE_FILE, "r") as f:
            state_data = json.load(f)
            processed = set(state_data[-MAX_STATE_SIZE:]) if isinstance(state_data, list) else set()

        # 2. Ingestion
        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid") or entry.get("link", "")
                if guid in processed: continue
                intel_items.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "summary": entry.get("summary", entry.get("description", ""))
                })
                processed.add(guid)
        
        if not intel_items:
            logger.info("Intelligence sweep complete. No new threats detected.")
            return

        # 3. Multi-Vendor Enrichment (Geo + VT)
        corpus = " ".join([i['summary'] for i in intel_items])
        extracted_iocs = enricher.extract_iocs(corpus)
        threat_category = enricher.categorize_threat(extracted_iocs)
        
        enriched_metadata = {}
        for ioc_type, values in extracted_iocs.items():
            for val in values[:3]: # Limit for VT Public API speed
                context = enricher_pro.get_ip_context(val) if ioc_type == "ipv4" else {"location": "-", "isp": "-"}
                reputation = vt_lookup.get_reputation(val, ioc_type)
                enriched_metadata[val] = {**context, "reputation": reputation}
        
        # 4. Assembly
        headline = generate_headline(intel_items)
        risk_score = _calculate_cdb_score(headline, corpus)
        threat_map_html = visualizer.generate_heat_map(enriched_metadata)
        stix_id = f"CDB-STIX-{int(time.time())}"
        
        full_html = generate_full_post_content(
            intel_items, iocs=extracted_iocs, pro_data=enriched_metadata, 
            map_html=threat_map_html, stix_id=stix_id
        )

        # 5. Global Dispatch
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "title": f"[{threat_category}] {headline} | {datetime.now(timezone.utc).strftime('%b %d')}",
                    "content": full_html,
                    "labels": ["ThreatIntel", "VT-Verified", "CyberDudeBivash"]
                }).execute()
                post_url = post.get("url")
                break
            except Exception: time.sleep(PUBLISH_RETRY_DELAY * attempt)

        if post_url:
            logger.info(f"✓ LIVE AT: {post_url}")
            send_sentinel_alert(headline, risk_score, post_url)
            with open(STATE_FILE, "w") as f: json.dump(list(processed), f)

    except Exception as e:
        logger.critical(f"Terminal failure: {e}")
        raise

if __name__ == "__main__":
    main()
