#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v4.6 APEX
Final Production: Forensic + Geo + VT Reputation Enrichment.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone

import feedparser
# Path safety for GitHub runner
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.blogger_auth import get_blogger_service
from agent.config import BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup # NEW
from agent.notifier import send_sentinel_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("=== CDB-SENTINEL v4.6 — Multi-Vendor Triage Active ===")
    try:
        # 1. State/Ingestion Logic (Standard)
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        with open(STATE_FILE, "r") as f:
            state_data = json.load(f)
            processed = set(state_data[-MAX_STATE_SIZE:]) if isinstance(state_data, list) else set()

        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid") or entry.get("link", "")
                if guid in processed: continue
                intel_items.append({"title": entry.get("title"), "link": entry.get("link"), "summary": entry.get("summary")})
                processed.add(guid)
        
        if not intel_items: return
        with open(STATE_FILE, "w") as f: json.dump(list(processed), f)

        # 2. Forensic, Geo & VT Enrichment
        corpus = " ".join([i['summary'] for i in intel_items])
        extracted_iocs = enricher.extract_iocs(corpus)
        threat_category = enricher.categorize_threat(extracted_iocs)
        
        # Deep Enrichment Matrix
        enriched_metadata = {}
        for ioc_type, values in extracted_iocs.items():
            for val in values[:3]: # Limit to top 3 per type for speed
                context = enricher_pro.get_ip_context(val) if ioc_type == "ipv4" else {"location": "-", "isp": "-"}
                reputation = vt_lookup.get_reputation(val, ioc_type)
                enriched_metadata[val] = {**context, "reputation": reputation}
        
        # 3. Content & Publication
        headline = generate_headline(intel_items)
        full_html = generate_full_post_content(intel_items, iocs=extracted_iocs, pro_data=enriched_metadata)
        risk_score = _calculate_cdb_score("", corpus)
        
        service = get_blogger_service()
        post = service.posts().insert(blogId=BLOG_ID, body={
            "title": f"[{threat_category}] {headline}",
            "content": full_html,
            "labels": ["ThreatIntel", "Forensics", "VT-Verified"]
        }).execute()

        if post.get("url"):
            logger.info(f"✓ LIVE AT: {post.get('url')}")
            send_sentinel_alert(headline, risk_score, post.get("url"))

    except Exception as e:
        logger.critical(f"Pipeline failure: {e}")

if __name__ == "__main__":
    main()
