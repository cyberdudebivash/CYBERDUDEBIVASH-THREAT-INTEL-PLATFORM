#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v4.2 APEX
Final Production Version: Intel Ingestion & Forensic Enrichment.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone

import feedparser
from googleapiclient.errors import HttpError

# CRITICAL: Resolve package path for GitHub Actions environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY
)
from agent.content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from agent.enricher import enricher
from agent.notifier import send_sentinel_alert
from agent.email_dispatcher import send_executive_briefing

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("=== CDB-SENTINEL v4.2 — Forensic Pipeline Initialized ===")
    try:
        # 1. Resilient State Management
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        try:
            with open(STATE_FILE, "r") as f:
                state_data = json.load(f)
                processed = set(state_data[-MAX_STATE_SIZE:]) if isinstance(state_data, list) else set()
        except Exception:
            processed = set()

        # 2. Intelligence Ingestion
        intel_items = []
        for url in RSS_FEEDS:
            try:
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
            except Exception as e: logger.error(f"Feed error: {e}")
        
        if not intel_items:
            logger.info("No new intelligence. Standing by.")
            return

        with open(STATE_FILE, "w") as f: json.dump(list(processed), f)

        # 3. Forensic Enrichment (IoC Extraction)
        corpus = " ".join([i['summary'] for i in intel_items])
        extracted_iocs = enricher.extract_iocs(corpus)
        threat_category = enricher.categorize_threat(extracted_iocs)
        
        # 4. Content Generation
        headline = generate_headline(intel_items)
        full_html = generate_full_post_content(intel_items, iocs=extracted_iocs)
        risk_score = _calculate_cdb_score("", corpus)
        
        # 5. Blogger Publication
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "title": f"[{threat_category}] {headline} | {datetime.now().strftime('%b %d')}",
                    "content": full_html,
                    "labels": ["ThreatIntel", "CyberDudeBivash", threat_category.replace(" ", "")]
                }).execute()
                post_url = post.get("url")
                break
            except Exception: time.sleep(PUBLISH_RETRY_DELAY * attempt)

        # 6. Global Dispatch
        if post_url:
            logger.info(f"✓ LIVE AT: {post_url}")
            send_sentinel_alert(headline, risk_score, post_url)
            if risk_score >= 7.0:
                send_executive_briefing(headline, risk_score, full_html, post_url)

    except Exception as e:
        logger.critical(f"Pipeline failure: {e}")
        raise

if __name__ == "__main__":
    main()
