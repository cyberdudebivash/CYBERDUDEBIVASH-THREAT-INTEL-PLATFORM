#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v3.8 APEX
Master Orchestrator: Feed -> Blogger -> Social -> Email.
Robust State-Resiliency & Absolute Path Safety.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone
from typing import Set

import feedparser
from googleapiclient.errors import HttpError

# CRITICAL: Resolve package path for GitHub Actions runner environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY
)
from agent.content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from agent.notifier import send_sentinel_alert
from agent.email_dispatcher import send_executive_briefing
from agent.social_bot import broadcast_to_social

# Production logging setup
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.FileHandler("sentinel.log"), logging.StreamHandler()]
)
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("=== CDB-SENTINEL v3.8 — Global Broadcast Initialized ===")
    try:
        # 1. Resilient State Management
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        try:
            with open(STATE_FILE, "r") as f:
                state_data = json.load(f)
                if not isinstance(state_data, list):
                    logger.warning("State corrupted. Resetting to empty list.")
                    state_data = []
                processed = set(state_data[-MAX_STATE_SIZE:])
        except Exception as e:
            logger.warning(f"State load failed: {e}. Resetting state.")
            processed = set()

        # 2. Intel Ingestion
        intel_items = []
        for url in RSS_FEEDS:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:MAX_PER_FEED]:
                    guid = entry.get("guid") or entry.get("link", "")
                    if guid in processed: continue
                    intel_items.append({
                        "guid": guid, "title": entry.get("title", "Untitled"),
                        "link": entry.get("link", ""), "summary": entry.get("summary", "")
                    })
                    processed.add(guid)
            except Exception as e: logger.error(f"Feed error {url}: {e}")
        
        if not intel_items:
            logger.info("No new intelligence. Standing by.")
            return

        # Atomic state save
        with open(STATE_FILE, "w") as f: json.dump(list(processed), f)

        # 3. Content Generation
        headline = generate_headline(intel_items)
        full_html = generate_full_post_content(intel_items)
        risk_score = _calculate_cdb_score("", " ".join(i.get("title", "") for i in intel_items))
        
        # 4. Blogger Dispatch
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "title": f"{headline} | {datetime.now().strftime('%B %d, %Y')}",
                    "content": full_html, "labels": ["ThreatIntel", "CyberDudeBivash"]
                }).execute()
                post_url = post.get("url")
                break
            except Exception: time.sleep(PUBLISH_RETRY_DELAY * attempt)

        # 5. Multi-Channel Dispatch
        if post_url:
            logger.info(f"✓ LIVE AT: {post_url}")
            
            # Social Broadcast (LinkedIn using w_member_social)
            try:
                broadcast_to_social(headline, post_url, risk_score)
            except Exception as e: logger.error(f"Social Dispatch Failure: {e}")

            # Instant Alerts (Telegram/Discord)
            try:
                send_sentinel_alert(headline, risk_score, post_url)
            except Exception as e: logger.error(f"Telegram Failure: {e}")
            
            # Executive Briefing (Email)
            if risk_score >= 6.5:
                try:
                    send_executive_briefing(headline, risk_score, full_html, post_url)
                except Exception as e: logger.error(f"Email Failure: {e}")

        logger.info("Pipeline executed successfully ✅")

    except Exception as e:
        logger.critical(f"System failure: {e}")
        raise

if __name__ == "__main__":
    main()
