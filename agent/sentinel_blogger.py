#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v3.3 APEX
Complete Multi-Channel Intel Orchestrator.
Integrated with LinkedIn Member Feed & X Broadcaster.

Author: Bivash Kumar Nayak (CyberDudeBivash)
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import os
import json
import logging
import time
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set

import feedparser
from googleapiclient.errors import HttpError

# Existing Infrastructure
from .blogger_auth import get_blogger_service
from .config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, MAX_POSTS_PER_RUN, PUBLISH_RETRY_MAX,
    PUBLISH_RETRY_DELAY, BRAND,
)

# AI & Notification Modules
from .content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from .notifier import send_sentinel_alert
from .email_dispatcher import send_executive_briefing

# NEW: Social Amplification Layer
from agent.social_bot import broadcast_to_social

# ═══════════════════════════════════════════════════
# LOGGING & METRICS
# ═══════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.FileHandler("cyberdudebivash.log"), logging.StreamHandler()],
)
logger = logging.getLogger("CDB-SENTINEL")

class RunMetrics:
    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.feeds_attempted = 0
        self.feeds_succeeded = 0
        self.items_new = 0
        self.posts_published = 0
        self.errors = []

    def summary(self) -> str:
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return (f"Run Summary: {elapsed:.1f}s | Feeds: {self.feeds_succeeded}/{self.feeds_attempted} | "
                f"Items: {self.items_new} new | Published: {self.posts_published} | Errors: {len(self.errors)}")

# ═══════════════════════════════════════════════════
# STATE MANAGEMENT
# ═══════════════════════════════════════════════════

def load_processed() -> Set[str]:
    if not os.path.exists(STATE_FILE): return set()
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
            return set(data[-MAX_STATE_SIZE:]) if isinstance(data, list) else set()
    except: return set()

def save_processed(processed: Set[str]):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(list(processed), f)
    except Exception as e: logger.error(f"State save failed: {e}")

# ═══════════════════════════════════════════════════
# MAIN PIPELINE
# ═══════════════════════════════════════════════════

def main():
    metrics = RunMetrics()
    logger.info("="*60 + "\nCDB-SENTINEL v3.3 APEX — Global Intel Dispatch\n" + "="*60)

    try:
        # Step 1: Intel Ingestion
        processed = load_processed()
        intel_items = []
        for url in RSS_FEEDS:
            metrics.feeds_attempted += 1
            try:
                feed = feedparser.parse(url)
                if feed.bozo and not feed.entries: continue
                source = feed.feed.get("title", url.split("//")[1].split("/")[0])
                for entry in feed.entries[:MAX_PER_FEED]:
                    guid = entry.get("guid") or entry.get("id") or entry.get("link", "")
                    if guid in processed: continue
                    intel_items.append({
                        "guid": guid, "title": entry.get("title", "Untitled"),
                        "link": entry.get("link", ""), "source": source,
                        "published": entry.get("published", datetime.now(timezone.utc).isoformat()),
                        "summary": entry.get("summary", entry.get("description", "")),
                    })
                    processed.add(guid)
                    metrics.items_new += 1
                metrics.feeds_succeeded += 1
                time.sleep(0.5)
            except Exception as e: metrics.errors.append(f"Feed {url}: {e}")
        
        if not intel_items:
            logger.info("No new intelligence detected. Pipeline standby.")
            return

        save_processed(processed)

        # Step 2: Generation & Scoring
        headline = generate_headline(intel_items)
        full_html = generate_full_post_content(intel_items)
        corpus = " ".join(i.get("title", "") + " " + i.get("summary", "") for i in intel_items)
        risk_score = _calculate_cdb_score("", corpus)
        
        # Step 3: Blogger Publication
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "kind": "blogger#post", "title": f"{headline} | {datetime.now().strftime('%B %d, %Y')}",
                    "content": full_html, "labels": ["ThreatIntel", "AI-Sentinel", "CyberDudeBivash"]
                }).execute()
                post_url = post.get("url")
                metrics.posts_published += 1
                break
            except Exception as e:
                if attempt == PUBLISH_RETRY_MAX: raise
                time.sleep(PUBLISH_RETRY_DELAY * attempt)

        # Step 4: Multi-Channel Alerting & Social Amplification
        if post_url:
            logger.info(f"✓ LIVE AT: {post_url}")
            
            # --- Social Broadcast (LinkedIn / X) ---
            try:
                # Dispatches only after Blogger success to ensure URL validity
                broadcast_to_social(headline, post_url, risk_score)
            except Exception as e:
                logger.error(f"Social broadcast component failed: {e}")

            # --- Sentinel Alerting (Telegram/Discord) ---
            try:
                send_sentinel_alert(headline, risk_score, post_url)
            except Exception as e:
                logger.error(f"Instant alert dispatch failed: {e}")
            
            # --- Executive Briefing (Email Dispatcher) ---
            if risk_score >= 6.5:
                logger.info(f"High risk score ({risk_score}) detected. Triggering Briefing...")
                try:
                    send_executive_briefing(headline, risk_score, full_html, post_url)
                except Exception as e:
                    logger.error(f"Executive briefing dispatch failed: {e}")

        logger.info(metrics.summary() + "\nPipeline completed successfully ✅")

    except Exception as e:
        logger.critical(f"Pipeline failure: {e}", exc_info=True)
        metrics.errors.append(f"Global: {e}")
        raise

if __name__ == "__main__":
    main()
