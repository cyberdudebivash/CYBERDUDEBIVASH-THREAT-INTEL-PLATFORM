#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v16.4.2 (SENTINEL APEX ULTRA PRO)
PRODUCTION ORCHESTRATOR: Hyper-Governor v2 with Jittered Exponential Backoff.
MANDATE: PERSISTENT RETRY • RSA SIGNED • ZERO-FAIL PIPELINE
"""

import os
import time
import random
import logging
import feedparser
from typing import Dict, List
from googleapiclient.errors import HttpError

# Core CDB Modules
from agent.blogger_auth import get_blogger_service
from agent.deduplication import dedup_engine
from agent.content.premium_report_generator import premium_report_gen
from agent.sovereignty_engine import sovereign_engine
from agent.upsell_injector import upsell_engine
from agent.asset_factory import asset_engine
from agent.gumroad_api import create_intel_product
from agent.config import BLOG_ID, CDB_RSS_FEED, RSS_FEEDS, MAX_ENTRIES_PER_FEED

# --- HYPER-GOVERNOR SETTINGS ---
BASE_POST_SPACING = 30   # Minimum seconds between successful posts
MAX_POSTS_PER_RUN = 5    # Top-tier intelligence cap
SEVERITY_THRESHOLD = 7.5 # Only critical threats reach the blog

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-SENTINEL] %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("=" * 80)
    logger.info("SENTINEL APEX v16.4.2 — HYPER-GOVERNOR v2 DISPATCH ACTIVE")
    logger.info("MANDATE: PERSISTENT RETRY • JITTERED BACKOFF • RSA SIGNED")
    logger.info("=" * 80)

    try:
        service = get_blogger_service()
    except Exception as e:
        logger.error(f"FATAL: Blogger Auth Failed: {e}")
        return

    all_feeds = [CDB_RSS_FEED] + RSS_FEEDS
    published_count = 0

    for feed_url in all_feeds:
        if published_count >= MAX_POSTS_PER_RUN: break
        
        entries = fetch_feed_entries(feed_url)
        for entry in entries:
            if published_count >= MAX_POSTS_PER_RUN: break
            
            # 1. Deduplication Gate
            if dedup_engine.is_duplicate(entry['title'], entry['link']):
                continue

            # 2. Sovereign Pipeline
            if process_and_monetize(entry, service):
                published_count += 1
                # Add jitter to spacing to avoid fingerprinting
                actual_sleep = BASE_POST_SPACING + random.randint(5, 15)
                logger.info(f"⏳ GOVERNOR: Post success. Cooling down for {actual_sleep}s...")
                time.sleep(actual_sleep)

    logger.info(f"🏁 RUN COMPLETE: {published_count} Signed advisories live.")

def publish_with_retry(service, blog_id, post_body, max_retries=5):
    """
    Hyper-Governor v2: Implements Jittered Exponential Backoff.
    Standard: wait = (2^attempt * 60) + random_jitter
    """
    for attempt in range(max_retries):
        try:
            return service.posts().insert(blogId=blog_id, body=post_body).execute()
        except HttpError as e:
            # 429 = Rate Limit | 403 = User Rate Limit Exceeded
            if e.resp.status in [403, 429]:
                # Exponential growth: 60s, 120s, 240s, 480s... 
                wait_time = (2 ** attempt) * 60 + random.uniform(10, 30)
                logger.warning(f"⚠️ QUOTA TRIGGERED (Attempt {attempt+1}/{max_retries}). "
                               f"Hyper-Governor backoff: {int(wait_time)}s...")
                time.sleep(wait_time)
                continue
            
            # Non-retryable error
            logger.error(f"✗ CRITICAL API ERROR: {e}")
            break
    return None

def process_and_monetize(entry: Dict, service) -> bool:
    """High-Value Intelligence Pipeline."""
    headline = entry['title']
    logger.info(f"▶ STARTING PIPELINE: {headline[:60]}...")

    try:
        # A. Intelligence Synthesis & Enrichment
        report_data = premium_report_gen.prepare_report(entry)
        risk = report_data.get('risk_score', 0)

        # B. Severity Gate
        if risk < SEVERITY_THRESHOLD:
            logger.info(f"⏭️ SEVERITY GATE: Risk {risk} below threshold.")
            return False

        # C. RSA Sovereign Signing
        content_hash = f"{report_data['headline']}{report_data.get('technical_dive', '')}"
        report_data['signature'] = sovereign_engine.sign_asset(content_hash)
        
        # D. Asset Forge (v16.4 Handshake)
        asset_engine.generate_defense_kit(report_data)
        
        # E. Monetization Check (Handles Gumroad 404/API limitations)
        product_url = create_intel_product(title=headline)
        
        # F. HTML Generation & CTA Injection
        report_html = premium_report_gen.generate_html(report_data)
        if product_url:
            report_html = upsell_engine.inject_premium_cta(report_html, product_url, risk)
        else:
            logger.info("ℹ️ Proceeding with Technical-only report (no monetized link).")

        # G. Dispatch through Hyper-Governor Retry Logic
        post_body = {
            "title": f"🚨 CDB-SOVEREIGN: {headline}",
            "content": report_html,
            "labels": ["Sovereign Intelligence", "RSA-Signed", "Apex v16.4"]
        }

        if publish_with_retry(service, BLOG_ID, post_body):
            dedup_engine.mark_processed(headline, entry['link'])
            logger.info(f"✅ PIPELINE SUCCESS: {headline[:50]}")
            return True

    except Exception as e:
        logger.error(f"✗ PIPELINE FAILURE: {e}")
        return False

def fetch_feed_entries(url: str) -> List[Dict]:
    """Retrieves and parses RSS feed entries."""
    try:
        feed = feedparser.parse(url)
        return [{'title': e.title, 'link': e.link} for e in feed.entries[:MAX_ENTRIES_PER_FEED]]
    except Exception as e:
        logger.error(f"Feed Fetch Error: {e}")
        return []

if __name__ == "__main__":
    main()
