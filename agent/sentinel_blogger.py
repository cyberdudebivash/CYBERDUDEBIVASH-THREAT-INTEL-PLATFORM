#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v16.4 (SENTINEL APEX ULTRA PRO)
PRODUCTION ORCHESTRATOR: Multi-feed fusion with Quota Hardening.
NEW v16.4: The "Governor" Logic — Client-side throttling & auto-retry.

MANDATE: ZERO REGRESSION. Core intelligence logic preserved 100%.
"""

import os
import time
import logging
import feedparser
from typing import Dict, List
from googleapiclient.errors import HttpError

# Core CDB Modules (Features Preserved)
from agent.enricher import enricher
from agent.blogger_auth import get_blogger_service
from agent.risk_engine import risk_engine
from agent.deduplication import dedup_engine
from agent.mitre_mapper import mitre_engine
from agent.integrations.actor_matrix import actor_matrix
from agent.content.premium_report_generator import premium_report_gen
from agent.config import BLOG_ID, CDB_RSS_FEED, RSS_FEEDS, MAX_ENTRIES_PER_FEED, RATE_LIMIT_DELAY

# v16.0 Sovereign & Commercial Modules (Advanced Features)
from agent.sovereignty_engine import sovereign_engine
from agent.upsell_injector import upsell_engine
from agent.asset_factory import asset_engine
from agent.gumroad_api import create_intel_product

# --- GOVERNOR CONFIGURATION ---
POST_SPACING = 15      # Seconds to wait between every successful post (Prevents 429)
MAX_POSTS_PER_RUN = 8  # Caps the sweep to the top 8 most critical threats
SEVERITY_THRESHOLD = 7.0 # Minimum Risk Score required for publication

# Institutional Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-SENTINEL-APEX] %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("=" * 80)
    logger.info("SENTINEL APEX v16.4 — THE GOVERNOR DISPATCH ACTIVATED")
    logger.info("Hardened Throttling • RSA Signed • Automated Monetization")
    logger.info("=" * 80)

    try:
        service = get_blogger_service()
    except Exception as e:
        logger.error(f"FATAL: Blogger Auth Failed: {e}")
        return

    all_feeds = [CDB_RSS_FEED] + RSS_FEEDS
    published_count = 0

    for feed_url in all_feeds:
        if published_count >= MAX_POSTS_PER_RUN:
            logger.info("🛑 RUN LIMIT REACHED: Capping run to preserve API quota.")
            break

        entries = fetch_feed_entries(feed_url)
        for entry in entries:
            if published_count >= MAX_POSTS_PER_RUN:
                break

            if dedup_engine.is_duplicate(entry['title'], entry['link']):
                continue

            # Dispatch Pipeline
            if process_and_monetize(entry, service):
                published_count += 1
                logger.info(f"⏳ GOVERNOR: Sleeping {POST_SPACING}s to maintain rate limit safety.")
                time.sleep(POST_SPACING)

    logger.info(f"V16.4 RUN COMPLETE: {published_count} Signed & Monetized advisories live.")

def publish_with_retry(service, blog_id, post_body, retries=3, base_delay=60):
    """
    Hardened API wrapper with Exponential Backoff for 429 errors.
   
    """
    for attempt in range(retries):
        try:
            return service.posts().insert(blogId=blog_id, body=post_body).execute()
        except HttpError as e:
            status = e.resp.status
            if status == 429:
                wait_time = base_delay * (2 ** attempt)
                logger.warning(f"⚠️ QUOTA EXHAUSTED (429). Backing off for {wait_time}s...")
                time.sleep(wait_time)
                continue
            elif status == 400:
                logger.error("❌ INVALID ARGUMENT (400): Sanitizing payload for next run.")
                break
            else:
                logger.error(f"✗ CRITICAL API ERROR: {e}")
                break
    return None

def process_and_monetize(entry: Dict, service) -> bool:
    """
    Surgically integrates Sovereignty and Monetization without breaking 
    Technical Intel logic.
    """
    headline = entry['title']
    logger.info(f"▶ PROCESSING: {headline[:70]}...")

    try:
        # 1. Core Intel Pipeline
        report_data = premium_report_gen.prepare_intel_data(entry) 
        
        # 2. Risk Gating (The Bouncer)
        risk = report_data.get('risk_score', 0)
        if risk < SEVERITY_THRESHOLD:
            logger.info(f"⏭️ SEVERITY GATE: Risk {risk} below threshold. No publish.")
            return False

        # 3. RSA Sovereign Signing
        content_hash = f"{report_data['headline']}{report_data['technical_dive']}"
        report_data['signature'] = sovereign_engine.sign_asset(content_hash)
        
        # 4. Generate & Monetize
        report_html = premium_report_gen.generate_html(report_data)
        
        logger.info(f"💰 HIGH-VALUE INTEL ({risk}): Triggering Asset Factory...")
        asset_engine.generate_defense_kit(report_data)
        product_url = create_intel_product(title=headline, price_usd=99.0)
        
        if product_url:
            report_html = upsell_engine.inject_premium_cta(report_html, product_url, risk)

        # 5. Final Dispatch
        post_body = {
            "title": headline,
            "content": report_html,
            "labels": ["Threat Intelligence", "CDB Signed", "Apex v16.4"]
        }

        if publish_with_retry(service, BLOG_ID, post_body):
            dedup_engine.mark_processed(headline, entry['link'])
            logger.info(f"✓ SIGNED & MONETIZED: {headline[:50]}")
            return True

    except Exception as e:
        logger.error(f"✗ PIPELINE FAILURE for {headline[:30]}: {e}")
        return False

def fetch_feed_entries(url: str) -> List[Dict]:
    feed = feedparser.parse(url)
    return [{'title': e.title, 'link': e.link} for e in feed.entries[:MAX_ENTRIES_PER_FEED]]

if __name__ == "__main__":
    main()
