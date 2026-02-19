#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v16.4 (SENTINEL APEX ULTRA PRO)
PRODUCTION ORCHESTRATOR: The "Governor" with Final Asset Handshake.
"""

import os
import time
import logging
import feedparser
from typing import Dict, List
from googleapiclient.errors import HttpError

# Core CDB Modules (Verified Handshakes)
from agent.blogger_auth import get_blogger_service
from agent.deduplication import dedup_engine
from agent.content.premium_report_generator import premium_report_gen
from agent.sovereignty_engine import sovereign_engine
from agent.upsell_injector import upsell_engine
from agent.asset_factory import asset_engine  # Linked to agent/asset_factory.py
from agent.gumroad_api import create_intel_product
from agent.config import BLOG_ID, CDB_RSS_FEED, RSS_FEEDS, MAX_ENTRIES_PER_FEED

# --- GOVERNOR CONFIGURATION ---
POST_SPACING = 20        # Seconds between posts (429 Protection)
MAX_POSTS_PER_RUN = 5    # Top-tier intelligence cap
SEVERITY_THRESHOLD = 7.5 # Only 7.5+ Risk Score triggers monetization

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-SENTINEL] %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("=" * 80)
    logger.info("SENTINEL APEX v16.4 — FINAL SYNC DISPATCH ACTIVATED")
    logger.info("MANDATE: RSA SIGNED • MONETIZED • THROTTLED")
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
            break
        
        entries = fetch_feed_entries(feed_url)
        for entry in entries:
            if published_count >= MAX_POSTS_PER_RUN:
                break
            
            # 1. Deduplication Gate
            if dedup_engine.is_duplicate(entry['title'], entry['link']):
                continue

            # 2. Sovereign Pipeline
            if process_and_monetize(entry, service):
                published_count += 1
                logger.info(f"⏳ GOVERNOR: Cooling down for {POST_SPACING}s...")
                time.sleep(POST_SPACING)

    logger.info(f"🏁 RUN COMPLETE: {published_count} Signed advisories live.")

def publish_with_retry(service, blog_id, post_body, retries=3):
    """Hardened API wrapper for Google Quota safety."""
    for attempt in range(retries):
        try:
            return service.posts().insert(blogId=blog_id, body=post_body).execute()
        except HttpError as e:
            if e.resp.status == 429:
                wait = 60 * (attempt + 1)
                logger.warning(f"⚠️ QUOTA 429: Waiting {wait}s...")
                time.sleep(wait)
                continue
            logger.error(f"✗ API Error: {e}")
            break
    return None

def process_and_monetize(entry: Dict, service) -> bool:
    """The High-Value Intelligence Funnel."""
    headline = entry['title']
    logger.info(f"▶ STARTING PIPELINE: {headline[:60]}...")

    try:
        # A. Intelligence Synthesis
        report_data = premium_report_gen.prepare_report(entry)
        
        # B. Severity Gate
        risk = report_data.get('risk_score', 0)
        if risk < SEVERITY_THRESHOLD:
            logger.info(f"⏭️ SEVERITY GATE: Risk {risk} insufficient for Apex publication.")
            return False

        # C. RSA Sovereign Signing
        content_hash = f"{report_data['headline']}{report_data.get('technical_dive', '')}"
        report_data['signature'] = sovereign_engine.sign_asset(content_hash)
        
        # D. Premium Asset Generation (Handshake Fixed)
        # Calls generate_defense_kit in agent/asset_factory.py
        asset_path = asset_engine.generate_defense_kit(report_data)
        
        # E. Monetization Injection
        product_url = create_intel_product(title=headline, price_usd=99.0)
        
        # F. HTML Rendering
        report_html = premium_report_gen.generate_html(report_data)
        if product_url:
            report_html = upsell_engine.inject_premium_cta(report_html, product_url, risk)

        # G. Final Dispatch
        post_body = {
            "title": f"🚨 CDB-SOVEREIGN: {headline}",
            "content": report_html,
            "labels": ["Sovereign Intelligence", "RSA-Signed", "Apex v16.4"]
        }

        if publish_with_retry(service, BLOG_ID, post_body):
            dedup_engine.mark_processed(headline, entry['link'])
            logger.info(f"✅ MISSION SUCCESS: {headline[:50]}")
            return True

    except Exception as e:
        logger.error(f"✗ PIPELINE CRITICAL FAILURE: {e}")
        return False

def fetch_feed_entries(url: str) -> List[Dict]:
    """Retrieves intelligence feed data."""
    try:
        feed = feedparser.parse(url)
        return [{'title': e.title, 'link': e.link} for e in feed.entries[:MAX_ENTRIES_PER_FEED]]
    except Exception as e:
        logger.error(f"Feed Fetch Error: {e}")
        return []

if __name__ == "__main__":
    main()
