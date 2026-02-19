#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v16.4 (SENTINEL APEX ULTRA PRO)
PRODUCTION ORCHESTRATOR: The "Governor" with Quota Hardening.
"""

import os
import time
import logging
import feedparser
from typing import Dict, List
from googleapiclient.errors import HttpError

# CDB Modules
from agent.blogger_auth import get_blogger_service
from agent.deduplication import dedup_engine
from agent.content.premium_report_generator import premium_report_gen
from agent.sovereignty_engine import sovereign_engine
from agent.upsell_injector import upsell_engine
from agent.asset_factory import asset_engine
from agent.gumroad_api import create_intel_product
from agent.config import BLOG_ID, CDB_RSS_FEED, RSS_FEEDS, MAX_ENTRIES_PER_FEED

# Governor Config
POST_SPACING = 20      # Increased to 20s for absolute 429 safety
MAX_POSTS_PER_RUN = 5  # Only the most critical 5 threats per run
SEVERITY_THRESHOLD = 7.0

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-ENRICHER] %(message)s")
logger = logging.getLogger("CDB-ENRICHER")

def main():
    logger.info("=" * 80)
    logger.info("SENTINEL APEX v16.4 — THE GOVERNOR DISPATCH ACTIVATED")
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
            if dedup_engine.is_duplicate(entry['title'], entry['link']): continue

            if process_and_monetize(entry, service):
                published_count += 1
                time.sleep(POST_SPACING)

def publish_with_retry(service, blog_id, post_body, retries=3):
    for attempt in range(retries):
        try:
            return service.posts().insert(blogId=blog_id, body=post_body).execute()
        except HttpError as e:
            if e.resp.status == 429:
                time.sleep(60 * (attempt + 1))
                continue
            logger.error(f"API Error: {e}")
            break
    return None

def process_and_monetize(entry: Dict, service) -> bool:
    headline = entry['title']
    logger.info(f"▶ PROCESSING: {headline[:70]}...")

    try:
        # 1. SYNCED PIPELINE: Calling 'prepare_report' (Corrected)
        report_data = premium_report_gen.prepare_report(entry)
        
        if report_data['risk_score'] < SEVERITY_THRESHOLD:
            logger.info(f"⏭️ SEVERITY GATE: Risk {report_data['risk_score']} below threshold.")
            return False

        # 2. RSA SIGNING
        content_hash = f"{report_data['headline']}{report_data['technical_dive']}"
        report_data['signature'] = sovereign_engine.sign_asset(content_hash)
        
        # 3. HTML & MONETIZATION
        report_html = premium_report_gen.generate_html(report_data)
        
        asset_engine.generate_defense_kit(report_data)
        product_url = create_intel_product(title=headline)
        
        if product_url:
            report_html = upsell_engine.inject_premium_cta(report_html, product_url, report_data['risk_score'])

        # 4. DISPATCH
        post_body = {"title": headline, "content": report_html, "labels": ["Signed Intel", "Apex v16.4"]}
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
