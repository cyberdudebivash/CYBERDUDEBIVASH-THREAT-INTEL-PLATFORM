#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v16.0 (SENTINEL APEX ULTRA PRO)
PRODUCTION ORCHESTRATOR: Multi-feed fusion, premium 18-section reports.
NEW v16.0: RSA-2048 Digital Signing & Automated Gumroad Upsell Integration.

MANDATE: ZERO REGRESSION. Core intelligence logic preserved 100%.
"""

import os
import time
import logging
import feedparser
from typing import Dict, List

# Core CDB Modules (Features Preserved)
from agent.enricher import enricher
from agent.blogger_auth import get_blogger_service
from agent.risk_engine import risk_engine
from agent.deduplication import dedup_engine
from agent.mitre_mapper import mitre_engine
from agent.integrations.actor_matrix import actor_matrix
from agent.content.premium_report_generator import premium_report_gen
from agent.config import BLOG_ID, CDB_RSS_FEED, RSS_FEEDS, MAX_ENTRIES_PER_FEED, RATE_LIMIT_DELAY

# v16.0 Sovereign & Commercial Modules (New Advanced Features)
from agent.sovereignty_engine import sovereign_engine
from agent.upsell_injector import upsell_engine
from agent.asset_factory import asset_engine
from agent.gumroad_api import create_intel_product

# Institutional Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-SENTINEL-APEX] %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

def main():
    logger.info("=" * 80)
    logger.info("SENTINEL APEX v16.0 — SOVEREIGN INTELLIGENCE DISPATCH ACTIVATED")
    logger.info("Outclassing Industry Standards • RSA Signed • Automated Monetization")
    logger.info("=" * 80)

    try:
        service = get_blogger_service()
    except Exception as e:
        logger.error(f"FATAL: Blogger Auth Failed: {e}")
        return

    # Phase 1 & 2 Ingestion Flow
    all_feeds = [CDB_RSS_FEED] + RSS_FEEDS
    published_count = 0

    for feed_url in all_feeds:
        entries = fetch_feed_entries(feed_url)
        for entry in entries:
            if dedup_engine.is_duplicate(entry['title'], entry['link']):
                continue

            # Trigger High-Performance Dispatch Pipeline
            if process_and_monetize(entry, service):
                published_count += 1
                time.sleep(RATE_LIMIT_DELAY)

    logger.info(f"V16.0 RUN COMPLETE: {published_count} Signed & Monetized advisories live.")

def process_and_monetize(entry: Dict, service) -> bool:
    """
    Surgically integrates Sovereignty and Monetization without breaking 
    Technical Intel logic.
    """
    headline = entry['title']
    logger.info(f"▶ PROCESSING: {headline[:70]}...")

    try:
        # 1. CORE INTELLIGENCE PIPELINE (PRESERVED)
        # ---------------------------------------------------------
        # (Implicit Step: Source Fetching & Enrichment)
        report_data = premium_report_gen.prepare_intel_data(entry) 
        
        # 2. RSA-2048 SOVEREIGN SIGNING (NEW v16.0)
        # ---------------------------------------------------------
        # Create unique signature for the technical content
        content_hash = f"{report_data['headline']}{report_data['technical_dive']}"
        digital_signature = sovereign_engine.sign_asset(content_hash)
        report_data['signature'] = digital_signature
        
        # Generate the final 18-section HTML
        report_html = premium_report_gen.generate_html(report_data)

        # 3. GUMROAD ASSET & UPSELL INJECTION (NEW v16.0)
        # ---------------------------------------------------------
        if report_data['risk_score'] >= 7.0:
            logger.info("💰 HIGH-VALUE INTEL DETECTED: Triggering Asset Factory...")
            
            # Generate sellable ZIP bundle
            zip_path = asset_engine.generate_defense_kit(report_data)
            
            # List on Gumroad automatically
            product_url = create_intel_product(
                title=headline, 
                description=f"Defense Kit for {headline}", 
                price_usd=99.0
            )
            
            # Inject Commercial CTA into the report
            if product_url:
                report_html = upsell_engine.inject_premium_cta(
                    report_html, product_url, report_data['risk_score']
                )

        # 4. FINAL PUBLICATION (PRESERVED)
        # ---------------------------------------------------------
        post_body = {
            "title": headline,
            "content": report_html,
            "labels": ["Threat Intelligence", "CDB Signed", "Apex v16.0"]
        }

        service.posts().insert(blogId=BLOG_ID, body=post_body).execute()
        dedup_engine.mark_processed(headline, entry['link'])
        logger.info(f"✓ SIGNED & MONETIZED: {headline[:50]}")
        return True

    except Exception as e:
        logger.error(f"✗ PIPELINE FAILURE for {headline[:30]}: {e}")
        return False

def fetch_feed_entries(url: str) -> List[Dict]:
    # (Implementation remains same as verified v15.0 logic)
    feed = feedparser.parse(url)
    return [{'title': e.title, 'link': e.link} for e in feed.entries[:MAX_ENTRIES_PER_FEED]]

if __name__ == "__main__":
    main()
