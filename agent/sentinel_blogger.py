#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v4.4 APEX
Final Production Version: Integrated Forensic Enrichment & Global Dispatch.

This is the central orchestrator that manages the end-to-end intelligence 
lifecycle: Ingestion -> Enrichment -> Triage -> Publication.

Author: Bivash Kumar Nayak (CyberDudeBivash)
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import os
import sys
import json
import logging
import time
from datetime import datetime, timezone
from typing import List, Dict, Set

import feedparser
from googleapiclient.errors import HttpError

# CRITICAL FIX: Ensure absolute path resolution for GitHub Actions runner
# This allows the script to locate the 'agent' package correctly.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Core Infrastructure Imports
from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY
)

# AI, Enrichment & Notification Modules
from agent.content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from agent.enricher import enricher  # Forensic IoC Engine
from agent.notifier import send_sentinel_alert
from agent.email_dispatcher import send_executive_briefing

# ═══════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.FileHandler("cyberdudebivash.log"), logging.StreamHandler()],
)
logger = logging.getLogger("CDB-SENTINEL")

# ═══════════════════════════════════════════════════
# MAIN PIPELINE
# ═══════════════════════════════════════════════════

def main():
    logger.info("="*60 + "\nCDB-SENTINEL v4.4 APEX — Forensic Pipeline Initialized\n" + "="*60)

    try:
        # Step 1: Resilient State Management
        # Prevents processing of previously triaged intelligence nodes.
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        try:
            with open(STATE_FILE, "r") as f:
                state_data = json.load(f)
                # Ensure state_data is a list to handle potential corruption
                processed = set(state_data[-MAX_STATE_SIZE:]) if isinstance(state_data, list) else set()
        except Exception:
            logger.warning("State file corrupted or missing. Initializing fresh state.")
            processed = set()

        # Step 2: Intelligence Ingestion
        # Aggregates raw data from multiple global threat feeds.
        intel_items = []
        for url in RSS_FEEDS:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:MAX_PER_FEED]:
                    guid = entry.get("guid") or entry.get("link", "")
                    if guid in processed: continue
                    
                    intel_items.append({
                        "guid": guid,
                        "title": entry.get("title", "Untitled"),
                        "link": entry.get("link", ""),
                        "summary": entry.get("summary", entry.get("description", ""))
                    })
                    processed.add(guid)
            except Exception as e:
                logger.error(f"Failed to ingest feed from {url}: {e}")
        
        if not intel_items:
            logger.info("No new intelligence detected in current sweep. Standing by.")
            return

        # Atomic state save to ensure persistency
        with open(STATE_FILE, "w") as f: json.dump(list(processed), f)

        # Step 3: Forensic Enrichment & Categorization
        # Scans corpus for Indicators of Compromise (IoCs) and labels the threat vector.
        corpus = " ".join([i['summary'] for i in intel_items])
        extracted_iocs = enricher.extract_iocs(corpus)
        threat_category = enricher.categorize_threat(extracted_iocs)
        
        ioc_count = sum(len(v) for v in extracted_iocs.values())
        logger.info(f"Enrichment: {ioc_count} indicators extracted. Primary Vector: {threat_category}")

        # Step 4: AI Triage & Content Generation
        headline = generate_headline(intel_items)
        # Injects technical indicators directly into the HTML generator
        full_html = generate_full_post_content(intel_items, iocs=extracted_iocs)
        risk_score = _calculate_cdb_score("", corpus)
        
        # Step 5: Global Publication (Blogger)
        # Final dispatch with retry logic for reliability.
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "kind": "blogger#post",
                    "title": f"[{threat_category}] {headline} | {datetime.now(timezone.utc).strftime('%b %d')}",
                    "content": full_html,
                    "labels": ["ThreatIntel", "CDB-Sentinel", threat_category.replace(" ", "")]
                }).execute()
                post_url = post.get("url")
                break
            except Exception as e:
                if attempt == PUBLISH_RETRY_MAX: 
                    logger.critical(f"Blogger publication failed after max retries: {e}")
                    raise
                time.sleep(PUBLISH_RETRY_DELAY * attempt)

        # Step 6: Multi-Channel Alerts & Briefings
        if post_url:
            logger.info(f"✓ THREAT REPORT LIVE: {post_url}")
            
            # --- Instant Alerting (Telegram/Discord) ---
            try:
                send_sentinel_alert(headline, risk_score, post_url)
            except Exception as e:
                logger.error(f"Instant alert dispatch failed: {e}")
            
            # --- Executive Briefing (High Severity Threshold) ---
            if risk_score >= 7.0:
                logger.info(f"High risk detected ({risk_score}). Dispatching Executive Briefing...")
                try:
                    send_executive_briefing(headline, risk_score, full_html, post_url)
                except Exception as e:
                    logger.error(f"Executive briefing failure: {e}")

        logger.info("=== Pipeline Execution Success ✅ ===")

    except Exception as e:
        logger.critical(f"Critical Pipeline Failure: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
