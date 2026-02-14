#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v4.0 APEX
Master Orchestrator: Intel Ingestion -> IoC Enrichment -> AI Triage -> Global Dispatch.

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

# CRITICAL: Resolve package path for GitHub Actions runner
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Core Infrastructure
from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY
)

# AI, Enrichment & Notification Modules
from agent.content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from agent.enricher import enricher  # NEW: IoC Extraction Engine
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
    logger.info("="*60 + "\nCDB-SENTINEL v4.0 APEX — Intel Enrichment Active\n" + "="*60)

    try:
        # Step 1: State Management (Resilient Load)
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        try:
            with open(STATE_FILE, "r") as f:
                state_data = json.load(f)
                processed = set(state_data[-MAX_STATE_SIZE:]) if isinstance(state_data, list) else set()
        except Exception:
            logger.warning("State file corrupted. Initializing fresh state.")
            processed = set()

        # Step 2: Intelligence Ingestion
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
                logger.error(f"Feed error at {url}: {e}")
        
        if not intel_items:
            logger.info("No new intelligence detected. Pipeline standby.")
            return

        # Atomic Save of state to prevent duplicates
        with open(STATE_FILE, "w") as f: json.dump(list(processed), f)

        # Step 3: Technical Enrichment (IoC Extraction)
        # Combine summaries for bulk extraction
        corpus = " ".join([i['summary'] for i in intel_items])
        extracted_iocs = enricher.extract_iocs(corpus)
        threat_category = enricher.categorize_threat(extracted_iocs)
        
        ioc_count = sum(len(v) for v in extracted_iocs.values())
        logger.info(f"Enrichment: Found {ioc_count} indicators. Category: {threat_category}")

        # Step 4: Content Generation & Risk Scoring
        headline = generate_headline(intel_items)
        # Pass enriched data to the post generator
        full_html = generate_full_post_content(intel_items) 
        risk_score = _calculate_cdb_score("", corpus)
        
        # Step 5: Blogger Publication
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "kind": "blogger#post",
                    "title": f"[{threat_category}] {headline} | {datetime.now().strftime('%b %d')}",
                    "content": full_html,
                    "labels": ["ThreatIntel", "CDB-Sentinel", threat_category.replace(" ", "")]
                }).execute()
                post_url = post.get("url")
                break
            except Exception as e:
                if attempt == PUBLISH_RETRY_MAX: raise
                time.sleep(PUBLISH_RETRY_DELAY * attempt)

        # Step 6: Multi-Channel Alerts
        if post_url:
            logger.info(f"✓ LIVE AT: {post_url}")
            
            # --- Sentinel Alerting (Telegram/Discord) ---
            try:
                send_sentinel_alert(headline, risk_score, post_url)
            except Exception as e:
                logger.error(f"Telegram alert failure: {e}")
            
            # --- Executive Briefing (High Risk Only) ---
            if risk_score >= 7.0:
                logger.info(f"Severity high ({risk_score}). Dispatching Executive Briefing...")
                try:
                    send_executive_briefing(headline, risk_score, full_html, post_url)
                except Exception as e:
                    logger.error(f"Email dispatch failure: {e}")

        logger.info("Pipeline completed successfully ✅")

    except Exception as e:
        logger.critical(f"Pipeline failure: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
