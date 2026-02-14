#!/usr/bin/env python3
"""
CDB-SENTINEL-BLOGGER v3.1 APEX — Automated Premium Threat Intel Publisher
UPDATED: Integrated Sentinel Alert Dispatcher & CDB-Risk Scoring.

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

# Existing Auth & Config
from .blogger_auth import get_blogger_service
from .config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, MAX_POSTS_PER_RUN, PUBLISH_RETRY_MAX,
    PUBLISH_RETRY_DELAY, BRAND,
)

# New Intelligence & Notification Modules
from .content.blog_post_generator import generate_full_post_content, generate_headline, _calculate_cdb_score
from .notifier import send_sentinel_alert

# ═══════════════════════════════════════════════════
# LOGGING & METRICS (Preserved from v3.0)
# ═══════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler("cyberdudebivash.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("CDB-SENTINEL")

class RunMetrics:
    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.feeds_attempted = 0
        self.feeds_succeeded = 0
        self.feeds_failed = 0
        self.items_fetched = 0
        self.items_new = 0
        self.posts_published = 0
        self.posts_failed = 0
        self.errors: List[str] = []

    def summary(self) -> str:
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return (
            f"Run Summary: {elapsed:.1f}s elapsed | "
            f"Feeds: {self.feeds_succeeded}/{self.feeds_attempted} | "
            f"Items: {self.items_new} new / {self.items_fetched} total | "
            f"Published: {self.posts_published} | Failed: {self.posts_failed}"
        )

# ═══════════════════════════════════════════════════
# STATE MANAGEMENT (Preserved from v3.0)
# ═══════════════════════════════════════════════════

def _ensure_state_dir():
    state_dir = os.path.dirname(STATE_FILE)
    if state_dir and not os.path.exists(state_dir):
        os.makedirs(state_dir, exist_ok=True)

def load_processed() -> Set[str]:
    _ensure_state_dir()
    if not os.path.exists(STATE_FILE): return set()
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
            return set(data[-MAX_STATE_SIZE:]) if isinstance(data, list) else set()
    except: return set()

def save_processed(processed: Set[str]):
    _ensure_state_dir()
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(processed), f)
    except Exception as exc: logger.error(f"State save failed: {exc}")

# ═══════════════════════════════════════════════════
# INTEL FETCHER (Preserved from v3.0)
# ═══════════════════════════════════════════════════

def fetch_latest_intel(metrics: RunMetrics) -> List[Dict]:
    intel_items = []
    processed = load_processed()
    for url in RSS_FEEDS:
        metrics.feeds_attempted += 1
        try:
            feed = feedparser.parse(url)
            if feed.bozo and not feed.entries:
                metrics.feeds_failed += 1
                continue
            source_name = feed.feed.get("title", url.split("//")[1].split("/")[0])
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid") or entry.get("id") or entry.get("link", "")
                if guid in processed: continue
                metrics.items_fetched += 1
                intel_items.append({
                    "guid": guid, "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""), "source": source_name,
                    "published": entry.get("published", datetime.now(timezone.utc).isoformat()),
                    "summary": entry.get("summary", entry.get("description", "")),
                })
                processed.add(guid)
                metrics.items_new += 1
            metrics.feeds_succeeded += 1
            time.sleep(1)
        except Exception as exc: metrics.feeds_failed += 1
    save_processed(processed)
    return intel_items

# ═══════════════════════════════════════════════════
# ENHANCED REPORT GENERATOR (Updated v3.1)
# ═══════════════════════════════════════════════════

def generate_premium_report(intel_items: List[Dict]) -> tuple:
    # 1. Headline & Date
    headline = generate_headline(intel_items)
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    title = f"{headline} | {today}"

    # 2. Body (HTML + JSON Export)
    content = generate_full_post_content(intel_items)

    # 3. Score for Notification
    full_text = " ".join(i.get("title", "") + " " + i.get("summary", "") for i in intel_items)
    score = _calculate_cdb_score("", full_text)

    return title, content, score

# ═══════════════════════════════════════════════════
# RESILIENT PUBLISHER (Preserved from v3.0)
# ═══════════════════════════════════════════════════

def publish_to_blogger(title: str, content: str, service) -> str:
    post_body = {
        "kind": "blogger#post", "title": title, "content": content,
        "labels": ["ThreatIntel", "CVE", "CyberDudeBivash", "SOC", "2026"],
    }
    for attempt in range(1, PUBLISH_RETRY_MAX + 1):
        try:
            response = service.posts().insert(blogId=BLOG_ID, body=post_body).execute()
            return response.get("url")
        except HttpError as exc:
            if attempt == PUBLISH_RETRY_MAX: raise
            time.sleep(PUBLISH_RETRY_DELAY * attempt)
    return None

# ═══════════════════════════════════════════════════
# MAIN ORCHESTRATOR (The Unified v3.1 Pipeline)
# ═══════════════════════════════════════════════════

def main():
    metrics = RunMetrics()
    logger.info("="*60 + "\nCDB-SENTINEL v3.1 APEX — Starting Pipeline\n" + "="*60)

    try:
        # Step 1: Fetch
        intel = fetch_latest_intel(metrics)
        if not intel:
            logger.warning("No new intel — skipping run.")
            logger.info(metrics.summary())
            return

        # Step 2: Auth
        service = get_blogger_service()

        # Step 3: Triage & Score
        title, content, score = generate_premium_report(intel[:MAX_POSTS_PER_RUN])

        # Step 4: Publish & Notify
        try:
            post_url = publish_to_blogger(title, content, service)
            if post_url:
                metrics.posts_published += 1
                logger.info(f"✓ LIVE: {post_url}")
                # NEW: Sentinel Alert Dispatch
                send_sentinel_alert(title, score, post_url)
        except Exception as exc:
            metrics.posts_failed += 1
            logger.error(f"Publication failed: {exc}")

        logger.info(metrics.summary() + "\nPipeline completed successfully ✅")

    except Exception as exc:
        logger.critical(f"Pipeline failure: {exc}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
