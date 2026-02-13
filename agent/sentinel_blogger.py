#!/usr/bin/env python3
"""
CDB-SENTINEL-BLOGGER v3.0 APEX — Automated Premium Threat Intel Publisher
Production-grade orchestrator with metrics, health checks, and resilient publishing.

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

from .blogger_auth import get_blogger_service
from .config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, MAX_POSTS_PER_RUN, PUBLISH_RETRY_MAX,
    PUBLISH_RETRY_DELAY, BRAND,
)


# ═══════════════════════════════════════════════════
# LOGGING
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


# ═══════════════════════════════════════════════════
# METRICS TRACKING
# ═══════════════════════════════════════════════════

class RunMetrics:
    """Track pipeline metrics for each run."""

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
            f"Published: {self.posts_published} | "
            f"Failed: {self.posts_failed} | "
            f"Errors: {len(self.errors)}"
        )


# ═══════════════════════════════════════════════════
# STATE MANAGEMENT
# ═══════════════════════════════════════════════════

def _ensure_state_dir():
    """Ensure the state directory exists."""
    state_dir = os.path.dirname(STATE_FILE)
    if state_dir and not os.path.exists(state_dir):
        os.makedirs(state_dir, exist_ok=True)
        logger.info(f"Created state directory: {state_dir}")


def load_processed() -> Set[str]:
    """Load processed item IDs from state file."""
    _ensure_state_dir()

    if not os.path.exists(STATE_FILE):
        logger.info("No state file found — starting fresh")
        return set()

    try:
        with open(STATE_FILE, "r") as f:
            content = f.read().strip()
            if not content:
                return set()

            data = json.loads(content)
            if not isinstance(data, list):
                logger.warning("Invalid state format — resetting")
                return set()

            # Prune if oversized
            if len(data) > MAX_STATE_SIZE:
                data = data[-MAX_STATE_SIZE:]
                logger.info(f"State pruned to {MAX_STATE_SIZE} entries")

            return set(data)

    except (json.JSONDecodeError, OSError) as exc:
        logger.error(f"State file error: {exc} — starting fresh")
        return set()


def save_processed(processed: Set[str]):
    """Persist processed item IDs."""
    _ensure_state_dir()
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(processed), f)
        logger.info(f"State saved: {len(processed)} items")
    except OSError as exc:
        logger.error(f"Failed to save state: {exc}")


# ═══════════════════════════════════════════════════
# INTEL FETCHER
# ═══════════════════════════════════════════════════

def fetch_latest_intel(
    max_per_feed: int = MAX_PER_FEED,
    metrics: Optional[RunMetrics] = None,
) -> List[Dict]:
    """
    Fetch new threat intel items from all RSS feeds.
    Deduplicates against previously processed items.
    """
    intel_items = []
    processed = load_processed()

    for url in RSS_FEEDS:
        if metrics:
            metrics.feeds_attempted += 1

        try:
            feed = feedparser.parse(url)

            if feed.bozo and not feed.entries:
                logger.warning(f"Feed unavailable: {url}")
                if metrics:
                    metrics.feeds_failed += 1
                continue

            source_name = feed.feed.get("title", url.split("//")[1].split("/")[0])
            new_from_feed = 0

            for entry in feed.entries[:max_per_feed]:
                guid = entry.get("guid") or entry.get("id") or entry.get("link", "")
                if not guid or guid in processed:
                    continue

                if metrics:
                    metrics.items_fetched += 1

                intel_items.append({
                    "guid": guid,
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "published": entry.get(
                        "published",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    "summary": entry.get("summary", entry.get("description", "")),
                    "source": source_name,
                })
                processed.add(guid)
                new_from_feed += 1

            if metrics:
                metrics.feeds_succeeded += 1
                metrics.items_new += new_from_feed

            if new_from_feed > 0:
                logger.info(f"  ✓ {source_name}: {new_from_feed} new items")

            time.sleep(1)  # Rate limiting

        except Exception as exc:
            logger.error(f"Feed error ({url}): {exc}")
            if metrics:
                metrics.feeds_failed += 1
                metrics.errors.append(f"Feed: {url} — {exc}")

    save_processed(processed)
    logger.info(f"Total new intel items: {len(intel_items)}")
    return intel_items


# ═══════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════

def generate_premium_report(
    intel_items: List[Dict],
) -> tuple:
    """
    Generate a premium threat intelligence report.
    Returns (title, html_content).
    """
    from .content.blog_post_generator import generate_full_post_content, generate_headline

    # Sort by publication date (newest first)
    intel_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    headline = generate_headline(intel_items)
    title = f"{headline} | {today}"

    content = generate_full_post_content(intel_items)

    word_count = len(content.split())
    logger.info(f"Report generated: ~{word_count} words, {len(intel_items)} incidents")

    return title, content


# ═══════════════════════════════════════════════════
# PUBLISHER
# ═══════════════════════════════════════════════════

def publish_to_blogger(
    title: str,
    content: str,
    service,
    labels: Optional[List[str]] = None,
) -> str:
    """
    Publish post to Blogger with exponential backoff retry.
    Returns the published post URL.
    """
    if labels is None:
        labels = [
            "ThreatIntel", "Cybersecurity", "CVE",
            "ZeroDay", "CyberDudeBivash", "SOC", "2026",
        ]

    post_body = {
        "kind": "blogger#post",
        "title": title,
        "content": content,
        "labels": labels,
    }

    for attempt in range(1, PUBLISH_RETRY_MAX + 1):
        try:
            response = service.posts().insert(
                blogId=BLOG_ID,
                body=post_body,
                isDraft=False,
            ).execute()

            url = response.get("url", "No URL returned")
            logger.info(f"✅ Published: {url}")
            return url

        except HttpError as exc:
            status = exc.resp.status if exc.resp else "unknown"
            logger.error(f"Blogger API error (attempt {attempt}/{PUBLISH_RETRY_MAX}): HTTP {status} — {exc}")

            if attempt < PUBLISH_RETRY_MAX:
                delay = PUBLISH_RETRY_DELAY * attempt
                logger.info(f"  Retrying in {delay}s...")
                time.sleep(delay)
            else:
                raise

        except Exception as exc:
            logger.critical(f"Unexpected publish error: {exc}")
            raise

    raise RuntimeError("Publish failed after all retries")


# ═══════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════

def main():
    """Main pipeline entry point."""
    metrics = RunMetrics()

    logger.info("=" * 60)
    logger.info(f"CDB-SENTINEL v3.0 APEX — Starting pipeline")
    logger.info(f"Blog ID: {BLOG_ID}")
    logger.info(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    logger.info("=" * 60)

    try:
        # Step 1: Fetch intel
        intel = fetch_latest_intel(metrics=metrics)

        if not intel:
            logger.warning("No new intel items found — skipping publication")
            logger.info(metrics.summary())
            return

        # Step 2: Authenticate
        service = get_blogger_service()

        # Step 3: Generate & publish report
        title, content = generate_premium_report(intel[:MAX_POSTS_PER_RUN])

        try:
            publish_to_blogger(title, content, service)
            metrics.posts_published += 1
        except Exception as exc:
            metrics.posts_failed += 1
            metrics.errors.append(f"Publish: {exc}")
            logger.error(f"Publication failed: {exc}")

        # Step 4: Log metrics
        logger.info("=" * 60)
        logger.info(metrics.summary())
        logger.info("Pipeline completed successfully ✅")
        logger.info("=" * 60)

    except Exception as exc:
        metrics.errors.append(f"Pipeline: {exc}")
        logger.critical(f"Pipeline failure: {exc}", exc_info=True)
        logger.info(metrics.summary())
        raise


if __name__ == "__main__":
    main()
