#!/usr/bin/env python3
"""
CDB-SENTINEL-BLOGGER v2.7 – CyberDudeBivash Automated Premium Threat Intel Publisher
Author: Bivash Kumar Nayak (CyberDudeBivash)
Last Updated: February 13, 2026 – Fixed relative import + safe state handling
"""

import os
import json
import logging
import time
from datetime import datetime, timezone
import feedparser
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from .blogger_auth import get_blogger_credentials  # FIXED: relative import with dot

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION – MATCH YOUR GITHUB SECRET NAMES EXACTLY
# ──────────────────────────────────────────────────────────────────────────────

REFRESH_TOKEN = os.getenv('REFRESH_TOKEN')
CLIENT_ID     = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
BLOG_ID       = os.getenv('BLOG_ID') or '1735779547938854877'

if not all([REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET]):
    raise ValueError("Missing Blogger OAuth secrets in environment variables")

SCOPES = ['https://www.googleapis.com/auth/blogger']

STATE_FILE = 'data/blogger_processed.json'
MAX_STATE_SIZE = 1000  # Limit state file growth

RSS_FEEDS = [
    'https://thehackernews.com/feeds/posts/default',
    'https://feeds.feedburner.com/Securityweek',
    'https://krebsonsecurity.com/feed/',
    'https://www.bleepingcomputer.com/feed/',
    'https://www.darkreading.com/rss_simple.asp',
    'https://www.us-cert.gov/ncas/alerts.xml',
    'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
    'https://cert-in.org.in/RSSFeed.jsp'  # India CERT-In RSS
]

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('cyberdudebivash.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# SAFE STATE MANAGEMENT (creates data/ folder if missing)
# ──────────────────────────────────────────────────────────────────────────────

STATE_DIR = os.path.dirname(STATE_FILE)  # 'data'
if not os.path.exists(STATE_DIR):
    os.makedirs(STATE_DIR)
    logger.info(f"Created missing state directory: {STATE_DIR}")

def load_processed():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            processed = json.load(f)
            if len(processed) > MAX_STATE_SIZE:
                processed = processed[-MAX_STATE_SIZE:]  # Keep last 1000
                logger.info("State file pruned to latest 1000 entries")
            return set(processed)
    logger.info("No state file found – starting fresh")
    return set()

def save_processed(processed):
    with open(STATE_FILE, 'w') as f:
        json.dump(list(processed), f)
    logger.info(f"Saved {len(processed)} processed items")

# ──────────────────────────────────────────────────────────────────────────────
# FETCH LATEST INTEL
# ──────────────────────────────────────────────────────────────────────────────

def fetch_latest_intel(max_per_feed=5):
    intel_items = []
    processed = load_processed()

    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            if feed.bozo:
                logger.warning(f"Feed parse warning {url}: {feed.bozo_exception}")
                continue

            for entry in feed.entries[:max_per_feed]:
                guid = entry.get('guid') or entry.get('id') or entry.link
                if guid in processed:
                    continue

                intel_items.append({
                    'guid': guid,
                    'title': entry.title,
                    'link': entry.link,
                    'published': entry.get('published', datetime.now(timezone.utc).isoformat()),
                    'summary': entry.get('summary', entry.get('description', '')),
                    'source': feed.feed.get('title', url.split('//')[1].split('/')[0])
                })
                processed.add(guid)
                time.sleep(1)  # Rate limit
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")

    save_processed(processed)
    logger.info(f"Fetched {len(intel_items)} new intel items")
    return intel_items

# ──────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def generate_premium_report(intel_items):
    # Relative import from agent/content/
    from .content.blog_post_generator import generate_full_post_content

    intel_items.sort(key=lambda x: x['published'], reverse=True)
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    title = f"CyberDudeBivash Premium Threat Intel Report – {today} | Zero-Days • Breaches • Malware"
    content = generate_full_post_content(intel_items)
    logger.info("Premium report generated successfully")
    return title, content

# ──────────────────────────────────────────────────────────────────────────────
# PUBLISH TO BLOGGER WITH RETRY
# ──────────────────────────────────────────────────────────────────────────────

def publish_to_blogger(title, content, service):
    post_body = {
        'kind': 'blogger#post',
        'title': title,
        'content': content,
        'labels': ['ThreatIntel', 'Cybersecurity', 'ZeroDay', 'CyberDudeBivash', '2026']
    }

    max_retries = 3
    for attempt in range(max_retries):
        try:
            request = service.posts().insert(blogId=BLOG_ID, body=post_body, isDraft=False)
            response = request.execute()
            url = response.get('url', 'No URL returned')
            logger.info(f"Successfully published: {url}")
            return url
        except HttpError as e:
            logger.error(f"Blogger API error (attempt {attempt+1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(10 * (attempt + 1))
            else:
                raise
        except Exception as e:
            logger.critical(f"Unexpected publish error: {e}")
            raise

    raise RuntimeError("Publish failed after retries")

# ──────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ──────────────────────────────────────────────────────────────────────────────

def main():
    logger.info("Starting CyberDudeBivash Threat Intel Automation – Sentinel Blogger v2.7")
    try:
        intel = fetch_latest_intel(max_per_feed=5)
        if not intel:
            logger.warning("No new intel items found. Skipping publication.")
            return

        service = get_blogger_service()
        title, content = generate_premium_report(intel)
        publish_to_blogger(title, content, service)
        logger.info("Automation run completed successfully")
    except Exception as e:
        logger.critical(f"Critical failure in main execution: {e}", exc_info=True)

if __name__ == "__main__":
    main()
