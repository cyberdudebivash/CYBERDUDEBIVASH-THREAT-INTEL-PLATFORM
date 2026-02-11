#!/usr/bin/env python3
"""
CDB-SENTINEL-BLOGGER v2.7 – CyberDudeBivash Automated Premium Threat Intel Publisher
Author: Bivash Kumar Nayak (CyberDudeBivash)
Last Updated: February 11, 2026 – Enhanced template integration
"""

import os
import json
import logging
import time
from datetime import datetime, timezone
import feedparser
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION – MATCH YOUR GITHUB SECRET NAMES EXACTLY
# ──────────────────────────────────────────────────────────────────────────────

REFRESH_TOKEN = os.getenv('REFRESH_TOKEN')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
BLOG_ID = os.getenv('BLOG_ID') or '1735779547938854877'

if not all([REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET]):
    raise ValueError("Missing Blogger OAuth secrets in environment variables")

SCOPES = ['https://www.googleapis.com/auth/blogger']

STATE_FILE = 'blogger_processed.json'

RSS_FEEDS = [
    'https://thehackernews.com/feeds/posts/default',
    'https://feeds.feedburner.com/Securityweek',
    'https://krebsonsecurity.com/feed/',
    'https://www.bleepingcomputer.com/feed/',
    'https://www.darkreading.com/rss_simple.asp',
    'https://threatpost.com/feed/',
    'https://www.us-cert.gov/ncas/alerts.xml',
    'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
    'https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.rss',
]

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION
# ──────────────────────────────────────────────────────────────────────────────

def get_blogger_service():
    creds = Credentials(
        None,
        refresh_token=REFRESH_TOKEN,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=SCOPES
    )
    creds.refresh(Request())
    logger.info("Blogger service authenticated successfully")
    return build('blogger', 'v3', credentials=creds)

# ──────────────────────────────────────────────────────────────────────────────
# STATE MANAGEMENT
# ──────────────────────────────────────────────────────────────────────────────

def load_processed_items():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return set(json.load(f))
    return set()

def save_processed_items(processed):
    with open(STATE_FILE, 'w') as f:
        json.dump(list(processed), f)
    logger.info(f"Saved {len(processed)} processed items")

# ──────────────────────────────────────────────────────────────────────────────
# FETCH LATEST INTEL
# ──────────────────────────────────────────────────────────────────────────────

def fetch_latest_intel(max_per_feed=5):
    intel_items = []
    processed = load_processed_items()

    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url, agent='CyberDudeBivash-Sentinel/2.7')
            if feed.bozo:
                logger.warning(f"Feed parse warning {url}: {feed.bozo_exception}")
                continue

            for entry in feed.entries[:max_per_feed]:
                guid = entry.get('guid', entry.get('id', entry.link))
                if guid in processed:
                    continue

                item = {
                    'guid': guid,
                    'title': entry.get('title', 'Untitled'),
                    'link': entry.link,
                    'published': entry.get('published', datetime.now(timezone.utc).isoformat()),
                    'summary': entry.get('summary', entry.get('description', '')),
                    'source': feed.feed.get('title', url.split('//')[1].split('/')[0])
                }
                intel_items.append(item)
                processed.add(guid)
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")

    save_processed_items(processed)
    logger.info(f"Fetched {len(intel_items)} new intel items")
    return intel_items

# ──────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def generate_premium_report(intel_items):
    from .content.blog_post_generator import generate_full_post_content

    intel_items.sort(key=lambda x: x['published'], reverse=True)
    title = f"CyberDudeBivash Premium Threat Intel Report – {datetime.now(timezone.utc).strftime('%B %d, %Y')} | Zero-Days • Breaches • Malware"
    content = generate_full_post_content(intel_items)
    return title, content

# ──────────────────────────────────────────────────────────────────────────────
# PUBLISH TO BLOGGER
# ──────────────────────────────────────────────────────────────────────────────

def publish_to_blogger(title, content):
    service = get_blogger_service()

    post_body = {
        'kind': 'blogger#post',
        'title': title,
        'content': content,
        'labels': ['ThreatIntel', 'Cybersecurity', 'ZeroDay', 'CyberDudeBivash']
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
                time.sleep(5 * (attempt + 1))
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
            logger.warning("No new intel items. Skipping publication.")
            return

        title, content = generate_premium_report(intel)
        publish_to_blogger(title, content)
        logger.info("Automation run completed successfully")
    except Exception as e:
        logger.critical(f"Critical failure in main execution: {e}", exc_info=True)

if __name__ == "__main__":
    main()
