#!/usr/bin/env python3
"""
CDB-SENTINEL-BLOGGER v2.1 – CyberDudeBivash Automated Threat Intel Publisher
Author: Bivash Kumar Nayak (CyberDudeBivash)
Purpose: Fetch latest cyber intel → Generate premium 2500–3000+ word reports → Post to Blogger
Runs via GitHub Actions every 6 hours
"""

import os
import json
import logging
import time
from datetime import datetime
import feedparser
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

BLOG_ID = os.getenv('BLOGGER_BLOG_ID', '1735779547938854877')
REFRESH_TOKEN = os.getenv('BLOGGER_REFRESH_TOKEN')
CLIENT_ID = os.getenv('BLOGGER_CLIENT_ID')
CLIENT_SECRET = os.getenv('BLOGGER_CLIENT_SECRET')

SCOPES = ['https://www.googleapis.com/auth/blogger']

STATE_FILE = 'blogger_processed.json'

# Top-tier cybersecurity RSS feeds (2026 curated)
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
    """Authenticate using refresh token from GitHub Secrets"""
    if not all([REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET]):
        logger.error("Missing Blogger credentials in environment variables")
        raise ValueError("Missing Blogger OAuth credentials")

    creds = Credentials(
        None,
        refresh_token=REFRESH_TOKEN,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=SCOPES
    )

    # Refresh token if expired
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        logger.info("Token refreshed successfully")

    return build('blogger', 'v3', credentials=creds)

# ──────────────────────────────────────────────────────────────────────────────
# STATE MANAGEMENT (Prevent duplicate posts)
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
# INTEL INGESTION
# ──────────────────────────────────────────────────────────────────────────────

def fetch_latest_intel(max_per_feed=5):
    intel_items = []
    processed = load_processed_items()

    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url, agent='CyberDudeBivash-Sentinel/2.1')
            if feed.bozo:
                logger.warning(f"Feed parse warning: {feed.bozo_exception}")
                continue

            for entry in feed.entries[:max_per_feed]:
                guid = entry.get('guid', entry.get('id', entry.link))
                if guid in processed:
                    continue

                item = {
                    'guid': guid,
                    'title': entry.get('title', 'Untitled'),
                    'link': entry.link,
                    'published': entry.get('published', datetime.utcnow().isoformat()),
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
    from blog_post_generator import generate_full_post_content  # Assuming you have this module

    # Sort by published date descending
    intel_items.sort(key=lambda x: x['published'], reverse=True)

    # Generate world-class content
    content = generate_full_post_content(intel_items)

    # Title with current date
    today = datetime.now().strftime("%B %d, %Y")
    title = f"CyberDudeBivash Premium Threat Intel Report – {today} | Zero-Days • Breaches • Malware"

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
        'labels': ['Cybersecurity', 'Threat Intel', 'Zero-Day', 'CyberDudeBivash', '2026']
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
                time.sleep(5 * (attempt + 1))  # Exponential backoff
            else:
                raise
        except Exception as e:
            logger.critical(f"Unexpected error during publish: {e}")
            raise

# ──────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ──────────────────────────────────────────────────────────────────────────────

def main():
    logger.info("Starting CyberDudeBivash Threat Intel Automation – Sentinel Blogger v2.1")
    try:
        intel = fetch_latest_intel(max_per_feed=4)  # Balanced volume
        if not intel:
            logger.warning("No new intel items found. Skipping post.")
            return

        title, content = generate_premium_report(intel)
        publish_url = publish_to_blogger(title, content)
        logger.info(f"Automation complete. Published to: {publish_url}")
    except Exception as e:
        logger.critical(f"Critical failure in main execution: {e}", exc_info=True)

if __name__ == "__main__":
    main()