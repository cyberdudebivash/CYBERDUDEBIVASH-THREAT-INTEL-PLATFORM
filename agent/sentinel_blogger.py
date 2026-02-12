#!/usr/bin/env python3
"""
CDB-SENTINEL-BLOGGER v2.6 – CyberDudeBivash Automated Premium Threat Intel Publisher
Author: Bivash Kumar Nayak (CyberDudeBivash)
Last Updated: February 12, 2026 – Full enhancements & new features
"""

import os
import json
import logging
import time
from datetime import datetime, timezone
import feedparser
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from blogger_auth import get_blogger_credentials  # Centralized auth

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

BLOG_ID = os.getenv('BLOG_ID') or '1735779547938854877'
NVD_API_KEY = os.getenv('NVD_API_KEY')

SCOPES = ['https://www.googleapis.com/auth/blogger']

STATE_FILE = 'data/blogger_processed.json'
MAX_STATE_SIZE = 1000  # New: Limit state file growth

RSS_FEEDS = [
    'https://thehackernews.com/feeds/posts/default',
    'https://feeds.feedburner.com/Securityweek',
    'https://krebsonsecurity.com/feed/',
    'https://www.bleepingcomputer.com/feed/',
    'https://www.darkreading.com/rss_simple.asp',
    'https://www.us-cert.gov/ncas/alerts.xml',
    'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
    'https://cert-in.org.in/RSSFeed.jsp'  # New: India CERT-In RSS
]

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('cyberdudebivash.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# STATE MANAGEMENT WITH CLEANUP
# ──────────────────────────────────────────────────────────────────────────────

def load_processed():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            processed = json.load(f)
            if len(processed) > MAX_STATE_SIZE:
                processed = processed[-MAX_STATE_SIZE:]  # Keep last 1000
                logger.info("State file pruned to latest 1000 entries")
            return set(processed)
    return set()

def save_processed(processed):
    with open(STATE_FILE, 'w') as f:
        json.dump(list(processed), f)
    logger.info(f"Saved {len(processed)} processed items")

# ──────────────────────────────────────────────────────────────────────────────
# FETCH INTEL (ENHANCED WITH NVD API + RATE LIMIT)
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

                item = {
                    'guid': guid,
                    'title': entry.title,
                    'link': entry.link,
                    'published': entry.get('published', datetime.now(timezone.utc).isoformat()),
                    'summary': entry.get('summary', entry.get('description', '')),
                    'source': feed.feed.get('title', url.split('//')[1].split('/')[0])
                }
                intel_items.append(item)
                processed.add(guid)
                time.sleep(1)  # Rate limit for feeds
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")

    # New: Add NVD API for CVSS ≥7 CVEs
    if NVD_API_KEY:
        try:
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&resultsPerPage=5&startIndex=0"
            headers = {"apiKey": NVD_API_KEY}
            r = requests.get(nvd_url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for vuln in data['vulnerabilities']:
                    cve = vuln['cve']
                    guid = cve['id']
                    if guid in processed:
                        continue

                    item = {
                        'guid': guid,
                        'title': cve['descriptions'][0]['value'],
                        'link': cve.get('sourceLink', 'https://nvd.nist.gov/vuln/detail/' + guid),
                        'published': cve['published'],
                        'summary': cve['descriptions'][0]['value'],
                        'source': 'NVD'
                    }
                    intel_items.append(item)
                    processed.add(guid)
                logger.info("Fetched additional critical CVEs from NVD API")
        except Exception as e:
            logger.error(f"NVD API fetch failed: {e}")

    save_processed(processed)
    return intel_items

# ──────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def generate_premium_report(intel_items):
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

# ──────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ──────────────────────────────────────────────────────────────────────────────

def main():
    logger.info("Starting CyberDudeBivash Threat Intel Automation – Sentinel Blogger v2.6")
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
