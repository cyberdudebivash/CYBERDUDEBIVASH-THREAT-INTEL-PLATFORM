#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE v1.0
RSS → Multi-Platform Social Media Automation
Replaces Make.com — 100% Free via GitHub Actions

Author: CyberDudeBivash Pvt. Ltd.
"""

import logging
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

from syndicate.rss_poller import RSSPoller
from syndicate.state_manager import StateManager
from syndicate.formatter import PostFormatter
from syndicate.config import SyndicationConfig

# Platform importers (graceful degradation)
PLATFORM_MODULES = {}
try:
    from syndicate.platforms.linkedin import LinkedInPoster
    PLATFORM_MODULES['linkedin'] = LinkedInPoster
except ImportError as e:
    print(f"[WARN] LinkedIn module unavailable: {e}")

try:
    from syndicate.platforms.twitter import TwitterPoster
    PLATFORM_MODULES['twitter'] = TwitterPoster
except ImportError as e:
    print(f"[WARN] Twitter module unavailable: {e}")

try:
    from syndicate.platforms.mastodon import MastodonPoster
    PLATFORM_MODULES['mastodon'] = MastodonPoster
except ImportError as e:
    print(f"[WARN] Mastodon module unavailable: {e}")

try:
    from syndicate.platforms.bluesky import BlueSkyPoster
    PLATFORM_MODULES['bluesky'] = BlueSkyPoster
except ImportError as e:
    print(f"[WARN] Bluesky module unavailable: {e}")

try:
    from syndicate.platforms.facebook import FacebookPoster
    PLATFORM_MODULES['facebook'] = FacebookPoster
except ImportError as e:
    print(f"[WARN] Facebook module unavailable: {e}")

try:
    from syndicate.platforms.tumblr import TumblrPoster
    PLATFORM_MODULES['tumblr'] = TumblrPoster
except ImportError as e:
    print(f"[WARN] Tumblr module unavailable: {e}")

try:
    from syndicate.platforms.reddit import RedditPoster
    PLATFORM_MODULES['reddit'] = RedditPoster
except ImportError as e:
    print(f"[WARN] Reddit module unavailable: {e}")

try:
    from syndicate.platforms.threads import ThreadsPoster
    PLATFORM_MODULES['threads'] = ThreadsPoster
except ImportError as e:
    print(f"[WARN] Threads module unavailable: {e}")

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("data/syndication_run.log", mode="a"),
    ],
)
log = logging.getLogger("SyndicationEngine")


def run():
    start_time = datetime.now(timezone.utc)
    log.info("=" * 60)
    log.info("CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE v1.0 STARTING")
    log.info(f"Run timestamp: {start_time.isoformat()}")
    log.info("=" * 60)

    config = SyndicationConfig()
    state = StateManager(config.STATE_FILE)
    poller = RSSPoller(config.RSS_URL)
    formatter = PostFormatter(config)

    # 1. Fetch RSS
    log.info(f"Polling RSS: {config.RSS_URL}")
    try:
        items = poller.fetch_new_items(state.get_posted_guids())
    except Exception as e:
        log.error(f"RSS fetch failed: {e}")
        sys.exit(1)

    if not items:
        log.info("No new items found. Nothing to syndicate.")
        _write_run_summary(start_time, [], {})
        return

    log.info(f"Found {len(items)} new item(s) to syndicate")

    # 2. Initialize platforms
    platforms = {}
    for name, cls in PLATFORM_MODULES.items():
        try:
            instance = cls(config)
            if instance.is_configured():
                platforms[name] = instance
                log.info(f"Platform READY: {name.upper()}")
            else:
                log.warning(f"Platform SKIPPED (not configured): {name.upper()}")
        except Exception as e:
            log.error(f"Platform init failed [{name}]: {e}")

    if not platforms:
        log.error("No platforms configured. Set secrets in GitHub repository settings.")
        sys.exit(1)

    # 3. Syndicate each item to all platforms
    run_results = {}

    for item in items:
        item_id = item['guid']
        log.info(f"── Syndicating: {item['title'][:60]}...")
        run_results[item_id] = {
            'title': item['title'],
            'url': item['link'],
            'platforms': {}
        }

        for platform_name, poster in platforms.items():
            try:
                post_text = formatter.format_post(item, platform=platform_name)
                result = poster.post(item, post_text)

                if result.get('success'):
                    log.info(f"  ✅ {platform_name.upper()}: Posted — {result.get('post_id', 'OK')}")
                    run_results[item_id]['platforms'][platform_name] = {
                        'status': 'success',
                        'post_id': result.get('post_id', ''),
                        'post_url': result.get('post_url', '')
                    }
                else:
                    log.warning(f"  ⚠️  {platform_name.upper()}: Failed — {result.get('error', 'Unknown error')}")
                    run_results[item_id]['platforms'][platform_name] = {
                        'status': 'failed',
                        'error': result.get('error', 'Unknown')
                    }

            except Exception as e:
                log.error(f"  ❌ {platform_name.upper()}: Exception — {e}")
                run_results[item_id]['platforms'][platform_name] = {
                    'status': 'exception',
                    'error': str(e)
                }

        # Mark as posted if at least one platform succeeded
        platform_results = run_results[item_id]['platforms']
        any_success = any(v.get('status') == 'success' for v in platform_results.values())
        if any_success:
            state.mark_posted(item)
            log.info(f"  📌 Marked as posted in state: {item_id}")
        else:
            log.warning(f"  ⚠️  All platforms failed for item — NOT marking as posted (will retry next run)")

    # 4. Persist state
    state.save()
    log.info("State saved.")

    # 5. Write run summary
    _write_run_summary(start_time, items, run_results)

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    log.info(f"Syndication complete. Duration: {duration:.1f}s | Items: {len(items)} | Platforms: {len(platforms)}")
    log.info("=" * 60)


def _write_run_summary(start_time: datetime, items: list, results: dict):
    """Write JSON run summary for audit trail."""
    summary = {
        'run_at': start_time.isoformat(),
        'items_processed': len(items),
        'results': results
    }
    summary_path = Path("data/last_run_summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)


if __name__ == "__main__":
    run()
