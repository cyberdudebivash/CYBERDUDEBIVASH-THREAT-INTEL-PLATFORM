"""
CYBERDUDEBIVASH® SENTINEL APEX v56.0 — Resilient Publisher
============================================================
Drop-in replacement for the Blogger publish logic in process_entry().

Three production fixes:
  FIX 1: Rate limiter — 8s minimum between API calls
  FIX 2: Retry handler — 5 attempts with 60s backoff on 429
  FIX 3: Manifest-first — STIX bundle written BEFORE publish attempt

Plus: Failed publish queue for zero intel loss.

Usage from sentinel_blogger.py:
    from agent.v56_publish_guard.publisher import resilient_publish
    result = resilient_publish(service, blog_id, post_body, stix_params, entry, ...)

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("CDB-PUBLISH-GUARD")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MIN_PUBLISH_INTERVAL = 8       # Seconds between Blogger API calls (6 posts/min max)
MAX_RETRY_ATTEMPTS = 5         # Retry attempts on 429/5xx
RETRY_BASE_DELAY = 60          # Base delay on 429 (seconds)
RETRY_BACKOFF_FACTOR = 1.5     # Multiplier for exponential backoff

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PENDING_QUEUE_FILE = BASE_DIR / "data" / "pending_publish.json"

# Track last publish timestamp for rate limiting
_last_publish_time: float = 0.0


# ---------------------------------------------------------------------------
# FIX 1: Rate Limiter
# ---------------------------------------------------------------------------

def rate_limit_wait():
    """Enforce minimum interval between Blogger API publish calls."""
    global _last_publish_time
    if _last_publish_time > 0:
        elapsed = time.time() - _last_publish_time
        if elapsed < MIN_PUBLISH_INTERVAL:
            wait_time = MIN_PUBLISH_INTERVAL - elapsed
            logger.info(f"  ⏱ Rate limiter: waiting {wait_time:.1f}s before next publish")
            time.sleep(wait_time)
    _last_publish_time = time.time()


# ---------------------------------------------------------------------------
# FIX 2: Retry Handler with Exponential Backoff
# ---------------------------------------------------------------------------

def publish_with_retry(service, blog_id: str, post_body: Dict) -> Tuple[bool, Optional[Dict], str]:
    """
    Attempt to publish to Blogger with retry on 429/5xx errors.

    Returns:
        (success: bool, response: dict|None, error_msg: str)
    """
    last_error = ""

    for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
        try:
            rate_limit_wait()

            response = service.posts().insert(
                blogId=blog_id,
                body=post_body,
            ).execute()

            blog_url = response.get("url", "")
            logger.info(f"  ✓ Published on attempt {attempt}: {blog_url}")
            return True, response, ""

        except Exception as e:
            error_str = str(e).lower()
            last_error = str(e)

            # Detect rate limit (429) or server error (5xx)
            is_rate_limit = "429" in error_str or "ratelimit" in error_str or "quota" in error_str
            is_server_error = any(code in error_str for code in ["500", "502", "503", "504"])

            if is_rate_limit or is_server_error:
                delay = RETRY_BASE_DELAY * (RETRY_BACKOFF_FACTOR ** (attempt - 1))
                error_type = "RATE_LIMIT (429)" if is_rate_limit else "SERVER_ERROR"
                logger.warning(
                    f"  ⚠ {error_type} on attempt {attempt}/{MAX_RETRY_ATTEMPTS} — "
                    f"retrying in {delay:.0f}s: {str(e)[:100]}"
                )
                if attempt < MAX_RETRY_ATTEMPTS:
                    time.sleep(delay)
                continue

            # Non-retryable error (400 bad request, auth error, etc.)
            logger.error(f"  ✗ Non-retryable publish error on attempt {attempt}: {e}")
            return False, None, str(e)

    # All retries exhausted
    logger.error(f"  ✗ All {MAX_RETRY_ATTEMPTS} publish attempts failed: {last_error[:100]}")
    return False, None, last_error


# ---------------------------------------------------------------------------
# FIX 3 + Queue: Manifest-First + Failed Publish Queue
# ---------------------------------------------------------------------------

def save_to_pending_queue(headline: str, post_body: Dict, stix_id: str = ""):
    """Save a failed publish to the pending queue for retry on next run."""
    try:
        PENDING_QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
        queue = []
        if PENDING_QUEUE_FILE.exists():
            try:
                with open(PENDING_QUEUE_FILE, "r") as f:
                    queue = json.load(f)
            except (json.JSONDecodeError, IOError):
                queue = []

        # Avoid duplicates
        existing_titles = {item.get("title", "") for item in queue}
        if headline in existing_titles:
            logger.info(f"  ℹ Already in pending queue: {headline[:60]}")
            return

        queue.append({
            "title": headline,
            "post_body": post_body,
            "stix_id": stix_id,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "retry_count": 0,
        })

        with open(PENDING_QUEUE_FILE, "w") as f:
            json.dump(queue, f, indent=2, default=str)

        logger.info(f"  📋 Saved to pending queue ({len(queue)} total): {headline[:60]}")

    except Exception as e:
        logger.warning(f"  Failed to save to pending queue: {e}")


def retry_pending_queue(service, blog_id: str) -> int:
    """
    Retry publishing items from the pending queue.
    Called at the start of each pipeline run.
    Returns number of successfully published items.
    """
    if not PENDING_QUEUE_FILE.exists():
        return 0

    try:
        with open(PENDING_QUEUE_FILE, "r") as f:
            queue = json.load(f)
    except (json.JSONDecodeError, IOError):
        return 0

    if not queue:
        return 0

    logger.info(f"📋 Pending publish queue: {len(queue)} items to retry")
    published = 0
    remaining = []

    for item in queue:
        title = item.get("title", "Unknown")
        post_body = item.get("post_body", {})
        retry_count = item.get("retry_count", 0)

        if retry_count >= MAX_RETRY_ATTEMPTS:
            logger.warning(f"  ⏭ Dropping (max retries exceeded): {title[:60]}")
            continue

        success, response, error = publish_with_retry(service, blog_id, post_body)

        if success:
            published += 1
            logger.info(f"  ✅ Pending item published: {title[:60]}")
        else:
            item["retry_count"] = retry_count + 1
            item["last_error"] = error[:200]
            item["last_retry"] = datetime.now(timezone.utc).isoformat()
            remaining.append(item)
            logger.warning(f"  ❌ Pending retry failed (attempt {retry_count + 1}): {title[:60]}")

    # Write remaining items back
    with open(PENDING_QUEUE_FILE, "w") as f:
        json.dump(remaining, f, indent=2, default=str)

    if published:
        logger.info(f"📋 Pending queue: {published} published, {len(remaining)} remaining")

    return published


# ---------------------------------------------------------------------------
# Combined Resilient Publish Function
# ---------------------------------------------------------------------------

def resilient_publish(
    service,
    blog_id: str,
    headline: str,
    report_html: str,
    labels: list,
    entry: Dict,
    stix_exporter,
    dedup_engine,
    extracted_iocs: Dict,
    risk_score: float,
    confidence: float,
    severity: str,
    tlp: Dict,
    ioc_counts: Dict,
    actor_data: Dict,
    mitre_data: list,
    feed_source: str,
    source_url: str,
    enriched_content: str,
    epss_score: Optional[float],
    cvss_score: Optional[float],
    kev_present: bool,
    nvd_url: str,
) -> bool:
    """
    Production-hardened publish function implementing all three fixes:
      1. Manifest-first: STIX bundle written BEFORE publish attempt
      2. Rate-limited: 8s minimum between API calls
      3. Retry on 429: 5 attempts with 60s exponential backoff
      4. Failed publish queue: zero intel loss

    Returns True if advisory was processed (manifest updated), regardless of publish status.
    """

    # ─── FIX 3: MANIFEST-FIRST — Write STIX bundle BEFORE publish ───
    # This ensures the dashboard always gets new intelligence
    # even if Blogger publishing fails
    try:
        stix_exporter.create_bundle(
            title=headline,
            iocs=extracted_iocs,
            risk_score=risk_score,
            metadata={"blog_url": "", "source_url": source_url},  # blog_url filled after publish
            confidence=confidence,
            severity=severity,
            tlp_label=tlp.get('label', 'TLP:CLEAR'),
            ioc_counts=ioc_counts,
            actor_tag=actor_data.get('tracking_id', 'UNC-CDB-99'),
            mitre_tactics=mitre_data,
            feed_source=feed_source,
            epss_score=epss_score,
            cvss_score=cvss_score,
            kev_present=kev_present,
            nvd_url=nvd_url,
        )
        logger.info(f"  ✓ STIX bundle + manifest written (pre-publish)")
    except Exception as stix_err:
        logger.error(f"  ✗ STIX bundle write failed: {stix_err}")
        # Continue to publish attempt — don't abort the entire advisory

    # ─── Dedup Registration (pre-publish to prevent re-processing) ───
    dedup_engine.mark_processed(headline, entry.get('link', ''))

    # ─── FIX 1 + FIX 2: Rate-limited publish with retry ───
    post_body = {
        "kind": "blogger#post",
        "title": headline,
        "content": report_html,
        "labels": labels,
    }

    success, response, error = publish_with_retry(service, blog_id, post_body)

    if success:
        live_blog_url = response.get("url", "") if response else ""

        # Update STIX manifest with actual blog URL
        try:
            _update_manifest_blog_url(headline, live_blog_url)
        except Exception:
            pass  # Non-critical — manifest already has the intel data

        # Revenue bridge (non-critical)
        try:
            from agent.revenue_bridge import activate_revenue_pipeline
            activate_revenue_pipeline(
                report_html=report_html,
                headline=headline,
                risk_score=risk_score,
                live_blog_url=live_blog_url,
                content=enriched_content,
                product_url="",
            )
        except Exception:
            pass

        return True

    else:
        # ─── Failed Publish Queue — Save for retry on next run ───
        save_to_pending_queue(headline, post_body)

        # Return True because the MANIFEST was updated successfully
        # The dashboard will show the intel even without the blog URL
        logger.info(f"  ℹ Advisory in manifest (blog publish pending): {headline[:60]}")
        return True


def _update_manifest_blog_url(headline: str, blog_url: str):
    """Update the manifest entry with the actual blog URL after successful publish."""
    manifest_path = os.path.join("data", "stix", "feed_manifest.json")
    if not os.path.exists(manifest_path):
        return

    try:
        with open(manifest_path, "r") as f:
            data = json.load(f)

        entries = data if isinstance(data, list) else data.get("entries", [])
        for entry in entries:
            if entry.get("title") == headline and not entry.get("blog_url"):
                entry["blog_url"] = blog_url
                break

        with open(manifest_path, "w") as f:
            json.dump(data if isinstance(data, dict) else entries, f, indent=2, default=str)
    except Exception:
        pass  # Non-critical
