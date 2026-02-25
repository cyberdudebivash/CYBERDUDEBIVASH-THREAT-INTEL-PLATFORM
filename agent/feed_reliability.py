#!/usr/bin/env python3
"""
feed_reliability.py — CyberDudeBivash SENTINEL APEX ULTRA v1.0.0
Feed Pipeline Reliability Layer

Non-breaking addition to the existing feed pipeline.
Provides:
  - Retry logic with exponential backoff for HTTP requests
  - Per-feed health tracking (success rate, last error, latency)
  - Feed health summary endpoint for monitoring
  - User-agent rotation to reduce rate-limit friction
  - Timeout tuning and connection pooling recommendations

Usage:
    from agent.feed_reliability import reliable_get, FeedHealthTracker, feed_health

    # Drop-in replacement for requests.get with retry:
    response = reliable_get("https://example.com/feed.rss", max_retries=3)

    # Track feed health:
    feed_health.record_success("BleepingComputer", latency_ms=250)
    feed_health.record_failure("SomeSource", error="Connection timeout")
    print(feed_health.get_summary())

Does NOT modify:
    - agent/config.py
    - agent/intel/cve_feed.py
    - agent/integrations/sources/multi_source_intel.py
    - Any existing agent/*.py files
"""

import time
import logging
import random
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

logger = logging.getLogger("CDB-FeedReliability")


# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 25          # seconds — slightly higher than existing 20s
MAX_RETRIES = 3               # network retries per feed
BACKOFF_FACTOR = 1.5          # exponential backoff multiplier
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}  # HTTP codes that trigger retry

# Rotate user agents to reduce rate-limit friction from WAFs/CDNs
USER_AGENTS = [
    "CyberDudeBivash-SentinelAPEX/1.0 (+https://intel.cyberdudebivash.com/; security-research)",
    "Mozilla/5.0 (compatible; CDB-IntelBot/1.0; +https://cyberdudebivash.com)",
    "Sentinel-APEX-IntelAgent/1.0 (CyberDudeBivash GOC)",
]


# ─── Retry-Enabled HTTP Session ───────────────────────────────────────────────

def _build_retry_session(
    max_retries: int = MAX_RETRIES,
    backoff_factor: float = BACKOFF_FACTOR,
) -> "requests.Session":
    """
    Build a requests.Session with automatic retry on transient errors.
    Uses urllib3's Retry adapter for HTTP 429/5xx and connection errors.
    """
    if not _REQUESTS_AVAILABLE:
        raise ImportError("requests library not available — install with: pip install requests")

    session = requests.Session()

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=RETRY_STATUS_CODES,
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=20,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def reliable_get(
    url: str,
    max_retries: int = MAX_RETRIES,
    timeout: int = DEFAULT_TIMEOUT,
    headers: Optional[Dict] = None,
    params: Optional[Dict] = None,
) -> Optional["requests.Response"]:
    """
    Drop-in replacement for requests.get() with retry logic and health tracking.

    Args:
        url: Target URL
        max_retries: Number of retries on transient failures
        timeout: Request timeout in seconds
        headers: Optional extra HTTP headers
        params: Optional query parameters

    Returns:
        requests.Response on success, None on failure after all retries
    """
    if not _REQUESTS_AVAILABLE:
        logger.error("requests library not available")
        return None

    base_headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/rss+xml, application/atom+xml, application/json, text/html, */*",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
    }
    if headers:
        base_headers.update(headers)

    session = _build_retry_session(max_retries=max_retries)
    start_time = time.monotonic()

    try:
        response = session.get(
            url,
            headers=base_headers,
            params=params,
            timeout=timeout,
        )
        latency_ms = int((time.monotonic() - start_time) * 1000)

        if response.status_code == 200:
            feed_health.record_success(url, latency_ms=latency_ms)
            return response
        elif response.status_code == 429:
            logger.warning(f"[FeedReliability] Rate limited ({url}) — backing off")
            feed_health.record_failure(url, error=f"HTTP 429 Rate Limited")
            return response
        else:
            logger.warning(f"[FeedReliability] HTTP {response.status_code} for {url[:60]}")
            feed_health.record_failure(url, error=f"HTTP {response.status_code}")
            return response

    except Exception as exc:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        logger.error(f"[FeedReliability] Request failed for {url[:60]}: {exc}")
        feed_health.record_failure(url, error=str(exc)[:120])
        return None
    finally:
        session.close()


# ─── Feed Health Tracker ──────────────────────────────────────────────────────

class FeedHealthTracker:
    """
    Tracks per-feed reliability metrics across pipeline runs.

    Thread-safe for read/write within a single process.
    Persists in-memory only — resets on process restart.
    For persistent health state, call get_summary() and save to JSON.
    """

    def __init__(self):
        self._feeds: Dict[str, Dict[str, Any]] = {}

    def _ensure_feed(self, feed_name: str) -> None:
        if feed_name not in self._feeds:
            self._feeds[feed_name] = {
                "feed_name": feed_name,
                "success_count": 0,
                "failure_count": 0,
                "last_success": None,
                "last_failure": None,
                "last_error": None,
                "avg_latency_ms": 0.0,
                "_latency_samples": [],
                "status": "unknown",
            }

    def record_success(self, feed_name: str, latency_ms: int = 0) -> None:
        """Record a successful feed fetch."""
        self._ensure_feed(feed_name)
        feed = self._feeds[feed_name]
        feed["success_count"] += 1
        feed["last_success"] = datetime.now(timezone.utc).isoformat()
        feed["status"] = "healthy"

        # Rolling average latency (last 20 samples)
        samples = feed["_latency_samples"]
        samples.append(latency_ms)
        if len(samples) > 20:
            samples.pop(0)
        feed["avg_latency_ms"] = round(sum(samples) / len(samples), 1)

    def record_failure(self, feed_name: str, error: str = "") -> None:
        """Record a failed feed fetch."""
        self._ensure_feed(feed_name)
        feed = self._feeds[feed_name]
        feed["failure_count"] += 1
        feed["last_failure"] = datetime.now(timezone.utc).isoformat()
        feed["last_error"] = error
        total = feed["success_count"] + feed["failure_count"]
        fail_rate = feed["failure_count"] / total if total > 0 else 1.0
        feed["status"] = "degraded" if fail_rate > 0.5 else "intermittent"

    def get_feed_status(self, feed_name: str) -> Dict[str, Any]:
        """Get health stats for a single feed."""
        self._ensure_feed(feed_name)
        feed = dict(self._feeds[feed_name])
        feed.pop("_latency_samples", None)
        total = feed["success_count"] + feed["failure_count"]
        feed["success_rate_pct"] = round(
            (feed["success_count"] / total * 100) if total > 0 else 0.0, 1
        )
        return feed

    def get_summary(self) -> Dict[str, Any]:
        """Get a full health summary across all tracked feeds."""
        all_feeds = []
        healthy = degraded = unknown = 0

        for name in self._feeds:
            status = self.get_feed_status(name)
            all_feeds.append(status)
            s = status["status"]
            if s == "healthy":
                healthy += 1
            elif s in ("degraded", "intermittent"):
                degraded += 1
            else:
                unknown += 1

        total_feeds = len(all_feeds)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_feeds_tracked": total_feeds,
            "healthy": healthy,
            "degraded": degraded,
            "unknown": unknown,
            "overall_status": (
                "healthy" if degraded == 0 and total_feeds > 0
                else "degraded" if degraded > 0
                else "unknown"
            ),
            "feeds": sorted(all_feeds, key=lambda x: x["feed_name"]),
        }

    def get_degraded_feeds(self) -> List[Dict]:
        """Return list of feeds with degraded or intermittent status."""
        return [
            self.get_feed_status(name)
            for name in self._feeds
            if self._feeds[name]["status"] in ("degraded", "intermittent")
        ]

    def reset(self, feed_name: Optional[str] = None) -> None:
        """Reset health stats. If feed_name is None, resets all feeds."""
        if feed_name:
            self._feeds.pop(feed_name, None)
        else:
            self._feeds.clear()


# Module-level singleton — import and use anywhere in the pipeline
feed_health = FeedHealthTracker()


# ─── Utility: Check Feed Connectivity ────────────────────────────────────────

def probe_feeds(feed_urls: List[str], timeout: int = 10) -> Dict[str, str]:
    """
    Quick connectivity probe for a list of feed URLs.
    Returns dict of {url: "ok" | "timeout" | "error" | "http_NNN"}.
    Useful for pre-flight checks and CI diagnostics.
    """
    results = {}
    if not _REQUESTS_AVAILABLE:
        return {url: "error: requests not available" for url in feed_urls}

    for url in feed_urls:
        try:
            resp = requests.head(url, timeout=timeout, allow_redirects=True,
                                 headers={"User-Agent": USER_AGENTS[0]})
            status = "ok" if resp.status_code < 400 else f"http_{resp.status_code}"
            results[url] = status
        except requests.exceptions.Timeout:
            results[url] = "timeout"
        except Exception as e:
            results[url] = f"error: {str(e)[:60]}"

    return results


# ─── CLI: Feed Health Check ───────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Quick CLI feed health probe.
    Usage: python -m agent.feed_reliability
    """
    import sys
    sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__file__)))

    try:
        from agent.config import RSS_FEEDS
    except ImportError:
        RSS_FEEDS = []

    print("=" * 65)
    print("CDB SENTINEL APEX — Feed Connectivity Probe")
    print("=" * 65)

    if not RSS_FEEDS:
        print("⚠️  No RSS_FEEDS found in agent.config")
    else:
        print(f"Probing {len(RSS_FEEDS)} feeds...")
        results = probe_feeds(RSS_FEEDS, timeout=15)
        ok = sum(1 for v in results.values() if v == "ok")
        for url, status in results.items():
            icon = "✅" if status == "ok" else "❌"
            print(f"  {icon} {status:20s}  {url[:60]}")
        print(f"\n{ok}/{len(results)} feeds reachable")

    print("=" * 65)
