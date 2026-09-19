"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — RATE LIMITER v1.0                       ║
║  Redis-backed with in-memory fallback · Tier-aware · Zero-crash guarantee ║
╚══════════════════════════════════════════════════════════════════════════════╝
Architecture:
  Primary:  Redis (if REDIS_URL env var set and Redis reachable)
  Fallback: In-memory TTL dict (thread-safe, process-local)
  Strategy: NEVER block request due to rate limiter failure
"""

from __future__ import annotations

import os
import time
import hashlib
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

logger = logging.getLogger("CDB-RATE-LIMITER")

# ── Tier Quotas (requests per day) ────────────────────────────────────────────
TIER_DAILY_LIMITS: Dict[str, int] = {
    "FREE":       100,
    "PRO":       10_000,
    "ENTERPRISE":100_000,
    "MSSP":      -1,       # -1 = unlimited
    # Legacy lowercase keys
    "free":       100,
    "pro":       10_000,
    "enterprise":100_000,
    "mssp":      -1,
}

# ── Redis connection pool (lazy init) ─────────────────────────────────────────
_redis_client = None
_redis_lock = threading.Lock()
_redis_failed = False  # Circuit breaker: if Redis fails, stay on in-memory


def _get_redis():
    """Lazy Redis connection with circuit breaker."""
    global _redis_client, _redis_failed
    if _redis_failed:
        return None
    if _redis_client is not None:
        return _redis_client

    redis_url = os.getenv("REDIS_URL", "")
    if not redis_url:
        return None

    with _redis_lock:
        if _redis_client is not None:
            return _redis_client
        try:
            import redis
            client = redis.from_url(
                redis_url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
                retry_on_timeout=False,
            )
            client.ping()
            _redis_client = client
            logger.info("Redis rate limiter connected")
            return _redis_client
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}) — using in-memory rate limiter")
            _redis_failed = True
            return None


# ── In-Memory Fallback Rate Limiter ──────────────────────────────────────────
class InMemoryRateLimiter:
    """
    Thread-safe in-memory rate limiter with per-day sliding window.
    Resets at UTC midnight. Uses minimal memory.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {key: {"count": int, "date": "YYYY-MM-DD"}}
        self._counters: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "date": ""})

    def _today(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def check_and_increment(self, key: str, limit: int) -> Tuple[bool, int, int]:
        """
        Returns (allowed, current_count, limit).
        If limit == -1 (MSSP), always allowed.
        """
        if limit == -1:
            return True, 0, -1

        today = self._today()
        with self._lock:
            entry = self._counters[key]
            # Reset counter at midnight
            if entry["date"] != today:
                entry["count"] = 0
                entry["date"] = today

            if entry["count"] >= limit:
                return False, entry["count"], limit

            entry["count"] += 1
            return True, entry["count"], limit

    def get_remaining(self, key: str, limit: int) -> int:
        if limit == -1:
            return 999_999
        today = self._today()
        with self._lock:
            entry = self._counters[key]
            if entry["date"] != today:
                return limit
            return max(0, limit - entry["count"])

    def cleanup_old_keys(self) -> int:
        """Remove stale entries (yesterday's keys). Call periodically."""
        today = self._today()
        with self._lock:
            stale = [k for k, v in self._counters.items() if v["date"] < today]
            for k in stale:
                del self._counters[k]
        return len(stale)


# ── Redis Rate Limiter ────────────────────────────────────────────────────────
class RedisRateLimiter:
    """Redis-backed sliding window counter using atomic INCR + EXPIRE."""

    def check_and_increment(self, redis_client, key: str, limit: int) -> Tuple[bool, int, int]:
        if limit == -1:
            return True, 0, -1
        try:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            redis_key = f"ratelimit:{key}:{today}"
            pipe = redis_client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, 86400)  # 24h TTL
            results = pipe.execute()
            count = int(results[0])
            if count > limit:
                return False, count, limit
            return True, count, limit
        except Exception as e:
            logger.warning(f"Redis rate limit check failed: {e}")
            raise  # Let caller fall back to in-memory


# ── Unified Rate Limiter (Primary + Fallback) ─────────────────────────────────
_in_memory = InMemoryRateLimiter()
_redis_limiter = RedisRateLimiter()


def check_rate_limit(api_key_hash: str, tier: str) -> Tuple[bool, int, int]:
    """
    Primary entry point. Returns (allowed, current_count, daily_limit).
    NEVER raises — always returns a usable result.
    Safe fallback: if both Redis and in-memory fail, ALLOW the request.
    """
    limit = TIER_DAILY_LIMITS.get(tier.upper(), 100)
    key = hashlib.sha256(api_key_hash.encode()).hexdigest()[:16]

    # Try Redis first
    redis = _get_redis()
    if redis is not None:
        try:
            return _redis_limiter.check_and_increment(redis, key, limit)
        except Exception:
            pass  # Fall through to in-memory

    # In-memory fallback
    try:
        return _in_memory.check_and_increment(key, limit)
    except Exception as e:
        logger.error(f"Rate limiter fatal fallback: {e}")
        return True, 0, limit  # Allow on total failure — never block


def get_quota_remaining(api_key_hash: str, tier: str) -> int:
    """Returns remaining quota for the day. NEVER raises."""
    limit = TIER_DAILY_LIMITS.get(tier.upper(), 100)
    if limit == -1:
        return 999_999
    key = hashlib.sha256(api_key_hash.encode()).hexdigest()[:16]
    try:
        redis = _get_redis()
        if redis is not None:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            redis_key = f"ratelimit:{key}:{today}"
            count = int(redis.get(redis_key) or 0)
            return max(0, limit - count)
    except Exception:
        pass
    try:
        return _in_memory.get_remaining(key, limit)
    except Exception:
        return limit


def get_tier_limit(tier: str) -> int:
    """Returns daily limit for a tier."""
    return TIER_DAILY_LIMITS.get(tier.upper(), 100)


def is_redis_available() -> bool:
    """Health check for Redis availability."""
    try:
        r = _get_redis()
        if r:
            r.ping()
            return True
    except Exception:
        pass
    return False
