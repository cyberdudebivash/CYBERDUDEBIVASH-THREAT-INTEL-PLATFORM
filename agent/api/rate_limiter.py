#!/usr/bin/env python3
"""
rate_limiter.py — CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
NEW MODULE: Token-Bucket API Rate Limiting Engine

Provides per-API-key and per-IP rate limiting for all API tiers.
Fully in-memory (no Redis dependency) — production-ready for single-node.
Thread-safe via per-bucket locks.

Usage (FastAPI middleware integration):
    from agent.api.rate_limiter import rate_limiter
    allowed, info = rate_limiter.check("ip:1.2.3.4", tier="FREE")
"""
import time
import threading
import logging
from typing import Dict, Tuple, Optional
from datetime import datetime, timezone

from agent.config import (
    API_RATE_LIMIT_PUBLIC,
    API_RATE_LIMIT_PRO,
    API_RATE_LIMIT_ENTERPRISE,
    API_RATE_WINDOW_SECONDS,
    AUDIT_LOG_ENABLED,
    AUDIT_LOG_PATH,
    AUDIT_MAX_ENTRIES,
)

logger = logging.getLogger("CDB-RATE-LIMITER")


TIER_LIMITS = {
    "FREE":       API_RATE_LIMIT_PUBLIC,
    "PRO":        API_RATE_LIMIT_PRO,
    "ENTERPRISE": API_RATE_LIMIT_ENTERPRISE,
}


class _Bucket:
    """Sliding-window token bucket per identity+tier."""
    __slots__ = ("tokens", "last_refill", "lock")

    def __init__(self, capacity: int):
        self.tokens: float = capacity
        self.last_refill: float = time.monotonic()
        self.lock = threading.Lock()


class RateLimiter:
    """
    Token-bucket rate limiter.

    Each (identity, tier) pair gets its own bucket that refills
    at capacity/window_seconds tokens per second.
    Excess requests are rejected with HTTP 429 metadata.
    """

    def __init__(self):
        self._buckets: Dict[str, _Bucket] = {}
        self._global_lock = threading.Lock()
        self._denied_count: Dict[str, int] = {}
        self._request_log: list = []

    def _get_bucket(self, key: str, tier: str) -> _Bucket:
        bucket_key = f"{tier}:{key}"
        with self._global_lock:
            if bucket_key not in self._buckets:
                capacity = TIER_LIMITS.get(tier, TIER_LIMITS["FREE"])
                self._buckets[bucket_key] = _Bucket(capacity)
        return self._buckets[f"{tier}:{key}"]

    def check(
        self,
        identity: str,
        tier: str = "FREE",
        cost: float = 1.0,
        endpoint: str = "",
    ) -> Tuple[bool, Dict]:
        """
        Check and consume rate limit tokens.

        Args:
            identity: IP address or API key identifier
            tier: "FREE" | "PRO" | "ENTERPRISE"
            cost: token cost of this request (default 1.0)
            endpoint: endpoint path for logging

        Returns:
            (allowed: bool, info: dict with retry_after, remaining, limit)
        """
        capacity = TIER_LIMITS.get(tier, TIER_LIMITS["FREE"])
        bucket = self._get_bucket(identity, tier)
        now = time.monotonic()

        with bucket.lock:
            # Refill tokens based on elapsed time
            elapsed = now - bucket.last_refill
            refill_rate = capacity / API_RATE_WINDOW_SECONDS
            bucket.tokens = min(capacity, bucket.tokens + elapsed * refill_rate)
            bucket.last_refill = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                remaining = int(bucket.tokens)
                allowed = True
                retry_after = None
            else:
                deficit = cost - bucket.tokens
                retry_after = round(deficit / refill_rate, 1)
                remaining = 0
                allowed = False

        info = {
            "allowed":     allowed,
            "tier":        tier,
            "limit":       capacity,
            "remaining":   remaining,
            "window_sec":  API_RATE_WINDOW_SECONDS,
            "retry_after": retry_after,
            "identity":    identity[:20],  # truncate for logging
        }

        if not allowed:
            deny_key = f"{tier}:{identity}"
            self._denied_count[deny_key] = self._denied_count.get(deny_key, 0) + 1
            logger.warning(
                f"RATE LIMITED | tier={tier} identity={identity[:20]} "
                f"endpoint={endpoint} retry_after={retry_after}s"
            )
            if AUDIT_LOG_ENABLED:
                self._audit("RATE_LIMIT_DENIED", identity, tier, endpoint)

        return allowed, info

    def get_headers(self, info: Dict) -> Dict[str, str]:
        """Generate standard rate limit response headers."""
        headers = {
            "X-RateLimit-Limit":     str(info["limit"]),
            "X-RateLimit-Remaining": str(info["remaining"]),
            "X-RateLimit-Window":    str(info["window_sec"]),
            "X-RateLimit-Tier":      info["tier"],
        }
        if info.get("retry_after") is not None:
            headers["Retry-After"] = str(info["retry_after"])
            headers["X-RateLimit-Reset"] = str(int(time.time() + info["retry_after"]))
        return headers

    def get_stats(self) -> Dict:
        """Return rate limiter operational statistics."""
        with self._global_lock:
            total_buckets = len(self._buckets)
            total_denied = sum(self._denied_count.values())
            by_tier = {}
            for key in self._buckets:
                tier = key.split(":")[0]
                by_tier[tier] = by_tier.get(tier, 0) + 1
        return {
            "active_buckets":   total_buckets,
            "total_denied":     total_denied,
            "denied_by_id":     dict(self._denied_count),
            "buckets_by_tier":  by_tier,
            "tier_limits":      TIER_LIMITS,
            "window_seconds":   API_RATE_WINDOW_SECONDS,
            "computed_at":      datetime.now(timezone.utc).isoformat(),
        }

    def reset(self, identity: str, tier: str = "FREE"):
        """Reset rate limit bucket for a specific identity (admin use)."""
        bucket_key = f"{tier}:{identity}"
        with self._global_lock:
            if bucket_key in self._buckets:
                del self._buckets[bucket_key]
                logger.info(f"Rate limit reset for {identity} ({tier})")

    def _audit(self, event: str, identity: str, tier: str, endpoint: str):
        """Append event to audit log (non-blocking)."""
        try:
            import json, os
            entry = {
                "ts":       datetime.now(timezone.utc).isoformat(),
                "event":    event,
                "identity": identity[:64],
                "tier":     tier,
                "endpoint": endpoint,
            }
            log = []
            if os.path.exists(AUDIT_LOG_PATH):
                try:
                    with open(AUDIT_LOG_PATH, "r") as f:
                        log = json.load(f)
                except Exception:
                    log = []
            log.append(entry)
            if len(log) > AUDIT_MAX_ENTRIES:
                log = log[-AUDIT_MAX_ENTRIES:]
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            with open(AUDIT_LOG_PATH, "w") as f:
                json.dump(log, f)
        except Exception as e:
            logger.debug(f"Audit log write failed: {e}")


# Global singleton
rate_limiter = RateLimiter()
