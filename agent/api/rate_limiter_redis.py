#!/usr/bin/env python3
"""
rate_limiter_redis.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE REDIS-BACKED RATE LIMITER

Replaces the in-memory token bucket with a Redis sliding-window limiter
enabling horizontal scaling across multiple API pods.

Design:
  - Uses Redis sorted sets (ZSET) for O(log N) sliding-window computation
  - Atomic pipeline operations — race-condition safe
  - Automatic fallback to existing in-memory RateLimiter if Redis unavailable
  - Same interface as existing rate_limiter.py — zero breaking changes
  - Exposes per-tier limit headers: X-RateLimit-Limit, X-RateLimit-Remaining,
    X-RateLimit-Reset for RFC 6585 compliance

Usage:
    from agent.api.rate_limiter_redis import redis_rate_limiter
    allowed, info = redis_rate_limiter.check("ip:1.2.3.4", tier="FREE")

Rollback: remove REDIS_URL env var → automatic fallback to in-memory limiter.
"""

import os
import time
import logging
from typing import Tuple, Dict, Optional

logger = logging.getLogger("CDB-RATE-LIMITER-REDIS")

REDIS_URL = os.environ.get("REDIS_URL", "")

# Per-tier rate limit overrides (requests per window) — env-configurable
_TIER_LIMITS: Dict[str, int] = {
    "FREE":       int(os.environ.get("RL_FREE",       "100")),
    "STANDARD":   int(os.environ.get("RL_STANDARD",   "500")),
    "PREMIUM":    int(os.environ.get("RL_PREMIUM",    "2000")),
    "PRO":        int(os.environ.get("RL_PRO",        "2000")),   # legacy alias
    "ENTERPRISE": int(os.environ.get("RL_ENTERPRISE", "10000")),
    "MSSP":       int(os.environ.get("RL_MSSP",       "50000")),
    "INTERNAL":   int(os.environ.get("RL_INTERNAL",   "999999")),
}

_WINDOW_SECONDS = int(os.environ.get("API_RATE_WINDOW_SECONDS", "3600"))
_KEY_PREFIX     = "cdb:rl"


class RedisRateLimiter:
    """
    Sliding-window rate limiter backed by Redis sorted sets.

    Algorithm:
      1. Remove entries older than (now - window)  → ZREMRANGEBYSCORE
      2. Count remaining entries                    → ZCARD
      3. Add current request with timestamp score   → ZADD
      4. Set TTL to window duration                 → EXPIRE
      All in one atomic MULTI/EXEC pipeline.

    Falls back transparently to in-memory limiter when Redis unavailable.
    """

    def __init__(self):
        self._redis: Optional[object] = None
        self._fallback: Optional[object] = None
        self._redis_healthy = False
        self._init_redis()

    def _init_redis(self) -> None:
        if not REDIS_URL:
            logger.info("[RATE-REDIS] No REDIS_URL configured — using in-memory fallback")
            self._activate_fallback()
            return
        try:
            import redis as redis_lib
            client = redis_lib.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
                retry_on_timeout=False,
            )
            client.ping()
            self._redis = client
            self._redis_healthy = True
            logger.info("[RATE-REDIS] Redis rate limiter active")
        except Exception as e:
            logger.warning(f"[RATE-REDIS] Redis unavailable ({e}) — activating in-memory fallback")
            self._activate_fallback()

    def _activate_fallback(self) -> None:
        try:
            from agent.api.rate_limiter import rate_limiter
            self._fallback = rate_limiter
        except ImportError:
            self._fallback = None
            logger.warning("[RATE-REDIS] In-memory fallback also unavailable")

    def _ensure_redis_healthy(self) -> bool:
        """Lightweight health check — re-attempt reconnect if down."""
        if self._redis_healthy:
            return True
        if self._redis:
            try:
                self._redis.ping()
                self._redis_healthy = True
                return True
            except Exception:
                self._redis_healthy = False
        return False

    def check(self, identity: str, tier: str = "FREE") -> Tuple[bool, Dict]:
        """
        Check rate limit for identity+tier.

        Args:
            identity: Unique identifier (api_key hash, IP, etc.)
            tier:     Rate limit tier (FREE/STANDARD/PREMIUM/ENTERPRISE)

        Returns:
            (allowed: bool, info: dict)
            info contains: tier, limit, remaining, reset_at, backend
        """
        # Fallback path
        if not self._ensure_redis_healthy():
            if self._fallback:
                return self._fallback.check(identity, tier)
            # No fallback available — fail open with warning (availability > security for rate limiting)
            logger.error("[RATE-REDIS] All backends unavailable — failing open")
            return True, {"tier": tier, "limit": 0, "remaining": 0, "backend": "none", "warning": "rate_limiting_unavailable"}

        limit   = _TIER_LIMITS.get(tier, _TIER_LIMITS["FREE"])
        window  = _WINDOW_SECONDS
        now     = time.time()
        cutoff  = now - window
        key     = f"{_KEY_PREFIX}:{tier}:{identity}"

        try:
            pipe = self._redis.pipeline(transaction=True)
            pipe.zremrangebyscore(key, "-inf", cutoff)    # Evict stale entries
            pipe.zcard(key)                                # Count current window requests
            pipe.zadd(key, {f"{now:.6f}": now})           # Add this request
            pipe.expire(key, window + 60)                  # TTL with buffer
            results = pipe.execute()

            current_count = int(results[1])  # count BEFORE adding this request
            allowed       = current_count < limit
            remaining     = max(0, limit - current_count - 1) if allowed else 0

            # If over limit, remove the request we just added (don't pollute window)
            if not allowed:
                self._redis.zrem(key, f"{now:.6f}")

            return allowed, {
                "tier":      tier,
                "limit":     limit,
                "remaining": remaining,
                "reset_at":  round(now + window),
                "window_s":  window,
                "backend":   "redis",
                "identity":  identity[:8] + "…",  # Truncate for safe logging
            }

        except Exception as e:
            self._redis_healthy = False
            logger.warning(f"[RATE-REDIS] Redis error ({e}) — falling back to in-memory")
            if self._fallback:
                return self._fallback.check(identity, tier)
            return True, {"tier": tier, "limit": limit, "remaining": limit, "backend": "error_fallback"}

    def get_stats(self) -> Dict:
        """Return rate limiter health stats for observability."""
        return {
            "backend":         "redis" if self._redis_healthy else "in-memory",
            "redis_healthy":   self._redis_healthy,
            "redis_configured": bool(REDIS_URL),
            "tier_limits":     _TIER_LIMITS,
            "window_seconds":  _WINDOW_SECONDS,
        }

    def reset_identity(self, identity: str, tier: str) -> bool:
        """Reset rate limit for a specific identity (admin use only)."""
        if not self._ensure_redis_healthy():
            return False
        try:
            key = f"{_KEY_PREFIX}:{tier}:{identity}"
            self._redis.delete(key)
            logger.info(f"[RATE-REDIS] Reset limit for {identity[:8]}… tier={tier}")
            return True
        except Exception as e:
            logger.error(f"[RATE-REDIS] Reset failed: {e}")
            return False


# Singleton — drop-in replacement for rate_limiter.rate_limiter
redis_rate_limiter = RedisRateLimiter()
