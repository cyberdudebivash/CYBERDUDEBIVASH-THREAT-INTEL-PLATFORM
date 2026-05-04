"""
SENTINEL APEX — Rate Limiting Middleware v143.0.0
Dual-window sliding rate limiter: per-minute (Enterprise burst) + per-day (quota).

Enterprise tier: 2,000 req/min burst + 100,000/day
MSSP tier:       2,000 req/min burst + unlimited/day
PRO tier:        500  req/min + 10,000/day
FREE tier:        60  req/min + 100/day

Headers injected on every response:
  X-RateLimit-Limit          — daily quota
  X-RateLimit-Remaining      — daily quota remaining
  X-RateLimit-Burst-Limit    — per-minute limit
  X-RateLimit-Burst-Remaining — per-minute remaining
  X-RateLimit-Reset          — daily reset timestamp (epoch)
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional, Tuple

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import get_settings

logger = logging.getLogger("sentinel.ratelimit")
settings = get_settings()

# Per-tier burst (per-minute) limits
TIER_BURST_LIMITS = {
    "MSSP":       2000,
    "ENTERPRISE": 2000,
    "PRO":         500,
    "FREE":         60,
}


class InMemoryRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter.
    Dual-window: 60-second burst + 86400-second daily.
    Sufficient for single-instance Railway deployment.
    Replace with Redis for multi-instance horizontal scaling.
    """

    def __init__(self):
        # Separate tracking windows for burst (1m) and daily (24h)
        self._daily:  dict[str, list[float]] = defaultdict(list)   # 86400s
        self._burst:  dict[str, list[float]] = defaultdict(list)   # 60s
        self._last_cleanup = time.time()

    def _cleanup(self):
        """Purge expired entries every 2 minutes."""
        now = time.time()
        if now - self._last_cleanup < 120:
            return
        day_cutoff  = now - 86400
        burst_cutoff = now - 60
        for key in list(self._daily):
            self._daily[key] = [t for t in self._daily[key] if t > day_cutoff]
            if not self._daily[key]:
                del self._daily[key]
        for key in list(self._burst):
            self._burst[key] = [t for t in self._burst[key] if t > burst_cutoff]
            if not self._burst[key]:
                del self._burst[key]
        self._last_cleanup = now

    def check_and_increment(self, key: str, daily_limit: int,
                            burst_limit: int = 0) -> Tuple[bool, int, int, int, int]:
        """
        Dual-window rate limit check.
        Returns: (allowed, daily_current, daily_limit, burst_current, burst_limit)
        Returning burst_limit=0 means no burst enforcement for this tier.
        """
        self._cleanup()
        now = time.time()

        # ── Daily window ──────────────────────────────────────────────────────
        day_cutoff = now - 86400
        self._daily[key] = [t for t in self._daily[key] if t > day_cutoff]
        daily_current = len(self._daily[key])

        if daily_limit > 0 and daily_current >= daily_limit:
            return False, daily_current, daily_limit, 0, burst_limit

        # ── Burst window (per minute) ─────────────────────────────────────────
        if burst_limit > 0:
            burst_cutoff = now - 60
            self._burst[key] = [t for t in self._burst[key] if t > burst_cutoff]
            burst_current = len(self._burst[key])
            if burst_current >= burst_limit:
                return False, daily_current, daily_limit, burst_current, burst_limit
            self._burst[key].append(now)
        else:
            burst_current = 0

        self._daily[key].append(now)
        return True, daily_current + 1, daily_limit, burst_current + 1, burst_limit

    def get_count(self, key: str) -> Tuple[int, int]:
        """Return (daily_count, burst_count)."""
        now = time.time()
        self._daily[key] = [t for t in self._daily[key] if t > now - 86400]
        self._burst[key]  = [t for t in self._burst[key]  if t > now - 60]
        return len(self._daily[key]), len(self._burst[key])


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware that checks API key or IP-based limits.
    Injects rate limit headers into response.
    """

    EXEMPT_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc"}
    EXEMPT_PREFIXES = ("/api/v1/ingest",)  # Pipeline endpoints use secret auth, not rate limits

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip rate limiting for non-API paths and pipeline endpoints
        if path in self.EXEMPT_PATHS or not path.startswith("/api/"):
            return await call_next(request)
        if any(path.startswith(p) for p in self.EXEMPT_PREFIXES):
            return await call_next(request)

        # Determine rate limit key, tier, and limits
        api_key     = request.headers.get("x-api-key")
        auth_header = request.headers.get("authorization", "")

        # Attempt tier resolution from request state (set by auth middleware/dep)
        tier: str = getattr(request.state, "tier", "FREE").upper()

        if api_key:
            key   = f"apikey:{api_key[:24]}"
            if tier in ("ENTERPRISE", "MSSP"):
                daily_limit = -1 if tier == "MSSP" else settings.RATE_LIMIT_ENTERPRISE
                burst_limit = TIER_BURST_LIMITS["ENTERPRISE"]
            else:
                daily_limit = settings.RATE_LIMIT_PRO
                burst_limit = TIER_BURST_LIMITS.get(tier, TIER_BURST_LIMITS["PRO"])
        elif auth_header.startswith("Bearer "):
            key         = f"jwt:{auth_header[7:20]}"
            daily_limit = settings.RATE_LIMIT_PRO
            burst_limit = TIER_BURST_LIMITS.get(tier, TIER_BURST_LIMITS["PRO"])
        else:
            # Unauthenticated — rate limit by IP
            client_ip = request.headers.get("x-forwarded-for",
                                            request.client.host if request.client else "unknown")
            if "," in client_ip:
                client_ip = client_ip.split(",")[0].strip()
            key         = f"ip:{client_ip}"
            daily_limit = settings.RATE_LIMIT_FREE
            burst_limit = TIER_BURST_LIMITS["FREE"]

        allowed, daily_cur, daily_lim, burst_cur, burst_lim = rate_limiter.check_and_increment(
            key, daily_limit, burst_limit
        )

        if not allowed:
            # Determine whether daily or burst limit was hit
            if burst_lim > 0 and burst_cur >= burst_lim:
                detail = (
                    f"Burst limit of {burst_lim} req/min exceeded. "
                    f"Enterprise tier supports {burst_lim:,} requests/minute."
                )
                retry_after = "60"
            else:
                detail = (
                    f"Daily limit of {daily_lim} requests exceeded. "
                    "Upgrade your plan at https://app.cyberdudebivash.com/billing"
                )
                retry_after = str(int(time.time()) + 86400)

            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "detail": detail, "status_code": 429},
                headers={
                    "X-RateLimit-Limit":           str(daily_lim) if daily_lim > 0 else "unlimited",
                    "X-RateLimit-Remaining":       "0",
                    "X-RateLimit-Reset":           str(int(time.time()) + 86400),
                    "X-RateLimit-Burst-Limit":     str(burst_lim),
                    "X-RateLimit-Burst-Remaining": "0",
                    "Retry-After":                 retry_after,
                },
            )

        # Process request
        response = await call_next(request)

        # Inject dual-window rate limit headers on all responses
        remaining_daily = (
            "unlimited" if daily_lim <= 0
            else str(max(0, daily_lim - daily_cur))
        )
        response.headers["X-RateLimit-Limit"]           = str(daily_lim) if daily_lim > 0 else "unlimited"
        response.headers["X-RateLimit-Remaining"]        = remaining_daily
        response.headers["X-RateLimit-Reset"]            = str(int(time.time()) + 86400)
        response.headers["X-RateLimit-Burst-Limit"]      = str(burst_lim)
        response.headers["X-RateLimit-Burst-Remaining"]  = str(max(0, burst_lim - burst_cur))
        response.headers["X-RateLimit-Policy"]           = (
            f"Enterprise;burst={burst_lim}/min;daily={daily_lim}"
            if tier in ("ENTERPRISE", "MSSP") else
            f"Standard;burst={burst_lim}/min;daily={daily_lim}"
        )

        return response
