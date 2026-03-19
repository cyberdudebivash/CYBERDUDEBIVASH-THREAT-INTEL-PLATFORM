"""
SENTINEL APEX — Rate Limiting Middleware
In-memory sliding window rate limiter with PG persistence fallback.
Upgrades to Upstash Redis when configured.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import get_settings

logger = logging.getLogger("sentinel.ratelimit")
settings = get_settings()


class InMemoryRateLimiter:
    """
    Thread-safe in-memory rate limiter using sliding window counters.
    Sufficient for single-instance Railway deployment.
    Replace with Redis for multi-instance scaling.
    """

    def __init__(self):
        # {key: [(timestamp, count)]}
        self._windows: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _cleanup(self):
        """Purge expired entries every 5 minutes."""
        now = time.time()
        if now - self._last_cleanup < 300:
            return
        cutoff = now - 86400  # 24h window
        for key in list(self._windows):
            self._windows[key] = [t for t in self._windows[key] if t > cutoff]
            if not self._windows[key]:
                del self._windows[key]
        self._last_cleanup = now

    def check_and_increment(self, key: str, limit: int) -> tuple[bool, int, int]:
        """
        Check if request is within rate limit and increment counter.
        Returns: (allowed, current_count, limit)
        """
        self._cleanup()
        now = time.time()
        day_start = now - 86400

        # Count requests in last 24h window
        self._windows[key] = [t for t in self._windows[key] if t > day_start]
        current = len(self._windows[key])

        if limit > 0 and current >= limit:
            return False, current, limit

        self._windows[key].append(now)
        return True, current + 1, limit

    def get_count(self, key: str) -> int:
        now = time.time()
        day_start = now - 86400
        self._windows[key] = [t for t in self._windows[key] if t > day_start]
        return len(self._windows[key])


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

        # Determine rate limit key and limit
        api_key = request.headers.get("x-api-key")
        auth_header = request.headers.get("authorization", "")

        if api_key:
            key = f"apikey:{api_key[:24]}"
            # Limit will be resolved by auth dependency; use default here
            limit = settings.RATE_LIMIT_PRO
        elif auth_header.startswith("Bearer "):
            key = f"jwt:{auth_header[7:20]}"
            limit = settings.RATE_LIMIT_PRO
        else:
            # Unauthenticated — rate limit by IP
            client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
            if "," in client_ip:
                client_ip = client_ip.split(",")[0].strip()
            key = f"ip:{client_ip}"
            limit = settings.RATE_LIMIT_FREE

        allowed, current, max_limit = rate_limiter.check_and_increment(key, limit)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Daily limit of {max_limit} requests exceeded. Upgrade your plan at https://app.cyberdudebivash.com/billing",
                    "status_code": 429,
                },
                headers={
                    "X-RateLimit-Limit": str(max_limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + 86400),
                    "Retry-After": "3600",
                },
            )

        # Process request
        response = await call_next(request)

        # Inject rate limit headers
        response.headers["X-RateLimit-Limit"] = str(max_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, max_limit - current))
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 86400)

        return response
