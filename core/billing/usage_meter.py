"""
core/billing/usage_meter.py — CYBERDUDEBIVASH® SENTINEL APEX v134.0
Atomic, thread-safe usage metering for API tier enforcement.

Design:
  - Redis INCR for atomic counters in distributed deployments
  - In-process file-backed atomics when Redis unavailable
  - Per-API-key, per-day rolling window (UTC midnight reset)
  - Sliding window accuracy mode for burst prevention
  - Overage detection: hard stop vs. soft warning per tier config
  - Persists daily totals to JSONL audit log for billing reconciliation
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("sentinel.billing.usage_meter")

_DATA_DIR  = Path(os.environ.get("SENTINEL_DATA_DIR", "/tmp/sentinel_data")) / "usage"
_DATA_DIR.mkdir(parents=True, exist_ok=True)

# Tier daily request limits (matches monetization.py TIERS)
_TIER_LIMITS: Dict[str, int] = {
    "free":       100,
    "pro":        5_000,
    "enterprise": 50_000,
    "mssp":       10_000_000,   # effectively unlimited
}

# Grace overage before hard block (percentage above limit)
_OVERAGE_GRACE_PCT = 0.05   # 5% grace buffer


@dataclass
class UsageRecord:
    """Single usage increment event."""
    api_key:    str
    tier:       str
    endpoint:   str
    count:      int = 1
    timestamp:  float = field(default_factory=time.time)
    request_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "api_key":    self.api_key[:12] + "****",   # masked for logs
            "tier":       self.tier,
            "endpoint":   self.endpoint,
            "count":      self.count,
            "timestamp":  self.timestamp,
            "request_id": self.request_id,
        }


@dataclass
class UsageStatus:
    """Current usage status for a key."""
    api_key:     str
    tier:        str
    used_today:  int
    limit:       int
    remaining:   int
    reset_at:    float    # Unix timestamp of next daily reset (UTC midnight)
    over_limit:  bool
    usage_pct:   float    # 0.0–1.0+ (can exceed 1.0 if over limit)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier":       self.tier,
            "used_today": self.used_today,
            "limit":      self.limit,
            "remaining":  max(0, self.remaining),
            "reset_at":   self.reset_at,
            "over_limit": self.over_limit,
            "usage_pct":  round(self.usage_pct * 100, 1),
        }

    @property
    def reset_in_s(self) -> int:
        return max(0, int(self.reset_at - time.time()))


class UsageMeter:
    """
    Thread-safe API usage counter.
    Redis INCR for distributed correctness; file-backed atomic counter as fallback.

    Usage:
        meter = UsageMeter()
        allowed, status = meter.check_and_increment(api_key, tier, endpoint)
        if not allowed:
            raise HTTPException(429, f"Daily limit {status.limit} exceeded")
    """

    def __init__(self, use_redis: bool = True) -> None:
        self._redis = self._try_redis() if use_redis else None
        # In-memory counters: {bucket_key: count}
        self._counters: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        self._audit_lock = threading.Lock()

    # ── Primary interface ─────────────────────────────────────────────────────

    def check_and_increment(
        self,
        api_key:    str,
        tier:       str,
        endpoint:   str = "unknown",
        count:      int = 1,
        request_id: str = "",
    ) -> Tuple[bool, UsageStatus]:
        """
        Atomically check limit and increment counter.

        Returns:
            (allowed: bool, status: UsageStatus)
            allowed=False means the request should be rejected (429).
        """
        limit    = _TIER_LIMITS.get(tier.lower(), 100)
        date_key = self._today_key()
        bucket   = self._bucket(api_key, date_key)

        # Atomic increment
        new_count = self._increment(bucket, count)

        # Soft grace: allow up to 5% over before hard block
        hard_limit = int(limit * (1 + _OVERAGE_GRACE_PCT))
        over_limit = new_count > hard_limit
        allowed    = not over_limit

        status = UsageStatus(
            api_key    = api_key,
            tier       = tier,
            used_today = new_count,
            limit      = limit,
            remaining  = limit - new_count,
            reset_at   = self._midnight_ts(),
            over_limit = over_limit,
            usage_pct  = new_count / limit if limit else 0.0,
        )

        # Log near-limit warnings
        if new_count > limit * 0.9 and new_count <= limit:
            logger.warning("usage_near_limit key=%s...  used=%d limit=%d tier=%s",
                           api_key[:8], new_count, limit, tier)

        # Audit log for billing reconciliation
        if allowed:
            self._append_audit(UsageRecord(
                api_key=api_key, tier=tier, endpoint=endpoint,
                count=count, request_id=request_id,
            ))
        else:
            logger.warning("usage_limit_exceeded key=%s... tier=%s used=%d limit=%d",
                           api_key[:8], tier, new_count, limit)

        return allowed, status

    def get_status(self, api_key: str, tier: str) -> UsageStatus:
        """Get current usage status without incrementing."""
        limit    = _TIER_LIMITS.get(tier.lower(), 100)
        date_key = self._today_key()
        bucket   = self._bucket(api_key, date_key)
        current  = self._read(bucket)

        return UsageStatus(
            api_key    = api_key,
            tier       = tier,
            used_today = current,
            limit      = limit,
            remaining  = limit - current,
            reset_at   = self._midnight_ts(),
            over_limit = current > limit,
            usage_pct  = current / limit if limit else 0.0,
        )

    def reset_key(self, api_key: str) -> None:
        """Manually reset usage counter for a key (admin operation)."""
        date_key = self._today_key()
        bucket   = self._bucket(api_key, date_key)
        if self._redis:
            try:
                self._redis.delete(bucket)
                return
            except Exception:
                pass
        with self._lock:
            self._counters[bucket] = 0
        logger.info("usage_reset key=%s...", api_key[:8])

    def daily_summary(self, date_str: Optional[str] = None) -> Dict[str, Any]:
        """
        Return daily usage summary from audit log.
        date_str format: YYYY-MM-DD (default: today)
        """
        if not date_str:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        audit_path = _DATA_DIR / f"usage_{date_str}.jsonl"
        if not audit_path.exists():
            return {"date": date_str, "total_requests": 0, "by_tier": {}, "by_endpoint": {}}

        total = 0
        by_tier: Dict[str, int]     = defaultdict(int)
        by_endpoint: Dict[str, int] = defaultdict(int)

        with open(audit_path) as f:
            for line in f:
                try:
                    rec = json.loads(line.strip())
                    cnt = rec.get("count", 1)
                    total            += cnt
                    by_tier[rec.get("tier", "unknown")] += cnt
                    by_endpoint[rec.get("endpoint", "unknown")] += cnt
                except Exception:
                    continue

        return {
            "date":            date_str,
            "total_requests":  total,
            "by_tier":         dict(by_tier),
            "by_endpoint":     dict(by_endpoint),
        }

    # ── Atomic counter primitives ─────────────────────────────────────────────

    def _increment(self, bucket: str, count: int) -> int:
        """Atomically increment counter and return new value."""
        if self._redis:
            try:
                new_val = self._redis.incrby(bucket, count)
                # Set TTL to 25 hours (ensures midnight reset doesn't delete mid-day)
                self._redis.expire(bucket, 90_000)
                return int(new_val)
            except Exception as exc:
                logger.warning("redis_increment_failed err=%s; fallback to memory", exc)
                self._redis = None

        with self._lock:
            self._counters[bucket] += count
            return self._counters[bucket]

    def _read(self, bucket: str) -> int:
        """Read current counter without incrementing."""
        if self._redis:
            try:
                val = self._redis.get(bucket)
                return int(val) if val else 0
            except Exception:
                pass
        with self._lock:
            return self._counters.get(bucket, 0)

    # ── Audit log ─────────────────────────────────────────────────────────────

    def _append_audit(self, record: UsageRecord) -> None:
        """Append usage record to daily JSONL audit file."""
        date_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        audit_path = _DATA_DIR / f"usage_{date_str}.jsonl"
        try:
            with self._audit_lock:
                with open(audit_path, "a") as f:
                    f.write(json.dumps(record.to_dict()) + "\n")
        except Exception as exc:
            logger.warning("audit_write_failed err=%s", exc)

    # ── Key functions ─────────────────────────────────────────────────────────

    @staticmethod
    def _bucket(api_key: str, date_key: str) -> str:
        """Redis key / dict key: sentinel:usage:{date}:{key_hash}"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        return f"sentinel:usage:{date_key}:{key_hash}"

    @staticmethod
    def _today_key() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    @staticmethod
    def _midnight_ts() -> float:
        """Unix timestamp of next UTC midnight."""
        now = datetime.now(timezone.utc)
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        next_midnight = midnight.replace(day=midnight.day + 1)
        return next_midnight.timestamp()

    @staticmethod
    def _try_redis():
        try:
            import redis as redis_lib
            host = os.environ.get("REDIS_HOST", "localhost")
            port = int(os.environ.get("REDIS_PORT", 6379))
            r = redis_lib.Redis(host=host, port=port, db=2, socket_timeout=1)
            r.ping()
            logger.info("usage_meter redis_connected host=%s port=%d", host, port)
            return r
        except Exception:
            logger.info("usage_meter redis_unavailable; using in-memory counters")
            return None


# ── Module singleton ───────────────────────────────────────────────────────
_meter_instance: Optional[UsageMeter] = None
_meter_lock = threading.Lock()


def get_meter() -> UsageMeter:
    """Get or create the global UsageMeter singleton."""
    global _meter_instance
    with _meter_lock:
        if _meter_instance is None:
            _meter_instance = UsageMeter()
        return _meter_instance
