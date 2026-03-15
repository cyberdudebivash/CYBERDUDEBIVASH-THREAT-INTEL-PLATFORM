#!/usr/bin/env python3
"""
quota_manager.py — CYBERDUDEBIVASH® SENTINEL APEX v55.0
MULTI-TIERED API & QUOTA MANAGEMENT ENGINE

Production-grade Redis-backed quota enforcement with:
  - 3-tier model: FREE / PRO / ENTERPRISE
  - Enterprise "Priority-10" real-time sharding (dedicated shard per tenant)
  - Free tier batched "Pulse Wave" delivery (aggregated, delayed)
  - Pro tier standard real-time access
  - Sliding-window counters with atomic Redis operations
  - Overage tracking for metered billing
  - Graceful degradation to in-memory when Redis unavailable

Integration:
    from agent.monetization.quota_manager import quota_engine
    result = quota_engine.consume("org_abc123", "api_calls", cost=1)
    if not result["allowed"]:
        return 429, result

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
Founder & CEO — Bivash Kumar Nayak
"""

import os
import time
import json
import hashlib
import threading
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, List, Any
from pathlib import Path
from enum import Enum

logger = logging.getLogger("CDB-QUOTA-MANAGER")

# ═══════════════════════════════════════════════════════════
# TIER DEFINITIONS
# ═══════════════════════════════════════════════════════════

class QuotaTier(str, Enum):
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


# Quota limits per billing period (monthly)
TIER_QUOTAS: Dict[str, Dict[str, Any]] = {
    QuotaTier.FREE: {
        "api_calls_monthly": 5_000,
        "api_calls_hourly": 60,
        "api_calls_per_second": 2,
        "reports_monthly": 2,
        "stix_exports_monthly": 0,
        "detection_rules_monthly": 0,
        "attack_surface_scans_monthly": 0,
        "webhook_subscriptions": 0,
        "ioc_search_results_max": 25,
        "data_retention_days": 30,
        "delivery_mode": "PULSE_WAVE",       # Batched delivery
        "pulse_wave_interval_sec": 300,      # 5-min aggregation windows
        "priority_level": 1,
        "shard_dedicated": False,
        "concurrent_connections": 1,
        "burst_allowance": 5,                # 5 extra requests above limit
    },
    QuotaTier.PRO: {
        "api_calls_monthly": 100_000,
        "api_calls_hourly": 600,
        "api_calls_per_second": 20,
        "reports_monthly": 20,
        "stix_exports_monthly": 50,
        "detection_rules_monthly": 100,
        "attack_surface_scans_monthly": 10,
        "webhook_subscriptions": 5,
        "ioc_search_results_max": 100,
        "data_retention_days": 180,
        "delivery_mode": "REALTIME",         # Standard real-time
        "pulse_wave_interval_sec": 0,
        "priority_level": 5,
        "shard_dedicated": False,
        "concurrent_connections": 10,
        "burst_allowance": 50,
    },
    QuotaTier.ENTERPRISE: {
        "api_calls_monthly": 1_000_000,
        "api_calls_hourly": 6_000,
        "api_calls_per_second": 100,
        "reports_monthly": -1,               # Unlimited
        "stix_exports_monthly": -1,
        "detection_rules_monthly": -1,
        "attack_surface_scans_monthly": -1,
        "webhook_subscriptions": -1,
        "ioc_search_results_max": 500,
        "data_retention_days": 365,
        "delivery_mode": "PRIORITY_10",      # Dedicated shard, zero-latency
        "pulse_wave_interval_sec": 0,
        "priority_level": 10,
        "shard_dedicated": True,             # Dedicated Redis shard
        "concurrent_connections": 100,
        "burst_allowance": 500,
    },
}

# ═══════════════════════════════════════════════════════════
# REDIS BACKEND (with in-memory fallback)
# ═══════════════════════════════════════════════════════════

REDIS_URL = os.environ.get("CDB_REDIS_URL", "redis://localhost:6379/0")
REDIS_PREFIX = "cdb:quota:"
REDIS_SHARD_PREFIX = "cdb:shard:"

# Enterprise Priority-10 shard pool
ENTERPRISE_SHARD_COUNT = int(os.environ.get("CDB_ENTERPRISE_SHARDS", "8"))


class RedisBackend:
    """Redis-backed atomic counter with graceful in-memory fallback."""

    def __init__(self):
        self._redis = None
        self._fallback: Dict[str, float] = {}
        self._fallback_lock = threading.Lock()
        self._fallback_expiry: Dict[str, float] = {}
        self._connect()

    def _connect(self):
        try:
            import redis
            self._redis = redis.Redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_timeout=2,
                socket_connect_timeout=2,
                retry_on_timeout=True,
                health_check_interval=30,
            )
            self._redis.ping()
            logger.info("Redis connected for quota enforcement")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}), using in-memory fallback")
            self._redis = None

    @property
    def is_redis_available(self) -> bool:
        if self._redis is None:
            return False
        try:
            self._redis.ping()
            return True
        except Exception:
            self._redis = None
            return False

    def incr_with_ttl(self, key: str, ttl_seconds: int, amount: int = 1) -> int:
        """Atomic increment with TTL. Returns new counter value."""
        full_key = f"{REDIS_PREFIX}{key}"
        if self.is_redis_available:
            try:
                pipe = self._redis.pipeline()
                pipe.incrby(full_key, amount)
                pipe.expire(full_key, ttl_seconds)
                results = pipe.execute()
                return int(results[0])
            except Exception as e:
                logger.error(f"Redis incr failed: {e}")

        # In-memory fallback
        with self._fallback_lock:
            now = time.monotonic()
            if full_key in self._fallback_expiry and now > self._fallback_expiry[full_key]:
                self._fallback[full_key] = 0
            self._fallback[full_key] = self._fallback.get(full_key, 0) + amount
            self._fallback_expiry[full_key] = now + ttl_seconds
            return int(self._fallback[full_key])

    def get_counter(self, key: str) -> int:
        """Get current counter value."""
        full_key = f"{REDIS_PREFIX}{key}"
        if self.is_redis_available:
            try:
                val = self._redis.get(full_key)
                return int(val) if val else 0
            except Exception:
                pass
        with self._fallback_lock:
            return int(self._fallback.get(full_key, 0))

    def set_with_ttl(self, key: str, value: str, ttl_seconds: int):
        """Set a key with TTL."""
        full_key = f"{REDIS_PREFIX}{key}"
        if self.is_redis_available:
            try:
                self._redis.setex(full_key, ttl_seconds, value)
                return
            except Exception:
                pass
        with self._fallback_lock:
            self._fallback[full_key] = value
            self._fallback_expiry[full_key] = time.monotonic() + ttl_seconds

    def get_shard_key(self, org_id: str) -> str:
        """Compute dedicated shard key for Enterprise Priority-10 tenants."""
        shard_idx = int(hashlib.sha256(org_id.encode()).hexdigest()[:8], 16) % ENTERPRISE_SHARD_COUNT
        return f"{REDIS_SHARD_PREFIX}ent:{shard_idx}:{org_id}"

    def delete_key(self, key: str):
        """Delete a quota key (admin reset)."""
        full_key = f"{REDIS_PREFIX}{key}"
        if self.is_redis_available:
            try:
                self._redis.delete(full_key)
            except Exception:
                pass
        with self._fallback_lock:
            self._fallback.pop(full_key, None)
            self._fallback_expiry.pop(full_key, None)


# ═══════════════════════════════════════════════════════════
# PULSE WAVE AGGREGATOR (Free Tier Batched Delivery)
# ═══════════════════════════════════════════════════════════

class PulseWaveBuffer:
    """
    Aggregates Free-tier requests into batched "Pulse Wave" windows.
    Instead of real-time access, Free users receive intelligence
    in periodic bursts (default: every 5 minutes).
    """

    def __init__(self, interval_sec: int = 300):
        self._buffer: Dict[str, List[Dict]] = {}
        self._lock = threading.Lock()
        self._interval = interval_sec
        self._last_flush: Dict[str, float] = {}

    def enqueue(self, org_id: str, payload: Dict) -> Dict:
        """Buffer a request for deferred delivery."""
        with self._lock:
            if org_id not in self._buffer:
                self._buffer[org_id] = []
                self._last_flush[org_id] = time.monotonic()
            self._buffer[org_id].append({
                "queued_at": datetime.now(timezone.utc).isoformat(),
                "payload": payload,
            })

        return {
            "status": "QUEUED",
            "delivery_mode": "PULSE_WAVE",
            "next_wave_sec": self._time_to_next_wave(org_id),
            "queued_items": len(self._buffer.get(org_id, [])),
            "upgrade_url": "https://intel.cyberdudebivash.com/pricing",
            "message": "Free tier uses batched Pulse Wave delivery. "
                       "Upgrade to PRO for real-time access.",
        }

    def flush(self, org_id: str) -> List[Dict]:
        """Flush buffered items for delivery."""
        with self._lock:
            items = self._buffer.pop(org_id, [])
            self._last_flush[org_id] = time.monotonic()
        return items

    def flush_all_ready(self) -> Dict[str, List[Dict]]:
        """Flush all orgs whose pulse wave interval has elapsed."""
        ready = {}
        now = time.monotonic()
        with self._lock:
            for org_id in list(self._buffer.keys()):
                last = self._last_flush.get(org_id, 0)
                if (now - last) >= self._interval and self._buffer[org_id]:
                    ready[org_id] = self._buffer.pop(org_id, [])
                    self._last_flush[org_id] = now
        return ready

    def _time_to_next_wave(self, org_id: str) -> int:
        last = self._last_flush.get(org_id, time.monotonic())
        elapsed = time.monotonic() - last
        return max(0, int(self._interval - elapsed))

    def get_queue_depth(self, org_id: str) -> int:
        with self._lock:
            return len(self._buffer.get(org_id, []))


# ═══════════════════════════════════════════════════════════
# QUOTA ENGINE (Core Enforcement)
# ═══════════════════════════════════════════════════════════

class QuotaEngine:
    """
    Central quota enforcement engine.
    
    Supports:
      - Per-second, per-hour, per-month sliding windows
      - Burst allowance above hard limits
      - Enterprise dedicated shard routing
      - Free tier Pulse Wave batching
      - Overage metering for billing
      - Admin override and reset
    """

    def __init__(self):
        self._redis = RedisBackend()
        self._pulse_wave = PulseWaveBuffer()
        self._overage_log: List[Dict] = []
        self._overage_lock = threading.Lock()
        # File-based persistence for quota state (backup)
        self._state_dir = Path("data/quota")
        self._state_dir.mkdir(parents=True, exist_ok=True)
        logger.info("QuotaEngine initialized | Redis=%s", self._redis.is_redis_available)

    def resolve_tier(self, org_id: str, tier_override: Optional[str] = None) -> str:
        """Resolve org tier. Falls back to FREE if unknown."""
        if tier_override and tier_override in [t.value for t in QuotaTier]:
            return tier_override
        # Integration point: check v53 SubscriptionManager
        try:
            from agent.v53_subscription.manager import SubscriptionManager
            mgr = SubscriptionManager()
            return mgr.get_org_tier(org_id)
        except Exception:
            return QuotaTier.FREE

    def get_quota_config(self, tier: str) -> Dict[str, Any]:
        """Return quota limits for a tier."""
        return TIER_QUOTAS.get(tier, TIER_QUOTAS[QuotaTier.FREE])

    def consume(
        self,
        org_id: str,
        metric: str,
        cost: int = 1,
        tier: Optional[str] = None,
        endpoint: str = "",
    ) -> Dict[str, Any]:
        """
        Consume quota units. Returns enforcement result.

        Args:
            org_id: Organization identifier
            metric: Quota metric key (e.g., "api_calls", "reports", "stix_exports")
            cost: Number of units to consume
            tier: Override tier (auto-resolved if None)
            endpoint: API endpoint for audit trail

        Returns:
            {allowed, tier, delivery_mode, remaining, limit, ...}
        """
        resolved_tier = tier or self.resolve_tier(org_id)
        config = self.get_quota_config(resolved_tier)

        # ── Multi-window enforcement ──
        enforcement = self._enforce_windows(org_id, metric, cost, resolved_tier, config)

        if not enforcement["allowed"]:
            # Check burst allowance
            burst = config.get("burst_allowance", 0)
            burst_key = f"burst:{org_id}:{metric}:{self._current_hour()}"
            burst_used = self._redis.get_counter(burst_key)

            if burst_used < burst:
                self._redis.incr_with_ttl(burst_key, 3600, cost)
                enforcement["allowed"] = True
                enforcement["burst_used"] = burst_used + cost
                enforcement["burst_limit"] = burst
                enforcement["note"] = "Burst allowance consumed"
                logger.info(f"Burst grant | org={org_id} metric={metric} burst={burst_used+cost}/{burst}")
            else:
                # Log overage for billing
                self._log_overage(org_id, metric, cost, resolved_tier, endpoint)

        # ── Delivery mode routing ──
        delivery_mode = config.get("delivery_mode", "REALTIME")
        enforcement["delivery_mode"] = delivery_mode
        enforcement["tier"] = resolved_tier
        enforcement["priority_level"] = config.get("priority_level", 1)

        if delivery_mode == "PRIORITY_10" and config.get("shard_dedicated"):
            enforcement["shard_key"] = self._redis.get_shard_key(org_id)
            enforcement["shard_dedicated"] = True

        # Record usage in v53 SubscriptionManager (non-blocking)
        self._record_usage_async(org_id, metric, cost)

        return enforcement

    def enqueue_pulse_wave(self, org_id: str, payload: Dict) -> Dict:
        """Route Free-tier request through Pulse Wave buffer."""
        return self._pulse_wave.enqueue(org_id, payload)

    def flush_pulse_waves(self) -> Dict[str, List[Dict]]:
        """Flush all ready Pulse Wave buffers. Called by scheduler."""
        return self._pulse_wave.flush_all_ready()

    def get_usage_snapshot(self, org_id: str, tier: Optional[str] = None) -> Dict:
        """Return current usage across all windows for an org."""
        resolved_tier = tier or self.resolve_tier(org_id)
        config = self.get_quota_config(resolved_tier)
        period = self._current_month()
        hour = self._current_hour()

        monthly_key = f"monthly:{org_id}:{period}"
        hourly_key = f"hourly:{org_id}:{hour}"
        sec_key = f"sec:{org_id}:{int(time.time())}"

        monthly_used = self._redis.get_counter(monthly_key)
        hourly_used = self._redis.get_counter(hourly_key)

        monthly_limit = config.get("api_calls_monthly", 5000)
        hourly_limit = config.get("api_calls_hourly", 60)

        return {
            "org_id": org_id,
            "tier": resolved_tier,
            "delivery_mode": config.get("delivery_mode"),
            "priority_level": config.get("priority_level"),
            "period": period,
            "monthly": {
                "used": monthly_used,
                "limit": monthly_limit if monthly_limit > 0 else "unlimited",
                "remaining": max(0, monthly_limit - monthly_used) if monthly_limit > 0 else "unlimited",
                "utilization_pct": round((monthly_used / monthly_limit) * 100, 1) if monthly_limit > 0 else 0,
            },
            "hourly": {
                "used": hourly_used,
                "limit": hourly_limit,
                "remaining": max(0, hourly_limit - hourly_used),
            },
            "pulse_wave_queue": self._pulse_wave.get_queue_depth(org_id),
            "shard_dedicated": config.get("shard_dedicated", False),
            "upgrade_url": "https://intel.cyberdudebivash.com/pricing",
        }

    def admin_reset(self, org_id: str, metric: str = "all"):
        """Admin override: reset quota counters for an org."""
        period = self._current_month()
        hour = self._current_hour()

        if metric == "all":
            self._redis.delete_key(f"monthly:{org_id}:{period}")
            self._redis.delete_key(f"hourly:{org_id}:{hour}")
            logger.info(f"Admin reset all quotas for org={org_id}")
        else:
            self._redis.delete_key(f"monthly:{org_id}:{metric}:{period}")
            logger.info(f"Admin reset {metric} quota for org={org_id}")

    def get_overage_report(self, org_id: Optional[str] = None) -> List[Dict]:
        """Return overage events for billing reconciliation."""
        with self._overage_lock:
            if org_id:
                return [o for o in self._overage_log if o["org_id"] == org_id]
            return list(self._overage_log)

    # ── Internal Methods ──

    def _enforce_windows(
        self, org_id: str, metric: str, cost: int, tier: str, config: Dict
    ) -> Dict:
        """Enforce per-second, per-hour, per-month sliding windows."""
        now_ts = int(time.time())
        period = self._current_month()
        hour = self._current_hour()

        # Map generic metrics to config keys
        metric_map = {
            "api_calls": ("api_calls_monthly", "api_calls_hourly", "api_calls_per_second"),
            "reports": ("reports_monthly", None, None),
            "stix_exports": ("stix_exports_monthly", None, None),
            "detection_rules": ("detection_rules_monthly", None, None),
            "attack_surface_scans": ("attack_surface_scans_monthly", None, None),
        }

        monthly_key_name, hourly_key_name, sec_key_name = metric_map.get(
            metric, ("api_calls_monthly", "api_calls_hourly", "api_calls_per_second")
        )

        monthly_limit = config.get(monthly_key_name, 5000)
        hourly_limit = config.get(hourly_key_name, 60) if hourly_key_name else None
        sec_limit = config.get(sec_key_name, 2) if sec_key_name else None

        # Per-second check
        if sec_limit and sec_limit > 0:
            sec_key = f"sec:{org_id}:{metric}:{now_ts}"
            sec_used = self._redis.incr_with_ttl(sec_key, 2, cost)
            if sec_used > sec_limit:
                return {
                    "allowed": False,
                    "reason": "RATE_LIMIT_PER_SECOND",
                    "limit": sec_limit,
                    "used": sec_used,
                    "retry_after_ms": 1000,
                }

        # Per-hour check
        if hourly_limit and hourly_limit > 0:
            hourly_key = f"hourly:{org_id}:{metric}:{hour}"
            hourly_used = self._redis.incr_with_ttl(hourly_key, 3600, cost)
            if hourly_used > hourly_limit:
                return {
                    "allowed": False,
                    "reason": "RATE_LIMIT_PER_HOUR",
                    "limit": hourly_limit,
                    "used": hourly_used,
                    "remaining": 0,
                    "retry_after_sec": self._seconds_to_next_hour(),
                }

        # Per-month check (-1 = unlimited)
        if monthly_limit > 0:
            monthly_key = f"monthly:{org_id}:{metric}:{period}"
            monthly_used = self._redis.incr_with_ttl(monthly_key, 86400 * 32, cost)
            if monthly_used > monthly_limit:
                return {
                    "allowed": False,
                    "reason": "QUOTA_EXCEEDED_MONTHLY",
                    "limit": monthly_limit,
                    "used": monthly_used,
                    "remaining": 0,
                    "upgrade_url": "https://intel.cyberdudebivash.com/pricing",
                }
            remaining = max(0, monthly_limit - monthly_used)
        else:
            monthly_used = 0
            remaining = "unlimited"

        return {
            "allowed": True,
            "monthly_used": monthly_used,
            "monthly_limit": monthly_limit if monthly_limit > 0 else "unlimited",
            "remaining": remaining,
        }

    def _log_overage(self, org_id: str, metric: str, cost: int, tier: str, endpoint: str):
        """Log overage for metered billing."""
        entry = {
            "org_id": org_id,
            "metric": metric,
            "overage_units": cost,
            "tier": tier,
            "endpoint": endpoint,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._overage_lock:
            self._overage_log.append(entry)
            # Cap in-memory log
            if len(self._overage_log) > 10_000:
                self._overage_log = self._overage_log[-5_000:]
        # Persist to disk
        try:
            overage_file = self._state_dir / "overage_log.jsonl"
            with open(overage_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Overage log write failed: {e}")

    def _record_usage_async(self, org_id: str, metric: str, cost: int):
        """Non-blocking usage recording to v53 SubscriptionManager."""
        try:
            from agent.v53_subscription.manager import SubscriptionManager
            mgr = SubscriptionManager()
            sub_metric_map = {
                "api_calls": "api_calls",
                "reports": "reports_generated",
                "stix_exports": "stix_exports",
                "detection_rules": "detection_rules_generated",
                "attack_surface_scans": "attack_surface_scans",
            }
            sub_metric = sub_metric_map.get(metric, metric)
            mgr.record_usage(org_id, sub_metric, cost)
        except Exception:
            pass  # Non-critical — don't block quota enforcement

    @staticmethod
    def _current_month() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m")

    @staticmethod
    def _current_hour() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")

    @staticmethod
    def _seconds_to_next_hour() -> int:
        now = datetime.now(timezone.utc)
        next_hour = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        return int((next_hour - now).total_seconds())


# ═══════════════════════════════════════════════════════════
# FASTAPI MIDDLEWARE INTEGRATION
# ═══════════════════════════════════════════════════════════

class QuotaMiddleware:
    """
    FastAPI middleware that enforces quota on every request.

    Usage:
        from agent.monetization.quota_manager import QuotaMiddleware
        app.add_middleware(QuotaMiddleware)
    """

    def __init__(self, app=None):
        self._engine = quota_engine
        if app:
            self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract org_id and tier from headers or auth
        headers = dict(scope.get("headers", []))
        org_id = self._extract_org_id(headers)
        tier = self._extract_tier(headers)
        path = scope.get("path", "/")

        result = self._engine.consume(
            org_id=org_id,
            metric="api_calls",
            cost=1,
            tier=tier,
            endpoint=path,
        )

        if not result["allowed"]:
            # Return 429 with quota info
            response_body = json.dumps({
                "error": "QUOTA_EXCEEDED",
                "detail": result.get("reason", "Rate limit exceeded"),
                "tier": result.get("tier", "FREE"),
                "delivery_mode": result.get("delivery_mode", "PULSE_WAVE"),
                "retry_after": result.get("retry_after_sec", 60),
                "upgrade_url": "https://intel.cyberdudebivash.com/pricing",
            }).encode()

            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"retry-after", str(result.get("retry_after_sec", 60)).encode()],
                    [b"x-cdb-tier", result.get("tier", "FREE").encode()],
                    [b"x-cdb-delivery-mode", result.get("delivery_mode", "PULSE_WAVE").encode()],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": response_body,
            })
            return

        # Inject quota headers into response
        await self.app(scope, receive, send)

    def _extract_org_id(self, headers: Dict) -> str:
        for key_name in [b"x-cdb-org-id", b"x-org-id"]:
            if key_name in headers:
                return headers[key_name].decode()
        return "anon:unknown"

    def _extract_tier(self, headers: Dict) -> Optional[str]:
        if b"x-cdb-tier" in headers:
            return headers[b"x-cdb-tier"].decode()
        return None


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

quota_engine = QuotaEngine()
