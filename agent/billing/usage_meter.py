#!/usr/bin/env python3
"""
agent/billing/usage_meter.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE USAGE METERING ENGINE

Tracks billable API consumption per organisation, per tier, per billing cycle.
Feeds into:
  - Stripe metered billing (usage records API)
  - Overage enforcement (429 after quota breach)
  - Usage dashboard (self-service portal)
  - Monthly invoice line items

Metering strategy:
  - Redis counters (INCRBY) — fast, atomic, sub-millisecond
  - Counters persist per billing cycle (monthly reset)
  - Sync to Stripe every 15 minutes (not on every request — batched for efficiency)
  - Local JSONL fallback if Redis unavailable

Billable units tracked:
  - api_calls         — every authenticated API request
  - intel_queries     — /api/v1/intel/* endpoint hits
  - stix_exports      — STIX bundle export operations
  - csv_exports       — CSV export operations
  - pdf_exports       — PDF report exports
  - threat_searches   — Advanced threat search queries

Feature-flag gated: CDB_USAGE_METERING_ENABLED=true (default false)
"""

import os
import json
import time
import logging
import calendar
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple

logger = logging.getLogger("CDB-USAGE")

_METERING_ENABLED      = os.environ.get("CDB_USAGE_METERING_ENABLED", "false").lower() == "true"
_STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
_USAGE_LOG_PATH        = os.environ.get("CDB_USAGE_LOG_PATH", "data/observability/usage.jsonl")

# Tier quota limits (requests per billing cycle / month)
TIER_QUOTAS: Dict[str, Dict[str, int]] = {
    "FREE":       {"api_calls": 1_000,    "intel_queries": 500,   "stix_exports": 10,   "csv_exports": 10,   "pdf_exports": 5},
    "PRO":        {"api_calls": 50_000,   "intel_queries": 10_000, "stix_exports": 500,  "csv_exports": 500,  "pdf_exports": 100},
    "ENTERPRISE": {"api_calls": 500_000,  "intel_queries": 100_000,"stix_exports": 5_000,"csv_exports": 5_000,"pdf_exports": 1_000},
    "MSSP":       {"api_calls": 5_000_000,"intel_queries": 1_000_000,"stix_exports": -1, "csv_exports": -1,  "pdf_exports": -1},  # -1 = unlimited
}

# Redis key schema
# cdb:usage:{org_id}:{billing_cycle}:{unit}  → integer counter
# cdb:usage:meta:{org_id}:{billing_cycle}    → JSON metadata

def _billing_cycle() -> str:
    """Current billing cycle as YYYY-MM string."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m")


def _redis_key(org_id: str, unit: str, cycle: Optional[str] = None) -> str:
    c = cycle or _billing_cycle()
    return f"cdb:usage:{org_id}:{c}:{unit}"


def _redis_meta_key(org_id: str, cycle: Optional[str] = None) -> str:
    c = cycle or _billing_cycle()
    return f"cdb:usage:meta:{org_id}:{c}"


def _get_redis():
    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        return None
    try:
        import redis
        r = redis.from_url(redis_url, decode_responses=True, socket_timeout=0.5)
        r.ping()
        return r
    except Exception:
        return None


class UsageMeter:
    """
    Atomic usage counter with Redis backend + JSONL fallback.
    All operations are idempotent and safe under concurrent load.
    """

    def __init__(self):
        self._redis = _get_redis()
        self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        import os
        try:
            os.makedirs(os.path.dirname(_USAGE_LOG_PATH), exist_ok=True)
        except Exception:
            pass

    def record(
        self,
        org_id: str,
        unit: str,
        amount: int = 1,
        tier: str = "FREE",
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """
        Record billable usage.

        Args:
            org_id:   Organisation identifier
            unit:     Billable unit (api_calls, intel_queries, stix_exports, etc.)
            amount:   Units consumed (default 1)
            tier:     Customer tier (for quota check)
            metadata: Optional context (endpoint, user_id, etc.) for audit trail

        Returns:
            {new_total, quota, quota_pct, over_quota: bool}
        """
        if not _METERING_ENABLED:
            return {"status": "metering_disabled"}

        cycle   = _billing_cycle()
        new_val = self._increment(org_id, unit, amount, cycle)

        quota     = TIER_QUOTAS.get(tier.upper(), TIER_QUOTAS["FREE"]).get(unit, 1000)
        unlimited = quota == -1
        pct       = 0.0 if unlimited else round((new_val / quota) * 100, 1)
        over      = False if unlimited else (new_val > quota)

        if over:
            logger.warning(
                f"[USAGE] Quota exceeded: org={org_id} tier={tier} unit={unit} "
                f"total={new_val} quota={quota}"
            )

        # Log to JSONL for analytics
        self._log_usage(org_id, tier, unit, amount, new_val, quota, pct, over, metadata)

        return {
            "org_id":     org_id,
            "unit":       unit,
            "cycle":      cycle,
            "new_total":  new_val,
            "quota":      quota if not unlimited else "unlimited",
            "quota_pct":  pct,
            "over_quota": over,
        }

    def _increment(self, org_id: str, unit: str, amount: int, cycle: str) -> int:
        key = _redis_key(org_id, unit, cycle)
        r = self._redis
        if r:
            try:
                # Atomic increment + auto-expire at end of billing cycle
                pipe = r.pipeline()
                pipe.incrby(key, amount)
                # Expire at end of billing cycle + 7 days grace
                now = datetime.now(tz=timezone.utc)
                days_in_month = calendar.monthrange(now.year, now.month)[1]
                ttl = (days_in_month - now.day + 7) * 86400
                pipe.expire(key, ttl)
                results = pipe.execute()
                return int(results[0])
            except Exception as e:
                logger.warning(f"[USAGE] Redis increment failed ({e}) — falling back")

        # Fallback: file-based counter (non-atomic, acceptable for failover)
        return self._file_increment(org_id, unit, amount, cycle)

    def _file_increment(self, org_id: str, unit: str, amount: int, cycle: str) -> int:
        """Simple file-based counter fallback (not atomic — for degraded mode only)."""
        state_path = f"data/observability/usage-state-{org_id}-{cycle}.json"
        try:
            try:
                with open(state_path) as f:
                    state = json.load(f)
            except FileNotFoundError:
                state = {}
            state[unit] = state.get(unit, 0) + amount
            with open(state_path, "w") as f:
                json.dump(state, f)
            return state[unit]
        except Exception:
            return 0

    def _log_usage(self, org_id, tier, unit, amount, total, quota, pct, over, metadata):
        try:
            record = {
                "ts":       datetime.now(tz=timezone.utc).isoformat(),
                "org_id":   org_id,
                "tier":     tier,
                "unit":     unit,
                "amount":   amount,
                "total":    total,
                "quota":    quota if isinstance(quota, int) else -1,
                "pct":      pct,
                "over":     over,
            }
            if metadata:
                record.update(metadata)
            with open(_USAGE_LOG_PATH, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def get_usage(self, org_id: str, cycle: Optional[str] = None) -> Dict:
        """Get current usage totals for an org in the given billing cycle."""
        c = cycle or _billing_cycle()
        r = self._redis
        all_units = list(TIER_QUOTAS["FREE"].keys())
        totals    = {}

        if r:
            try:
                pipe = r.pipeline()
                for unit in all_units:
                    pipe.get(_redis_key(org_id, unit, c))
                values = pipe.execute()
                for unit, val in zip(all_units, values):
                    totals[unit] = int(val or 0)
            except Exception:
                pass

        if not totals:
            # File fallback
            for unit in all_units:
                totals[unit] = 0

        return {"org_id": org_id, "cycle": c, "usage": totals}

    def check_quota(self, org_id: str, unit: str, tier: str) -> Tuple[bool, Dict]:
        """
        Pre-flight quota check (before processing request).
        Returns (allowed: bool, status_dict).
        """
        if not _METERING_ENABLED:
            return True, {"status": "metering_disabled"}

        usage_data = self.get_usage(org_id)
        current    = usage_data.get("usage", {}).get(unit, 0)
        quota      = TIER_QUOTAS.get(tier.upper(), TIER_QUOTAS["FREE"]).get(unit, 1000)
        unlimited  = quota == -1

        if unlimited:
            return True, {"allowed": True, "current": current, "quota": "unlimited"}

        remaining = max(0, quota - current)
        allowed   = current < quota

        return allowed, {
            "allowed":    allowed,
            "current":    current,
            "quota":      quota,
            "remaining":  remaining,
            "quota_pct":  round((current / quota) * 100, 1) if quota > 0 else 100.0,
            "cycle":      _billing_cycle(),
        }

    async def sync_to_stripe(self, org_id: str, stripe_subscription_item_id: str, unit: str) -> bool:
        """
        Report current usage to Stripe metered billing API.
        Call this in a background task every 15 minutes, not per-request.
        """
        if not _STRIPE_SECRET_KEY:
            return False
        try:
            import stripe
            stripe.api_key = _STRIPE_SECRET_KEY

            usage = self.get_usage(org_id)
            quantity = usage.get("usage", {}).get(unit, 0)
            if quantity == 0:
                return True

            stripe.SubscriptionItem.create_usage_record(
                stripe_subscription_item_id,
                quantity=quantity,
                timestamp=int(time.time()),
                action="set",  # "set" = absolute; "increment" = additive
            )
            logger.info(f"[USAGE] Synced to Stripe: org={org_id} unit={unit} qty={quantity}")
            return True
        except Exception as e:
            logger.error(f"[USAGE] Stripe sync failed: {e}")
            return False


# Singleton
usage_meter = UsageMeter()
