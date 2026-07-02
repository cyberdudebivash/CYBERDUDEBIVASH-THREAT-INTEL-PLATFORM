#!/usr/bin/env python3
"""
api/subscription.py — CYBERDUDEBIVASH SENTINEL APEX
ENTERPRISE SUBSCRIPTION MANAGEMENT LAYER v1.0

Manages:
  - Subscription lifecycle (create, upgrade, downgrade, cancel)
  - Plan entitlements and feature gates
  - Subscription state machine
  - Usage reports per subscription
  - Auto-renewal tracking
  - Trial period management

States:
  TRIAL    → active trial, full-tier access, expires in N days
  ACTIVE   → paid subscription, full-tier access
  PAST_DUE → payment failed, grace period (48h), degraded access
  PAUSED   → manually paused, no access
  CANCELLED → no access, data retained for 90 days

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-SUBSCRIPTION")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR       = Path(__file__).resolve().parent.parent
DATA_DIR       = BASE_DIR / "data"
SUB_DIR        = DATA_DIR / "subscriptions"
SUBS_FILE      = SUB_DIR / "subscriptions.json"
SUB_EVENTS     = SUB_DIR / "subscription_events.jsonl"

# ---------------------------------------------------------------------------
# Subscription states
# ---------------------------------------------------------------------------
STATE_TRIAL     = "TRIAL"
STATE_ACTIVE    = "ACTIVE"
STATE_PAST_DUE  = "PAST_DUE"
STATE_PAUSED    = "PAUSED"
STATE_CANCELLED = "CANCELLED"

ACTIVE_STATES   = {STATE_TRIAL, STATE_ACTIVE}
GRACE_HOURS     = 48  # hours before PAST_DUE → CANCELLED
DATA_RETAIN_DAYS = 90

# ---------------------------------------------------------------------------
# Safe IO
# ---------------------------------------------------------------------------

def _safe_write_json(path: Path, data: Any) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.error(f"Write failed {path.name}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def _safe_load_json(path: Path, default: Any = None) -> Any:
    try:
        if path.exists() and path.stat().st_size > 0:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Load failed {path.name}: {e}")
    return default if default is not None else {}


def _append_sub_event(event: Dict) -> None:
    SUB_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(SUB_EVENTS, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        logger.warning(f"Sub event append failed: {e}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _sub_id(owner: str, tier: str) -> str:
    """Generate stable subscription ID."""
    import hashlib
    raw = f"{owner}:{tier}:{int(time.time() // 86400)}"
    return "SUB-" + hashlib.md5(raw.encode()).hexdigest()[:12].upper()


# ===========================================================================
# SUBSCRIPTION RECORD
# ===========================================================================

def _make_subscription(
    owner: str,
    tier: str,
    billing_cycle: str = "monthly",
    trial_days: int = 0,
    stripe_subscription_id: str = "",
    stripe_customer_id: str = "",
    metadata: Optional[Dict] = None,
) -> Dict:
    """Build a new subscription record."""
    now = _now()
    sub_id = _sub_id(owner, tier)

    state = STATE_TRIAL if trial_days > 0 else STATE_ACTIVE
    trial_end = (now + timedelta(days=trial_days)).isoformat() if trial_days > 0 else None

    # Billing cycle dates
    if billing_cycle == "annual":
        next_billing = (now + timedelta(days=365)).isoformat()
    else:
        next_billing = (now + timedelta(days=30)).isoformat()

    return {
        "subscription_id": sub_id,
        "owner": owner,
        "tier": tier.upper(),
        "state": state,
        "billing_cycle": billing_cycle,
        "trial_end": trial_end,
        "current_period_start": now.isoformat(),
        "current_period_end": next_billing,
        "next_billing_date": next_billing,
        "stripe_subscription_id": stripe_subscription_id,
        "stripe_customer_id": stripe_customer_id,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "cancelled_at": None,
        "cancellation_reason": None,
        "past_due_since": None,
        "metadata": metadata or {},
        "auto_renew": True,
        "usage_this_period": 0,
        "total_usage": 0,
    }


# ===========================================================================
# SUBSCRIPTION MANAGER
# ===========================================================================

class SubscriptionManager:
    """
    Manages the full subscription lifecycle.
    All state transitions are logged to the events JSONL.
    """

    def __init__(self):
        SUB_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict:
        return _safe_load_json(SUBS_FILE, default={"subscriptions": {}})

    def _save(self, data: Dict) -> bool:
        return _safe_write_json(SUBS_FILE, data)

    def _get_sub_by_owner(self, owner: str) -> Optional[Tuple[str, Dict]]:
        """Get most recent active subscription for owner."""
        data = self._load()
        owner_subs = [
            (sid, sub)
            for sid, sub in data.get("subscriptions", {}).items()
            if sub.get("owner") == owner
        ]
        if not owner_subs:
            return None
        # Return most recently created
        owner_subs.sort(key=lambda x: x[1].get("created_at", ""), reverse=True)
        return owner_subs[0]

    # ─────────────────────────────────────────────────────
    # CREATE
    # ─────────────────────────────────────────────────────

    def create(
        self,
        owner: str,
        tier: str,
        billing_cycle: str = "monthly",
        stripe_subscription_id: str = "",
        stripe_customer_id: str = "",
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """Create a new subscription."""
        from api.billing import PLAN_PRICING
        trial_days = PLAN_PRICING.get(tier.upper(), {}).get("trial_days", 0)

        sub = _make_subscription(
            owner=owner,
            tier=tier,
            billing_cycle=billing_cycle,
            trial_days=trial_days,
            stripe_subscription_id=stripe_subscription_id,
            stripe_customer_id=stripe_customer_id,
            metadata=metadata,
        )

        data = self._load()
        data["subscriptions"][sub["subscription_id"]] = sub
        self._save(data)

        _append_sub_event({
            "event": "subscription.created",
            "subscription_id": sub["subscription_id"],
            "owner": owner,
            "tier": tier,
            "state": sub["state"],
            "trial_days": trial_days,
            "timestamp": _now_iso(),
        })

        logger.info(f"Subscription created: {sub['subscription_id']} owner={owner} tier={tier} state={sub['state']}")
        return sub

    # ─────────────────────────────────────────────────────
    # UPGRADE
    # ─────────────────────────────────────────────────────

    def upgrade(self, owner: str, new_tier: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Upgrade subscription to a higher tier.
        Immediate effect (proration handled by billing).
        Returns (success, message, updated_sub).
        """
        from api.auth import TIERS
        tier_order = {"FREE": 0, "PRO": 1, "ENTERPRISE": 2, "MSSP": 3}
        result = self._get_sub_by_owner(owner)
        if not result:
            return False, "No subscription found", None

        sub_id, sub = result
        old_tier = sub.get("tier", "FREE")
        new_tier  = new_tier.upper()

        if new_tier not in TIERS:
            return False, f"Unknown tier: {new_tier}", None

        if tier_order.get(new_tier, 0) <= tier_order.get(old_tier, 0):
            return False, f"Cannot upgrade from {old_tier} to {new_tier} — use downgrade instead", None

        old_state = sub["state"]
        sub["tier"]       = new_tier
        sub["state"]      = STATE_ACTIVE  # Upgrade always activates
        sub["updated_at"] = _now_iso()
        sub["trial_end"]  = None  # Clear trial on upgrade

        data = self._load()
        data["subscriptions"][sub_id] = sub
        self._save(data)

        _append_sub_event({
            "event": "subscription.upgraded",
            "subscription_id": sub_id,
            "owner": owner,
            "old_tier": old_tier,
            "new_tier": new_tier,
            "old_state": old_state,
            "new_state": STATE_ACTIVE,
            "timestamp": _now_iso(),
        })

        logger.info(f"Subscription upgraded: {sub_id} {old_tier}→{new_tier}")
        return True, f"Upgraded from {old_tier} to {new_tier}", sub

    # ─────────────────────────────────────────────────────
    # DOWNGRADE
    # ─────────────────────────────────────────────────────

    def downgrade(self, owner: str, new_tier: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Schedule a tier downgrade for next billing cycle.
        Does NOT take immediate effect.
        """
        from api.auth import TIERS
        result = self._get_sub_by_owner(owner)
        if not result:
            return False, "No subscription found", None

        sub_id, sub = result
        old_tier  = sub.get("tier", "FREE")
        new_tier  = new_tier.upper()

        if new_tier not in TIERS:
            return False, f"Unknown tier: {new_tier}", None

        # Schedule downgrade for next billing date
        sub["pending_downgrade_tier"] = new_tier
        sub["pending_downgrade_date"] = sub.get("current_period_end", _now_iso())
        sub["updated_at"] = _now_iso()

        data = self._load()
        data["subscriptions"][sub_id] = sub
        self._save(data)

        _append_sub_event({
            "event": "subscription.downgrade_scheduled",
            "subscription_id": sub_id,
            "owner": owner,
            "old_tier": old_tier,
            "new_tier": new_tier,
            "effective_date": sub["pending_downgrade_date"],
            "timestamp": _now_iso(),
        })

        logger.info(f"Downgrade scheduled: {sub_id} {old_tier}→{new_tier} at {sub['pending_downgrade_date']}")
        return True, f"Downgrade from {old_tier} to {new_tier} scheduled for next billing cycle", sub

    # ─────────────────────────────────────────────────────
    # CANCEL
    # ─────────────────────────────────────────────────────

    def cancel(
        self,
        owner: str,
        reason: str = "",
        immediate: bool = False,
    ) -> Tuple[bool, str, Optional[Dict]]:
        """
        Cancel subscription.
        immediate=False: cancels at period end (data retained)
        immediate=True: cancels now (data retained for DATA_RETAIN_DAYS)
        """
        result = self._get_sub_by_owner(owner)
        if not result:
            return False, "No subscription found", None

        sub_id, sub = result
        now = _now()

        if immediate:
            sub["state"]               = STATE_CANCELLED
            sub["cancelled_at"]        = now.isoformat()
            sub["cancellation_reason"] = reason[:200]
            sub["data_retain_until"]   = (now + timedelta(days=DATA_RETAIN_DAYS)).isoformat()
        else:
            # Schedule cancellation at period end
            sub["cancel_at_period_end"]  = True
            sub["cancellation_reason"]   = reason[:200]
            sub["scheduled_cancel_date"] = sub.get("current_period_end", now.isoformat())

        sub["updated_at"] = now.isoformat()
        data = self._load()
        data["subscriptions"][sub_id] = sub
        self._save(data)

        _append_sub_event({
            "event": "subscription.cancelled",
            "subscription_id": sub_id,
            "owner": owner,
            "immediate": immediate,
            "reason": reason[:200],
            "timestamp": now.isoformat(),
        })

        msg = "Subscription cancelled immediately" if immediate else f"Subscription will cancel at {sub.get('current_period_end','period end')}"
        logger.info(f"Subscription cancelled: {sub_id} immediate={immediate}")
        return True, msg, sub

    # ─────────────────────────────────────────────────────
    # ACTIVATE (from PAST_DUE / PAUSED)
    # ─────────────────────────────────────────────────────

    def activate(self, owner: str) -> Tuple[bool, str, Optional[Dict]]:
        """Re-activate a PAST_DUE or PAUSED subscription."""
        result = self._get_sub_by_owner(owner)
        if not result:
            return False, "No subscription found", None

        sub_id, sub = result
        old_state = sub.get("state")

        if old_state == STATE_ACTIVE:
            return True, "Already active", sub

        if old_state == STATE_CANCELLED:
            return False, "Cannot reactivate cancelled subscription — create a new one", None

        sub["state"]         = STATE_ACTIVE
        sub["past_due_since"] = None
        sub["updated_at"]    = _now_iso()

        data = self._load()
        data["subscriptions"][sub_id] = sub
        self._save(data)

        _append_sub_event({
            "event": "subscription.activated",
            "subscription_id": sub_id,
            "owner": owner,
            "old_state": old_state,
            "timestamp": _now_iso(),
        })
        return True, "Subscription activated", sub

    # ─────────────────────────────────────────────────────
    # MARK PAST DUE (called by payment failure webhook)
    # ─────────────────────────────────────────────────────

    def mark_past_due(self, owner: str) -> bool:
        result = self._get_sub_by_owner(owner)
        if not result:
            return False

        sub_id, sub = result
        if sub.get("state") == STATE_PAST_DUE:
            return True  # Already past due

        sub["state"]          = STATE_PAST_DUE
        sub["past_due_since"] = _now_iso()
        sub["updated_at"]     = _now_iso()
        sub["grace_expires"]  = (_now() + timedelta(hours=GRACE_HOURS)).isoformat()

        data = self._load()
        data["subscriptions"][sub_id] = sub
        self._save(data)

        _append_sub_event({
            "event": "subscription.past_due",
            "subscription_id": sub_id,
            "owner": owner,
            "grace_expires": sub["grace_expires"],
            "timestamp": _now_iso(),
        })
        return True

    # ─────────────────────────────────────────────────────
    # STATE CHECK
    # ─────────────────────────────────────────────────────

    def get_effective_state(self, owner: str) -> Tuple[str, str]:
        """
        Returns (effective_state, tier) for access control.
        Handles trial expiry and grace period expiry automatically.
        """
        result = self._get_sub_by_owner(owner)
        if not result:
            return STATE_CANCELLED, "FREE"

        sub_id, sub = result
        state = sub.get("state", STATE_CANCELLED)
        tier  = sub.get("tier", "FREE")
        now   = _now()

        # Check trial expiry
        if state == STATE_TRIAL:
            trial_end = sub.get("trial_end")
            if trial_end:
                try:
                    t = datetime.fromisoformat(trial_end)
                    if now > t:
                        # Trial expired — downgrade to FREE unless payment info present
                        stripe_id = sub.get("stripe_subscription_id", "")
                        if not stripe_id:
                            state = STATE_CANCELLED
                            tier  = "FREE"
                            # Persist state
                            sub["state"] = state
                            sub["updated_at"] = now.isoformat()
                            data = self._load()
                            data["subscriptions"][sub_id] = sub
                            self._save(data)
                            _append_sub_event({
                                "event": "trial.expired",
                                "subscription_id": sub_id,
                                "owner": owner,
                                "timestamp": now.isoformat(),
                            })
                        else:
                            state = STATE_ACTIVE  # Stripe will handle billing
                except Exception:
                    pass

        # Check PAST_DUE grace period expiry
        if state == STATE_PAST_DUE:
            grace = sub.get("grace_expires")
            if grace:
                try:
                    g = datetime.fromisoformat(grace)
                    if now > g:
                        state = STATE_CANCELLED
                        tier  = "FREE"
                        sub["state"] = STATE_CANCELLED
                        sub["updated_at"] = now.isoformat()
                        data = self._load()
                        data["subscriptions"][sub_id] = sub
                        self._save(data)
                        _append_sub_event({
                            "event": "subscription.grace_expired",
                            "subscription_id": sub_id,
                            "owner": owner,
                            "timestamp": now.isoformat(),
                        })
                except Exception:
                    pass

        return state, tier

    def is_active(self, owner: str) -> bool:
        state, _ = self.get_effective_state(owner)
        return state in ACTIVE_STATES

    # ─────────────────────────────────────────────────────
    # USAGE TRACKING
    # ─────────────────────────────────────────────────────

    def record_usage(self, owner: str, units: int = 1) -> bool:
        result = self._get_sub_by_owner(owner)
        if not result:
            return False
        sub_id, sub = result
        sub["usage_this_period"] = sub.get("usage_this_period", 0) + units
        sub["total_usage"]       = sub.get("total_usage", 0) + units
        data = self._load()
        data["subscriptions"][sub_id] = sub
        return self._save(data)

    # ─────────────────────────────────────────────────────
    # REPORTS
    # ─────────────────────────────────────────────────────

    def get_subscription(self, owner: str) -> Optional[Dict]:
        result = self._get_sub_by_owner(owner)
        if not result:
            return None
        _, sub = result
        # Add computed effective state
        state, tier = self.get_effective_state(owner)
        return {
            **sub,
            "effective_state": state,
            "effective_tier": tier,
            "is_active": state in ACTIVE_STATES,
        }

    def get_usage_report(self, owner: str) -> Dict:
        """Return usage report for current billing period."""
        sub = self.get_subscription(owner)
        if not sub:
            return {"error": "No subscription found"}

        from api.auth import TIERS
        from api.billing import PLAN_PRICING
        tier      = sub.get("effective_tier", "FREE")
        tier_def  = TIERS.get(tier, TIERS["FREE"])
        pricing   = PLAN_PRICING.get(tier, {})

        daily_limit = tier_def.get("requests_per_day", 100)
        monthly_est = daily_limit * 30 if daily_limit != -1 else -1
        usage_period = sub.get("usage_this_period", 0)

        return {
            "owner": owner,
            "tier": tier,
            "state": sub.get("effective_state"),
            "period_start": sub.get("current_period_start"),
            "period_end": sub.get("current_period_end"),
            "usage_this_period": usage_period,
            "monthly_quota_estimate": monthly_est if monthly_est != -1 else "unlimited",
            "remaining_quota": max(0, monthly_est - usage_period) if monthly_est != -1 else "unlimited",
            "pct_used": round(usage_period / max(monthly_est, 1) * 100, 1) if monthly_est != -1 else 0,
            "total_usage_all_time": sub.get("total_usage", 0),
            "features": tier_def.get("features", {}),
            "next_billing_date": sub.get("next_billing_date"),
            "auto_renew": sub.get("auto_renew", True),
        }

    def list_all_subscriptions(self, active_only: bool = False) -> List[Dict]:
        """List all subscriptions (admin use)."""
        data = self._load()
        subs = list(data.get("subscriptions", {}).values())
        if active_only:
            subs = [s for s in subs if s.get("state") in ACTIVE_STATES]
        return sorted(subs, key=lambda x: x.get("created_at", ""), reverse=True)

    def get_mrr_summary(self) -> Dict:
        """Calculate Monthly Recurring Revenue summary."""
        from api.billing import PLAN_PRICING
        subs = self.list_all_subscriptions(active_only=True)
        mrr_cents = 0
        tier_counts: Dict[str, int] = {}

        for sub in subs:
            tier = sub.get("tier", "FREE")
            state = sub.get("state", "")
            if state not in ACTIVE_STATES:
                continue
            pricing  = PLAN_PRICING.get(tier, {})
            monthly  = pricing.get("monthly_cents", 0)
            if sub.get("billing_cycle") == "annual":
                monthly = pricing.get("annual_cents", 0) // 12
            mrr_cents += monthly
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        return {
            "mrr_cents": mrr_cents,
            "mrr_usd": f"${mrr_cents / 100:.2f}",
            "arr_cents": mrr_cents * 12,
            "arr_usd": f"${mrr_cents * 12 / 100:.2f}",
            "active_subscriptions": len(subs),
            "by_tier": tier_counts,
            "calculated_at": _now_iso(),
        }


# Singleton
_sub_manager: Optional[SubscriptionManager] = None

def get_subscription_manager() -> SubscriptionManager:
    global _sub_manager
    if _sub_manager is None:
        _sub_manager = SubscriptionManager()
    return _sub_manager
