#!/usr/bin/env python3
"""
api/billing.py — CYBERDUDEBIVASH SENTINEL APEX
ENTERPRISE BILLING LAYER v1.0

Manages:
  - Tier definitions and pricing
  - Usage quota enforcement
  - Billing events log (immutable append-only)
  - Usage metering (atomic counters)
  - Upgrade / downgrade logic
  - Stripe webhook processing (safe, validated)

Design:
  - Atomic JSON writes (no data loss)
  - Append-only billing log (never overwrites history)
  - No plaintext payment data stored (PCI scope minimization)
  - All money values in USD cents (integer, no floating-point rounding)

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-BILLING")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR      = Path(__file__).resolve().parent.parent
DATA_DIR      = BASE_DIR / "data"
BILLING_DIR   = DATA_DIR / "billing"
USAGE_FILE    = BILLING_DIR / "usage_meters.json"
EVENTS_FILE   = BILLING_DIR / "billing_events.jsonl"  # append-only log
INVOICES_FILE = BILLING_DIR / "invoices.json"

# ---------------------------------------------------------------------------
# Pricing (USD cents — integer, no float rounding risk)
# ---------------------------------------------------------------------------
PLAN_PRICING: Dict[str, Dict] = {
    "FREE": {
        "monthly_cents": 0,
        "annual_cents": 0,
        "overage_per_1k_cents": 0,  # No overage — hard cap
        "trial_days": 0,
    },
    "PRO": {
        "monthly_cents": 4900,      # $49/mo
        "annual_cents": 47040,      # $470.40/yr (20% discount)
        "overage_per_1k_cents": 100, # $1.00 per 1k extra requests
        "trial_days": 14,
    },
    "ENTERPRISE": {
        "monthly_cents": 49900,     # $499/mo
        "annual_cents": 479040,     # $4,790.40/yr (20% discount)
        "overage_per_1k_cents": 50,  # $0.50 per 1k extra requests
        "trial_days": 30,
    },
    "MSSP": {
        "monthly_cents": 199900,    # $1,999/mo
        "annual_cents": 1919040,    # $19,190.40/yr (20% discount)
        "overage_per_1k_cents": 0,  # Unlimited — no overage
        "trial_days": 30,
    },
}

# Billing event types
EVT_SUBSCRIPTION_CREATED  = "subscription.created"
EVT_SUBSCRIPTION_UPGRADED = "subscription.upgraded"
EVT_SUBSCRIPTION_DOWNGRADED = "subscription.downgraded"
EVT_SUBSCRIPTION_CANCELLED = "subscription.cancelled"
EVT_PAYMENT_SUCCEEDED     = "payment.succeeded"
EVT_PAYMENT_FAILED        = "payment.failed"
EVT_QUOTA_EXCEEDED        = "quota.exceeded"
EVT_TRIAL_STARTED         = "trial.started"
EVT_TRIAL_ENDED           = "trial.ended"
EVT_KEY_CREATED           = "key.created"
EVT_KEY_REVOKED           = "key.revoked"
EVT_OVERAGE_CHARGED       = "overage.charged"

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


def _append_event(event: Dict) -> bool:
    """Append a billing event to the JSONL log (append-only, never overwrites)."""
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        return True
    except Exception as e:
        logger.error(f"Event append failed: {e}")
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _this_month_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


# ===========================================================================
# USAGE METER
# ===========================================================================

class UsageMeter:
    """
    Atomic per-key usage counters.
    Resets daily and monthly counters automatically.
    """

    def __init__(self):
        BILLING_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict:
        return _safe_load_json(USAGE_FILE, default={"meters": {}})

    def _save(self, data: Dict) -> bool:
        return _safe_write_json(USAGE_FILE, data)

    def record_request(self, key_prefix: str, tier: str, endpoint: str) -> Dict:
        """
        Increment usage counters for a request.
        Returns updated meter.
        """
        data  = self._load()
        today = _today_utc()
        month = _this_month_utc()

        meters = data.setdefault("meters", {})
        if key_prefix not in meters:
            meters[key_prefix] = {
                "tier": tier,
                "total_requests": 0,
                "requests_today": 0,
                "requests_this_month": 0,
                "day_reset": today,
                "month_reset": month,
                "endpoint_counts": {},
                "first_seen": _now_iso(),
                "last_seen": _now_iso(),
            }

        m = meters[key_prefix]

        # Reset daily counter
        if m.get("day_reset") != today:
            m["requests_today"] = 0
            m["day_reset"] = today

        # Reset monthly counter
        if m.get("month_reset") != month:
            m["requests_this_month"] = 0
            m["month_reset"] = month

        m["total_requests"]        = m.get("total_requests", 0) + 1
        m["requests_today"]        = m.get("requests_today", 0) + 1
        m["requests_this_month"]   = m.get("requests_this_month", 0) + 1
        m["last_seen"]             = _now_iso()
        m["tier"]                  = tier

        ep_counts = m.setdefault("endpoint_counts", {})
        ep_counts[endpoint] = ep_counts.get(endpoint, 0) + 1

        self._save(data)
        return dict(m)

    def get_meter(self, key_prefix: str) -> Optional[Dict]:
        data = self._load()
        return data.get("meters", {}).get(key_prefix)

    def get_all_meters(self) -> List[Dict]:
        data = self._load()
        return list(data.get("meters", {}).values())

    def calculate_overage(self, key_prefix: str, tier: str) -> Tuple[int, int]:
        """
        Returns (overage_requests, overage_cost_cents).
        """
        from api.auth import TIERS
        meter = self.get_meter(key_prefix)
        if not meter:
            return 0, 0

        tier_def     = TIERS.get(tier, TIERS.get("FREE", {}))
        monthly_limit = tier_def.get("requests_per_day", 100)
        if monthly_limit == -1:
            return 0, 0  # Unlimited

        # Estimate monthly from daily limit × 30
        monthly_quota = monthly_limit * 30
        monthly_actual = meter.get("requests_this_month", 0)

        overage = max(0, monthly_actual - monthly_quota)
        pricing = PLAN_PRICING.get(tier, {})
        cost_per_1k = pricing.get("overage_per_1k_cents", 0)
        overage_cost = (overage // 1000) * cost_per_1k

        return overage, overage_cost


# ===========================================================================
# BILLING MANAGER
# ===========================================================================

class BillingManager:
    """
    Core billing operations. Manages subscriptions, events, invoices.
    """

    def __init__(self):
        BILLING_DIR.mkdir(parents=True, exist_ok=True)
        self.usage = UsageMeter()

    def _load_invoices(self) -> Dict:
        return _safe_load_json(INVOICES_FILE, default={"invoices": []})

    def create_subscription(
        self,
        owner: str,
        tier: str,
        billing_cycle: str = "monthly",
        stripe_customer_id: str = "",
        stripe_subscription_id: str = "",
    ) -> Dict:
        """Record a new subscription creation."""
        tier = tier.upper()
        pricing = PLAN_PRICING.get(tier, PLAN_PRICING["FREE"])

        if billing_cycle == "annual":
            amount_cents = pricing["annual_cents"]
        else:
            amount_cents = pricing["monthly_cents"]

        event = {
            "event_type": EVT_SUBSCRIPTION_CREATED,
            "owner": owner,
            "tier": tier,
            "billing_cycle": billing_cycle,
            "amount_cents": amount_cents,
            "stripe_customer_id": stripe_customer_id,
            "stripe_subscription_id": stripe_subscription_id,
            "timestamp": _now_iso(),
            "trial_ends": None,
        }

        trial_days = pricing.get("trial_days", 0)
        if trial_days > 0:
            from datetime import timedelta
            trial_end = (datetime.now(timezone.utc) + timedelta(days=trial_days)).isoformat()
            event["trial_ends"] = trial_end
            _append_event({**event, "event_type": EVT_TRIAL_STARTED, "trial_days": trial_days})

        _append_event(event)
        logger.info(f"Subscription created: owner={owner} tier={tier}")
        return event

    def upgrade_subscription(self, owner: str, old_tier: str, new_tier: str) -> Dict:
        """Record a tier upgrade."""
        event = {
            "event_type": EVT_SUBSCRIPTION_UPGRADED,
            "owner": owner,
            "old_tier": old_tier.upper(),
            "new_tier": new_tier.upper(),
            "timestamp": _now_iso(),
            "proration_note": "Prorated credit applied for remaining billing period",
        }
        _append_event(event)
        logger.info(f"Subscription upgraded: owner={owner} {old_tier}→{new_tier}")
        return event

    def downgrade_subscription(self, owner: str, old_tier: str, new_tier: str) -> Dict:
        """Record a tier downgrade (takes effect at next billing cycle)."""
        event = {
            "event_type": EVT_SUBSCRIPTION_DOWNGRADED,
            "owner": owner,
            "old_tier": old_tier.upper(),
            "new_tier": new_tier.upper(),
            "timestamp": _now_iso(),
            "effective_note": "Change takes effect at next billing cycle renewal",
        }
        _append_event(event)
        logger.info(f"Subscription downgraded: owner={owner} {old_tier}→{new_tier}")
        return event

    def cancel_subscription(self, owner: str, tier: str, reason: str = "") -> Dict:
        """Record subscription cancellation."""
        event = {
            "event_type": EVT_SUBSCRIPTION_CANCELLED,
            "owner": owner,
            "tier": tier.upper(),
            "reason": reason[:200],
            "timestamp": _now_iso(),
        }
        _append_event(event)
        logger.info(f"Subscription cancelled: owner={owner}")
        return event

    def record_payment(
        self,
        owner: str,
        tier: str,
        amount_cents: int,
        stripe_charge_id: str = "",
        success: bool = True,
    ) -> Dict:
        """Record a payment event (succeeded or failed)."""
        event_type = EVT_PAYMENT_SUCCEEDED if success else EVT_PAYMENT_FAILED
        event = {
            "event_type": event_type,
            "owner": owner,
            "tier": tier.upper(),
            "amount_cents": amount_cents,
            "amount_usd": f"${amount_cents / 100:.2f}",
            "stripe_charge_id": stripe_charge_id,
            "timestamp": _now_iso(),
        }
        _append_event(event)
        return event

    def record_quota_exceeded(self, owner: str, tier: str, endpoint: str) -> Dict:
        """Record a quota-exceeded event."""
        event = {
            "event_type": EVT_QUOTA_EXCEEDED,
            "owner": owner,
            "tier": tier,
            "endpoint": endpoint,
            "timestamp": _now_iso(),
        }
        _append_event(event)
        return event

    def generate_invoice(
        self,
        owner: str,
        tier: str,
        billing_period: str,
        amount_cents: int,
        line_items: Optional[List[Dict]] = None,
    ) -> Dict:
        """Generate a billing invoice record."""
        from datetime import date
        inv_id = f"INV-{int(time.time() * 1000)}"
        invoice = {
            "invoice_id": inv_id,
            "owner": owner,
            "tier": tier.upper(),
            "billing_period": billing_period,
            "amount_cents": amount_cents,
            "amount_usd": f"${amount_cents / 100:.2f}",
            "line_items": line_items or [{"description": f"{tier} Plan", "amount_cents": amount_cents}],
            "status": "issued",
            "issued_at": _now_iso(),
            "due_date": None,
        }

        invoices_data = self._load_invoices()
        invoices_data["invoices"].append(invoice)
        _safe_write_json(INVOICES_FILE, invoices_data)

        _append_event({
            "event_type": "invoice.issued",
            "invoice_id": inv_id,
            "owner": owner,
            "amount_cents": amount_cents,
            "timestamp": _now_iso(),
        })
        return invoice

    def get_billing_summary(self, owner: str) -> Dict:
        """Return billing summary for an owner."""
        events: List[Dict] = []
        if EVENTS_FILE.exists():
            try:
                with open(EVENTS_FILE, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                evt = json.loads(line)
                                if evt.get("owner") == owner:
                                    events.append(evt)
                            except Exception:
                                pass
            except Exception as e:
                logger.warning(f"Event log read error: {e}")

        total_paid = sum(
            e.get("amount_cents", 0)
            for e in events
            if e.get("event_type") == EVT_PAYMENT_SUCCEEDED
        )
        last_payment = next(
            (e for e in reversed(events) if e.get("event_type") == EVT_PAYMENT_SUCCEEDED),
            None,
        )

        return {
            "owner": owner,
            "total_events": len(events),
            "total_paid_cents": total_paid,
            "total_paid_usd": f"${total_paid / 100:.2f}",
            "last_payment": last_payment,
            "recent_events": events[-5:],
        }

    def process_stripe_webhook(self, payload: Dict, signature: str, secret: str) -> Dict:
        """
        Process Stripe webhook events safely.
        Validates signature before processing.
        Returns processing result.
        """
        import hmac as hmac_mod
        import hashlib

        # Validate Stripe signature (timestamp + payload)
        try:
            parts = {p.split("=")[0]: p.split("=")[1] for p in signature.split(",") if "=" in p}
            ts = parts.get("t", "")
            sig = parts.get("v1", "")
            signed_payload = f"{ts}.{json.dumps(payload, separators=(',', ':'))}"
            expected = hmac_mod.new(
                secret.encode("utf-8"),
                signed_payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac_mod.compare_digest(sig, expected):
                return {"status": "rejected", "reason": "invalid_signature"}
        except Exception as e:
            return {"status": "rejected", "reason": f"signature_error: {e}"}

        event_type = payload.get("type", "")
        data        = payload.get("data", {}).get("object", {})

        result = {"status": "processed", "event_type": event_type}

        if event_type == "invoice.payment_succeeded":
            self.record_payment(
                owner=data.get("customer_email", "unknown"),
                tier=data.get("metadata", {}).get("tier", "UNKNOWN"),
                amount_cents=data.get("amount_paid", 0),
                stripe_charge_id=data.get("charge", ""),
                success=True,
            )
        elif event_type == "invoice.payment_failed":
            self.record_payment(
                owner=data.get("customer_email", "unknown"),
                tier=data.get("metadata", {}).get("tier", "UNKNOWN"),
                amount_cents=data.get("amount_due", 0),
                stripe_charge_id="",
                success=False,
            )
        elif event_type == "customer.subscription.deleted":
            self.cancel_subscription(
                owner=data.get("metadata", {}).get("owner", "unknown"),
                tier=data.get("metadata", {}).get("tier", "UNKNOWN"),
                reason="stripe_cancelled",
            )
        else:
            result["status"] = "unhandled"

        return result

    def get_plan_comparison(self) -> Dict:
        """Return plan comparison table for marketing/API."""
        from api.auth import TIERS
        plans = []
        for tier_name, tier_def in TIERS.items():
            pricing = PLAN_PRICING.get(tier_name, {})
            plans.append({
                "tier": tier_name,
                "name": tier_def["name"],
                "price_monthly": f"${pricing.get('monthly_cents', 0) / 100:.0f}/mo",
                "price_annual": f"${pricing.get('annual_cents', 0) / 100:.0f}/yr",
                "requests_per_day": tier_def.get("requests_per_day", 0),
                "advisories_per_request": tier_def.get("advisories_per_request", 0),
                "features": tier_def.get("features", {}),
                "trial_days": pricing.get("trial_days", 0),
            })
        return {"plans": plans}


# Singleton
_billing_manager: Optional[BillingManager] = None

def get_billing_manager() -> BillingManager:
    global _billing_manager
    if _billing_manager is None:
        _billing_manager = BillingManager()
    return _billing_manager
