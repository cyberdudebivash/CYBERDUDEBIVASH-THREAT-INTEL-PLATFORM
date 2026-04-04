"""
core/billing/subscription.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
Subscription lifecycle state machine.

States:
  trialing → active → past_due → canceled
                    ↘ canceled
  trialing → canceled
  past_due → active   (payment recovered)
  past_due → canceled (dunning exhausted)

Stripe webhook events drive all transitions:
  checkout.session.completed      → trialing/active
  customer.subscription.updated   → active/past_due/canceled
  customer.subscription.deleted   → canceled
  invoice.payment_succeeded       → active (recovery from past_due)
  invoice.payment_failed          → past_due

Design:
  - Explicit state machine: invalid transitions raise SubscriptionError
  - Atomic file writes for local persistence (tmp → rename)
  - Idempotent: replaying the same event is a no-op
  - Emits audit log entry on every transition
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("sentinel.billing.subscription")

_STORE_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", "/tmp/sentinel_data")) / "subscriptions"
_STORE_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────
# State + Event enumerations
# ─────────────────────────────────────────────

class SubscriptionState(str, Enum):
    TRIALING    = "trialing"
    ACTIVE      = "active"
    PAST_DUE    = "past_due"
    CANCELED    = "canceled"
    UNPAID      = "unpaid"
    INCOMPLETE  = "incomplete"


class SubscriptionEvent(str, Enum):
    # Stripe webhook-derived events
    CHECKOUT_COMPLETED      = "checkout.session.completed"
    SUBSCRIPTION_UPDATED    = "customer.subscription.updated"
    SUBSCRIPTION_DELETED    = "customer.subscription.deleted"
    PAYMENT_SUCCEEDED       = "invoice.payment_succeeded"
    PAYMENT_FAILED          = "invoice.payment_failed"
    TRIAL_WILL_END          = "customer.subscription.trial_will_end"
    # Internal administrative events
    ADMIN_ACTIVATE          = "admin.activate"
    ADMIN_CANCEL            = "admin.cancel"
    ADMIN_SUSPEND           = "admin.suspend"


class SubscriptionError(Exception):
    """Raised on invalid state transitions."""


# ─────────────────────────────────────────────
# Subscription record
# ─────────────────────────────────────────────

@dataclass
class SubscriptionRecord:
    subscription_id:  str
    customer_id:      str
    email:            str
    tier:             str                  # FREE | PRO | ENTERPRISE | MSSP
    state:            SubscriptionState
    api_key:          str
    stripe_sub_id:    str = ""
    stripe_customer:  str = ""
    plan_id:          str = ""
    current_period_end: Optional[float] = None
    trial_end:          Optional[float] = None
    cancel_at_period_end: bool = False
    created_at:       float = field(default_factory=time.time)
    updated_at:       float = field(default_factory=time.time)
    last_event:       str = ""
    event_history:    List[Dict[str, Any]] = field(default_factory=list)
    metadata:         Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SubscriptionRecord":
        d = dict(d)
        d["state"] = SubscriptionState(d.get("state", "active"))
        # event_history contains plain dicts — safe to pass as-is
        return cls(**d)


# ─────────────────────────────────────────────
# Transition table
# ─────────────────────────────────────────────

# (current_state, event) → new_state
_TRANSITIONS: Dict[tuple, SubscriptionState] = {
    # Checkout creates subscription
    (SubscriptionState.INCOMPLETE, SubscriptionEvent.CHECKOUT_COMPLETED):   SubscriptionState.ACTIVE,
    (SubscriptionState.TRIALING,   SubscriptionEvent.CHECKOUT_COMPLETED):   SubscriptionState.ACTIVE,

    # Payment success
    (SubscriptionState.TRIALING,   SubscriptionEvent.PAYMENT_SUCCEEDED):    SubscriptionState.ACTIVE,
    (SubscriptionState.ACTIVE,     SubscriptionEvent.PAYMENT_SUCCEEDED):    SubscriptionState.ACTIVE,
    (SubscriptionState.PAST_DUE,   SubscriptionEvent.PAYMENT_SUCCEEDED):    SubscriptionState.ACTIVE,
    (SubscriptionState.UNPAID,     SubscriptionEvent.PAYMENT_SUCCEEDED):    SubscriptionState.ACTIVE,

    # Payment failure
    (SubscriptionState.ACTIVE,     SubscriptionEvent.PAYMENT_FAILED):       SubscriptionState.PAST_DUE,
    (SubscriptionState.TRIALING,   SubscriptionEvent.PAYMENT_FAILED):       SubscriptionState.PAST_DUE,
    (SubscriptionState.PAST_DUE,   SubscriptionEvent.PAYMENT_FAILED):       SubscriptionState.UNPAID,

    # Subscription update (Stripe sends this on plan change)
    (SubscriptionState.ACTIVE,     SubscriptionEvent.SUBSCRIPTION_UPDATED): SubscriptionState.ACTIVE,
    (SubscriptionState.TRIALING,   SubscriptionEvent.SUBSCRIPTION_UPDATED): SubscriptionState.TRIALING,
    (SubscriptionState.PAST_DUE,   SubscriptionEvent.SUBSCRIPTION_UPDATED): SubscriptionState.PAST_DUE,

    # Cancellation
    (SubscriptionState.ACTIVE,     SubscriptionEvent.SUBSCRIPTION_DELETED): SubscriptionState.CANCELED,
    (SubscriptionState.TRIALING,   SubscriptionEvent.SUBSCRIPTION_DELETED): SubscriptionState.CANCELED,
    (SubscriptionState.PAST_DUE,   SubscriptionEvent.SUBSCRIPTION_DELETED): SubscriptionState.CANCELED,
    (SubscriptionState.UNPAID,     SubscriptionEvent.SUBSCRIPTION_DELETED): SubscriptionState.CANCELED,

    # Admin overrides (any → target)
    (SubscriptionState.INCOMPLETE, SubscriptionEvent.ADMIN_ACTIVATE):       SubscriptionState.ACTIVE,
    (SubscriptionState.TRIALING,   SubscriptionEvent.ADMIN_ACTIVATE):       SubscriptionState.ACTIVE,
    (SubscriptionState.PAST_DUE,   SubscriptionEvent.ADMIN_ACTIVATE):       SubscriptionState.ACTIVE,
    (SubscriptionState.UNPAID,     SubscriptionEvent.ADMIN_ACTIVATE):       SubscriptionState.ACTIVE,
    (SubscriptionState.CANCELED,   SubscriptionEvent.ADMIN_ACTIVATE):       SubscriptionState.ACTIVE,
    (SubscriptionState.ACTIVE,     SubscriptionEvent.ADMIN_CANCEL):         SubscriptionState.CANCELED,
    (SubscriptionState.TRIALING,   SubscriptionEvent.ADMIN_CANCEL):         SubscriptionState.CANCELED,
    (SubscriptionState.PAST_DUE,   SubscriptionEvent.ADMIN_CANCEL):         SubscriptionState.CANCELED,
    (SubscriptionState.ACTIVE,     SubscriptionEvent.ADMIN_SUSPEND):        SubscriptionState.PAST_DUE,
}

# Access privileges per state
_STATE_ACCESS: Dict[SubscriptionState, bool] = {
    SubscriptionState.TRIALING:   True,
    SubscriptionState.ACTIVE:     True,
    SubscriptionState.PAST_DUE:   True,   # grace period — still allow access
    SubscriptionState.UNPAID:     False,
    SubscriptionState.CANCELED:   False,
    SubscriptionState.INCOMPLETE: False,
}


# ─────────────────────────────────────────────
# State Machine
# ─────────────────────────────────────────────

class SubscriptionStateMachine:
    """
    Manages subscription state transitions driven by Stripe webhook events.
    Thread-safe via per-subscription locks.
    Persists state to atomic JSON files.
    Supports on_transition callbacks for downstream side-effects.
    """

    def __init__(self, store_dir: Path = _STORE_DIR) -> None:
        self._store_dir = store_dir
        self._locks: Dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()
        self._callbacks: List[Callable[[SubscriptionRecord, SubscriptionState], None]] = []
        # Processed event IDs for idempotency (Stripe may retry webhooks)
        self._processed_events: Set[str] = set()

    # ── Public API ────────────────────────────────────────────────────────────

    def create_subscription(
        self,
        subscription_id:  str,
        customer_id:      str,
        email:            str,
        tier:             str,
        api_key:          str,
        stripe_sub_id:    str = "",
        initial_state:    SubscriptionState = SubscriptionState.TRIALING,
        metadata:         Optional[Dict[str, Any]] = None,
    ) -> SubscriptionRecord:
        """Create and persist a new subscription record."""
        record = SubscriptionRecord(
            subscription_id = subscription_id,
            customer_id     = customer_id,
            email           = email,
            tier            = tier.upper(),
            state           = initial_state,
            api_key         = api_key,
            stripe_sub_id   = stripe_sub_id,
            metadata        = metadata or {},
        )
        self._save(record)
        logger.info("subscription_created sub_id=%s tier=%s state=%s",
                    subscription_id, tier, initial_state.value)
        return record

    def transition(
        self,
        subscription_id: str,
        event:           SubscriptionEvent,
        stripe_event_id: str = "",
        payload:         Optional[Dict[str, Any]] = None,
    ) -> SubscriptionRecord:
        """
        Apply a lifecycle event to a subscription, advancing its state.

        Args:
            subscription_id: Internal subscription UUID
            event:           The lifecycle event to apply
            stripe_event_id: Stripe webhook evt_* ID for idempotency
            payload:         Optional Stripe event data for metadata updates

        Returns:
            Updated SubscriptionRecord

        Raises:
            SubscriptionError: If transition is invalid or subscription not found
        """
        # Idempotency: skip replayed Stripe events
        if stripe_event_id:
            event_key = f"{subscription_id}:{stripe_event_id}"
            if event_key in self._processed_events:
                logger.info("idempotent_skip event_id=%s", stripe_event_id)
                return self.get(subscription_id)
            self._processed_events.add(event_key)

        lock = self._get_lock(subscription_id)
        with lock:
            record = self.get(subscription_id)
            current = record.state
            new_state = _TRANSITIONS.get((current, event))

            if new_state is None:
                raise SubscriptionError(
                    f"Invalid transition: {current.value} + {event.value} "
                    f"has no defined target state"
                )

            old_state = record.state
            record.state      = new_state
            record.updated_at = time.time()
            record.last_event = event.value

            # Update billing fields from payload
            if payload:
                self._apply_payload(record, event, payload)

            # Append to audit history
            record.event_history.append({
                "ts":         record.updated_at,
                "event":      event.value,
                "from_state": old_state.value,
                "to_state":   new_state.value,
                "stripe_id":  stripe_event_id,
            })

            self._save(record)
            logger.info(
                "subscription_transition sub_id=%s %s+%s→%s",
                subscription_id, old_state.value, event.value, new_state.value
            )

            # Fire callbacks (side-effects: key gating, email, Slack alert)
            for cb in self._callbacks:
                try:
                    cb(record, old_state)
                except Exception as exc:
                    logger.error("transition_callback_error err=%s", exc)

            return record

    def get(self, subscription_id: str) -> SubscriptionRecord:
        """Load a subscription record by ID."""
        path = self._path(subscription_id)
        if not path.exists():
            raise SubscriptionError(f"Subscription not found: {subscription_id}")
        with open(path) as f:
            return SubscriptionRecord.from_dict(json.load(f))

    def get_by_api_key(self, api_key: str) -> Optional[SubscriptionRecord]:
        """Find subscription by API key (linear scan — use cache in prod)."""
        for path in self._store_dir.glob("*.json"):
            try:
                with open(path) as f:
                    d = json.load(f)
                if d.get("api_key") == api_key:
                    return SubscriptionRecord.from_dict(d)
            except Exception:
                continue
        return None

    def can_access(self, subscription_id: str) -> bool:
        """Check if this subscription currently has API access."""
        try:
            record = self.get(subscription_id)
            return _STATE_ACCESS.get(record.state, False)
        except Exception:
            return False

    def on_transition(
        self,
        callback: Callable[[SubscriptionRecord, SubscriptionState], None],
    ) -> None:
        """Register a callback fired on every state transition."""
        self._callbacks.append(callback)

    def list_by_state(self, state: SubscriptionState) -> List[SubscriptionRecord]:
        """List all subscriptions in a given state."""
        results = []
        for path in self._store_dir.glob("*.json"):
            try:
                with open(path) as f:
                    d = json.load(f)
                if d.get("state") == state.value:
                    results.append(SubscriptionRecord.from_dict(d))
            except Exception:
                continue
        return results

    def summary(self) -> Dict[str, Any]:
        """Return subscription counts by state."""
        counts: Dict[str, int] = {s.value: 0 for s in SubscriptionState}
        total = 0
        for path in self._store_dir.glob("*.json"):
            try:
                with open(path) as f:
                    d = json.load(f)
                state = d.get("state", "unknown")
                counts[state] = counts.get(state, 0) + 1
                total += 1
            except Exception:
                continue
        return {"total": total, "by_state": counts}

    # ── Internal ──────────────────────────────────────────────────────────────

    def _save(self, record: SubscriptionRecord) -> None:
        path = self._path(record.subscription_id)
        tmp  = Path(str(path) + ".tmp")
        with open(tmp, "w") as f:
            json.dump(record.to_dict(), f, indent=2, default=str)
        os.replace(tmp, path)

    def _path(self, subscription_id: str) -> Path:
        safe = hashlib.sha256(subscription_id.encode()).hexdigest()[:16]
        return self._store_dir / f"sub_{safe}.json"

    def _get_lock(self, subscription_id: str) -> threading.Lock:
        with self._global_lock:
            if subscription_id not in self._locks:
                self._locks[subscription_id] = threading.Lock()
            return self._locks[subscription_id]

    @staticmethod
    def _apply_payload(record: SubscriptionRecord,
                       event: SubscriptionEvent,
                       payload: Dict[str, Any]) -> None:
        """Extract billing fields from Stripe event payload."""
        sub = payload.get("subscription") or payload.get("object") or {}

        if isinstance(sub, dict):
            if sub.get("current_period_end"):
                record.current_period_end = float(sub["current_period_end"])
            if sub.get("trial_end"):
                record.trial_end = float(sub["trial_end"])
            if sub.get("cancel_at_period_end") is not None:
                record.cancel_at_period_end = bool(sub["cancel_at_period_end"])
            # Plan ID for tier mapping
            plan = (sub.get("plan") or sub.get("items", {})
                    .get("data", [{}])[0].get("plan", {}))
            if isinstance(plan, dict) and plan.get("id"):
                record.plan_id = plan["id"]

        # Stripe metadata → our metadata dict
        if payload.get("metadata"):
            record.metadata.update(payload["metadata"])
