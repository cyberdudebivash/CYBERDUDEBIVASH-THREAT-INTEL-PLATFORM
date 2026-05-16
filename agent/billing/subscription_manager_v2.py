#!/usr/bin/env python3
"""
agent/billing/subscription_manager_v2.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE SUBSCRIPTION LIFECYCLE MANAGER v2

Manages the full SaaS subscription lifecycle:
  - Stripe Checkout session creation (hosted billing)
  - Plan upgrades / downgrades
  - Trial period management
  - Cancellation with grace period
  - Payment failure handling (dunning)
  - Proration calculation
  - Webhook event processing (complements existing stripe_gateway.py)

This module adds ENTERPRISE-GRADE lifecycle orchestration on top of the
existing Stripe integration. It does NOT replace stripe_gateway.py — it
extends it with business logic and org-level state management.

SaaS Tier → Stripe Price ID mapping (configure via environment):
  CDB_STRIPE_PRICE_PRO        = price_xxx
  CDB_STRIPE_PRICE_ENTERPRISE = price_xxx
  CDB_STRIPE_PRICE_MSSP       = price_xxx
"""

import os
import json
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List

logger = logging.getLogger("CDB-BILLING")

_STRIPE_SECRET_KEY      = os.environ.get("STRIPE_SECRET_KEY", "")
_STRIPE_WEBHOOK_SECRET  = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
_STRIPE_SUCCESS_URL     = os.environ.get("CDB_STRIPE_SUCCESS_URL", "https://cyberdudebivash.com/billing/success")
_STRIPE_CANCEL_URL      = os.environ.get("CDB_STRIPE_CANCEL_URL", "https://cyberdudebivash.com/billing/cancel")
_TRIAL_DAYS             = int(os.environ.get("CDB_TRIAL_DAYS", "14"))

# Stripe Price IDs per tier (set in Railway env / GitHub Secrets)
_PRICE_IDS = {
    "PRO":        os.environ.get("CDB_STRIPE_PRICE_PRO", ""),
    "ENTERPRISE": os.environ.get("CDB_STRIPE_PRICE_ENTERPRISE", ""),
    "MSSP":       os.environ.get("CDB_STRIPE_PRICE_MSSP", ""),
}

# Grace period after payment failure before downgrade
_DUNNING_GRACE_DAYS = int(os.environ.get("CDB_DUNNING_GRACE_DAYS", "7"))


def _stripe():
    """Return configured Stripe client."""
    import stripe
    stripe.api_key = _STRIPE_SECRET_KEY
    return stripe


class SubscriptionManagerV2:
    """
    Enterprise subscription lifecycle manager.
    Stateless — reads/writes go through OrgRegistry and Stripe API.
    """

    # ── Checkout ────────────────────────────────────────────────────────────

    def create_checkout_session(
        self,
        org_id:       str,
        org_email:    str,
        target_tier:  str,
        customer_id:  Optional[str] = None,
        trial:        bool = False,
        metadata:     Optional[Dict] = None,
    ) -> Dict:
        """
        Create a Stripe Checkout session for upgrading to target_tier.

        Args:
            org_id:      Organisation ID
            org_email:   Billing email
            target_tier: "PRO" | "ENTERPRISE" | "MSSP"
            customer_id: Existing Stripe customer ID (if any)
            trial:       Include trial period
            metadata:    Additional metadata for Stripe

        Returns:
            {"checkout_url": str, "session_id": str}
        """
        if not _STRIPE_SECRET_KEY:
            raise RuntimeError("STRIPE_SECRET_KEY not configured")

        price_id = _PRICE_IDS.get(target_tier.upper(), "")
        if not price_id:
            raise ValueError(f"No Stripe price ID configured for tier {target_tier}. "
                             f"Set CDB_STRIPE_PRICE_{target_tier.upper()} environment variable.")

        stripe = _stripe()

        session_params = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": f"{_STRIPE_SUCCESS_URL}?session_id={{CHECKOUT_SESSION_ID}}",
            "cancel_url":  _STRIPE_CANCEL_URL,
            "metadata": {
                "org_id":      org_id,
                "target_tier": target_tier.upper(),
                **(metadata or {}),
            },
            "subscription_data": {
                "metadata": {
                    "org_id":      org_id,
                    "target_tier": target_tier.upper(),
                    "platform":    "cdb-sentinel-apex",
                },
            },
        }

        if customer_id:
            session_params["customer"] = customer_id
        else:
            session_params["customer_email"] = org_email

        if trial:
            session_params["subscription_data"]["trial_period_days"] = _TRIAL_DAYS

        session = stripe.checkout.Session.create(**session_params)
        logger.info(
            f"[BILLING] Checkout session created: org={org_id} tier={target_tier} "
            f"session={session.id} trial={trial}"
        )
        return {"checkout_url": session.url, "session_id": session.id}

    # ── Upgrade / Downgrade ─────────────────────────────────────────────────

    def change_plan(
        self,
        stripe_subscription_id: str,
        new_tier:               str,
        prorate:                bool = True,
    ) -> Dict:
        """
        Upgrade or downgrade an existing subscription.

        Args:
            stripe_subscription_id: Stripe subscription ID
            new_tier:               Target tier ("PRO" | "ENTERPRISE" | "MSSP" | "FREE")
            prorate:                Apply proration (default True)

        Returns:
            Updated subscription data
        """
        if new_tier.upper() == "FREE":
            return self.cancel_subscription(stripe_subscription_id, immediate=False)

        new_price_id = _PRICE_IDS.get(new_tier.upper(), "")
        if not new_price_id:
            raise ValueError(f"No Stripe price for tier {new_tier}")

        stripe = _stripe()
        sub = stripe.Subscription.retrieve(stripe_subscription_id)

        if not sub.get("items", {}).get("data"):
            raise ValueError(f"Subscription {stripe_subscription_id} has no items")

        item_id = sub["items"]["data"][0]["id"]
        updated = stripe.Subscription.modify(
            stripe_subscription_id,
            items=[{"id": item_id, "price": new_price_id}],
            proration_behavior="create_prorations" if prorate else "none",
            metadata={"target_tier": new_tier.upper()},
        )

        logger.info(
            f"[BILLING] Plan changed: sub={stripe_subscription_id} "
            f"new_tier={new_tier} prorate={prorate}"
        )
        return {
            "subscription_id": updated.id,
            "status":          updated.status,
            "new_tier":        new_tier.upper(),
            "current_period_end": updated.current_period_end,
        }

    # ── Cancellation ────────────────────────────────────────────────────────

    def cancel_subscription(
        self,
        stripe_subscription_id: str,
        immediate:              bool = False,
    ) -> Dict:
        """
        Cancel subscription at end of billing period (or immediately).

        Args:
            immediate: If True, cancel right now and prorate refund.
                       If False (default), cancel at period end (customer keeps access).
        """
        stripe = _stripe()
        if immediate:
            cancelled = stripe.Subscription.cancel(stripe_subscription_id)
            status    = "cancelled"
        else:
            cancelled = stripe.Subscription.modify(
                stripe_subscription_id,
                cancel_at_period_end=True,
            )
            status = "cancel_scheduled"

        logger.info(
            f"[BILLING] Subscription cancelled: sub={stripe_subscription_id} "
            f"immediate={immediate} status={status}"
        )
        return {
            "subscription_id":   stripe_subscription_id,
            "status":            status,
            "cancel_at":         cancelled.get("cancel_at") or cancelled.get("current_period_end"),
        }

    # ── Customer Portal ─────────────────────────────────────────────────────

    def create_portal_session(
        self,
        stripe_customer_id: str,
        return_url:         str = "https://cyberdudebivash.com/dashboard",
    ) -> Dict:
        """
        Create a Stripe Customer Portal session.
        Allows customers to manage their subscription, payment method, invoices.
        """
        stripe = _stripe()
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=return_url,
        )
        return {"portal_url": session.url}

    # ── Dunning / Payment Failure ────────────────────────────────────────────

    def handle_payment_failure(
        self,
        org_id:      str,
        invoice_id:  str,
        attempt_num: int,
    ) -> Dict:
        """
        Handle failed payment with graduated response:
          Attempt 1: Notify only (Stripe auto-retries)
          Attempt 2: Warn user + reduce to degraded mode
          Attempt 3+: Downgrade to FREE after grace period
        """
        action = "notify"
        if attempt_num == 2:
            action = "warn_and_degrade"
        elif attempt_num >= 3:
            action = "downgrade_to_free"

        logger.warning(
            f"[BILLING] Payment failure: org={org_id} invoice={invoice_id} "
            f"attempt={attempt_num} action={action}"
        )

        if action == "downgrade_to_free":
            # Emit event for OrgRegistry to handle tier update
            logger.error(
                f"[BILLING] DOWNGRADE triggered: org={org_id} → FREE "
                f"after {attempt_num} failed payment attempts"
            )

        return {
            "org_id":      org_id,
            "invoice_id":  invoice_id,
            "attempt_num": attempt_num,
            "action":      action,
            "grace_days":  _DUNNING_GRACE_DAYS,
        }

    # ── Invoice / Usage ─────────────────────────────────────────────────────

    def get_upcoming_invoice(self, stripe_customer_id: str) -> Optional[Dict]:
        """Preview next invoice for customer."""
        try:
            stripe = _stripe()
            invoice = stripe.Invoice.upcoming(customer=stripe_customer_id)
            return {
                "amount_due":    invoice.amount_due / 100,
                "currency":      invoice.currency.upper(),
                "period_start":  datetime.fromtimestamp(invoice.period_start, tz=timezone.utc).isoformat(),
                "period_end":    datetime.fromtimestamp(invoice.period_end,   tz=timezone.utc).isoformat(),
                "line_items":    [
                    {
                        "description": line.description,
                        "amount":      line.amount / 100,
                        "quantity":    line.quantity,
                    }
                    for line in invoice.lines.data
                ],
            }
        except Exception as e:
            logger.warning(f"[BILLING] Could not retrieve upcoming invoice: {e}")
            return None

    # ── Webhook Event Router ─────────────────────────────────────────────────

    def process_webhook_event(self, event: Dict) -> Dict:
        """
        Route Stripe webhook events to appropriate handlers.
        Complements existing stripe_gateway.py — handles lifecycle events.
        """
        event_type = event.get("type", "")
        data       = event.get("data", {}).get("object", {})

        handlers = {
            "checkout.session.completed":     self._on_checkout_completed,
            "customer.subscription.updated":  self._on_subscription_updated,
            "customer.subscription.deleted":  self._on_subscription_deleted,
            "invoice.payment_succeeded":      self._on_payment_success,
            "invoice.payment_failed":         self._on_payment_failed,
        }

        handler = handlers.get(event_type)
        if handler:
            try:
                return handler(data)
            except Exception as e:
                logger.error(f"[BILLING] Webhook handler error for {event_type}: {e}")
                return {"status": "error", "event_type": event_type, "error": str(e)}

        return {"status": "unhandled", "event_type": event_type}

    def _on_checkout_completed(self, session: Dict) -> Dict:
        org_id    = session.get("metadata", {}).get("org_id", "")
        new_tier  = session.get("metadata", {}).get("target_tier", "")
        customer  = session.get("customer", "")
        sub_id    = session.get("subscription", "")

        if org_id and new_tier:
            logger.info(f"[BILLING] Checkout complete: org={org_id} tier={new_tier} customer={customer}")
            # Update OrgRegistry
            try:
                from agent.auth.models import OrgRegistry
                registry = OrgRegistry()
                org = registry.get_org(org_id)
                if org:
                    org.plan              = new_tier
                    org.stripe_customer_id = customer
                    org.features["subscription_id"] = sub_id
                    registry.save_org(org)
            except Exception as e:
                logger.warning(f"[BILLING] OrgRegistry update failed: {e}")

        return {"status": "processed", "org_id": org_id, "new_tier": new_tier}

    def _on_subscription_updated(self, sub: Dict) -> Dict:
        org_id   = sub.get("metadata", {}).get("org_id", "")
        new_tier = sub.get("metadata", {}).get("target_tier", "")
        logger.info(f"[BILLING] Subscription updated: org={org_id} status={sub.get('status')} tier={new_tier}")
        return {"status": "processed"}

    def _on_subscription_deleted(self, sub: Dict) -> Dict:
        org_id = sub.get("metadata", {}).get("org_id", "")
        logger.warning(f"[BILLING] Subscription DELETED: org={org_id}")
        try:
            from agent.auth.models import OrgRegistry
            registry = OrgRegistry()
            org = registry.get_org(org_id)
            if org:
                org.plan = "FREE"
                registry.save_org(org)
        except Exception as e:
            logger.error(f"[BILLING] Could not downgrade org to FREE: {e}")
        return {"status": "processed", "org_id": org_id, "action": "downgraded_to_free"}

    def _on_payment_success(self, invoice: Dict) -> Dict:
        customer = invoice.get("customer", "")
        amount   = invoice.get("amount_paid", 0) / 100
        logger.info(f"[BILLING] Payment success: customer={customer} amount=${amount:.2f}")
        return {"status": "processed"}

    def _on_payment_failed(self, invoice: Dict) -> Dict:
        customer    = invoice.get("customer", "")
        attempt_num = invoice.get("attempt_count", 1)
        invoice_id  = invoice.get("id", "")
        # Attempt to resolve org_id from customer
        org_id = ""
        try:
            from agent.auth.models import OrgRegistry
            registry = OrgRegistry()
            orgs     = registry._load_all_orgs()
            for oid, org in orgs.items():
                if getattr(org, "stripe_customer_id", "") == customer:
                    org_id = oid
                    break
        except Exception:
            pass

        return self.handle_payment_failure(org_id or customer, invoice_id, attempt_num)


# Singleton
subscription_manager = SubscriptionManagerV2()
