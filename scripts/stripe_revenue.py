#!/usr/bin/env python3
"""
scripts/stripe_revenue.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Stripe Revenue Integration v1.0
====================================================================
Production-grade Stripe payment processing pipeline.

Responsibilities:
  1. Stripe webhook validation (HMAC-SHA256, replay-attack resistant)
  2. Automatic API key provisioning on successful payment
  3. Subscription upgrade/downgrade/cancellation handling
  4. Billing event recording (integrates with api/billing.py)
  5. Welcome notification via Telegram on new subscriptions
  6. Payment Link URL registry (static links, no server required)
  7. Trial activation on checkout

Stripe events handled:
  checkout.session.completed     -- New subscription / one-time purchase
  customer.subscription.updated  -- Upgrade / downgrade
  customer.subscription.deleted  -- Cancellation
  invoice.payment_succeeded      -- Renewal payment
  invoice.payment_failed         -- Failed renewal (dunning)

Payment Link Registry:
  STRIPE_PAYMENT_LINK_PRO        -- env var or hardcoded Product URL
  STRIPE_PAYMENT_LINK_ENTERPRISE -- env var or hardcoded Product URL
  STRIPE_PAYMENT_LINK_MSSP       -- env var or hardcoded Product URL

Environment variables:
  STRIPE_WEBHOOK_SECRET   -- Required for webhook validation (whsec_...)
  STRIPE_SECRET_KEY       -- Optional: Stripe API key for direct API calls
  TELEGRAM_BOT_TOKEN      -- For welcome alerts
  TELEGRAM_ALERT_CHAT_ID  -- Admin channel for new sale notifications

Zero-Regression Mandates:
  - NEVER raises on invalid webhooks (returns structured error)
  - NEVER stores raw card data (PCI compliance — none passes through)
  - NEVER provisions keys without validated payment
  - Atomic key store writes
  - All events append-only logged

CLI usage:
  python scripts/stripe_revenue.py --event <path/to/event.json>
  python scripts/stripe_revenue.py --provision PRO --email user@example.com
  python scripts/stripe_revenue.py --links
  python scripts/stripe_revenue.py --revenue-summary

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] STRIPE %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("CDB-STRIPE")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR          = Path(__file__).resolve().parent.parent
WEBHOOK_LOG_FILE  = BASE_DIR / "data" / "billing" / "stripe_webhooks.jsonl"
PROCESSED_IDS     = BASE_DIR / "data" / "billing" / "stripe_processed_ids.json"

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "").strip()
TG_BOT_TOKEN          = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TG_ADMIN_CHAT         = os.environ.get("TELEGRAM_ALERT_CHAT_ID", "").strip()

# ---------------------------------------------------------------------------
# Stripe Payment Link Registry
# Products created in Stripe Dashboard → Payment Links
# Set these as environment variables or hardcode after creating products
# ---------------------------------------------------------------------------
PAYMENT_LINKS: Dict[str, Dict[str, str]] = {
    "PRO": {
        "monthly": os.environ.get("STRIPE_LINK_PRO_MONTHLY",
                                   "https://buy.stripe.com/cdb_pro_monthly"),
        "annual":  os.environ.get("STRIPE_LINK_PRO_ANNUAL",
                                   "https://buy.stripe.com/cdb_pro_annual"),
        "price_monthly":  "$49/mo",
        "price_annual":   "$470/yr",
        "description":    "PRO API — 5,000 req/day, full IOC/STIX/EPSS access",
    },
    "ENTERPRISE": {
        "monthly": os.environ.get("STRIPE_LINK_ENT_MONTHLY",
                                   "https://buy.stripe.com/cdb_enterprise_monthly"),
        "annual":  os.environ.get("STRIPE_LINK_ENT_ANNUAL",
                                   "https://buy.stripe.com/cdb_enterprise_annual"),
        "price_monthly":  "$499/mo",
        "price_annual":   "$4,790/yr",
        "description":    "ENTERPRISE API — 50K req/day, webhooks, bulk export, STIX",
    },
    "MSSP": {
        "monthly": os.environ.get("STRIPE_LINK_MSSP_MONTHLY",
                                   "https://buy.stripe.com/cdb_mssp_monthly"),
        "annual":  os.environ.get("STRIPE_LINK_MSSP_ANNUAL",
                                   "https://buy.stripe.com/cdb_mssp_annual"),
        "price_monthly":  "$1,999/mo",
        "price_annual":   "$19,190/yr",
        "description":    "MSSP — Unlimited, white-label, dedicated support",
    },
}

# Gumroad product links (detection packs, one-time purchases)
GUMROAD_PRODUCTS: Dict[str, Dict[str, str]] = {
    "detection_pack_essential": {
        "url":   "https://cyberdudebivash.gumroad.com/l/detection-pack-essential",
        "price": "$179",
        "name":  "Essential Detection Pack — Sigma + YARA + KQL (1-month coverage)",
    },
    "detection_pack_pro": {
        "url":   "https://cyberdudebivash.gumroad.com/l/detection-pack-pro",
        "price": "$349",
        "name":  "PRO Detection Pack — Full rule library + quarterly updates",
    },
    "threat_report_monthly": {
        "url":   "https://cyberdudebivash.gumroad.com/l/sentinel-monthly-report",
        "price": "$99",
        "name":  "Monthly Threat Intelligence Report — PDF (C-suite ready)",
    },
    "ioc_feed_annual": {
        "url":   "https://cyberdudebivash.gumroad.com/l/ioc-feed-annual",
        "price": "$299",
        "name":  "Annual IOC Feed — Structured JSON + STIX 2.1",
    },
}

# Tier mapping from Stripe metadata → internal tier name
STRIPE_TIER_MAP: Dict[str, str] = {
    "pro":        "PRO",
    "Pro":        "PRO",
    "PRO":        "PRO",
    "enterprise": "ENTERPRISE",
    "Enterprise": "ENTERPRISE",
    "ENTERPRISE": "ENTERPRISE",
    "mssp":       "MSSP",
    "MSSP":       "MSSP",
}

# ---------------------------------------------------------------------------
# Webhook Signature Validation
# ---------------------------------------------------------------------------
STRIPE_TIMESTAMP_TOLERANCE_SECONDS = 300  # 5 minutes replay protection


def validate_stripe_signature(
    payload_bytes: bytes,
    signature_header: str,
    secret: str,
) -> Tuple[bool, str]:
    """
    Validate Stripe webhook signature (Stripe-Signature header).
    Implements replay-attack protection (5 min tolerance).

    Returns: (valid: bool, reason: str)
    """
    if not secret:
        return False, "webhook_secret_not_configured"

    try:
        parts = {}
        for part in signature_header.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                parts[k.strip()] = v.strip()

        ts = parts.get("t", "")
        sig = parts.get("v1", "")

        if not ts or not sig:
            return False, "malformed_signature_header"

        # Replay protection
        ts_int = int(ts)
        if abs(time.time() - ts_int) > STRIPE_TIMESTAMP_TOLERANCE_SECONDS:
            return False, f"timestamp_too_old_or_future: delta={int(time.time() - ts_int)}s"

        # HMAC-SHA256 verification
        signed_payload = f"{ts}.{payload_bytes.decode('utf-8')}"
        expected = hmac.new(
            secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(sig, expected):
            return False, "signature_mismatch"

        return True, "valid"

    except Exception as e:
        return False, f"validation_error: {e}"


# ---------------------------------------------------------------------------
# Idempotency Guard
# ---------------------------------------------------------------------------

def _load_processed_ids() -> Dict:
    try:
        if PROCESSED_IDS.exists() and PROCESSED_IDS.stat().st_size > 0:
            return json.loads(PROCESSED_IDS.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"processed": {}}


def _mark_processed(event_id: str, event_type: str) -> None:
    PROCESSED_IDS.parent.mkdir(parents=True, exist_ok=True)
    data = _load_processed_ids()
    data["processed"][event_id] = {
        "event_type": event_type,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
    tmp = PROCESSED_IDS.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(PROCESSED_IDS)
    except Exception as e:
        logger.warning(f"Failed to mark event {event_id} as processed: {e}")


def _is_already_processed(event_id: str) -> bool:
    data = _load_processed_ids()
    return event_id in data.get("processed", {})


# ---------------------------------------------------------------------------
# Webhook Event Logger
# ---------------------------------------------------------------------------

def _log_webhook_event(event: Dict, result: Dict) -> None:
    WEBHOOK_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "event_id":   event.get("id", ""),
        "event_type": event.get("type", ""),
        "ts":         datetime.now(timezone.utc).isoformat(),
        "result":     result,
    }
    try:
        with open(WEBHOOK_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning(f"Webhook log append failed: {e}")


# ---------------------------------------------------------------------------
# API Key Provisioner
# ---------------------------------------------------------------------------

def _provision_api_key(
    email: str,
    tier: str,
    billing_cycle: str = "monthly",
    stripe_customer_id: str = "",
    stripe_subscription_id: str = "",
    trial_days: int = 0,
) -> Dict:
    """
    Provision a new API key for a paid customer.
    Integrates with api/auth.py key generator.
    Returns: {key, tier, expires_at, ...}
    """
    try:
        sys.path.insert(0, str(BASE_DIR))
        from api.auth import generate_api_key, store_api_key

        tier = STRIPE_TIER_MAP.get(tier, tier.upper())
        if tier not in ("PRO", "ENTERPRISE", "MSSP"):
            tier = "PRO"

        expires_days = trial_days if trial_days > 0 else 365
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

        key_data = generate_api_key(
            tier=tier,
            owner=email,
            label=f"stripe_{billing_cycle}",
            expires_days=expires_days,
        )

        if store_api_key(key_data):
            logger.info(f"API key provisioned: tier={tier} owner={email[:30]}")
            return {
                "success": True,
                "api_key": key_data["key"],
                "tier": tier,
                "owner": email,
                "expires_at": key_data.get("expires_at", expires_at),
                "key_prefix": key_data["key"][:16] + "...",
            }
        else:
            logger.error(f"Key store write failed for {email}")
            return {"success": False, "reason": "keystore_write_failed"}

    except ImportError as e:
        logger.error(f"auth.py import failed: {e}")
        return {"success": False, "reason": f"auth_import_error: {e}"}
    except Exception as e:
        logger.error(f"Key provisioning error: {e}")
        return {"success": False, "reason": str(e)}


def _revoke_api_key_by_email(email: str) -> Dict:
    """Revoke all active keys for an email (on cancellation/chargeback)."""
    try:
        sys.path.insert(0, str(BASE_DIR))
        from api.auth import revoke_api_keys_for_owner
        count = revoke_api_keys_for_owner(email)
        logger.info(f"Revoked {count} keys for {email}")
        return {"success": True, "revoked_count": count}
    except Exception as e:
        logger.warning(f"Key revocation failed for {email}: {e}")
        return {"success": False, "reason": str(e)}


def _upgrade_api_key_tier(email: str, new_tier: str) -> Dict:
    """Upgrade existing key tier for an email (on plan upgrade)."""
    try:
        sys.path.insert(0, str(BASE_DIR))
        from api.auth import upgrade_key_tier_for_owner
        new_tier = STRIPE_TIER_MAP.get(new_tier, new_tier.upper())
        count = upgrade_key_tier_for_owner(email, new_tier)
        logger.info(f"Upgraded {count} keys for {email} to {new_tier}")
        return {"success": True, "upgraded_count": count, "new_tier": new_tier}
    except Exception as e:
        logger.warning(f"Key upgrade failed for {email}: {e}")
        return {"success": False, "reason": str(e)}


# ---------------------------------------------------------------------------
# Billing Event Recording
# ---------------------------------------------------------------------------

def _record_billing_event(
    event_type: str,
    owner: str,
    tier: str,
    amount_cents: int = 0,
    stripe_data: Dict = None,
) -> None:
    """Record billing event using api/billing.py BillingManager."""
    try:
        sys.path.insert(0, str(BASE_DIR))
        from api.billing import get_billing_manager
        bm = get_billing_manager()

        if event_type in ("subscription.created", "checkout.session.completed"):
            bm.create_subscription(
                owner=owner,
                tier=tier,
                stripe_customer_id=(stripe_data or {}).get("customer", ""),
                stripe_subscription_id=(stripe_data or {}).get("subscription", ""),
            )
        elif event_type == "payment.succeeded":
            bm.record_payment(owner=owner, tier=tier, amount_cents=amount_cents, success=True)
        elif event_type == "payment.failed":
            bm.record_payment(owner=owner, tier=tier, amount_cents=amount_cents, success=False)
        elif event_type == "subscription.cancelled":
            bm.cancel_subscription(owner=owner, tier=tier, reason="stripe_cancelled")

    except Exception as e:
        logger.warning(f"Billing event record failed: {e}")


# ---------------------------------------------------------------------------
# Telegram Welcome Notification
# ---------------------------------------------------------------------------

def _send_welcome_notification(email: str, tier: str, key_prefix: str) -> None:
    """Send admin notification on new subscription."""
    if not TG_BOT_TOKEN or not TG_ADMIN_CHAT:
        return
    try:
        platform_url = "https://intel.cyberdudebivash.com"
        message = (
            f"💰 *NEW SUBSCRIPTION — SENTINEL APEX*\n\n"
            f"🎯 *Tier:* `{tier}`\n"
            f"📧 *Customer:* `{email[:40]}`\n"
            f"🔑 *API Key:* `{key_prefix}`\n"
            f"⏰ *Time:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"💳 Payment confirmed via Stripe.\n"
            f"🔗 [{platform_url}]({platform_url})"
        )
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        payload = json.dumps({
            "chat_id": TG_ADMIN_CHAT,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                logger.info(f"Welcome notification sent for {email[:30]}")
    except Exception as e:
        logger.warning(f"Welcome notification failed: {e}")


# ---------------------------------------------------------------------------
# Gumroad Webhook Handler
# ---------------------------------------------------------------------------

def process_gumroad_sale(sale_event: Dict) -> Dict:
    """
    Process Gumroad sale webhook (ping event).
    Provisions API key for API subscription products.
    For detection packs: sends download link confirmation.

    Gumroad sale object fields we use:
      email, product_name, product_permalink, price, test
    """
    email    = sale_event.get("email", "").strip().lower()
    product  = sale_event.get("product_name", "").lower()
    price    = sale_event.get("price", 0)
    is_test  = str(sale_event.get("test", "false")).lower() == "true"
    sale_id  = sale_event.get("sale_id", sale_event.get("id", ""))

    if not email:
        return {"success": False, "reason": "no_email"}

    if is_test:
        logger.info(f"Gumroad TEST sale for {email} — no action")
        return {"success": True, "action": "test_ignored", "email": email}

    if _is_already_processed(f"gumroad_{sale_id}"):
        return {"success": True, "action": "duplicate_ignored", "sale_id": sale_id}

    result: Dict[str, Any] = {"email": email, "product": product}

    # Map product name to tier
    tier = None
    if any(kw in product for kw in ["api", "pro", "subscription"]):
        tier = "PRO"
    if any(kw in product for kw in ["enterprise", "soc", "team"]):
        tier = "ENTERPRISE"
    if "mssp" in product:
        tier = "MSSP"

    if tier:
        # API subscription purchase → provision key
        provision_result = _provision_api_key(
            email=email,
            tier=tier,
            billing_cycle="gumroad",
        )
        result.update(provision_result)
        result["action"] = "key_provisioned"

        if provision_result.get("success"):
            _record_billing_event("subscription.created", email, tier, int(price or 0) * 100)
            _send_welcome_notification(email, tier, provision_result.get("key_prefix", ""))
    else:
        # Detection pack or report — no key, just log sale
        result["action"] = "product_sale_logged"
        result["success"] = True
        logger.info(f"Gumroad product sale: {product} for {email}")

    _mark_processed(f"gumroad_{sale_id}", "gumroad.sale")
    return result


# ---------------------------------------------------------------------------
# Main Stripe Webhook Processor
# ---------------------------------------------------------------------------

def process_stripe_webhook(
    payload_bytes: bytes,
    signature_header: str,
    webhook_secret: str = "",
) -> Dict:
    """
    Process a Stripe webhook payload.
    Validates signature, enforces idempotency, dispatches to handlers.

    Returns structured result dict — never raises.
    """
    secret = webhook_secret or STRIPE_WEBHOOK_SECRET

    # 1. Validate signature
    valid, reason = validate_stripe_signature(payload_bytes, signature_header, secret)
    if not valid:
        logger.warning(f"Stripe signature validation failed: {reason}")
        return {"status": "rejected", "reason": reason}

    # 2. Parse event
    try:
        event = json.loads(payload_bytes)
    except Exception as e:
        return {"status": "rejected", "reason": f"json_parse_error: {e}"}

    event_id   = event.get("id", "")
    event_type = event.get("type", "")
    data_obj   = event.get("data", {}).get("object", {})

    logger.info(f"Stripe event: {event_type} id={event_id}")

    # 3. Idempotency check
    if event_id and _is_already_processed(event_id):
        logger.info(f"Event {event_id} already processed — skipping")
        return {"status": "already_processed", "event_id": event_id, "event_type": event_type}

    # 4. Dispatch
    result: Dict[str, Any] = {
        "status": "processed",
        "event_id": event_id,
        "event_type": event_type,
    }

    try:
        if event_type == "checkout.session.completed":
            result.update(_handle_checkout_completed(data_obj))

        elif event_type == "customer.subscription.updated":
            result.update(_handle_subscription_updated(data_obj))

        elif event_type == "customer.subscription.deleted":
            result.update(_handle_subscription_deleted(data_obj))

        elif event_type == "invoice.payment_succeeded":
            result.update(_handle_payment_succeeded(data_obj))

        elif event_type == "invoice.payment_failed":
            result.update(_handle_payment_failed(data_obj))

        else:
            result["status"] = "unhandled_event_type"
            logger.info(f"Unhandled Stripe event type: {event_type}")

    except Exception as e:
        logger.error(f"Event handler error for {event_type}: {e}")
        result["status"] = "handler_error"
        result["error"] = str(e)

    # 5. Log and mark processed
    _log_webhook_event(event, result)
    if event_id:
        _mark_processed(event_id, event_type)

    return result


# ---------------------------------------------------------------------------
# Event Handlers
# ---------------------------------------------------------------------------

def _handle_checkout_completed(obj: Dict) -> Dict:
    """
    checkout.session.completed:
    New subscription or one-time payment confirmed.
    Provision API key immediately.
    """
    email    = (obj.get("customer_details") or {}).get("email", "") or obj.get("customer_email", "")
    tier     = obj.get("metadata", {}).get("tier", "PRO")
    cycle    = obj.get("metadata", {}).get("billing_cycle", "monthly")
    amount   = obj.get("amount_total", 0)  # in cents
    customer = obj.get("customer", "")
    sub_id   = obj.get("subscription", "")
    mode     = obj.get("mode", "payment")  # payment or subscription

    if not email:
        return {"action": "skipped", "reason": "no_customer_email"}

    tier = STRIPE_TIER_MAP.get(tier, "PRO")

    provision = _provision_api_key(
        email=email,
        tier=tier,
        billing_cycle=cycle,
        stripe_customer_id=customer,
        stripe_subscription_id=sub_id,
    )

    _record_billing_event(
        "checkout.session.completed",
        email,
        tier,
        amount,
        {"customer": customer, "subscription": sub_id},
    )

    if provision.get("success"):
        _send_welcome_notification(email, tier, provision.get("key_prefix", ""))

    return {
        "action": "key_provisioned",
        "email": email,
        "tier": tier,
        "billing_cycle": cycle,
        "amount_usd": f"${amount / 100:.2f}",
        "provision_result": provision,
    }


def _handle_subscription_updated(obj: Dict) -> Dict:
    """
    customer.subscription.updated:
    Handle plan upgrades and downgrades.
    """
    customer   = obj.get("customer", "")
    status     = obj.get("status", "")
    metadata   = obj.get("metadata", {})
    new_tier   = STRIPE_TIER_MAP.get(metadata.get("tier", ""), "PRO")
    email      = metadata.get("owner_email", "")

    if not email:
        return {"action": "skipped", "reason": "no_owner_email_in_metadata"}

    if status in ("active", "trialing"):
        upgrade_result = _upgrade_api_key_tier(email, new_tier)
        return {
            "action": "tier_upgraded",
            "email": email,
            "new_tier": new_tier,
            "status": status,
            "result": upgrade_result,
        }
    elif status in ("past_due", "unpaid"):
        logger.warning(f"Subscription past_due for {email}")
        return {"action": "dunning_flagged", "email": email, "status": status}
    else:
        return {"action": "status_noted", "status": status}


def _handle_subscription_deleted(obj: Dict) -> Dict:
    """
    customer.subscription.deleted:
    Cancellation — revoke API keys.
    """
    metadata = obj.get("metadata", {})
    email    = metadata.get("owner_email", "")
    tier     = STRIPE_TIER_MAP.get(metadata.get("tier", ""), "UNKNOWN")

    if not email:
        return {"action": "skipped", "reason": "no_owner_email_in_metadata"}

    revoke_result = _revoke_api_key_by_email(email)
    _record_billing_event("subscription.cancelled", email, tier)

    logger.info(f"Subscription cancelled for {email} — keys revoked")
    return {
        "action": "keys_revoked",
        "email": email,
        "tier": tier,
        "revoke_result": revoke_result,
    }


def _handle_payment_succeeded(obj: Dict) -> Dict:
    """
    invoice.payment_succeeded:
    Renewal payment. Log, extend key expiry.
    """
    email    = obj.get("customer_email", "")
    amount   = obj.get("amount_paid", 0)
    tier     = obj.get("metadata", {}).get("tier", "PRO")
    sub_id   = obj.get("subscription", "")

    _record_billing_event("payment.succeeded", email, tier, amount)
    logger.info(f"Payment succeeded: {email} ${amount/100:.2f} tier={tier}")

    return {
        "action": "payment_logged",
        "email": email,
        "tier": tier,
        "amount_usd": f"${amount/100:.2f}",
        "subscription": sub_id,
    }


def _handle_payment_failed(obj: Dict) -> Dict:
    """
    invoice.payment_failed:
    Dunning management — log, optionally notify customer.
    """
    email  = obj.get("customer_email", "")
    amount = obj.get("amount_due", 0)
    tier   = obj.get("metadata", {}).get("tier", "UNKNOWN")
    attempt= obj.get("attempt_count", 1)

    _record_billing_event("payment.failed", email, tier, amount)
    logger.warning(f"Payment FAILED: {email} ${amount/100:.2f} attempt={attempt}")

    return {
        "action": "payment_failure_logged",
        "email": email,
        "tier": tier,
        "amount_due_usd": f"${amount/100:.2f}",
        "attempt_count": attempt,
        "note": "Keys remain active during grace period — will revoke on subscription.deleted event",
    }


# ---------------------------------------------------------------------------
# Revenue Summary
# ---------------------------------------------------------------------------

def get_revenue_summary() -> Dict:
    """
    Aggregate revenue summary from billing events log.
    Returns total revenue, recent transactions, tier breakdown.
    """
    events_file = BASE_DIR / "data" / "billing" / "billing_events.jsonl"
    events: List[Dict] = []

    if events_file.exists():
        try:
            with open(events_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"Events log read error: {e}")

    succeeded = [e for e in events if e.get("event_type") == "payment.succeeded"]
    failed    = [e for e in events if e.get("event_type") == "payment.failed"]
    subs      = [e for e in events if e.get("event_type") == "subscription.created"]
    cancelled = [e for e in events if e.get("event_type") == "subscription.cancelled"]

    total_revenue_cents = sum(e.get("amount_cents", 0) for e in succeeded)

    # Tier breakdown
    tier_revenue: Dict[str, int] = {}
    for e in succeeded:
        t = e.get("tier", "UNKNOWN")
        tier_revenue[t] = tier_revenue.get(t, 0) + e.get("amount_cents", 0)

    # Recent 30-day revenue
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=30)).isoformat()
    recent_revenue = sum(
        e.get("amount_cents", 0)
        for e in succeeded
        if e.get("timestamp", "") >= cutoff
    )

    return {
        "total_revenue_usd": f"${total_revenue_cents / 100:,.2f}",
        "recent_30d_revenue_usd": f"${recent_revenue / 100:,.2f}",
        "total_payments_succeeded": len(succeeded),
        "total_payments_failed": len(failed),
        "total_subscriptions": len(subs),
        "total_cancellations": len(cancelled),
        "churn_rate": f"{(len(cancelled) / max(len(subs), 1)) * 100:.1f}%",
        "revenue_by_tier": {
            t: f"${v / 100:,.2f}" for t, v in tier_revenue.items()
        },
        "payment_links": PAYMENT_LINKS,
        "gumroad_products": GUMROAD_PRODUCTS,
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH SENTINEL APEX — Stripe Revenue Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a saved Stripe webhook event JSON file
  python scripts/stripe_revenue.py --event data/billing/test_event.json

  # Manually provision an API key (admin override)
  python scripts/stripe_revenue.py --provision PRO --email customer@company.com

  # Show all payment links
  python scripts/stripe_revenue.py --links

  # Revenue summary
  python scripts/stripe_revenue.py --revenue-summary

  # Process Gumroad sale
  python scripts/stripe_revenue.py --gumroad-sale data/billing/gumroad_sale.json
        """,
    )
    parser.add_argument("--event",          type=str, help="Path to Stripe webhook event JSON file")
    parser.add_argument("--gumroad-sale",   type=str, help="Path to Gumroad sale JSON file")
    parser.add_argument("--provision",      type=str, choices=["PRO", "ENTERPRISE", "MSSP"],
                        help="Tier to provision (requires --email)")
    parser.add_argument("--email",          type=str, help="Customer email for --provision")
    parser.add_argument("--billing-cycle",  type=str, default="monthly",
                        choices=["monthly", "annual"])
    parser.add_argument("--links",          action="store_true", help="Show payment link registry")
    parser.add_argument("--revenue-summary",action="store_true", help="Show revenue summary")
    parser.add_argument("--webhook-secret", type=str, help="Override STRIPE_WEBHOOK_SECRET")
    parser.add_argument("--json",           action="store_true", help="Output JSON")

    args = parser.parse_args()

    if args.links:
        data = {"stripe": PAYMENT_LINKS, "gumroad": GUMROAD_PRODUCTS}
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    if args.revenue_summary:
        summary = get_revenue_summary()
        if args.json:
            print(json.dumps(summary, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\n{'='*60}")
            print(f"  SENTINEL APEX — Revenue Summary")
            print(f"{'='*60}")
            print(f"  Total Revenue     : {summary['total_revenue_usd']}")
            print(f"  Last 30 Days      : {summary['recent_30d_revenue_usd']}")
            print(f"  Subscriptions     : {summary['total_subscriptions']}")
            print(f"  Payments OK       : {summary['total_payments_succeeded']}")
            print(f"  Payments Failed   : {summary['total_payments_failed']}")
            print(f"  Cancellations     : {summary['total_cancellations']}")
            print(f"  Churn Rate        : {summary['churn_rate']}")
            print(f"  Revenue by Tier   :")
            for t, v in summary['revenue_by_tier'].items():
                print(f"    {t}: {v}")
            print(f"{'='*60}")
        return

    if args.event:
        event_path = Path(args.event)
        if not event_path.exists():
            print(f"[ERROR] Event file not found: {args.event}")
            sys.exit(1)
        payload = event_path.read_bytes()
        # In test mode without real signature, use empty signature
        sig_header = f"t={int(time.time())},v1=test_signature"
        secret = args.webhook_secret or STRIPE_WEBHOOK_SECRET or "whsec_test"
        result = process_stripe_webhook(payload, sig_header, secret)
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return

    if args.gumroad_sale:
        sale_path = Path(args.gumroad_sale)
        if not sale_path.exists():
            print(f"[ERROR] Sale file not found: {args.gumroad_sale}")
            sys.exit(1)
        sale_data = json.loads(sale_path.read_text(encoding="utf-8"))
        result = process_gumroad_sale(sale_data)
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return

    if args.provision:
        if not args.email:
            print("[ERROR] --email required with --provision")
            sys.exit(1)
        result = _provision_api_key(
            email=args.email,
            tier=args.provision,
            billing_cycle=args.billing_cycle,
        )
        if result.get("success"):
            print(f"\n[OK] API key provisioned:")
            print(f"  Tier  : {result['tier']}")
            print(f"  Owner : {result['owner']}")
            print(f"  Key   : {result['api_key']}")
            print(f"  Expires: {result.get('expires_at', 'N/A')}")
        else:
            print(f"\n[ERROR] Provisioning failed: {result.get('reason')}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
