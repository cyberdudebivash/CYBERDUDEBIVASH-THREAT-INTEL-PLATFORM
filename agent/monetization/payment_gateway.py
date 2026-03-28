"""
CYBERDUDEBIVASH® SENTINEL APEX — Payment Gateway v1.0
======================================================
Unified Stripe + Razorpay payment gateway.

STRIPE (primary — international):
  - Checkout sessions for subscription creation
  - Webhook event handling (subscription lifecycle)
  - Automatic API key provisioning on payment success

RAZORPAY (India/APAC):
  - Subscription creation for INR billing
  - Webhook verification + event handling
  - API key provisioning on activation

ACTIVATION:
  Set in GitHub repo secrets:
    STRIPE_SECRET_KEY      = sk_live_...
    STRIPE_WEBHOOK_SECRET  = whsec_...
    RAZORPAY_KEY_ID        = rzp_live_...
    RAZORPAY_KEY_SECRET    = <secret>

PRICING (USD):
  Free:       $0/mo
  Pro:        $49/mo
  Enterprise: $499/mo
  MSSP:       $1,999/mo

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations
import hashlib, hmac, json, logging, os, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("CDB-PAYMENT-GW")

# ── Stripe config ─────────────────────────────────────────────────────────────
STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRO_PRICE_ID   = os.environ.get("CDB_STRIPE_PRO_PRICE_ID", "")
STRIPE_ENT_PRICE_ID   = os.environ.get("CDB_STRIPE_ENT_PRICE_ID", "")
STRIPE_MSP_PRICE_ID   = os.environ.get("CDB_STRIPE_MSP_PRICE_ID", "")

# ── Razorpay config ───────────────────────────────────────────────────────────
RAZORPAY_KEY_ID     = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")

# ── Pricing ───────────────────────────────────────────────────────────────────
PRICES_USD = {"free": 0, "pro": 49, "enterprise": 499, "mssp": 1999}
PRICES_INR = {"free": 0, "pro": 4099, "enterprise": 41599, "mssp": 166599}

TIER_FROM_STRIPE_PRICE = {
    STRIPE_PRO_PRICE_ID: "pro",
    STRIPE_ENT_PRICE_ID: "enterprise",
    STRIPE_MSP_PRICE_ID: "mssp",
}

BASE_DIR      = Path(__file__).resolve().parent.parent.parent
EVENTS_FILE   = BASE_DIR / "data" / "monetization" / "payment_events.json"
DASHBOARD_URL = "https://intel.cyberdudebivash.com"
SUCCESS_URL   = f"{DASHBOARD_URL}?upgrade=success"
CANCEL_URL    = f"{DASHBOARD_URL}?upgrade=cancelled"


def _append_event(event: Dict) -> None:
    """Persist payment event for audit trail."""
    try:
        EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        events = []
        if EVENTS_FILE.exists():
            with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
        events.append({**event, "recorded_at": datetime.now(timezone.utc).isoformat()})
        events = events[-500:]   # keep last 500 events
        with open(EVENTS_FILE, "wb") as f:
            f.write(json.dumps(events, indent=2, default=str).encode())
    except Exception as e:
        logger.warning(f"[PAYMENT-GW] Event append failed (non-fatal): {e}")


# ── STRIPE ─────────────────────────────────────────────────────────────────────

def create_stripe_checkout_session(tier: str, customer_email: str,
                                   customer_name: str = "") -> Dict:
    """
    Create Stripe checkout session for subscription.
    Returns {"url": checkout_url, "session_id": sid} or {"error": ...}
    """
    if not STRIPE_SECRET_KEY:
        return {"error": "Stripe not configured — set STRIPE_SECRET_KEY"}
    price_map = {"pro": STRIPE_PRO_PRICE_ID,
                 "enterprise": STRIPE_ENT_PRICE_ID,
                 "mssp": STRIPE_MSP_PRICE_ID}
    price_id = price_map.get(tier.lower())
    if not price_id:
        return {"error": f"No Stripe price ID for tier: {tier}"}
    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=customer_email or None,
            metadata={
                "tier": tier, "customer_name": customer_name,
                "platform": "CYBERDUDEBIVASH-SENTINEL-APEX",
            },
            success_url=SUCCESS_URL + "&session_id={CHECKOUT_SESSION_ID}",
            cancel_url=CANCEL_URL,
        )
        logger.info(f"[PAYMENT-GW] Stripe checkout created: {tier} for {customer_email}")
        return {"url": session.url, "session_id": session.id, "provider": "stripe"}
    except Exception as e:
        logger.warning(f"[PAYMENT-GW] Stripe checkout error: {e}")
        return {"error": str(e)[:200]}

def handle_stripe_webhook(payload: bytes, sig_header: str) -> Tuple[bool, str]:
    """
    Verify and process Stripe webhook event.
    On success: provisions API key, logs event.
    Returns (success: bool, message: str)
    """
    if not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        return False, "Stripe not configured"
    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return False, f"Signature verification failed: {e}"

    etype = event.get("type", "")
    data  = event.get("data", {}).get("object", {})

    try:
        if etype in ("checkout.session.completed", "customer.subscription.created"):
            meta  = data.get("metadata", {})
            tier  = meta.get("tier", "pro")
            email = data.get("customer_email") or data.get("customer_details", {}).get("email","")
            name  = meta.get("customer_name", email)
            sub_id= data.get("subscription") or data.get("id","")
            if email and tier in ("pro","enterprise","mssp"):
                _provision_subscriber(tier=tier, name=name, email=email,
                                      stripe_sub_id=sub_id, provider="stripe")

        elif etype in ("customer.subscription.deleted", "invoice.payment_failed"):
            sub_id = data.get("id","")
            if sub_id:
                _revoke_by_stripe_sub_id(sub_id, reason=etype)

        _append_event({"type": etype, "provider": "stripe",
                       "data_id": data.get("id","")})
        return True, f"Event {etype} processed"
    except Exception as e:
        logger.error(f"[PAYMENT-GW] Stripe webhook processing error: {e}")
        return False, str(e)[:200]


# ── RAZORPAY ───────────────────────────────────────────────────────────────────

def create_razorpay_subscription(tier: str, customer_email: str,
                                  customer_name: str = "") -> Dict:
    """
    Create Razorpay subscription link for INR billing.
    Returns {"short_url": ..., "subscription_id": ...} or {"error": ...}
    """
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        return {"error": "Razorpay not configured — set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET"}
    price_inr = PRICES_INR.get(tier.lower(), 0)
    if price_inr == 0:
        return {"error": "Free tier requires no payment"}
    try:
        import razorpay
        client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        # Create a payment link (simpler than full subscription API for launch)
        link = client.payment_link.create({
            "amount":       price_inr * 100,   # paise
            "currency":     "INR",
            "description":  f"CYBERDUDEBIVASH Sentinel APEX — {tier.title()} Plan",
            "customer": {
                "name":  customer_name or customer_email,
                "email": customer_email,
            },
            "notify":       {"sms": False, "email": True},
            "reminder_enable": True,
            "callback_url": SUCCESS_URL,
            "callback_method": "get",
            "notes": {
                "tier":     tier,
                "platform": "CYBERDUDEBIVASH-SENTINEL-APEX",
            },
        })
        logger.info(f"[PAYMENT-GW] Razorpay link created: {tier} for {customer_email}")
        return {"url": link.get("short_url"), "link_id": link.get("id"),
                "amount_inr": price_inr, "provider": "razorpay"}
    except Exception as e:
        logger.warning(f"[PAYMENT-GW] Razorpay error: {e}")
        return {"error": str(e)[:200]}


def handle_razorpay_webhook(payload: bytes, sig_header: str) -> Tuple[bool, str]:
    """Verify and process Razorpay webhook. Provisions API key on payment."""
    if not RAZORPAY_KEY_SECRET:
        return False, "Razorpay not configured"
    try:
        expected = hmac.new(
            RAZORPAY_KEY_SECRET.encode(), payload, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, sig_header):
            return False, "Signature mismatch"
        event = json.loads(payload)
        etype = event.get("event","")
        if etype in ("payment.captured", "subscription.activated"):
            entity = event.get("payload", {}).get("payment", {}).get("entity", {})
            notes  = entity.get("notes", {})
            tier   = notes.get("tier", "pro")
            email  = entity.get("email","")
            name   = entity.get("contact","")
            sub_id = entity.get("id","")
            if email and tier in ("pro","enterprise","mssp"):
                _provision_subscriber(tier=tier, name=name or email,
                                      email=email, stripe_sub_id=sub_id,
                                      provider="razorpay")
        _append_event({"type": etype, "provider": "razorpay"})
        return True, f"Event {etype} processed"
    except Exception as e:
        logger.error(f"[PAYMENT-GW] Razorpay webhook error: {e}")
        return False, str(e)[:200]

# ── Provisioning helpers ──────────────────────────────────────────────────────

def _provision_subscriber(tier: str, name: str, email: str,
                           stripe_sub_id: str, provider: str) -> str:
    """Generate API key + send welcome email on successful payment."""
    from agent.monetization.api_key_manager import generate_key
    api_key = generate_key(tier=tier, name=name, email=email,
                            stripe_sub_id=stripe_sub_id,
                            notes=f"auto-provisioned via {provider}")
    logger.info(f"[PAYMENT-GW] Provisioned {tier} key for {email} via {provider}")
    _send_welcome_email(email=email, name=name, tier=tier, api_key=api_key)
    _append_event({"type": "key_provisioned", "tier": tier,
                   "email": email, "provider": provider})
    return api_key


def _revoke_by_stripe_sub_id(sub_id: str, reason: str) -> None:
    """Revoke all keys associated with a Stripe subscription ID."""
    from agent.monetization.api_key_manager import _load, revoke_key
    keys = _load()
    for k, v in keys.items():
        if v.get("stripe_sub_id") == sub_id and v.get("status") == "active":
            revoke_key(k, reason=reason)
            logger.info(f"[PAYMENT-GW] Revoked key for sub {sub_id} ({reason})")


def _send_welcome_email(email: str, name: str, tier: str, api_key: str) -> None:
    """Send API key delivery email. Non-blocking, fails silently."""
    try:
        import requests
        sendgrid_key  = os.environ.get("SENDGRID_API_KEY","")
        sender        = os.environ.get("SENDER_EMAIL","bivash@cyberdudebivash.com")
        if not sendgrid_key or not email:
            return
        price_map = {"pro": 49, "enterprise": 499, "mssp": 1999}
        limit_map = {
            "free": "10 advisories/req, 60 req/hr",
            "pro": "100 advisories/req, 1000 req/hr",
            "enterprise": "500 advisories/req, 10000 req/hr",
            "mssp": "Unlimited",
        }
        api_base  = "https://cyberdudebivash-threat-intel-platform-production.up.railway.app"
        price_str = "$" + str(price_map.get(tier, 0)) + "/mo"
        body = (
            "Welcome to CYBERDUDEBIVASH\u00ae Sentinel APEX \u2014 " + tier.title() + " Plan!\n\n"
            "Your API Key: " + api_key + "\n\n"
            "Quick Start:\n"
            "  curl -H \"X-API-Key: " + api_key + "\" \\\n"
            "       " + api_base + "/api/v1/intel/latest\n\n"
            "Dashboard: https://intel.cyberdudebivash.com\n"
            "Docs: " + api_base + "/docs\n\n"
            "Plan: " + tier.title() + " | " + price_str + "\n"
            "Limits: " + limit_map.get(tier, "see docs") + "\n\n"
            "Best regards,\nBivash | CyberDudeBivash Pvt. Ltd.\n"
        )
        requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json={"personalizations": [{"to": [{"email": email, "name": name}]}],
                  "from": {"email": sender, "name": "CyberDudeBivash Sentinel APEX"},
                  "subject": f"Your Sentinel APEX {tier.title()} API Key",
                  "content": [{"type": "text/plain", "value": body}]},
            headers={"Authorization": f"Bearer {sendgrid_key}",
                     "Content-Type": "application/json"},
            timeout=10,
        )
        logger.info(f"[PAYMENT-GW] Welcome email sent to {email}")
    except Exception as e:
        logger.debug(f"[PAYMENT-GW] Email send failed (non-fatal): {e}")
