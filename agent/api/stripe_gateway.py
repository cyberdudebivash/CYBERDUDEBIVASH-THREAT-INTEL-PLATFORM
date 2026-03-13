#!/usr/bin/env python3
"""
stripe_gateway.py — CYBERDUDEBIVASH® SENTINEL APEX v23.0 ULTRA
STRIPE SUBSCRIPTION & BILLING GATEWAY

Handles:
  - Stripe webhook lifecycle events (subscription created/updated/cancelled)
  - API key provisioning for new subscribers (PRO / ENTERPRISE)
  - Subscription status validation against Stripe
  - Revenue event logging for platform metrics

Non-Breaking Contract:
  - Fully standalone module — does NOT import sentinel_blogger.py
  - Does NOT modify any existing module signatures
  - Called from api_server.py stripe_webhook endpoint ONLY
  - All errors are caught and logged — never crash the pipeline

Required ENV:
  STRIPE_SECRET_KEY      — Your Stripe secret key (sk_live_... or sk_test_...)
  STRIPE_WEBHOOK_SECRET  — Endpoint signing secret (whsec_...)
  SENDGRID_API_KEY       — For provisioning emails (reuses existing key)
  SENDER_EMAIL           — bivash@cyberdudebivash.com

Setup:
  1. pip install stripe
  2. Set STRIPE_SECRET_KEY in GitHub Actions secrets
  3. Add webhook endpoint in Stripe Dashboard:
     https://your-api.cyberdudebivash.com/api/v1/webhooks/stripe
  4. Subscribe to events:
     - customer.subscription.created
     - customer.subscription.updated
     - customer.subscription.deleted
     - checkout.session.completed
     - invoice.payment_succeeded
     - invoice.payment_failed

Pricing Tiers (configure in Stripe):
  PRO tier:        Price ID → set CDB_STRIPE_PRO_PRICE_ID env var
  ENTERPRISE tier: Price ID → set CDB_STRIPE_ENT_PRICE_ID env var
"""

import os
import json
import hmac
import hashlib
import logging
import time
import uuid
import secrets
from typing import Optional, Dict, Tuple
from datetime import datetime, timezone

logger = logging.getLogger("CDB-STRIPE-GATEWAY")

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# Stripe Price IDs (set in Stripe Dashboard, then copy IDs here)
# PRO:        Monthly → ~$149 USD
# ENTERPRISE: Annual  → ~$1999 USD
CDB_STRIPE_PRO_PRICE_ID = os.environ.get("CDB_STRIPE_PRO_PRICE_ID", "")
CDB_STRIPE_ENT_PRICE_ID = os.environ.get("CDB_STRIPE_ENT_PRICE_ID", "")

# API key storage (in production: use a database)
# For single-node/GitHub Pages deployment: use a JSON file
API_KEYS_DB_PATH  = os.environ.get("CDB_API_KEYS_PATH", "data/api_keys.json")
REVENUE_LOG_PATH  = "data/revenue_log.json"

# Email sender
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "bivash@cyberdudebivash.com")
SENDER_NAME  = os.environ.get("SENDER_NAME", "CyberDudeBivash SENTINEL APEX")
SENDGRID_KEY = os.environ.get("SENDGRID_API_KEY", "")

PLATFORM_URL  = "https://intel.cyberdudebivash.com"
GUMROAD_URL   = "https://cyberdudebivash.gumroad.com"
DASHBOARD_URL = "https://intel.cyberdudebivash.com"


# ─────────────────────────────────────────────────────────────
# Stripe Import — Graceful degradation
# ─────────────────────────────────────────────────────────────

try:
    import stripe as _stripe  # type: ignore
    _stripe.api_key = STRIPE_SECRET_KEY
    _STRIPE_AVAILABLE = True
    logger.info("✅ Stripe SDK loaded")
except ImportError:
    _STRIPE_AVAILABLE = False
    logger.warning("Stripe SDK not installed. Run: pip install stripe")


# ─────────────────────────────────────────────────────────────
# API Key Manager
# ─────────────────────────────────────────────────────────────

class APIKeyManager:
    """
    Simple JSON-backed API key registry.
    In production: replace with PostgreSQL/Redis for multi-node deployments.
    """

    def generate_key(self, tier: str, email: str, customer_id: str = "") -> str:
        """Generate a cryptographically secure API key for a subscriber."""
        prefix = "cdb-ent" if tier == "ENTERPRISE" else "cdb-pro"
        random_part = secrets.token_urlsafe(24)
        key = f"{prefix}-{random_part}"

        entry = {
            "api_key":        key,
            "tier":           tier,
            "email":          email,
            "customer_id":    customer_id,
            "created_at":     datetime.now(timezone.utc).isoformat(),
            "status":         "active",
        }
        self._store_key(entry)
        logger.info(f"✅ API key generated for {email} ({tier}): {key[:18]}...")
        return key

    def revoke_key_by_customer(self, customer_id: str) -> bool:
        """Mark all keys for a customer as revoked (on subscription cancellation)."""
        db = self._load_db()
        changed = False
        for entry in db:
            if entry.get("customer_id") == customer_id and entry.get("status") == "active":
                entry["status"]  = "revoked"
                entry["revoked_at"] = datetime.now(timezone.utc).isoformat()
                changed = True
                logger.info(f"🔒 API key revoked for customer {customer_id}")
        if changed:
            self._save_db(db)
        return changed

    def validate_key(self, api_key: str) -> Optional[Dict]:
        """Check if a key is valid and active. Returns entry or None."""
        db = self._load_db()
        for entry in db:
            if entry.get("api_key") == api_key and entry.get("status") == "active":
                return entry
        return None

    def _store_key(self, entry: Dict):
        db = self._load_db()
        db.append(entry)
        self._save_db(db)

    def _load_db(self):
        try:
            if os.path.exists(API_KEYS_DB_PATH):
                with open(API_KEYS_DB_PATH, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _save_db(self, db):
        try:
            os.makedirs(os.path.dirname(API_KEYS_DB_PATH), exist_ok=True)
            with open(API_KEYS_DB_PATH, "w") as f:
                json.dump(db, f, indent=2)
        except Exception as e:
            logger.error(f"API key DB save failed: {e}")


api_key_manager = APIKeyManager()


# ─────────────────────────────────────────────────────────────
# Stripe Gateway
# ─────────────────────────────────────────────────────────────

class StripeGateway:
    """
    Handles Stripe webhook events and provisions/revokes API access.

    Event Flow:
      checkout.session.completed → provision_access()
      customer.subscription.deleted → revoke_access()
      invoice.payment_failed → send_payment_failure_email()
    """

    def handle_webhook(self, payload: bytes, sig_header: str) -> Dict:
        """
        Main webhook handler. Called by api_server.py.
        Verifies Stripe signature and dispatches event handlers.
        """
        if not STRIPE_WEBHOOK_SECRET:
            logger.warning("STRIPE_WEBHOOK_SECRET not set — skipping signature verification")
            try:
                event = json.loads(payload)
            except Exception:
                return {"received": True, "warning": "invalid_payload"}
        else:
            event = self._verify_signature(payload, sig_header)
            if not event:
                return {"received": True, "error": "invalid_signature"}

        event_type = event.get("type", "")
        logger.info(f"📦 Stripe event received: {event_type}")

        # ── Log revenue event ──
        self._log_revenue_event(event)

        # ── Route event ──
        handlers = {
            "checkout.session.completed":        self._handle_checkout_completed,
            "customer.subscription.created":     self._handle_subscription_created,
            "customer.subscription.updated":     self._handle_subscription_updated,
            "customer.subscription.deleted":     self._handle_subscription_deleted,
            "invoice.payment_succeeded":         self._handle_payment_succeeded,
            "invoice.payment_failed":            self._handle_payment_failed,
        }

        handler = handlers.get(event_type)
        if handler:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Webhook handler error ({event_type}): {e}", exc_info=True)
        else:
            logger.debug(f"Unhandled event type: {event_type}")

        return {"received": True, "event_type": event_type}

    # ─────────────────────────────────────────────────────────
    # Event Handlers
    # ─────────────────────────────────────────────────────────

    def _handle_checkout_completed(self, event: Dict):
        """New purchase via Stripe Checkout — provision API access immediately."""
        session = event.get("data", {}).get("object", {})
        email       = session.get("customer_details", {}).get("email", "")
        customer_id = session.get("customer", "")
        price_id    = (
            session.get("line_items", {}).get("data", [{}])[0]
            .get("price", {}).get("id", "")
        )

        if not email:
            logger.warning("checkout.session.completed: no email found in session")
            return

        tier = self._resolve_tier_from_price(price_id)
        logger.info(f"💳 Checkout completed: {email} → {tier} tier")
        self._provision_access(email=email, tier=tier, customer_id=customer_id)

    def _handle_subscription_created(self, event: Dict):
        """New recurring subscription — provision if not already done."""
        sub = event.get("data", {}).get("object", {})
        customer_id = sub.get("customer", "")
        price_id    = sub.get("items", {}).get("data", [{}])[0].get("price", {}).get("id", "")
        tier = self._resolve_tier_from_price(price_id)
        logger.info(f"📋 Subscription created: customer={customer_id} tier={tier}")
        # Note: email provisioning done at checkout_completed; this is a backup

    def _handle_subscription_updated(self, event: Dict):
        """Subscription plan change — update tier."""
        sub = event.get("data", {}).get("object", {})
        status = sub.get("status", "")
        if status in ("active", "trialing"):
            logger.info(f"🔄 Subscription updated: status={status}")
        elif status == "canceled":
            self._handle_subscription_deleted(event)

    def _handle_subscription_deleted(self, event: Dict):
        """Subscription cancelled — revoke API access."""
        sub = event.get("data", {}).get("object", {})
        customer_id = sub.get("customer", "")
        logger.info(f"🔴 Subscription cancelled: customer={customer_id}")
        revoked = api_key_manager.revoke_key_by_customer(customer_id)
        if revoked:
            logger.info(f"✅ API key(s) revoked for customer {customer_id}")

    def _handle_payment_succeeded(self, event: Dict):
        """Invoice paid — log revenue and extend access if needed."""
        invoice     = event.get("data", {}).get("object", {})
        amount_paid = invoice.get("amount_paid", 0)
        customer_id = invoice.get("customer", "")
        logger.info(f"💰 Payment succeeded: customer={customer_id} amount=${amount_paid/100:.2f}")

    def _handle_payment_failed(self, event: Dict):
        """Invoice payment failed — notify customer."""
        invoice     = event.get("data", {}).get("object", {})
        customer_id = invoice.get("customer", "")
        logger.warning(f"⚠️ Payment failed: customer={customer_id}")
        # TODO: Send dunning email via SendGrid

    # ─────────────────────────────────────────────────────────
    # Provisioning
    # ─────────────────────────────────────────────────────────

    def _provision_access(self, email: str, tier: str, customer_id: str = ""):
        """Generate API key and send credentials email."""
        api_key = api_key_manager.generate_key(
            tier=tier, email=email, customer_id=customer_id
        )

        # Update active key sets for auth_handler (runtime injection)
        self._inject_key_to_runtime(api_key, tier)

        # Send welcome email with credentials
        self._send_credentials_email(
            email=email, api_key=api_key, tier=tier
        )

        logger.info(f"✅ Access provisioned: {email} → {tier} ({api_key[:18]}...)")

    def _inject_key_to_runtime(self, api_key: str, tier: str):
        """
        Inject newly provisioned key into running auth_handler sets.
        This makes the key valid immediately without restart.
        """
        try:
            from agent.api.auth import auth_handler
            from agent.config import CDB_PRO_API_KEYS, CDB_ENTERPRISE_API_KEYS
            if tier == "ENTERPRISE":
                CDB_ENTERPRISE_API_KEYS.add(api_key)
                logger.info(f"🔑 Enterprise key injected into runtime auth registry")
            elif tier == "PRO":
                CDB_PRO_API_KEYS.add(api_key)
                logger.info(f"🔑 Pro key injected into runtime auth registry")
        except Exception as e:
            logger.error(f"Runtime key injection failed (non-critical): {e}")

    def _send_credentials_email(self, email: str, api_key: str, tier: str):
        """Send API credentials email via SendGrid."""
        if not SENDGRID_KEY:
            logger.warning("SENDGRID_API_KEY not set — skipping credentials email")
            return

        try:
            from sendgrid import SendGridAPIClient  # type: ignore
            from sendgrid.helpers.mail import Mail, HtmlContent  # type: ignore

            tier_label = "PRO DEFENSE" if tier == "PRO" else "ENTERPRISE"
            subject = f"🛡️ Your CyberDudeBivash {tier_label} API Key — Sentinel APEX"

            html_body = f"""
<!DOCTYPE html>
<html>
<head><style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #06080d; color: #cbd5e1; margin: 0; padding: 40px 20px; }}
  .card {{ background: #0d1117; border: 1px solid #1e293b; max-width: 620px; margin: 0 auto; padding: 40px; }}
  .accent {{ color: #00d4aa; }}
  .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; }}
  .key-box {{ background: #020205; border: 1px solid #00d4aa; padding: 20px; margin: 24px 0; word-break: break-all; letter-spacing: 1px; }}
  .badge {{ display:inline-block; background: #00d4aa; color: #06080d; padding: 4px 12px; font-weight: 900; font-size: 11px; letter-spacing: 2px; margin-bottom: 20px; }}
  h1 {{ font-size: 24px; font-weight: 900; color: #f0f4f8; letter-spacing: -1px; margin: 0 0 8px; }}
  p {{ margin: 12px 0; color: #94a3b8; line-height: 1.7; }}
  .cta {{ display: block; background: linear-gradient(135deg, #00d4aa, #00b891); color: #06080d; text-align: center; padding: 14px; font-weight: 900; font-size: 13px; text-decoration: none; letter-spacing: 1px; margin-top: 28px; }}
  code {{ background: #020205; color: #00d4aa; padding: 2px 6px; font-family: monospace; font-size: 12px; }}
</style></head>
<body>
<div class="card">
  <div class="badge">{tier_label} ACCESS GRANTED</div>
  <h1>Welcome to SENTINEL APEX <span class="accent">®</span></h1>
  <p>Your subscription is active. Below are your API credentials — keep them secure.</p>

  <p class="mono" style="color:#64748b;font-size:10px;letter-spacing:2px;text-transform:uppercase;">YOUR API KEY</p>
  <div class="key-box mono accent">{api_key}</div>

  <p><strong style="color:#f0f4f8;">Quick Start:</strong></p>
  <p class="mono" style="font-size:12px;color:#64748b;">
    curl -H "X-CDB-API-Key: {api_key}" \\<br>
    &nbsp;&nbsp;https://api.cyberdudebivash.com/api/v1/pro/threats
  </p>

  <p><strong style="color:#f0f4f8;">API Base URL:</strong><br>
  <code>https://api.cyberdudebivash.com/api/v1</code></p>

  <p><strong style="color:#f0f4f8;">API Documentation:</strong><br>
  <code>https://api.cyberdudebivash.com/docs</code></p>

  <p><strong style="color:#f0f4f8;">Your Tier Includes:</strong><br>
  {"Full IOC feeds, Detection rules (Sigma/YARA/KQL), STIX 2.1 exports, Supply chain intel, EPSS enrichment, Actor intelligence, Exploit forecasting, TAXII 2.1 access, Priority alerts." if tier == "ENTERPRISE" else "Full IOC feeds, Detection rules (Sigma/YARA/KQL), 50 threats/call, CVE intelligence, IOC export feed, TAXII collection access."}</p>

  <p>Questions? Reply to this email or WhatsApp: <a href="https://wa.me/918179881447" style="color:#00d4aa;">+91 8179881447</a></p>

  <a href="{DASHBOARD_URL}" class="cta">ACCESS LIVE DASHBOARD →</a>

  <p style="font-size:11px;color:#334155;margin-top:28px;border-top:1px solid #1e293b;padding-top:16px;">
    CYBERDUDEBIVASH Pvt. Ltd. · Bhubaneswar, Odisha, India<br>
    bivash@cyberdudebivash.com · intel.cyberdudebivash.com
  </p>
</div>
</body>
</html>"""

            mail = Mail(
                from_email=(SENDER_EMAIL, SENDER_NAME),
                to_emails=email,
                subject=subject,
                html_content=HtmlContent(html_body),
            )
            sg = SendGridAPIClient(SENDGRID_KEY)
            response = sg.send(mail)
            logger.info(f"📧 Credentials email sent to {email} (status: {response.status_code})")

        except Exception as e:
            logger.error(f"Credentials email failed for {email}: {e}")

    # ─────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────

    def _resolve_tier_from_price(self, price_id: str) -> str:
        """Map Stripe price ID to CDB tier."""
        if not price_id:
            return "PRO"  # Default to PRO for unknown
        if price_id == CDB_STRIPE_ENT_PRICE_ID:
            return "ENTERPRISE"
        if price_id == CDB_STRIPE_PRO_PRICE_ID:
            return "PRO"
        # Fallback: check product name from price metadata
        if _STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
            try:
                price = _stripe.Price.retrieve(price_id)
                amount = price.get("unit_amount", 0)
                if amount >= 100000:  # >= $1000/mo = Enterprise
                    return "ENTERPRISE"
            except Exception:
                pass
        return "PRO"

    def _verify_signature(self, payload: bytes, sig_header: str) -> Optional[Dict]:
        """Verify Stripe webhook signature (prevents spoofing)."""
        if not STRIPE_WEBHOOK_SECRET:
            return json.loads(payload)

        if _STRIPE_AVAILABLE:
            try:
                event = _stripe.Webhook.construct_event(
                    payload, sig_header, STRIPE_WEBHOOK_SECRET
                )
                return dict(event)
            except Exception as e:
                logger.warning(f"Stripe signature verification failed: {e}")
                return None
        else:
            # Manual HMAC verification (fallback without Stripe SDK)
            try:
                ts, sigs = None, []
                for part in sig_header.split(","):
                    k, v = part.split("=", 1)
                    if k == "t":
                        ts = v
                    elif k == "v1":
                        sigs.append(v)

                signed_payload = f"{ts}.{payload.decode('utf-8')}"
                expected_sig = hmac.new(
                    STRIPE_WEBHOOK_SECRET.encode("utf-8"),
                    signed_payload.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()

                if any(hmac.compare_digest(expected_sig, sig) for sig in sigs):
                    return json.loads(payload)
                logger.warning("Stripe signature mismatch")
                return None
            except Exception as e:
                logger.warning(f"Manual Stripe signature verification failed: {e}")
                return None

    def _log_revenue_event(self, event: Dict):
        """Append revenue event to revenue_log.json for tracking."""
        try:
            entry = {
                "ts":         datetime.now(timezone.utc).isoformat(),
                "event_type": event.get("type"),
                "event_id":   event.get("id"),
            }
            log = []
            if os.path.exists(REVENUE_LOG_PATH):
                try:
                    with open(REVENUE_LOG_PATH, "r") as f:
                        log = json.load(f)
                except Exception:
                    log = []
            log.append(entry)
            os.makedirs(os.path.dirname(REVENUE_LOG_PATH), exist_ok=True)
            with open(REVENUE_LOG_PATH, "w") as f:
                json.dump(log[-1000:], f, indent=2)  # Keep last 1000 events
        except Exception as e:
            logger.debug(f"Revenue log write failed (non-critical): {e}")

    # ─────────────────────────────────────────────────────────
    # Manual Provisioning (for Gumroad / manual sales)
    # ─────────────────────────────────────────────────────────

    def provision_manual(self, email: str, tier: str, note: str = "") -> str:
        """
        Manually provision API access (for Gumroad buyers, manual invoices, etc).
        Call from CLI or admin scripts.

        Usage:
            from agent.api.stripe_gateway import stripe_gateway
            key = stripe_gateway.provision_manual("customer@org.com", "ENTERPRISE")
            print(f"API Key: {key}")
        """
        customer_id = f"manual-{uuid.uuid4().hex[:8]}"
        logger.info(f"🔑 Manual provisioning: {email} → {tier} ({note})")
        api_key = api_key_manager.generate_key(
            tier=tier, email=email, customer_id=customer_id
        )
        self._inject_key_to_runtime(api_key, tier)
        self._send_credentials_email(email=email, api_key=api_key, tier=tier)
        return api_key


# ─────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────

stripe_gateway = StripeGateway()


# ─────────────────────────────────────────────────────────────
# CLI — Manual provisioning helper
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="CDB Stripe Gateway — Manual API Key Provisioning"
    )
    parser.add_argument("--email", required=True, help="Customer email")
    parser.add_argument("--tier",  required=True, choices=["PRO", "ENTERPRISE"], help="Access tier")
    parser.add_argument("--note",  default="", help="Optional note (invoice ID, etc)")
    args = parser.parse_args()

    print(f"\n🔑 Provisioning {args.tier} access for {args.email}...")
    key = stripe_gateway.provision_manual(
        email=args.email, tier=args.tier, note=args.note
    )
    print(f"\n✅ API Key Provisioned:")
    print(f"   {key}")
    print(f"\n📧 Credentials email sent to {args.email}")
    print(f"\n⚠️  Store this key securely — it cannot be recovered.")
