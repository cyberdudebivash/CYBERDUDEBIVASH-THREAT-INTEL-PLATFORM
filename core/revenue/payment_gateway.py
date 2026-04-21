#!/usr/bin/env python3
"""
core/revenue/payment_gateway.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0 -- ENTERPRISE PAYMENT GATEWAY
=======================================================================
Dual-provider payment processing: Razorpay (India) + Stripe (Global)

Products:
  - API Key (Monthly):   $49/mo    -- Programmatic access to intel API
  - Intel Report Basic:  $49       -- Single threat intelligence report
  - Intel Report Full:   $99       -- Full enterprise tactical dossier
  - PRO Subscription:    $49/mo    -- 5,000 API calls/day + IOC access
  - Enterprise Annual:   $2,999/yr -- Unlimited + STIX + AI + SLA

Billing Tiers:
  FREE:       100 calls/day  |  No IOCs  |  No AI
  PRO:        5,000/day      |  IOCs     |  Partial AI  |  $49/mo
  ENTERPRISE: Unlimited      |  Full     |  Full AI     |  $299/mo

Webhook validation:
  - Stripe:    HMAC-SHA256 signature verification
  - Razorpay:  HMAC-SHA256 signature verification

Usage tracking:
  - Per API key usage counters
  - Tier enforcement at request time
  - Overage detection + upgrade prompts

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib import request as _urllib_request
from urllib.error import HTTPError

logger = logging.getLogger("CDB-PAYMENT-GATEWAY")

# ─── Environment configuration ───────────────────────────────────────────────

_STRIPE_SECRET_KEY          = os.environ.get("STRIPE_SECRET_KEY", "")
_STRIPE_WEBHOOK_SECRET      = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
_STRIPE_PRO_PRICE_ID        = os.environ.get("STRIPE_PRO_PRICE_ID", "price_pro_monthly")
_STRIPE_ENT_PRICE_ID        = os.environ.get("STRIPE_ENT_PRICE_ID", "price_enterprise_monthly")
_RAZORPAY_KEY_ID            = os.environ.get("RAZORPAY_KEY_ID", "")
_RAZORPAY_KEY_SECRET        = os.environ.get("RAZORPAY_KEY_SECRET", "")
_RAZORPAY_WEBHOOK_SECRET    = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")

_STRIPE_API_BASE    = "https://api.stripe.com/v1"
_RAZORPAY_API_BASE  = "https://api.razorpay.com/v1"


# ─── Enums & Constants ───────────────────────────────────────────────────────

class Tier(str, Enum):
    FREE       = "free"
    PRO        = "pro"
    ENTERPRISE = "enterprise"

class Provider(str, Enum):
    STRIPE    = "stripe"
    RAZORPAY  = "razorpay"
    INTERNAL  = "internal"

class ProductType(str, Enum):
    REPORT_BASIC      = "report_basic"
    REPORT_ENTERPRISE = "report_enterprise"
    API_KEY_MONTHLY   = "api_key_monthly"
    PRO_SUBSCRIPTION  = "pro_subscription"
    ENT_SUBSCRIPTION  = "enterprise_subscription"

# Pricing catalog (USD)
PRICE_CATALOG: Dict[ProductType, float] = {
    ProductType.REPORT_BASIC:      49.00,
    ProductType.REPORT_ENTERPRISE: 99.00,
    ProductType.API_KEY_MONTHLY:   49.00,
    ProductType.PRO_SUBSCRIPTION:  49.00,
    ProductType.ENT_SUBSCRIPTION:  299.00,
}

# Tier limits
TIER_LIMITS: Dict[Tier, Dict[str, Any]] = {
    Tier.FREE: {
        "api_calls_day":   100,
        "ioc_visible":     False,
        "stix":            False,
        "ai":              False,
        "max_items":       10,
    },
    Tier.PRO: {
        "api_calls_day":   5000,
        "ioc_visible":     True,
        "stix":            False,
        "ai":              "partial",
        "max_items":       100,
    },
    Tier.ENTERPRISE: {
        "api_calls_day":   -1,   # unlimited
        "ioc_visible":     True,
        "stix":            True,
        "ai":              "full",
        "max_items":       9999,
    },
}


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class PaymentIntent:
    id:           str
    provider:     Provider
    product:      ProductType
    amount_usd:   float
    currency:     str
    customer_id:  Optional[str]
    customer_email: Optional[str]
    metadata:     Dict[str, Any] = field(default_factory=dict)
    status:       str = "pending"   # pending | completed | failed | refunded
    created_at:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provider_id:  Optional[str] = None  # Stripe payment_intent_id / Razorpay order_id

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class APIKeyRecord:
    key:          str
    tier:         Tier
    customer_id:  str
    customer_email: str
    created_at:   str
    expires_at:   Optional[str]
    calls_today:  int  = 0
    calls_total:  int  = 0
    last_reset:   str  = field(default_factory=lambda: datetime.now(timezone.utc).date().isoformat())
    active:       bool = True
    metadata:     Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class UsageRecord:
    api_key:    str
    endpoint:   str
    tier:       str
    timestamp:  str
    cost_usd:   float = 0.0
    blocked:    bool  = False
    block_reason: Optional[str] = None


# ─── Stripe Provider ─────────────────────────────────────────────────────────

class StripeGateway:
    """Stripe payment processing for global customers."""

    def __init__(self, secret_key: str = _STRIPE_SECRET_KEY):
        self.secret_key = secret_key

    def _api_call(self, method: str, path: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an authenticated Stripe API call."""
        url = f"{_STRIPE_API_BASE}{path}"
        headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type":  "application/x-www-form-urlencoded",
            "Stripe-Version": "2024-04-10",
        }
        body = None
        if data:
            body = "&".join(f"{k}={v}" for k, v in self._flatten(data).items()).encode()

        req = _urllib_request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            with _urllib_request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            err = json.loads(e.read().decode())
            raise PaymentError(f"Stripe API error: {err.get('error', {}).get('message', str(e))}") from e

    def create_payment_intent(
        self,
        amount_usd:     float,
        product:        ProductType,
        customer_email: Optional[str] = None,
        metadata:       Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Create a Stripe PaymentIntent."""
        amount_cents = int(amount_usd * 100)
        data: Dict[str, Any] = {
            "amount":   amount_cents,
            "currency": "usd",
            "automatic_payment_methods[enabled]": "true",
            "description": f"SENTINEL APEX — {product.value}",
        }
        if customer_email:
            data["receipt_email"] = customer_email
        if metadata:
            for k, v in metadata.items():
                data[f"metadata[{k}]"] = str(v)
        data["metadata[product]"]  = product.value
        data["metadata[platform]"] = "SENTINEL-APEX-v134"

        result = self._api_call("POST", "/payment_intents", data)
        logger.info("Stripe PaymentIntent created: %s amount=$%.2f", result.get("id"), amount_usd)
        return result

    def create_checkout_session(
        self,
        product:        ProductType,
        success_url:    str,
        cancel_url:     str,
        customer_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a Stripe Checkout Session (hosted payment page)."""
        amount_cents = int(PRICE_CATALOG[product] * 100)
        is_subscription = product in (ProductType.PRO_SUBSCRIPTION, ProductType.ENT_SUBSCRIPTION, ProductType.API_KEY_MONTHLY)

        data: Dict[str, Any] = {
            "success_url": success_url,
            "cancel_url":  cancel_url,
            "mode":        "subscription" if is_subscription else "payment",
            "line_items[0][quantity]": "1",
            "metadata[product]":  product.value,
            "metadata[platform]": "SENTINEL-APEX-v134",
        }

        if is_subscription:
            price_id = _STRIPE_ENT_PRICE_ID if product == ProductType.ENT_SUBSCRIPTION else _STRIPE_PRO_PRICE_ID
            data["line_items[0][price]"] = price_id
        else:
            data["line_items[0][price_data][currency]"]                  = "usd"
            data["line_items[0][price_data][unit_amount]"]               = str(amount_cents)
            data["line_items[0][price_data][product_data][name]"]        = f"SENTINEL APEX — {product.value}"
            data["line_items[0][price_data][product_data][description]"] = f"CYBERDUDEBIVASH Threat Intelligence"

        if customer_email:
            data["customer_email"] = customer_email

        result = self._api_call("POST", "/checkout/sessions", data)
        logger.info("Stripe Checkout Session: %s → %s", result.get("id"), result.get("url"))
        return result

    def verify_webhook(self, payload: bytes, sig_header: str) -> Dict[str, Any]:
        """Validate Stripe webhook signature and return event."""
        secret = _STRIPE_WEBHOOK_SECRET
        if not secret:
            raise PaymentError("STRIPE_WEBHOOK_SECRET not configured")

        parts = {kv.split("=")[0]: kv.split("=")[1] for kv in sig_header.split(",") if "=" in kv}
        timestamp = parts.get("t", "")
        sig       = parts.get("v1", "")

        signed = f"{timestamp}.{payload.decode()}"
        expected = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, sig):
            raise PaymentError("Stripe webhook signature verification FAILED")
        if abs(time.time() - int(timestamp)) > 300:
            raise PaymentError("Stripe webhook timestamp too old (replay attack?)")

        return json.loads(payload)

    def _flatten(self, data: Dict, prefix: str = "") -> Dict[str, str]:
        """Flatten nested dict for form encoding."""
        out: Dict[str, str] = {}
        for k, v in data.items():
            key = f"{prefix}[{k}]" if prefix else k
            if isinstance(v, dict):
                out.update(self._flatten(v, key))
            else:
                out[key] = str(v)
        return out


# ─── Razorpay Provider ───────────────────────────────────────────────────────

class RazorpayGateway:
    """Razorpay payment processing for India-region customers."""

    def __init__(self, key_id: str = _RAZORPAY_KEY_ID, key_secret: str = _RAZORPAY_KEY_SECRET):
        self.key_id     = key_id
        self.key_secret = key_secret

    def _api_call(self, method: str, path: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        import base64
        url = f"{_RAZORPAY_API_BASE}{path}"
        creds = base64.b64encode(f"{self.key_id}:{self.key_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {creds}",
            "Content-Type":  "application/json",
        }
        body = json.dumps(data).encode() if data else None
        req = _urllib_request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            with _urllib_request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            err = json.loads(e.read().decode())
            raise PaymentError(f"Razorpay API error: {err.get('error', {}).get('description', str(e))}") from e

    def create_order(
        self,
        amount_usd:  float,
        product:     ProductType,
        receipt_id:  Optional[str] = None,
        notes:       Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Create a Razorpay order (INR, converted from USD at ~84x)."""
        # Razorpay uses smallest currency unit (paise for INR)
        inr_rate   = float(os.environ.get("USD_TO_INR_RATE", "84"))
        amount_inr = int(amount_usd * inr_rate * 100)  # in paise

        data: Dict[str, Any] = {
            "amount":   amount_inr,
            "currency": "INR",
            "receipt":  receipt_id or f"receipt_{secrets.token_hex(8)}",
            "notes":    notes or {"product": product.value, "platform": "SENTINEL-APEX-v134"},
        }
        result = self._api_call("POST", "/orders", data)
        logger.info("Razorpay order created: %s amount=INR%.2f (~$%.2f)",
                    result.get("id"), amount_inr/100, amount_usd)
        return result

    def verify_payment_signature(
        self,
        order_id:   str,
        payment_id: str,
        signature:  str,
    ) -> bool:
        """Verify Razorpay payment signature HMAC-SHA256."""
        msg     = f"{order_id}|{payment_id}"
        expected = hmac.new(
            self.key_secret.encode(), msg.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def verify_webhook(self, payload: bytes, sig_header: str) -> Dict[str, Any]:
        """Validate Razorpay webhook signature."""
        secret = _RAZORPAY_WEBHOOK_SECRET
        if not secret:
            raise PaymentError("RAZORPAY_WEBHOOK_SECRET not configured")
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig_header):
            raise PaymentError("Razorpay webhook signature FAILED")
        return json.loads(payload)


# ─── API Key Manager ─────────────────────────────────────────────────────────

class APIKeyManager:
    """
    Manages API key lifecycle:  issuance → validation → usage tracking → billing.
    Production: backed by Cloudflare KV / D1 / your database.
    Here: in-memory store (replace _store with DB calls in production).
    """

    def __init__(self) -> None:
        self._store: Dict[str, APIKeyRecord] = {}

    def issue_key(
        self,
        tier:           Tier,
        customer_id:    str,
        customer_email: str,
        expires_days:   Optional[int] = 30,
        metadata:       Optional[Dict] = None,
    ) -> APIKeyRecord:
        """Generate and store a new API key."""
        key = f"sxa_{tier.value}_{secrets.token_urlsafe(32)}"
        now = datetime.now(timezone.utc)
        expires_at = None
        if expires_days:
            from datetime import timedelta
            expires_at = (now + timedelta(days=expires_days)).isoformat()

        record = APIKeyRecord(
            key=key,
            tier=tier,
            customer_id=customer_id,
            customer_email=customer_email,
            created_at=now.isoformat(),
            expires_at=expires_at,
            metadata=metadata or {},
        )
        self._store[key] = record
        logger.info("API key issued: tier=%s customer=%s key=%s...", tier.value, customer_email, key[:20])
        return record

    def validate_and_track(self, api_key: str, endpoint: str = "/api/feed") -> Tuple[bool, Optional[str], Optional[APIKeyRecord]]:
        """
        Validate API key and check usage limits.
        Returns (allowed, reason, record).
        """
        record = self._store.get(api_key)
        if not record:
            return False, "INVALID_API_KEY", None

        if not record.active:
            return False, "API_KEY_REVOKED", None

        # Check expiry
        if record.expires_at:
            if datetime.now(timezone.utc).isoformat() > record.expires_at:
                record.active = False
                return False, "API_KEY_EXPIRED", None

        # Reset daily counter if new day
        today = datetime.now(timezone.utc).date().isoformat()
        if record.last_reset != today:
            record.calls_today = 0
            record.last_reset  = today

        # Check daily limit
        limit = TIER_LIMITS[record.tier]["api_calls_day"]
        if limit != -1 and record.calls_today >= limit:
            return False, f"DAILY_LIMIT_EXCEEDED_tier={record.tier.value}_limit={limit}_upgrade_url=https://intel.cyberdudebivash.com/upgrade", record

        # Track usage
        record.calls_today += 1
        record.calls_total += 1
        return True, None, record

    def revoke_key(self, api_key: str) -> bool:
        record = self._store.get(api_key)
        if record:
            record.active = False
            logger.info("API key revoked: %s...", api_key[:20])
            return True
        return False

    def get_usage_stats(self, api_key: str) -> Optional[Dict[str, Any]]:
        record = self._store.get(api_key)
        if not record:
            return None
        limit = TIER_LIMITS[record.tier]["api_calls_day"]
        return {
            "api_key_prefix": api_key[:12] + "...",
            "tier":           record.tier.value,
            "calls_today":    record.calls_today,
            "daily_limit":    limit if limit != -1 else "unlimited",
            "calls_total":    record.calls_total,
            "created_at":     record.created_at,
            "expires_at":     record.expires_at,
            "active":         record.active,
            "upgrade_url":    "https://intel.cyberdudebivash.com/upgrade",
        }


# ─── Unified Payment Gateway ─────────────────────────────────────────────────

class PaymentGateway:
    """
    Unified payment gateway: routes to Stripe (global) or Razorpay (India)
    based on customer currency / region preference.
    """

    def __init__(self) -> None:
        self.stripe    = StripeGateway()
        self.razorpay  = RazorpayGateway()
        self.key_mgr   = APIKeyManager()
        self._intents: Dict[str, PaymentIntent] = {}

    def create_checkout(
        self,
        product:        ProductType,
        provider:       Provider = Provider.STRIPE,
        customer_email: Optional[str] = None,
        success_url:    str = "https://intel.cyberdudebivash.com/success",
        cancel_url:     str  = "https://intel.cyberdudebivash.com/upgrade",
        metadata:       Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Create a payment checkout session.
        Returns provider-specific checkout data.
        """
        amount = PRICE_CATALOG[product]
        intent_id = f"pi_{secrets.token_hex(12)}"
        intent = PaymentIntent(
            id=intent_id,
            provider=provider,
            product=product,
            amount_usd=amount,
            currency="usd" if provider == Provider.STRIPE else "inr",
            customer_id=None,
            customer_email=customer_email,
            metadata=metadata or {},
        )

        if provider == Provider.STRIPE:
            result = self.stripe.create_checkout_session(
                product=product,
                success_url=f"{success_url}?session={{CHECKOUT_SESSION_ID}}&product={product.value}",
                cancel_url=cancel_url,
                customer_email=customer_email,
            )
            intent.provider_id = result.get("id")
            intent.status = "pending"
            checkout_url = result.get("url")

        elif provider == Provider.RAZORPAY:
            order = self.razorpay.create_order(
                amount_usd=amount,
                product=product,
                receipt_id=intent_id,
                notes={"product": product.value, "email": customer_email or ""},
            )
            intent.provider_id = order.get("id")
            intent.status = "pending"
            checkout_url = None  # Razorpay uses client-side SDK

        else:
            raise PaymentError(f"Unknown provider: {provider}")

        self._intents[intent_id] = intent
        logger.info("Checkout created: %s product=%s provider=%s amount=$%.2f",
                    intent_id, product.value, provider.value, amount)

        return {
            "intent_id":   intent_id,
            "provider":    provider.value,
            "product":     product.value,
            "amount_usd":  amount,
            "checkout_url": checkout_url,
            "provider_data": result if provider == Provider.STRIPE else order,
            "created_at":  intent.created_at,
        }

    def handle_stripe_webhook(self, payload: bytes, sig_header: str) -> Dict[str, Any]:
        """Process a Stripe webhook event."""
        event = self.stripe.verify_webhook(payload, sig_header)
        event_type = event.get("type", "")
        logger.info("Stripe webhook: %s", event_type)

        if event_type == "payment_intent.succeeded":
            pi = event["data"]["object"]
            self._on_payment_success(
                provider=Provider.STRIPE,
                provider_id=pi["id"],
                product_str=pi.get("metadata", {}).get("product", ""),
                customer_email=pi.get("receipt_email"),
            )
        elif event_type in ("checkout.session.completed",):
            sess = event["data"]["object"]
            self._on_payment_success(
                provider=Provider.STRIPE,
                provider_id=sess["id"],
                product_str=sess.get("metadata", {}).get("product", ""),
                customer_email=sess.get("customer_email"),
            )
        elif event_type in ("invoice.payment_failed", "payment_intent.payment_failed"):
            logger.warning("Payment failed: %s", event_type)

        return {"received": True, "event_type": event_type}

    def handle_razorpay_webhook(self, payload: bytes, sig_header: str) -> Dict[str, Any]:
        """Process a Razorpay webhook event."""
        event = self.razorpay.verify_webhook(payload, sig_header)
        event_type = event.get("event", "")
        logger.info("Razorpay webhook: %s", event_type)

        if event_type == "payment.captured":
            payment = event["payload"]["payment"]["entity"]
            notes   = payment.get("notes", {})
            self._on_payment_success(
                provider=Provider.RAZORPAY,
                provider_id=payment["id"],
                product_str=notes.get("product", ""),
                customer_email=payment.get("email"),
            )
        return {"received": True, "event_type": event_type}

    def _on_payment_success(
        self,
        provider:       Provider,
        provider_id:    str,
        product_str:    str,
        customer_email: Optional[str],
    ) -> None:
        """Post-payment fulfillment: issue API key, upgrade tier, send confirmation."""
        try:
            product = ProductType(product_str)
        except ValueError:
            logger.error("Unknown product on payment success: %s", product_str)
            return

        tier = self._product_to_tier(product)
        customer_id = f"cust_{hashlib.sha256((customer_email or provider_id).encode()).hexdigest()[:16]}"

        if product in (ProductType.API_KEY_MONTHLY, ProductType.PRO_SUBSCRIPTION,
                       ProductType.ENT_SUBSCRIPTION):
            record = self.key_mgr.issue_key(
                tier=tier,
                customer_id=customer_id,
                customer_email=customer_email or "unknown@unknown.com",
                expires_days=30 if tier != Tier.ENTERPRISE else 365,
                metadata={"provider": provider.value, "provider_id": provider_id},
            )
            logger.info("API key fulfilled: tier=%s email=%s key=%s...",
                        tier.value, customer_email, record.key[:20])

        elif product in (ProductType.REPORT_BASIC, ProductType.REPORT_ENTERPRISE):
            logger.info("Report purchase fulfilled: product=%s email=%s provider_id=%s",
                        product.value, customer_email, provider_id)
            # TODO: trigger report delivery email via Cloudflare Email Workers

    def _product_to_tier(self, product: ProductType) -> Tier:
        if product == ProductType.ENT_SUBSCRIPTION:  return Tier.ENTERPRISE
        if product in (ProductType.PRO_SUBSCRIPTION, ProductType.API_KEY_MONTHLY): return Tier.PRO
        return Tier.FREE

    def get_pricing_page(self) -> Dict[str, Any]:
        """Return pricing data for the frontend dashboard."""
        return {
            "version": "v134.0.0",
            "currency": "USD",
            "plans": [
                {
                    "id":           "free",
                    "name":         "FREE",
                    "price_month":  0,
                    "features":     ["10 threat reports/month", "100 API calls/day", "Basic dashboard"],
                    "cta":          "Get Started",
                    "cta_url":      "https://intel.cyberdudebivash.com/register",
                },
                {
                    "id":           "pro",
                    "name":         "PRO",
                    "price_month":  49,
                    "features":     ["100 reports/month", "5,000 API calls/day", "Full IOC access",
                                     "Sigma & YARA rules", "Partial AI analysis", "STIX 2.1 export"],
                    "cta":          "Upgrade to PRO — $49/mo",
                    "cta_url":      "https://intel.cyberdudebivash.com/checkout?product=pro_subscription",
                    "badge":        "MOST POPULAR",
                },
                {
                    "id":           "enterprise",
                    "name":         "ENTERPRISE",
                    "price_month":  299,
                    "price_annual": 2999,
                    "features":     ["Unlimited reports", "Unlimited API calls", "Full AI Analyst (MYTHOS)",
                                     "Custom SLA", "SIEM integrations", "STIX + MISP + OpenCTI",
                                     "Dedicated threat analyst", "Priority support"],
                    "cta":          "Contact Sales",
                    "cta_url":      "https://intel.cyberdudebivash.com/enterprise",
                },
            ],
            "one_time_products": [
                {"id": "report_basic",      "name": "Intel Report Basic",      "price": 49,  "cta_url": "https://intel.cyberdudebivash.com/checkout?product=report_basic"},
                {"id": "report_enterprise", "name": "Enterprise Dossier",      "price": 99,  "cta_url": "https://intel.cyberdudebivash.com/checkout?product=report_enterprise"},
                {"id": "api_key_monthly",   "name": "API Key (30 days)",       "price": 49,  "cta_url": "https://intel.cyberdudebivash.com/checkout?product=api_key_monthly"},
            ],
        }


# ─── Exceptions ──────────────────────────────────────────────────────────────

class PaymentError(Exception):
    """Raised on payment processing failures."""


# ─── Module singleton ────────────────────────────────────────────────────────

_gateway: Optional[PaymentGateway] = None

def get_payment_gateway() -> PaymentGateway:
    global _gateway
    if _gateway is None:
        _gateway = PaymentGateway()
    return _gateway


# ─── CLI self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    gw = get_payment_gateway()

    # Print pricing page
    pricing = gw.get_pricing_page()
    print(json.dumps(pricing, indent=2))

    # Issue test API keys
    free_key = gw.key_mgr.issue_key(Tier.FREE, "test_free", "free@test.com", expires_days=30)
    pro_key  = gw.key_mgr.issue_key(Tier.PRO,  "test_pro",  "pro@test.com",  expires_days=30)
    print(f"\nFREE key: {free_key.key[:30]}...")
    print(f"PRO  key: {pro_key.key[:30]}...")

    # Validate usage
    allowed, reason, rec = gw.key_mgr.validate_and_track(free_key.key, "/api/feed")
    print(f"\nFREE key validation: allowed={allowed} reason={reason}")
    stats = gw.key_mgr.get_usage_stats(free_key.key)
    print(f"Usage stats: {json.dumps(stats, indent=2)}")
