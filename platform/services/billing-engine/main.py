"""
SENTINEL APEX BILLING ENGINE v2.0
===================================
Production-grade usage-based billing + SaaS tier management:
- Stripe integration (subscriptions, usage metering, invoicing)
- Multi-tenant SaaS tier enforcement (FREE/PRO/ENTERPRISE/GOVERNMENT/OEM)
- API usage metering (per-call, per-token, per-query)
- GPU compute metering
- Webhook event processing
- Revenue analytics
- OEM / white-label licensing
- MSSP reseller billing
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

import stripe
import structlog
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field

log = structlog.get_logger("sentinel.billing")

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# ──────────────────────────────────────────────────────────
# TIER DEFINITIONS
# ──────────────────────────────────────────────────────────
class SaaSTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"
    OEM = "oem"
    MSSP = "mssp"

TIER_LIMITS = {
    SaaSTier.FREE: {
        "api_calls_per_month": 1_000,
        "ioc_enrichments_per_month": 100,
        "stix_bundles_per_month": 10,
        "pdf_reports_per_month": 5,
        "ai_queries_per_month": 50,
        "price_monthly_usd": 0,
        "price_annual_usd": 0,
    },
    SaaSTier.PRO: {
        "api_calls_per_month": 100_000,
        "ioc_enrichments_per_month": 10_000,
        "stix_bundles_per_month": 1_000,
        "pdf_reports_per_month": 500,
        "ai_queries_per_month": 5_000,
        "price_monthly_usd": 499,
        "price_annual_usd": 4_990,
    },
    SaaSTier.ENTERPRISE: {
        "api_calls_per_month": 10_000_000,
        "ioc_enrichments_per_month": 1_000_000,
        "stix_bundles_per_month": 100_000,
        "pdf_reports_per_month": 50_000,
        "ai_queries_per_month": 500_000,
        "price_monthly_usd": 4_999,
        "price_annual_usd": 49_990,
    },
    SaaSTier.GOVERNMENT: {
        "api_calls_per_month": -1,  # unlimited
        "ioc_enrichments_per_month": -1,
        "stix_bundles_per_month": -1,
        "pdf_reports_per_month": -1,
        "ai_queries_per_month": -1,
        "price_monthly_usd": 24_999,
        "price_annual_usd": 249_990,
    },
    SaaSTier.OEM: {
        "api_calls_per_month": -1,
        "ioc_enrichments_per_month": -1,
        "stix_bundles_per_month": -1,
        "pdf_reports_per_month": -1,
        "ai_queries_per_month": -1,
        "price_monthly_usd": 0,  # custom licensing
        "price_annual_usd": 0,
    },
    # Was missing entirely — GET /tiers threw a 500 on every call (KeyError)
    # since SaaSTier.MSSP has no entry here to look up. Not fixed by picking
    # a number: this repo has at least three mutually-inconsistent pricing
    # schemes for "mssp" across api/, platform/services/, and
    # sentinel-apex-api/ ($1,999, $2,499, and this file's own pro/enterprise
    # scale imply yet a different figure) with no evidence for which is
    # canonical. Treated as custom/negotiated pricing (matching this file's
    # own OEM tier, and mssp_operations_engine.py's actual per-customer
    # wholesale model) rather than inventing a flat rate — see the
    # cross-codebase pricing reconciliation this needs before any of those
    # numbers can be trusted.
    SaaSTier.MSSP: {
        "api_calls_per_month": -1,
        "ioc_enrichments_per_month": -1,
        "stix_bundles_per_month": -1,
        "pdf_reports_per_month": -1,
        "ai_queries_per_month": -1,
        "price_monthly_usd": 0,  # custom/negotiated — see comment above
        "price_annual_usd": 0,
    },
}

# ──────────────────────────────────────────────────────────
# MODELS
# ──────────────────────────────────────────────────────────
class UsageEvent(BaseModel):
    tenant_id: str
    user_id: str
    event_type: str  # api_call|ioc_enrichment|ai_query|stix_bundle|pdf_report|gpu_minute
    quantity: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SubscriptionCreate(BaseModel):
    tenant_id: str
    tier: SaaSTier
    billing_email: str
    annual: bool = False
    coupon_code: Optional[str] = None
    mssp_parent_id: Optional[str] = None

class UsageSummary(BaseModel):
    tenant_id: str
    tier: SaaSTier
    period_start: datetime
    period_end: datetime
    api_calls: int = 0
    ioc_enrichments: int = 0
    stix_bundles: int = 0
    pdf_reports: int = 0
    ai_queries: int = 0
    gpu_minutes: float = 0.0
    overage_usd: Decimal = Decimal("0.00")
    total_bill_usd: Decimal = Decimal("0.00")

# ──────────────────────────────────────────────────────────
# OVERAGE PRICING (per-unit USD)
# ──────────────────────────────────────────────────────────
OVERAGE_RATES = {
    "api_call": Decimal("0.001"),
    "ioc_enrichment": Decimal("0.01"),
    "stix_bundle": Decimal("0.05"),
    "pdf_report": Decimal("0.25"),
    "ai_query": Decimal("0.02"),
    "gpu_minute": Decimal("0.50"),
}

# ──────────────────────────────────────────────────────────
# APPLICATION
# ──────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("billing_engine.startup")
    yield
    log.info("billing_engine.shutdown")

app = FastAPI(
    title="Sentinel Apex Billing Engine",
    version="2.0.0",
    description="Production SaaS billing + usage metering for SENTINEL APEX",
    lifespan=lifespan,
)

FastAPIInstrumentor.instrument_app(app)
Instrumentator().instrument(app).expose(app)

# ──────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "billing-engine", "version": "2.0.0"}

@app.get("/tiers")
async def list_tiers():
    """Return all tier definitions + pricing."""
    return {
        "tiers": {
            tier.value: {
                **TIER_LIMITS[tier],
                "overage_rates": {k: str(v) for k, v in OVERAGE_RATES.items()},
            }
            for tier in SaaSTier
        }
    }

@app.post("/usage/record")
async def record_usage(event: UsageEvent, background_tasks: BackgroundTasks):
    """Record a usage event for metering."""
    event_id = str(uuid.uuid4())
    log.info("usage.recorded", event_id=event_id, **event.model_dump())
    # In production: write to TimescaleDB + emit Kafka event
    background_tasks.add_task(_emit_usage_event, event, event_id)
    return {"event_id": event_id, "status": "recorded"}

@app.get("/usage/{tenant_id}/summary")
async def usage_summary(tenant_id: str, period: str = "current"):
    """Get usage summary for a tenant. Not yet backed by a real metering
    store (TimescaleDB) — returns 503 rather than fabricated numbers. See
    docs/PRICING.md-equivalent note: never expose invented usage/billing
    figures as if they were queried."""
    raise HTTPException(
        status_code=503,
        detail=(
            "Usage metering is not yet connected to a real data store for this "
            f"service (tenant_id={tenant_id}). This endpoint previously returned "
            "hardcoded mock figures; that has been removed rather than fixed to "
            "read from TimescaleDB, which is not yet wired up."
        ),
    )

@app.post("/subscriptions")
async def create_subscription(payload: SubscriptionCreate):
    """Create or upgrade a tenant subscription. This previously fabricated a
    "status": "active" success response without ever calling Stripe or
    persisting anything — a caller had no way to know the subscription
    wasn't real. Returns 501 instead: a false "active" claim on a billing
    write is worse than an honest failure, since it can grant paid-tier
    access with nothing actually charged."""
    raise HTTPException(
        status_code=501,
        detail=(
            "Subscription creation is not implemented in this service (no Stripe "
            f"call, no persistence). Requested: tenant={payload.tenant_id}, "
            f"tier={payload.tier.value}. Use the real checkout/subscription path "
            "(agent/monetization/payment_gateway.py or api/monetization.py) instead."
        ),
    )

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """Handle Stripe webhook events. Fails closed: an unconfigured secret or a
    bad signature is rejected, never silently accepted as processed — see
    agent/monetization/payment_gateway.py's handle_stripe_webhook for the
    same pattern already used elsewhere in this codebase."""
    payload = await request.body()

    if not STRIPE_WEBHOOK_SECRET:
        log.error("stripe.webhook.rejected", reason="STRIPE_WEBHOOK_SECRET not configured")
        raise HTTPException(status_code=503, detail="Webhook processing not configured")

    if not stripe_signature:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header")

    try:
        event = stripe.Webhook.construct_event(payload, stripe_signature, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        log.error("stripe.webhook.signature_invalid", error=str(e))
        raise HTTPException(status_code=400, detail="Invalid signature") from e

    log.info("stripe.webhook.verified", event_type=event.get("type"), event_id=event.get("id"))
    # Event-type handling (subscription created/updated/cancelled, invoice
    # events, etc.) is not yet implemented in this service — verification is
    # the security-relevant fix; wiring real event handling is separate work.
    return {"status": "verified", "event_type": event.get("type")}

@app.get("/revenue/mrr")
async def get_mrr():
    """Monthly recurring revenue analytics. This endpoint previously returned
    entirely hardcoded figures ($284,750 MRR and similar) with no data source
    and no indication they were fake — removed rather than left in place,
    per the standing rule that revenue APIs must return real data, be
    clearly marked as demo, or be disabled. A real MRR implementation
    already exists elsewhere in this ecosystem (workers/revenue-engine's
    GET /api/revenue/mrr, which queries a real CRM database) — point
    consumers there instead of re-implementing it here without a data
    source to back it."""
    raise HTTPException(
        status_code=503,
        detail=(
            "Revenue analytics is not implemented in this service (no database "
            "connected). A working implementation exists in workers/revenue-engine "
            "(GET /api/revenue/mrr) — use that instead of this endpoint."
        ),
    )

@app.get("/licensing/oem/{license_id}")
async def get_oem_license(license_id: str):
    """OEM/white-label license validation. This previously returned
    "valid": True for every possible license_id with no license store behind
    it — an authorization bypass, not just fake data: anything calling this
    to gate white-label/full-API access would have granted it to any string.
    Fails closed (valid: false) until a real license store exists, which is
    the safe default for an unimplemented authorization check."""
    log.warning("oem_license.check_not_implemented", license_id=license_id)
    return {
        "license_id": license_id,
        "type": "oem",
        "valid": False,
        "reason": "License validation is not connected to a real license store in this service.",
        "features": [],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

async def _emit_usage_event(event: UsageEvent, event_id: str):
    """Emit usage event to Kafka for downstream consumers."""
    log.info("usage.kafka.emit", event_id=event_id, event_type=event.event_type)
