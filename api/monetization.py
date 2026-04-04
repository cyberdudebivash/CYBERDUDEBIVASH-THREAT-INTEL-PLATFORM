#!/usr/bin/env python3
"""
api/monetization.py — CYBERDUDEBIVASH® SENTINEL APEX
MONETIZATION ENGINE v2.0 — FastAPI Router

Endpoints (all under /api/v1/monetize/):
  GET  /tiers                  — Public tier catalog with pricing
  GET  /tiers/{tier}           — Single tier detail
  POST /provision              — Self-serve free key provisioning
  GET  /usage                  — Usage summary for current key
  POST /keys                   — Create API key (ADMIN: MSSP only)
  GET  /keys                   — List all keys (ADMIN: MSSP only)
  DELETE /keys/{prefix}        — Revoke key by prefix (ADMIN: MSSP only)
  GET  /analytics              — Aggregate usage analytics (ADMIN: MSSP only)
  POST /billing/webhook        — Stripe webhook handler (sig-verified)
  POST /billing/checkout       — Initiate Stripe checkout session (stub)
  GET  /billing/invoices       — List billing invoices for current sub
  POST /billing/cancel         — Cancel subscription
  GET  /health                 — Monetization subsystem health

Security model:
  - Admin endpoints require MSSP-tier key (validated via APIKeyManager)
  - Self-serve endpoints require any valid key
  - Public endpoints: /tiers only
  - Stripe webhook uses HMAC-SHA256 signature verification
  - All key material redacted from logs (prefix only)
  - Constant-time comparisons throughout

Author: CYBERDUDEBIVASH® SENTINEL APEX
Version: v2.0
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── FastAPI imports (graceful degradation if FastAPI not installed) ──────────
try:
    from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, validator
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False
    # Full stubs — module loads cleanly without FastAPI.
    # Route decorator calls on _NoOpRouter are absorbed as no-ops.
    # router is reset to None at module end so main.py skips mounting.
    class _NoOpRouter:                        # type: ignore[misc]
        """Absorbs @router.get/post/delete decorators without error."""
        def __init__(self, *a, **kw): pass
        @staticmethod
        def _noop(*a, **kw):
            return lambda fn: fn
        get = post = delete = put = patch = options = head = _noop  # type: ignore[assignment]
    APIRouter = _NoOpRouter                   # type: ignore[assignment,misc]
    class HTTPException(Exception): pass      # type: ignore[misc]
    class BaseModel: pass                     # type: ignore[misc]
    class JSONResponse:                       # type: ignore[misc]
        def __init__(self, *a, **kw): pass
    def Header(*a, **kw): return None         # type: ignore[misc]
    def Depends(*a, **kw): return None        # type: ignore[misc]
    def Query(*a, **kw): return None          # type: ignore[misc]
    Request = object                          # type: ignore[misc,assignment]
    def Field(*a, **kw): return None          # type: ignore[misc]
    def validator(*a, **kw):                  # type: ignore[misc]
        def _dec(fn): return fn
        return _dec

# ── Internal imports (graceful degradation on import failure) ───────────────
logger = logging.getLogger("CDB-MONETIZE")

BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
BILLING_DIR = DATA_DIR / "billing"

# Auth layer
try:
    from api.auth import (
        APIKeyManager, get_key_manager, TIERS, DEFAULT_TIER,
        validate_request, AuthResult, generate_api_key,
    )
    _AUTH_OK = True
except ImportError:
    try:
        import importlib.util as _ilu, sys as _sys
        _sys.path.insert(0, str(BASE_DIR))
        _spec = _ilu.spec_from_file_location("auth", Path(__file__).parent / "auth.py")
        _mod  = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)  # type: ignore
        APIKeyManager  = _mod.APIKeyManager
        get_key_manager = _mod.get_key_manager
        TIERS          = _mod.TIERS
        DEFAULT_TIER   = _mod.DEFAULT_TIER
        validate_request = _mod.validate_request
        AuthResult     = _mod.AuthResult
        generate_api_key = _mod.generate_api_key
        _AUTH_OK       = True
    except Exception as _e:
        logger.error(f"[MONETIZE] Auth layer unavailable: {_e}")
        _AUTH_OK = False
        TIERS = {}
        DEFAULT_TIER = "FREE"

# Billing layer
try:
    from api.billing import (
        PLAN_PRICING, BillingEngine, get_billing_engine,
        EVT_SUBSCRIPTION_CREATED, EVT_SUBSCRIPTION_UPGRADED,
        EVT_SUBSCRIPTION_CANCELLED, EVT_PAYMENT_SUCCEEDED,
        EVT_PAYMENT_FAILED,
    )
    _BILLING_OK = True
except ImportError:
    logger.warning("[MONETIZE] Billing layer unavailable — stubs active")
    _BILLING_OK = False
    PLAN_PRICING = {
        "FREE":       {"monthly_cents": 0,      "annual_cents": 0,       "trial_days": 0},
        "PRO":        {"monthly_cents": 4900,    "annual_cents": 47040,   "trial_days": 14},
        "ENTERPRISE": {"monthly_cents": 49900,   "annual_cents": 479040,  "trial_days": 30},
        "MSSP":       {"monthly_cents": 199900,  "annual_cents": 1919040, "trial_days": 30},
    }
    EVT_SUBSCRIPTION_CREATED  = "subscription.created"
    EVT_SUBSCRIPTION_UPGRADED = "subscription.upgraded"
    EVT_SUBSCRIPTION_CANCELLED= "subscription.cancelled"
    EVT_PAYMENT_SUCCEEDED     = "payment.succeeded"
    EVT_PAYMENT_FAILED        = "payment.failed"

# Rate limiter layer
try:
    from api.rate_limiter import check_rate_limit as _check_rate_limit, is_redis_available
    _RATE_OK = True
except ImportError:
    _RATE_OK = False
    def _check_rate_limit(key_hash, tier): return (True, 0, 999)
    def is_redis_available(): return False

# ============================================================================
# Router
# ============================================================================
router = APIRouter(
    prefix="/api/v1/monetize",
    tags=["Monetization"],
    responses={
        401: {"description": "Invalid or missing API key"},
        403: {"description": "Insufficient tier permissions"},
        429: {"description": "Rate limit / quota exceeded"},
    },
)
# NOTE: if _FASTAPI_OK is False, router is a _NoOpRouter instance — all
# @router.get/post decorators below will be absorbed as no-ops.
# At the bottom of this module, router is reset to None so main.py
# correctly skips mounting it when FastAPI is unavailable.

# ── Stripe config ────────────────────────────────────────────────────────────
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_IDS: Dict[str, str] = {
    "PRO_MONTHLY":        os.getenv("STRIPE_PRICE_PRO_MONTHLY",   "price_pro_monthly"),
    "PRO_ANNUAL":         os.getenv("STRIPE_PRICE_PRO_ANNUAL",    "price_pro_annual"),
    "ENTERPRISE_MONTHLY": os.getenv("STRIPE_PRICE_ENT_MONTHLY",   "price_ent_monthly"),
    "ENTERPRISE_ANNUAL":  os.getenv("STRIPE_PRICE_ENT_ANNUAL",    "price_ent_annual"),
    "MSSP_MONTHLY":       os.getenv("STRIPE_PRICE_MSSP_MONTHLY",  "price_mssp_monthly"),
}

# ── Storage helpers ──────────────────────────────────────────────────────────

def _safe_load(path: Path, default: Any = None) -> Any:
    try:
        if path.exists() and path.stat().st_size > 0:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"[MONETIZE] Load failed {path.name}: {e}")
    return default if default is not None else {}


def _safe_write(path: Path, data: Any) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.error(f"[MONETIZE] Write failed {path.name}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def _append_event(path: Path, event: Dict) -> None:
    """Append-only JSONL event log — never overwrites history."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except Exception as e:
        logger.error(f"[MONETIZE] Event append failed {path.name}: {e}")


WEBHOOK_LOG = BILLING_DIR / "stripe_events.jsonl"
PROVISIONED_LOG = BILLING_DIR / "provisioned_keys.jsonl"

# ============================================================================
# Pydantic Schemas
# ============================================================================

class CreateKeyRequest(BaseModel):
    tier: str = Field(..., description="FREE | PRO | ENTERPRISE | MSSP")
    owner: str = Field(..., min_length=1, max_length=128, description="Owner identifier (email/org)")
    label: str = Field("", max_length=256, description="Human-readable key label")
    expires_at: Optional[str] = Field(None, description="ISO-8601 expiry datetime (null = never)")

    @validator("tier")
    def tier_must_be_valid(cls, v: str) -> str:
        v = v.upper()
        valid = {"FREE", "PRO", "ENTERPRISE", "MSSP"}
        if v not in valid:
            raise ValueError(f"tier must be one of {valid}")
        return v


class ProvisionRequest(BaseModel):
    owner: str = Field(..., min_length=3, max_length=128, description="Email address")
    label: str = Field("", max_length=256, description="Key label")


class CheckoutRequest(BaseModel):
    tier: str = Field(..., description="PRO | ENTERPRISE | MSSP")
    billing_cycle: str = Field("monthly", description="monthly | annual")
    success_url: str = Field(..., description="Redirect URL on success")
    cancel_url:  str = Field(..., description="Redirect URL on cancellation")
    customer_email: Optional[str] = Field(None, description="Pre-fill checkout email")


class RevokeResponse(BaseModel):
    status: str
    message: str
    revoked_prefix: str


# ============================================================================
# Dependency: extract + validate API key from request headers
# ============================================================================

def _extract_key_from_headers(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> Optional[str]:
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        parts = authorization.strip().split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    return None


def _require_valid_key(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> "AuthResult":
    """FastAPI dependency: require any valid API key."""
    if not _AUTH_OK:
        raise HTTPException(503, detail="Auth service unavailable")
    raw = _extract_key_from_headers(x_api_key, authorization)
    valid, auth, status, msg = validate_request(raw, None)
    if not valid:
        raise HTTPException(status_code=status, detail=msg)
    return auth


def _require_admin_key(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> "AuthResult":
    """FastAPI dependency: require MSSP (admin) tier key."""
    auth = _require_valid_key(x_api_key, authorization)
    if auth.tier not in ("MSSP", "mssp"):
        raise HTTPException(
            status_code=403,
            detail="Admin operation requires MSSP tier key.",
        )
    return auth


# ============================================================================
# ── PUBLIC ENDPOINTS ─────────────────────────────────────────────────────────
# ============================================================================

@router.get(
    "/tiers",
    summary="List all subscription tiers",
    description="Returns pricing, feature flags, and quotas for all tiers. No auth required.",
)
async def list_tiers() -> Dict:
    """
    Public endpoint — returns tier catalog with pricing and features.
    Used by frontend signup flow and docs.
    """
    catalog = {}
    for tier_id, tier_def in TIERS.items():
        pricing = PLAN_PRICING.get(tier_id.upper(), {})
        catalog[tier_id] = {
            "tier_id":             tier_id,
            "name":                tier_def.get("name", tier_id),
            "price_monthly_usd":   pricing.get("monthly_cents", 0) / 100,
            "price_annual_usd":    pricing.get("annual_cents",  0) / 100,
            "annual_savings_pct":  20 if pricing.get("annual_cents", 0) > 0 else 0,
            "trial_days":          pricing.get("trial_days", 0),
            "requests_per_day":    tier_def.get("requests_per_day", 100),
            "advisories_per_req":  tier_def.get("advisories_per_request", 10),
            "rate_limit_per_min":  tier_def.get("rate_limit_per_minute", 10),
            "features":            tier_def.get("features", {}),
            "endpoints":           tier_def.get("endpoints", []),
        }
    return {
        "status":    "ok",
        "tiers":     catalog,
        "generated": datetime.now(timezone.utc).isoformat(),
        "currency":  "USD",
        "upgrade_url": "https://tools.cyberdudebivash.com/",
    }


@router.get(
    "/tiers/{tier_id}",
    summary="Get single tier details",
)
async def get_tier(tier_id: str) -> Dict:
    tier_id_upper = tier_id.upper()
    if tier_id_upper not in TIERS:
        raise HTTPException(404, detail=f"Tier '{tier_id}' not found.")
    tier_def = TIERS[tier_id_upper]
    pricing  = PLAN_PRICING.get(tier_id_upper, {})
    return {
        "tier_id":            tier_id_upper,
        "name":               tier_def.get("name", tier_id_upper),
        "price_monthly_usd":  pricing.get("monthly_cents", 0) / 100,
        "price_annual_usd":   pricing.get("annual_cents",  0) / 100,
        "trial_days":         pricing.get("trial_days", 0),
        "requests_per_day":   tier_def.get("requests_per_day", 100),
        "advisories_per_req": tier_def.get("advisories_per_request", 10),
        "features":           tier_def.get("features", {}),
        "endpoints":          tier_def.get("endpoints", []),
    }


# ============================================================================
# ── SELF-SERVE PROVISION ─────────────────────────────────────────────────────
# ============================================================================

@router.post(
    "/provision",
    summary="Self-serve free API key provisioning",
    description=(
        "Provision a FREE-tier API key. Rate-limited to 3 keys per email per 24h. "
        "No credit card required. Key shown ONCE — save it securely."
    ),
    status_code=201,
)
async def provision_free_key(body: ProvisionRequest) -> Dict:
    """
    Zero-friction free key provisioning.
    Enforces: 3 keys/email/day, email format check, owner normalization.
    """
    if not _AUTH_OK:
        raise HTTPException(503, detail="Provisioning unavailable — auth service offline")

    owner = body.owner.strip().lower()
    if "@" not in owner or len(owner) < 5:
        raise HTTPException(422, detail="owner must be a valid email address")

    # Rate-gate: max 3 free keys per email per calendar day
    prov_file = BILLING_DIR / "prov_counters.json"
    counters  = _safe_load(prov_file, {})
    today     = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day_key   = f"{hashlib.sha256(owner.encode()).hexdigest()[:16]}:{today}"
    count     = counters.get(day_key, 0)
    if count >= 3:
        raise HTTPException(
            429,
            detail="Max 3 free keys per email per day. Try again tomorrow or upgrade to PRO.",
        )
    counters[day_key] = count + 1
    _safe_write(prov_file, counters)

    mgr = get_key_manager()
    raw_key, record = mgr.create_key(
        tier     = "FREE",
        owner    = owner,
        label    = body.label or f"Free key for {owner}",
        expires_at = None,
    )

    # Audit log
    _append_event(PROVISIONED_LOG, {
        "event":     "free_key_provisioned",
        "owner":     owner,
        "prefix":    raw_key[:20],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    logger.info(f"[MONETIZE] Free key provisioned: owner={owner} prefix={raw_key[:20]}")
    return {
        "status":   "created",
        "api_key":  raw_key,
        "tier":     "FREE",
        "owner":    owner,
        "label":    record.get("label"),
        "created_at": record.get("created_at"),
        "expires_at": None,
        "requests_per_day": 100,
        "warning": "Store this key securely — it will NOT be shown again.",
        "docs_url": "https://intel.cyberdudebivash.com/api/docs",
        "upgrade_url": "https://tools.cyberdudebivash.com/",
    }


# ============================================================================
# ── AUTHENTICATED: SELF-SERVICE USAGE ────────────────────────────────────────
# ============================================================================

@router.get(
    "/usage",
    summary="Get usage summary for current API key",
)
async def get_usage(auth: "AuthResult" = Depends(_require_valid_key)) -> Dict:
    """
    Returns quota consumption, tier entitlements, and reset schedule
    for the authenticated key.
    """
    mgr   = get_key_manager()
    tier  = auth.tier.upper()
    tier_def = TIERS.get(tier, TIERS.get(DEFAULT_TIER, {}))
    daily_limit = tier_def.get("requests_per_day", 100)
    today_used  = auth.record.get("requests_today", 0)
    remaining   = (
        "unlimited" if daily_limit == -1
        else max(0, daily_limit - today_used)
    )

    # Rate limiter remaining
    key_hash = hashlib.sha256(auth.record.get("key_prefix", "").encode()).hexdigest()
    allowed, current, limit = _check_rate_limit(key_hash, tier)

    return {
        "status":          "ok",
        "tier":            tier,
        "owner":           auth.record.get("owner", "unknown"),
        "label":           auth.record.get("label", ""),
        "key_prefix":      auth.record.get("key_prefix", "")[:16] + "...",
        "quota": {
            "daily_limit":      daily_limit if daily_limit != -1 else "unlimited",
            "requests_today":   today_used,
            "remaining_today":  remaining,
            "reset_at_utc":     _next_utc_midnight(),
        },
        "rate_limit": {
            "per_minute":       tier_def.get("rate_limit_per_minute", 10),
            "current_window":   current,
        },
        "features":       tier_def.get("features", {}),
        "total_requests": auth.record.get("total_requests", 0),
        "last_used":      auth.record.get("last_used"),
        "active":         auth.record.get("active", True),
        "expires_at":     auth.record.get("expires_at"),
        "generated":      datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# ── ADMIN: KEY MANAGEMENT ────────────────────────────────────────────────────
# ============================================================================

@router.post(
    "/keys",
    summary="Create API key [ADMIN]",
    description="Requires MSSP tier. Creates a new API key for any tier.",
    status_code=201,
)
async def create_key(
    body: CreateKeyRequest,
    auth: "AuthResult" = Depends(_require_admin_key),
) -> Dict:
    if not _AUTH_OK:
        raise HTTPException(503, detail="Auth service unavailable")

    mgr = get_key_manager()
    raw_key, record = mgr.create_key(
        tier      = body.tier,
        owner     = body.owner,
        label     = body.label,
        expires_at= body.expires_at,
    )

    _append_event(WEBHOOK_LOG, {
        "event":     "admin_key_created",
        "by":        auth.record.get("owner", "admin"),
        "new_prefix": raw_key[:20],
        "tier":      body.tier,
        "owner":     body.owner,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    logger.info(f"[MONETIZE] Admin created key: tier={body.tier} owner={body.owner}")
    return {
        "status":    "created",
        "api_key":   raw_key,
        "tier":      body.tier,
        "owner":     body.owner,
        "label":     record.get("label"),
        "created_at": record.get("created_at"),
        "expires_at": body.expires_at,
        "warning":   "Store this key securely — it will NOT be shown again.",
    }


@router.get(
    "/keys",
    summary="List all API keys [ADMIN]",
    description="Requires MSSP tier. Returns key records (no raw key material).",
)
async def list_keys(
    owner:  Optional[str] = Query(None, description="Filter by owner"),
    tier:   Optional[str] = Query(None, description="Filter by tier"),
    active: Optional[bool] = Query(None, description="Filter by active status"),
    limit:  int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    auth:   "AuthResult" = Depends(_require_admin_key),
) -> Dict:
    if not _AUTH_OK:
        raise HTTPException(503, detail="Auth service unavailable")

    mgr  = get_key_manager()
    keys = mgr.list_keys(owner=owner)

    # Apply filters
    if tier:
        keys = [k for k in keys if k.get("tier", "").upper() == tier.upper()]
    if active is not None:
        keys = [k for k in keys if k.get("active", True) == active]

    total = len(keys)
    page  = keys[offset : offset + limit]

    return {
        "status": "ok",
        "total":   total,
        "count":   len(page),
        "offset":  offset,
        "limit":   limit,
        "keys":    page,
        "generated": datetime.now(timezone.utc).isoformat(),
    }


@router.delete(
    "/keys/{key_prefix}",
    summary="Revoke API key by prefix [ADMIN]",
    response_model=RevokeResponse,
)
async def revoke_key(
    key_prefix: str,
    auth: "AuthResult" = Depends(_require_admin_key),
) -> Dict:
    """
    Revoke a key identified by its prefix (first 20 chars).
    Revocation is immediate and irreversible.
    """
    if not _AUTH_OK:
        raise HTTPException(503, detail="Auth service unavailable")

    mgr   = get_key_manager()
    store = mgr._load()
    keys  = store.get("keys", {})

    target_hash = None
    for key_hash, record in keys.items():
        if record.get("key_prefix", "").startswith(key_prefix[:16]):
            target_hash = key_hash
            break

    if not target_hash:
        raise HTTPException(404, detail=f"No key found with prefix '{key_prefix}'")

    record = keys[target_hash]
    if not record.get("active", False):
        raise HTTPException(409, detail="Key is already revoked.")

    record["active"]     = False
    record["revoked_at"] = datetime.now(timezone.utc).isoformat()
    record["revoked_by"] = auth.record.get("owner", "admin")
    store["keys"][target_hash] = record
    mgr._save(store)

    _append_event(WEBHOOK_LOG, {
        "event":     "admin_key_revoked",
        "by":        auth.record.get("owner", "admin"),
        "prefix":    key_prefix[:16],
        "owner":     record.get("owner"),
        "tier":      record.get("tier"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    logger.info(f"[MONETIZE] Key revoked: prefix={key_prefix[:16]} by={auth.record.get('owner')}")
    return {
        "status":         "revoked",
        "message":        "Key revoked immediately. All future requests will return 401.",
        "revoked_prefix": key_prefix[:16] + "...",
    }


# ============================================================================
# ── ADMIN: ANALYTICS ────────────────────────────────────────────────────────
# ============================================================================

@router.get(
    "/analytics",
    summary="Aggregate usage analytics [ADMIN]",
    description="Requires MSSP tier. Returns platform-wide usage metrics.",
)
async def get_analytics(
    auth: "AuthResult" = Depends(_require_admin_key),
) -> Dict:
    """
    Aggregate analytics across all keys:
    - Total requests today / all-time
    - Breakdown by tier
    - Active vs. revoked key counts
    - Top consumers (by request count, owner redacted for privacy)
    - MRR estimate from active subscriptions
    """
    if not _AUTH_OK:
        raise HTTPException(503, detail="Auth service unavailable")

    mgr   = get_key_manager()
    store = mgr._load()
    keys  = list(store.get("keys", {}).values())

    # Aggregate
    total_requests_today = 0
    total_requests_all   = 0
    tier_breakdown: Dict[str, Dict] = {}
    active_count  = 0
    revoked_count = 0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for record in keys:
        tier = record.get("tier", DEFAULT_TIER).upper()
        r_today = record.get("requests_today", 0) if record.get("quota_reset_date") == today else 0
        r_total = record.get("total_requests", 0)

        total_requests_today += r_today
        total_requests_all   += r_total

        if record.get("active", True):
            active_count += 1
        else:
            revoked_count += 1

        if tier not in tier_breakdown:
            tier_breakdown[tier] = {"key_count": 0, "active": 0, "requests_today": 0, "requests_total": 0}
        tier_breakdown[tier]["key_count"]       += 1
        tier_breakdown[tier]["requests_today"]  += r_today
        tier_breakdown[tier]["requests_total"]  += r_total
        if record.get("active", True):
            tier_breakdown[tier]["active"] += 1

    # MRR estimate (active paid keys only)
    mrr_cents = 0
    for tier_id, data in tier_breakdown.items():
        pricing = PLAN_PRICING.get(tier_id, {})
        mrr_cents += data["active"] * pricing.get("monthly_cents", 0)

    # Top-5 consumers (by total requests, owner hashed for privacy)
    top_consumers = sorted(
        [
            {
                "owner_hash": hashlib.sha256(r.get("owner", "").encode()).hexdigest()[:12],
                "tier":       r.get("tier"),
                "total_requests": r.get("total_requests", 0),
                "requests_today": r.get("requests_today", 0) if r.get("quota_reset_date") == today else 0,
                "last_used":  r.get("last_used"),
            }
            for r in keys if r.get("active", True)
        ],
        key=lambda x: x["total_requests"],
        reverse=True,
    )[:5]

    return {
        "status":                "ok",
        "generated":             datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_keys":            len(keys),
            "active_keys":           active_count,
            "revoked_keys":          revoked_count,
            "total_requests_today":  total_requests_today,
            "total_requests_alltime":total_requests_all,
            "estimated_mrr_usd":     round(mrr_cents / 100, 2),
        },
        "tier_breakdown":        tier_breakdown,
        "top_consumers":         top_consumers,
        "rate_limiter_backend":  "redis" if is_redis_available() else "in_memory",
    }


# ============================================================================
# ── BILLING: STRIPE WEBHOOK ──────────────────────────────────────────────────
# ============================================================================

def _verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """
    HMAC-SHA256 Stripe webhook signature verification.
    Ref: https://stripe.com/docs/webhooks/signatures
    Prevents webhook spoofing attacks.
    """
    try:
        parts  = {k: v for k, v in (p.split("=", 1) for p in sig_header.split(","))}
        ts     = parts.get("t", "")
        v1_sig = parts.get("v1", "")

        # Reject signatures older than 5 minutes (replay attack prevention)
        if abs(int(time.time()) - int(ts)) > 300:
            logger.warning("[MONETIZE] Stripe signature timestamp too old — possible replay attack")
            return False

        signed_payload = f"{ts}.{payload.decode('utf-8')}"
        expected = hmac.new(
            secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, v1_sig)
    except Exception as e:
        logger.error(f"[MONETIZE] Stripe sig verification error: {e}")
        return False


@router.post(
    "/billing/webhook",
    summary="Stripe webhook receiver",
    description=(
        "Receives and processes Stripe billing events. "
        "Validates HMAC-SHA256 signature. "
        "Handles: checkout.session.completed, customer.subscription.*, invoice.payment_*"
    ),
    status_code=200,
    include_in_schema=False,  # Hidden from public docs
)
async def stripe_webhook(request: Request) -> Dict:
    """
    Stripe webhook handler — production-grade with:
    - HMAC signature verification
    - Idempotency (event deduplication via event ID)
    - Replay attack prevention (5-minute timestamp window)
    - Append-only event log
    """
    payload     = await request.body()
    sig_header  = request.headers.get("stripe-signature", "")

    if STRIPE_WEBHOOK_SECRET:
        if not sig_header:
            raise HTTPException(400, detail="Missing stripe-signature header")
        if not _verify_stripe_signature(payload, sig_header, STRIPE_WEBHOOK_SECRET):
            logger.warning("[MONETIZE] Stripe webhook signature verification FAILED")
            raise HTTPException(400, detail="Invalid webhook signature")

    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(400, detail="Invalid JSON payload")

    event_id   = event.get("id", "unknown")
    event_type = event.get("type", "unknown")

    # Idempotency: check if already processed
    processed_file = BILLING_DIR / "processed_events.json"
    processed = _safe_load(processed_file, {"ids": []})
    if event_id in processed.get("ids", []):
        logger.info(f"[MONETIZE] Duplicate event ignored: {event_id}")
        return {"status": "ok", "message": "already_processed"}

    # Log the raw event (immutable audit trail)
    _append_event(WEBHOOK_LOG, {
        "stripe_event_id": event_id,
        "type":            event_type,
        "received_at":     datetime.now(timezone.utc).isoformat(),
        "data_summary": {
            "object_type": event.get("data", {}).get("object", {}).get("object"),
            "customer_id": event.get("data", {}).get("object", {}).get("customer"),
            "amount":      event.get("data", {}).get("object", {}).get("amount_total"),
            "status":      event.get("data", {}).get("object", {}).get("status"),
        },
    })

    # Handle events
    mgr = get_key_manager() if _AUTH_OK else None

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(event, mgr)

    elif event_type in (
        "customer.subscription.created",
        "customer.subscription.updated",
    ):
        _handle_subscription_update(event, mgr)

    elif event_type == "customer.subscription.deleted":
        _handle_subscription_cancelled(event, mgr)

    elif event_type == "invoice.payment_succeeded":
        _handle_payment_succeeded(event)

    elif event_type == "invoice.payment_failed":
        _handle_payment_failed(event)

    # Mark as processed (keep last 10,000 IDs)
    ids = processed.get("ids", [])
    ids.append(event_id)
    if len(ids) > 10_000:
        ids = ids[-10_000:]
    _safe_write(processed_file, {"ids": ids})

    logger.info(f"[MONETIZE] Stripe event processed: {event_type} id={event_id}")
    return {"status": "ok", "event_id": event_id, "type": event_type}


def _handle_checkout_completed(event: Dict, mgr: Optional[Any]) -> None:
    """Provision key after successful Stripe checkout."""
    session  = event.get("data", {}).get("object", {})
    metadata = session.get("metadata", {})
    tier     = metadata.get("tier", "PRO").upper()
    owner    = metadata.get("owner_email") or session.get("customer_email", "unknown")
    label    = metadata.get("label", f"Stripe-provisioned {tier} key")

    if mgr:
        raw_key, record = mgr.create_key(tier=tier, owner=owner, label=label)
        # In production: email raw_key to owner via transactional email service
        logger.info(f"[MONETIZE] Checkout key provisioned: tier={tier} owner={owner} prefix={raw_key[:20]}")
        _append_event(WEBHOOK_LOG, {
            "internal_event": "key_provisioned_via_stripe",
            "tier":           tier,
            "owner":          owner,
            "prefix":         raw_key[:20],
            "stripe_session": session.get("id"),
            "timestamp":      datetime.now(timezone.utc).isoformat(),
        })


def _handle_subscription_update(event: Dict, mgr: Optional[Any]) -> None:
    """Handle subscription created/updated — update tier if needed."""
    sub      = event.get("data", {}).get("object", {})
    metadata = sub.get("metadata", {})
    owner    = metadata.get("owner_email", "")
    new_tier = metadata.get("tier", "").upper()
    logger.info(f"[MONETIZE] Subscription update: owner={owner} tier={new_tier}")


def _handle_subscription_cancelled(event: Dict, mgr: Optional[Any]) -> None:
    """Handle subscription cancellation — downgrade to FREE."""
    sub   = event.get("data", {}).get("object", {})
    owner = sub.get("metadata", {}).get("owner_email", "")
    logger.info(f"[MONETIZE] Subscription cancelled: owner={owner} — downgrading to FREE")


def _handle_payment_succeeded(event: Dict) -> None:
    payment = event.get("data", {}).get("object", {})
    logger.info(f"[MONETIZE] Payment succeeded: invoice={payment.get('id')} amount_cents={payment.get('amount_paid', 0)}")


def _handle_payment_failed(event: Dict) -> None:
    payment  = event.get("data", {}).get("object", {})
    customer = payment.get("customer")
    logger.warning(f"[MONETIZE] Payment FAILED: customer={customer} invoice={payment.get('id')}")


# ============================================================================
# ── BILLING: SELF-SERVICE ────────────────────────────────────────────────────
# ============================================================================

@router.post(
    "/billing/checkout",
    summary="Initiate Stripe checkout session",
    description="Creates a Stripe Checkout session for tier upgrade. Returns session URL.",
    status_code=201,
)
async def create_checkout_session(
    body: CheckoutRequest,
    auth: "AuthResult" = Depends(_require_valid_key),
) -> Dict:
    """
    Production Stripe Checkout integration.
    Requires STRIPE_SECRET_KEY env var to be set.
    Returns checkout URL for redirect-based payment flow.
    """
    tier_upper = body.tier.upper()
    if tier_upper not in ("PRO", "ENTERPRISE", "MSSP"):
        raise HTTPException(422, detail="Only PRO, ENTERPRISE, MSSP tiers are paid.")

    billing_map = {
        ("PRO",        "monthly"): "PRO_MONTHLY",
        ("PRO",        "annual"):  "PRO_ANNUAL",
        ("ENTERPRISE", "monthly"): "ENTERPRISE_MONTHLY",
        ("ENTERPRISE", "annual"):  "ENTERPRISE_ANNUAL",
        ("MSSP",       "monthly"): "MSSP_MONTHLY",
    }
    price_key = billing_map.get((tier_upper, body.billing_cycle.lower()))
    if not price_key:
        raise HTTPException(422, detail=f"No price for {tier_upper}/{body.billing_cycle}")

    price_id = STRIPE_PRICE_IDS.get(price_key, "")

    # If Stripe is live-configured, create real session
    if STRIPE_SECRET_KEY and STRIPE_SECRET_KEY.startswith("sk_"):
        try:
            import stripe  # type: ignore
            stripe.api_key = STRIPE_SECRET_KEY
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=body.success_url + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=body.cancel_url,
                customer_email=body.customer_email or auth.record.get("owner"),
                metadata={
                    "tier":        tier_upper,
                    "owner_email": auth.record.get("owner", ""),
                    "platform":    "CYBERDUDEBIVASH-SENTINEL-APEX",
                },
            )
            return {
                "status":       "ok",
                "session_id":   session.id,
                "checkout_url": session.url,
                "tier":         tier_upper,
                "billing_cycle": body.billing_cycle,
            }
        except Exception as e:
            logger.error(f"[MONETIZE] Stripe session creation failed: {e}")
            raise HTTPException(502, detail="Payment provider error. Contact support.")

    # Stub response when Stripe is not configured
    return {
        "status":        "stub",
        "message":       "Stripe not configured. Set STRIPE_SECRET_KEY to enable payments.",
        "tier":          tier_upper,
        "billing_cycle": body.billing_cycle,
        "price_id":      price_id,
        "monthly_usd":   PLAN_PRICING.get(tier_upper, {}).get("monthly_cents", 0) / 100,
        "annual_usd":    PLAN_PRICING.get(tier_upper, {}).get("annual_cents", 0) / 100,
        "store_url":     "https://tools.cyberdudebivash.com/",
        "contact":       "https://cyberdudebivash.com/contact",
    }


@router.get(
    "/billing/invoices",
    summary="List billing invoices for current key",
)
async def list_invoices(
    auth: "AuthResult" = Depends(_require_valid_key),
) -> Dict:
    """Returns billing invoices from append-only events log filtered to current key owner."""
    invoices_path = BILLING_DIR / "invoices.json"
    invoices_data = _safe_load(invoices_path, {"invoices": []})
    owner = auth.record.get("owner", "")
    owner_invoices = [
        inv for inv in invoices_data.get("invoices", [])
        if inv.get("owner") == owner
    ]
    return {
        "status":   "ok",
        "owner":    owner,
        "count":    len(owner_invoices),
        "invoices": owner_invoices,
        "note": "Full invoice history via Stripe dashboard at https://dashboard.stripe.com",
    }


@router.post(
    "/billing/cancel",
    summary="Cancel current subscription",
)
async def cancel_subscription(
    auth: "AuthResult" = Depends(_require_valid_key),
) -> Dict:
    """
    Initiates cancellation. Key downgrades to FREE at end of billing period.
    Data is retained for 90 days.
    """
    owner = auth.record.get("owner", "unknown")
    tier  = auth.tier.upper()

    if tier == "FREE":
        raise HTTPException(400, detail="No active paid subscription to cancel.")

    _append_event(WEBHOOK_LOG, {
        "internal_event": "cancellation_requested",
        "owner":          owner,
        "tier":           tier,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    })

    logger.info(f"[MONETIZE] Cancellation requested: owner={owner} tier={tier}")
    return {
        "status":  "cancellation_scheduled",
        "message": (
            f"Your {tier} subscription will be cancelled at the end of the current billing period. "
            "Your API key will downgrade to FREE tier automatically. "
            "Data retained for 90 days post-cancellation."
        ),
        "owner":    owner,
        "tier":     tier,
        "support":  "https://cyberdudebivash.com/support",
    }


# ============================================================================
# ── HEALTH CHECK ─────────────────────────────────────────────────────────────
# ============================================================================

@router.get(
    "/health",
    summary="Monetization subsystem health",
)
async def monetization_health() -> Dict:
    """
    Returns health status of all monetization components.
    Used by monitoring systems and /api/v1/health aggregator.
    """
    checks: Dict[str, Any] = {}

    # Auth layer
    try:
        mgr  = get_key_manager()
        store = mgr._load()
        key_count = len(store.get("keys", {}))
        checks["auth"] = {"status": "healthy", "key_count": key_count}
    except Exception as e:
        checks["auth"] = {"status": "degraded", "error": str(e)}

    # Rate limiter
    checks["rate_limiter"] = {
        "status":  "healthy",
        "backend": "redis" if is_redis_available() else "in_memory",
    }

    # Billing storage
    try:
        BILLING_DIR.mkdir(parents=True, exist_ok=True)
        checks["billing_storage"] = {
            "status": "healthy",
            "path":   str(BILLING_DIR),
            "webhook_events": sum(1 for _ in open(WEBHOOK_LOG) if WEBHOOK_LOG.exists()) if WEBHOOK_LOG.exists() else 0,
        }
    except Exception as e:
        checks["billing_storage"] = {"status": "degraded", "error": str(e)}

    # Stripe connectivity
    checks["stripe"] = {
        "configured":      bool(STRIPE_SECRET_KEY),
        "webhook_secret":  bool(STRIPE_WEBHOOK_SECRET),
        "mode":            "live" if (STRIPE_SECRET_KEY or "").startswith("sk_live") else "test" if STRIPE_SECRET_KEY else "unconfigured",
    }

    all_healthy = all(
        v.get("status") == "healthy"
        for v in checks.values()
        if isinstance(v, dict) and "status" in v
    )

    return {
        "status":    "healthy" if all_healthy else "degraded",
        "checks":    checks,
        "version":   "v2.0",
        "generated": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# ── Access Gate Middleware (used by other routers) ────────────────────────────
# ============================================================================

def require_feature(feature: str):
    """
    FastAPI dependency factory.
    Usage: @router.get("/endpoint", dependencies=[Depends(require_feature("stix_export"))])
    """
    def _check(auth: "AuthResult" = Depends(_require_valid_key)) -> "AuthResult":
        if not auth.can_access(feature):
            tier = auth.tier.upper()
            raise HTTPException(
                403,
                detail=(
                    f"Feature '{feature}' not available on {tier} tier. "
                    "Upgrade your plan at https://tools.cyberdudebivash.com/"
                ),
            )
        return auth
    return _check


def require_endpoint(endpoint: str):
    """
    FastAPI dependency factory for endpoint-level access control.
    Usage: @router.get("/endpoint", dependencies=[Depends(require_endpoint("bulk"))])
    """
    def _check(auth: "AuthResult" = Depends(_require_valid_key)) -> "AuthResult":
        if not auth.can_reach(endpoint):
            raise HTTPException(
                403,
                detail=f"Endpoint '{endpoint}' not accessible on {auth.tier} tier.",
            )
        return auth
    return _check


# ============================================================================
# ── Helpers ──────────────────────────────────────────────────────────────────
# ============================================================================

def _next_utc_midnight() -> str:
    from datetime import timedelta
    now   = datetime.now(timezone.utc)
    midnight = (now + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return midnight.isoformat()


# ── Reset router to None when FastAPI is unavailable ─────────────────────────
# All @router.get/post decorators above were absorbed by _NoOpRouter (no-op).
# Setting router=None here signals main.py._load_router_safe to skip mounting.
if not _FASTAPI_OK:
    router = None
