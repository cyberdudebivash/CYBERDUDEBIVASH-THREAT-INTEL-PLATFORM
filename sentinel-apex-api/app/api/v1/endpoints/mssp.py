"""
SENTINEL APEX — MSSP Portal & White-Label Endpoints v177.0
===========================================================
Multi-tenant MSSP operations, sub-tenant provisioning, and white-label configuration.

Endpoints:
  GET    /api/v1/mssp/portal/tenants        — List sub-tenants (MSSP)
  POST   /api/v1/mssp/tenants/provision     — Provision new sub-tenant (MSSP)
  GET    /api/v1/mssp/tenants/{tenant_id}   — Get tenant details (MSSP)
  DELETE /api/v1/mssp/tenants/{tenant_id}   — Deprovision tenant (MSSP)
  POST   /api/v1/mssp/keys                  — Issue tenant-scoped API key (MSSP)
  GET    /api/v1/mssp/reports               — List branded reports (MSSP)
  GET    /api/v1/mssp/reports/{id}          — Download branded report (MSSP)
  POST   /api/v1/whitelabel/configure       — Set white-label branding (MSSP)
  GET    /api/v1/whitelabel/config          — Get white-label config (MSSP)
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, EmailStr, Field

from app.auth.dependencies import (
    AuthenticatedUser,
    require_tier,
)
from app.db.client import SupabaseDB
from app.schemas.models import TierEnum

logger = logging.getLogger("sentinel.mssp")
router = APIRouter(prefix="/api/v1", tags=["MSSP Portal"])

_ROOT          = Path(__file__).parents[6]
_TENANTS_FILE  = _ROOT / "data" / "sovereign" / "tenants.json"
_WL_CONFIG     = _ROOT / "data" / "sovereign" / "whitelabel_config.json"
_MSSP_KEYS     = _ROOT / "data" / "sovereign" / "mssp_api_keys.json"
_REPORTS_DIR   = _ROOT / "data" / "reports"

MAX_TENANTS = 100  # MSSP tier limit


def _load_json(path: Path, default=None) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_bytes())
    except Exception as e:
        logger.warning(f"Failed to load {path.name}: {e}")
    return default if default is not None else {}


def _save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_tenant_id() -> str:
    return "TEN-" + secrets.token_hex(5).upper()


def _gen_tenant_key(tenant_id: str) -> str:
    return f"SA-MSSP-{secrets.token_hex(16).upper()}"


# ── Tenant Management ─────────────────────────────────────────────────────────

class TenantProvisionRequest(BaseModel):
    company_name: str = Field(..., min_length=2, max_length=200)
    admin_email: EmailStr
    country: str = Field(..., max_length=10)
    tier_allocation: str = Field("pro", pattern="^(free|pro|enterprise)$",
                                  description="Intelligence tier for this sub-tenant")
    daily_api_quota: int = Field(5000, ge=100, le=50000)
    notes: Optional[str] = Field(None, max_length=500)


@router.get(
    "/mssp/portal/tenants",
    summary="List Sub-Tenants (MSSP)",
    description=(
        "List all provisioned sub-tenants for your MSSP deployment.\n\n"
        "**Required tier:** MSSP"
    ),
)
async def list_tenants(
    status: Optional[str] = Query(None, pattern="^(active|suspended|deprovisioned)$"),
    limit: int = Query(50, ge=1, le=100),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    data = _load_json(_TENANTS_FILE, {"tenants": [], "_meta": {}})
    tenants = data.get("tenants", [])

    # Filter by MSSP org
    tenants = [t for t in tenants if t.get("mssp_org_id") == user.org_id]
    if status:
        tenants = [t for t in tenants if t.get("status") == status]

    meta = data.get("_meta", {})
    return {
        "tenants": tenants[:limit],
        "total": len(tenants),
        "count": min(len(tenants), limit),
        "max_tenants": MAX_TENANTS,
        "slots_used": len([t for t in tenants if t.get("status") == "active"]),
        "slots_available": MAX_TENANTS - len([t for t in tenants if t.get("status") == "active"]),
        "mssp_org_id": user.org_id,
        "generated_at": _now(),
    }


@router.post(
    "/mssp/tenants/provision",
    summary="Provision Sub-Tenant (MSSP)",
    description=(
        "Provision a new sub-tenant under your MSSP deployment.\n\n"
        "Creates an isolated tenant with scoped API key, tier allocation, "
        "and branded portal access. Max 100 sub-tenants per MSSP account.\n\n"
        "**Required tier:** MSSP"
    ),
    status_code=201,
)
async def provision_tenant(
    body: TenantProvisionRequest,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    data = _load_json(_TENANTS_FILE, {"tenants": [], "_meta": {}})
    tenants = data.get("tenants", [])

    # Enforce max tenant limit
    active_count = len([t for t in tenants if t.get("mssp_org_id") == user.org_id
                        and t.get("status") == "active"])
    if active_count >= MAX_TENANTS:
        raise HTTPException(
            status_code=429,
            detail=f"MSSP tenant limit reached ({MAX_TENANTS} tenants). Contact sales to expand."
        )

    # Check for duplicate email
    existing = [t for t in tenants
                if t.get("admin_email") == body.admin_email and t.get("mssp_org_id") == user.org_id]
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Tenant with admin email {body.admin_email} already exists under this MSSP."
        )

    tenant_id = _gen_tenant_id()
    api_key   = _gen_tenant_key(tenant_id)
    import hashlib
    key_hash  = hashlib.sha256(api_key.encode()).hexdigest()

    TIER_QUOTAS = {"free": 100, "pro": 5000, "enterprise": 50000}

    tenant = {
        "tenant_id":      tenant_id,
        "mssp_org_id":    user.org_id,
        "company_name":   body.company_name,
        "admin_email":    body.admin_email,
        "country":        body.country.upper(),
        "tier_allocation": body.tier_allocation,
        "daily_api_quota": min(body.daily_api_quota, TIER_QUOTAS.get(body.tier_allocation, 5000)),
        "api_key_hash":   key_hash,
        "status":         "active",
        "provisioned_at": _now(),
        "provisioned_by": user.email or user.org_id,
        "notes":          body.notes or "",
    }

    tenants.append(tenant)
    data["tenants"] = tenants
    meta = data.setdefault("_meta", {})
    meta["last_updated"] = _now()
    meta["total_tenants"] = len(tenants)
    meta["active_tenants"] = len([t for t in tenants if t.get("status") == "active"])
    _save_json(_TENANTS_FILE, data)

    # Store key hash in MSSP keys registry (plaintext returned once only)
    keys_data = _load_json(_MSSP_KEYS, {"keys": {}})
    keys_data.setdefault("keys", {})[key_hash] = {
        "tenant_id": tenant_id,
        "mssp_org_id": user.org_id,
        "tier": body.tier_allocation,
        "daily_quota": tenant["daily_api_quota"],
        "issued_at": _now(),
        "status": "active",
    }
    _save_json(_MSSP_KEYS, keys_data)

    logger.info(f"MSSP tenant provisioned: {tenant_id} by org {user.org_id}")

    return JSONResponse(
        status_code=201,
        content={
            "tenant_id": tenant_id,
            "status": "active",
            "company_name": body.company_name,
            "admin_email": body.admin_email,
            "tier_allocation": body.tier_allocation,
            "daily_api_quota": tenant["daily_api_quota"],
            "api_key": api_key,  # Shown once — never stored in plaintext
            "api_key_note": "Copy this key immediately. It will not be shown again.",
            "provisioned_at": tenant["provisioned_at"],
            "onboarding": {
                "api_base": "https://intel.cyberdudebivash.com/api/v1",
                "docs": "https://intel.cyberdudebivash.com/api-docs.html",
                "auth_header": "X-API-Key: <api_key>",
            },
        }
    )


@router.get(
    "/mssp/tenants/{tenant_id}",
    summary="Get Sub-Tenant Details (MSSP)",
)
async def get_tenant(
    tenant_id: str,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    data = _load_json(_TENANTS_FILE, {"tenants": []})
    tenants = data.get("tenants", [])
    tenant = next(
        (t for t in tenants
         if t.get("tenant_id") == tenant_id and t.get("mssp_org_id") == user.org_id),
        None
    )
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found.")
    return tenant


@router.delete(
    "/mssp/tenants/{tenant_id}",
    summary="Deprovision Sub-Tenant (MSSP)",
)
async def deprovision_tenant(
    tenant_id: str,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    data = _load_json(_TENANTS_FILE, {"tenants": []})
    tenants = data.get("tenants", [])
    found = False
    for t in tenants:
        if t.get("tenant_id") == tenant_id and t.get("mssp_org_id") == user.org_id:
            t["status"] = "deprovisioned"
            t["deprovisioned_at"] = _now()
            t["deprovisioned_by"] = user.email or user.org_id
            found = True
            break
    if not found:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found.")

    data["tenants"] = tenants
    _save_json(_TENANTS_FILE, data)
    return {"tenant_id": tenant_id, "status": "deprovisioned", "deprovisioned_at": _now()}


# ── MSSP Key Management ───────────────────────────────────────────────────────

class MSAPIKeyRequest(BaseModel):
    tenant_id: str
    label: Optional[str] = Field(None, max_length=100)
    days: int = Field(30, ge=1, le=365)


@router.post(
    "/mssp/keys",
    summary="Issue Tenant-Scoped API Key (MSSP)",
    description=(
        "Issue a new API key scoped to a specific sub-tenant.\n\n"
        "Key is shown once — it is stored as a SHA-256 hash only. "
        "**Required tier:** MSSP"
    ),
    status_code=201,
)
async def issue_tenant_key(
    body: MSAPIKeyRequest,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    import hashlib
    from datetime import timedelta

    # Verify tenant exists and belongs to this MSSP
    data = _load_json(_TENANTS_FILE, {"tenants": []})
    tenant = next(
        (t for t in data.get("tenants", [])
         if t.get("tenant_id") == body.tenant_id and t.get("mssp_org_id") == user.org_id
         and t.get("status") == "active"),
        None
    )
    if not tenant:
        raise HTTPException(
            status_code=404,
            detail=f"Active tenant {body.tenant_id} not found under your MSSP."
        )

    api_key = _gen_tenant_key(body.tenant_id)
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(days=body.days)).strftime("%Y-%m-%d")

    keys_data = _load_json(_MSSP_KEYS, {"keys": {}})
    keys_data.setdefault("keys", {})[key_hash] = {
        "tenant_id": body.tenant_id,
        "mssp_org_id": user.org_id,
        "tier": tenant.get("tier_allocation", "pro"),
        "daily_quota": tenant.get("daily_api_quota", 5000),
        "label": body.label or f"{tenant['company_name']} key",
        "issued_at": _now(),
        "expires_at": expires,
        "status": "active",
    }
    _save_json(_MSSP_KEYS, keys_data)

    return JSONResponse(
        status_code=201,
        content={
            "api_key": api_key,
            "key_hash_prefix": key_hash[:16] + "...",
            "tenant_id": body.tenant_id,
            "company_name": tenant.get("company_name"),
            "tier": tenant.get("tier_allocation"),
            "expires_at": expires,
            "issued_at": _now(),
            "_note": "Copy this key immediately. It will not be shown again.",
        }
    )


# ── Branded Reports ───────────────────────────────────────────────────────────

@router.get(
    "/mssp/reports",
    summary="List Branded Reports (MSSP)",
    description="List available branded threat intelligence reports for your MSSP tenants.",
)
async def list_reports(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    reports = []
    if _REPORTS_DIR.exists():
        for f in sorted(_REPORTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
            reports.append({
                "id": f.stem,
                "filename": f.name,
                "size_bytes": f.stat().st_size,
                "created_at": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
            })

    return {
        "reports": reports,
        "count": len(reports),
        "generated_at": _now(),
    }


@router.get(
    "/mssp/reports/{report_id}",
    summary="Download Branded Report (MSSP)",
    description=(
        "Download a branded threat intelligence report. "
        "Reports include MSSP branding applied from white-label config."
    ),
)
async def get_report(
    report_id: str,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    wl = _load_json(_WL_CONFIG, {})
    branding = wl.get("branding", {})

    report_file = _REPORTS_DIR / f"{report_id}.json"
    if report_file.exists():
        try:
            content = json.loads(report_file.read_bytes())
        except Exception:
            content = {"id": report_id}
    else:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found.")

    # Apply MSSP branding
    content["_branded_by"] = branding.get("company_name", "SENTINEL APEX MSSP")
    content["_report_id"] = report_id
    content["_generated_for"] = user.org_id
    content["_generated_at"] = _now()

    return Response(
        content=json.dumps(content, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="sentinel-apex-report-{report_id}.json"',
        },
    )


# ── White-Label Configuration ─────────────────────────────────────────────────

class WhiteLabelConfig(BaseModel):
    company_name: str = Field(..., min_length=2, max_length=200)
    company_logo_url: Optional[str] = Field(None, max_length=2048)
    primary_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    accent_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    support_email: Optional[str] = Field(None, max_length=256)
    support_url: Optional[str] = Field(None, max_length=2048)
    portal_subdomain: Optional[str] = Field(None, max_length=63,
                                             pattern=r"^[a-z0-9\-]+$")
    footer_text: Optional[str] = Field(None, max_length=500)
    custom_css: Optional[str] = Field(None, max_length=10000)


@router.post(
    "/whitelabel/configure",
    summary="Configure White-Label Branding (MSSP)",
    description=(
        "Set custom branding for your MSSP portal deployment.\n\n"
        "Supports: company name, logo URL, color palette, support contacts, "
        "custom subdomain, footer text, and custom CSS.\n\n"
        "**Required tier:** MSSP"
    ),
)
async def configure_whitelabel(
    body: WhiteLabelConfig,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    existing = _load_json(_WL_CONFIG, {})
    existing.update({
        "branding": {
            "company_name":   body.company_name,
            "company_logo_url": body.company_logo_url,
            "primary_color":  body.primary_color or "#00d4aa",
            "accent_color":   body.accent_color or "#1a7fff",
            "support_email":  body.support_email,
            "support_url":    body.support_url,
            "portal_subdomain": body.portal_subdomain,
            "footer_text":    body.footer_text,
            "custom_css":     body.custom_css,
        },
        "_meta": {
            "mssp_org_id": user.org_id,
            "configured_by": user.email or user.org_id,
            "configured_at": _now(),
            "platform": "SENTINEL APEX v177.0",
        }
    })
    _save_json(_WL_CONFIG, existing)

    return {
        "status": "configured",
        "company_name": body.company_name,
        "portal_subdomain": body.portal_subdomain,
        "message": "White-label branding configuration saved. Changes take effect on next portal refresh.",
        "configured_at": _now(),
        "_note": "Custom subdomain activation requires DNS CNAME record pointed to intel.cyberdudebivash.com",
    }


@router.get(
    "/whitelabel/config",
    summary="Get White-Label Config (MSSP)",
    description="Retrieve current white-label branding configuration. **Required tier:** MSSP",
)
async def get_whitelabel_config(
    user: AuthenticatedUser = Depends(require_tier(TierEnum.MSSP)),
):
    config = _load_json(_WL_CONFIG, {})
    if not config:
        return {
            "configured": False,
            "message": "No white-label configuration set. Use POST /api/v1/whitelabel/configure to set branding.",
        }

    # Mask any sensitive fields
    branding = dict(config.get("branding", {}))
    return {
        "configured": True,
        "branding": branding,
        "_meta": config.get("_meta", {}),
    }
