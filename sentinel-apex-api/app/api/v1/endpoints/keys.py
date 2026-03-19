"""
SENTINEL APEX — API Key Management Endpoints
Generate, list, revoke API keys for programmatic access
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import AuthenticatedUser, get_current_user, require_role
from app.core.security import generate_api_key
from app.db.client import SupabaseDB
from app.schemas.models import (
    APIKeyCreateRequest,
    APIKeyCreatedResponse,
    APIKeyListResponse,
    APIKeyResponse,
)

logger = logging.getLogger("sentinel.apikeys")
router = APIRouter(prefix="/api/v1/keys", tags=["API Keys"])

# Tier → rate limit mapping
TIER_LIMITS = {"free": 10, "pro": 1000, "enterprise": 100000, "mssp": 100000}
TIER_SCOPES = {
    "free": ["feed:read"],
    "pro": ["feed:read", "search:read", "stix:read", "rules:read"],
    "enterprise": ["feed:read", "search:read", "stix:read", "rules:read", "analyze:write", "alerts:write", "webhooks:write"],
    "mssp": ["feed:read", "search:read", "stix:read", "rules:read", "analyze:write", "alerts:write", "webhooks:write", "admin:all"],
}
MAX_KEYS_PER_TIER = {"free": 2, "pro": 5, "enterprise": 20, "mssp": 50}


@router.post("", response_model=APIKeyCreatedResponse, status_code=201)
async def create_api_key(
    body: APIKeyCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Generate a new API key. The full key is returned ONLY in this response.
    Store it securely — it cannot be retrieved again.
    """
    # Check key limit for tier
    existing = await SupabaseDB.query(
        "api_keys",
        select="id",
        filters={"org_id": f"eq.{user.org_id}", "status": "eq.active"},
    )
    max_keys = MAX_KEYS_PER_TIER.get(user.tier.value, 2)
    if len(existing["data"]) >= max_keys:
        raise HTTPException(
            status_code=403,
            detail=f"Maximum {max_keys} active API keys for {user.tier.value} tier. Revoke an existing key or upgrade.",
        )

    # Generate key
    full_key, prefix_display, key_hash = generate_api_key()
    tier = user.tier.value
    rate_limit = TIER_LIMITS.get(tier, 10)
    scopes = TIER_SCOPES.get(tier, ["feed:read"])

    # Store in database
    row = {
        "org_id": user.org_id,
        "created_by": user.user_id,
        "key_prefix": prefix_display,
        "key_hash": key_hash,
        "name": body.name,
        "tier": tier,
        "rate_limit_daily": rate_limit,
        "scopes": scopes,
        "status": "active",
    }

    result = await SupabaseDB.insert("api_keys", row)
    created = result["data"][0] if isinstance(result["data"], list) else result["data"]

    # Audit log
    try:
        await SupabaseDB.insert("audit_log", {
            "user_id": user.user_id,
            "org_id": user.org_id,
            "action": "api_key.created",
            "resource_type": "api_key",
            "resource_id": created["id"],
            "details": {"name": body.name, "tier": tier},
        })
    except Exception:
        pass

    return APIKeyCreatedResponse(
        id=created["id"],
        name=body.name,
        key_prefix=prefix_display,
        api_key=full_key,  # Only time the full key is exposed
        tier=tier,
        rate_limit_daily=rate_limit,
        scopes=scopes,
        status="active",
        created_at=created.get("created_at", datetime.now(timezone.utc).isoformat()),
        last_used_at=None,
    )


@router.get("", response_model=APIKeyListResponse)
async def list_api_keys(user: AuthenticatedUser = Depends(get_current_user)):
    """List all API keys for the current organization."""
    result = await SupabaseDB.query(
        "api_keys",
        select="id,name,key_prefix,tier,rate_limit_daily,scopes,status,created_at,last_used_at",
        filters={"org_id": f"eq.{user.org_id}"},
        order="created_at.desc",
    )

    keys = [
        APIKeyResponse(
            id=k["id"],
            name=k["name"],
            key_prefix=k["key_prefix"],
            tier=k["tier"],
            rate_limit_daily=k["rate_limit_daily"],
            scopes=k.get("scopes", []),
            status=k["status"],
            created_at=k["created_at"],
            last_used_at=k.get("last_used_at"),
        )
        for k in result["data"]
    ]
    return APIKeyListResponse(keys=keys, count=len(keys))


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Revoke an API key. This action is irreversible."""
    # Verify ownership
    existing = await SupabaseDB.query(
        "api_keys",
        select="id,org_id,status",
        filters={"id": f"eq.{key_id}", "org_id": f"eq.{user.org_id}"},
    )
    if not existing["data"]:
        raise HTTPException(status_code=404, detail="API key not found")

    if existing["data"][0]["status"] == "revoked":
        raise HTTPException(status_code=400, detail="API key already revoked")

    await SupabaseDB.update(
        "api_keys",
        {"status": "revoked", "revoked_at": datetime.now(timezone.utc).isoformat()},
        {"id": f"eq.{key_id}"},
    )

    # Audit
    try:
        await SupabaseDB.insert("audit_log", {
            "user_id": user.user_id,
            "org_id": user.org_id,
            "action": "api_key.revoked",
            "resource_type": "api_key",
            "resource_id": key_id,
        })
    except Exception:
        pass

    return {"status": "revoked", "key_id": key_id}
