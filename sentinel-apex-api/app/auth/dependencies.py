"""
SENTINEL APEX — Authentication Dependencies
JWT bearer auth + API key auth for FastAPI dependency injection
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.core.security import decode_supabase_token, hash_api_key
from app.db.client import SupabaseDB
from app.schemas.models import TierEnum, UserProfile

logger = logging.getLogger("sentinel.auth")
settings = get_settings()

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class AuthenticatedUser:
    """Represents an authenticated request context."""

    def __init__(
        self,
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        email: Optional[str] = None,
        role: str = "viewer",
        tier: TierEnum = TierEnum.FREE,
        api_key_id: Optional[str] = None,
        rate_limit_daily: int = 10,
        auth_method: str = "jwt",  # "jwt" or "api_key"
    ):
        self.user_id = user_id
        self.org_id = org_id
        self.email = email
        self.role = role
        self.tier = tier
        self.api_key_id = api_key_id
        self.rate_limit_daily = rate_limit_daily
        self.auth_method = auth_method

    @property
    def is_admin(self) -> bool:
        return self.role in ("admin",)

    @property
    def is_pro_or_above(self) -> bool:
        return self.tier in (TierEnum.PRO, TierEnum.ENTERPRISE, TierEnum.MSSP)

    @property
    def is_enterprise(self) -> bool:
        return self.tier in (TierEnum.ENTERPRISE, TierEnum.MSSP)


async def _resolve_jwt(token: str) -> AuthenticatedUser:
    """Resolve a Supabase JWT to an AuthenticatedUser."""
    try:
        payload = decode_supabase_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # Fetch user profile + org
    try:
        result = await SupabaseDB.query(
            "user_profiles",
            select="id,email,full_name,role,org_id,organizations(tier,name)",
            filters={"id": f"eq.{user_id}"},
            single=True,
        )
        profile = result["data"]
    except Exception:
        raise HTTPException(status_code=401, detail="User profile not found")

    org = profile.get("organizations", {}) or {}
    tier_val = org.get("tier", "free")

    tier_limits = {"free": 10, "pro": 1000, "enterprise": 100000, "mssp": 100000}

    return AuthenticatedUser(
        user_id=user_id,
        org_id=profile.get("org_id"),
        email=profile.get("email"),
        role=profile.get("role", "viewer"),
        tier=TierEnum(tier_val),
        rate_limit_daily=tier_limits.get(tier_val, 10),
        auth_method="jwt",
    )


async def _resolve_api_key(key: str) -> AuthenticatedUser:
    """Resolve an API key to an AuthenticatedUser."""
    key_hash = hash_api_key(key)

    try:
        result = await SupabaseDB.query(
            "api_keys",
            select="id,org_id,created_by,tier,rate_limit_daily,scopes,status,expires_at",
            filters={"key_hash": f"eq.{key_hash}", "status": "eq.active"},
            single=True,
        )
        api_key = result["data"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Check expiry
    if api_key.get("expires_at"):
        exp = datetime.fromisoformat(api_key["expires_at"].replace("Z", "+00:00"))
        if exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="API key expired")

    # Update last_used_at (fire-and-forget)
    try:
        await SupabaseDB.update(
            "api_keys",
            {"last_used_at": datetime.now(timezone.utc).isoformat()},
            {"id": f"eq.{api_key['id']}"},
        )
    except Exception:
        pass  # Non-critical

    return AuthenticatedUser(
        user_id=api_key.get("created_by"),
        org_id=api_key.get("org_id"),
        tier=TierEnum(api_key.get("tier", "free")),
        api_key_id=api_key["id"],
        rate_limit_daily=api_key.get("rate_limit_daily", 10),
        auth_method="api_key",
    )


async def get_current_user(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    x_api_key: Optional[str] = Security(api_key_header),
) -> AuthenticatedUser:
    """
    Resolve authentication from either:
    1. Bearer token (Supabase JWT) — used by the web app
    2. X-API-Key header — used by API consumers
    """
    # Try API key first (most common for programmatic access)
    if x_api_key:
        return await _resolve_api_key(x_api_key)

    # Try bearer token
    if bearer and bearer.credentials:
        return await _resolve_jwt(bearer.credentials)

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_optional_user(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    x_api_key: Optional[str] = Security(api_key_header),
) -> Optional[AuthenticatedUser]:
    """Optional auth — returns None if not authenticated (for free public endpoints)."""
    try:
        return await get_current_user(request, bearer, x_api_key)
    except HTTPException:
        return None


def require_tier(*tiers: TierEnum):
    """Dependency factory: require specific subscription tier."""
    async def _check(user: AuthenticatedUser = Depends(get_current_user)):
        if user.tier not in tiers:
            raise HTTPException(
                status_code=403,
                detail=f"This endpoint requires {' or '.join(t.value for t in tiers)} tier. "
                       f"Current tier: {user.tier.value}. Upgrade at https://app.cyberdudebivash.com/billing",
            )
        return user
    return _check


def require_role(*roles: str):
    """Dependency factory: require specific role."""
    async def _check(user: AuthenticatedUser = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {' or '.join(roles)}")
        return user
    return _check
