"""
SENTINEL APEX — Auth Endpoints
User registration, login, token refresh, OAuth
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.db.client import SupabaseAuth, SupabaseDB
from app.schemas.models import (
    AuthResponse,
    OAuthRequest,
    RefreshRequest,
    SignInRequest,
    SignUpRequest,
    TierEnum,
    UserProfile,
)

logger = logging.getLogger("sentinel.auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/signup", response_model=AuthResponse, status_code=201)
async def signup(body: SignUpRequest):
    """
    Register a new user account.
    Creates user in Supabase Auth → triggers auto-creation of org + profile.
    """
    try:
        result = await SupabaseAuth.sign_up(
            email=body.email,
            password=body.password,
            metadata={"full_name": body.full_name} if body.full_name else {},
        )
    except Exception as e:
        error_msg = str(e)
        if "already registered" in error_msg.lower() or "422" in error_msg:
            raise HTTPException(status_code=409, detail="Email already registered")
        logger.error(f"Signup error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

    session = result.get("session") or {}
    user = result.get("user", {})

    if not session.get("access_token"):
        # Email confirmation required (Supabase setting)
        return AuthResponse(
            access_token="",
            refresh_token=None,
            token_type="bearer",
            expires_in=0,
            user=UserProfile(
                id=user.get("id", ""),
                email=body.email,
                full_name=body.full_name,
                role="admin",
                org_id="pending",
                tier=TierEnum.FREE,
            ),
        )

    # Direct login (no email confirmation)
    profile = await _build_user_profile(user["id"])

    return AuthResponse(
        access_token=session["access_token"],
        refresh_token=session.get("refresh_token"),
        token_type="bearer",
        expires_in=session.get("expires_in", 3600),
        user=profile,
    )


@router.post("/signin", response_model=AuthResponse)
async def signin(body: SignInRequest):
    """Authenticate with email and password."""
    try:
        result = await SupabaseAuth.sign_in(body.email, body.password)
    except Exception as e:
        error_msg = str(e)
        if "400" in error_msg or "invalid" in error_msg.lower():
            raise HTTPException(status_code=401, detail="Invalid email or password")
        logger.error(f"Signin error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

    user = result.get("user", {})
    profile = await _build_user_profile(user["id"])

    # Update last login
    try:
        await SupabaseDB.update(
            "user_profiles",
            {"last_login_at": datetime.now(timezone.utc).isoformat()},
            {"id": f"eq.{user['id']}"},
        )
    except Exception:
        pass

    return AuthResponse(
        access_token=result["access_token"],
        refresh_token=result.get("refresh_token"),
        token_type="bearer",
        expires_in=result.get("expires_in", 3600),
        user=profile,
    )


@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(body: RefreshRequest):
    """Refresh an expired access token."""
    try:
        result = await SupabaseAuth.refresh_session(body.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = result.get("user", {})
    profile = await _build_user_profile(user["id"])

    return AuthResponse(
        access_token=result["access_token"],
        refresh_token=result.get("refresh_token"),
        token_type="bearer",
        expires_in=result.get("expires_in", 3600),
        user=profile,
    )


@router.post("/oauth")
async def oauth_login(body: OAuthRequest):
    """Get OAuth provider URL for SSO login (Google, GitHub)."""
    try:
        result = await SupabaseAuth.sign_in_with_oauth(body.provider, body.redirect_to)
        return {"url": result["url"], "provider": body.provider}
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        raise HTTPException(status_code=500, detail="OAuth initialization failed")


@router.get("/me", response_model=UserProfile)
async def get_me(user: AuthenticatedUser = Depends(get_current_user)):
    """Get current authenticated user profile."""
    return await _build_user_profile(user.user_id)


# ── Helpers ───────────────────────────────────────────────────────────

async def _build_user_profile(user_id: str) -> UserProfile:
    """Build UserProfile from database."""
    try:
        result = await SupabaseDB.query(
            "user_profiles",
            select="id,email,full_name,role,org_id,created_at,organizations(name,tier)",
            filters={"id": f"eq.{user_id}"},
            single=True,
        )
        p = result["data"]
        org = p.get("organizations", {}) or {}
        return UserProfile(
            id=p["id"],
            email=p["email"],
            full_name=p.get("full_name"),
            role=p.get("role", "viewer"),
            org_id=p["org_id"],
            org_name=org.get("name"),
            tier=org.get("tier", "free"),
            created_at=p.get("created_at"),
        )
    except Exception as e:
        logger.error(f"Profile fetch error for {user_id}: {e}")
        return UserProfile(id=user_id, email="", org_id="", tier=TierEnum.FREE)
