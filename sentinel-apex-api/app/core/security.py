"""
SENTINEL APEX — Security Utilities
JWT handling, API key generation, hashing
"""
from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
import bcrypt as _bcrypt

from app.core.config import get_settings

settings = get_settings()


# ── JWT Token Management ─────────────────────────────────────────────

def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": "access"})
    return jwt.encode(to_encode, settings.SUPABASE_JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": "refresh"})
    return jwt.encode(to_encode, settings.SUPABASE_JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate JWT. Raises jwt.InvalidTokenError on failure."""
    return jwt.decode(
        token,
        settings.SUPABASE_JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "sub"]},
    )


def decode_supabase_token(token: str) -> dict[str, Any]:
    """Decode Supabase-issued JWT (used for auth flow)."""
    return jwt.decode(
        token,
        settings.SUPABASE_JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        audience="authenticated",
        options={"require": ["exp", "sub"]},
    )


# ── API Key Management ───────────────────────────────────────────────

def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.
    Returns: (full_key, key_prefix_display, key_hash)
    """
    raw = secrets.token_hex(32)  # 64 char hex string
    full_key = f"{settings.API_KEY_PREFIX}{raw}"
    prefix_display = f"{settings.API_KEY_PREFIX}{raw[:8]}..."
    key_hash = hash_api_key(full_key)
    return full_key, prefix_display, key_hash


def hash_api_key(key: str) -> str:
    """SHA-256 hash of API key for storage."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ── Password Hashing ─────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
