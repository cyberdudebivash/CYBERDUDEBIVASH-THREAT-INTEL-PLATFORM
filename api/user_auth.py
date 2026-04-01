#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — USER AUTHENTICATION SYSTEM v1.0         ║
║  JWT sessions · bcrypt-equivalent hashing · Register / Login / Me         ║
║  Zero-dependency: uses hashlib+hmac (no bcrypt package required)           ║
╚══════════════════════════════════════════════════════════════════════════════╝
Endpoints (mounted at /auth/*):
  POST /auth/register   — create account
  POST /auth/login      — get JWT token
  GET  /auth/me         — current user profile + API keys
  POST /auth/logout     — invalidate token
  POST /auth/apikey/generate  — self-service API key creation

Security:
  - Passwords: PBKDF2-SHA256, 260,000 iterations, 32-byte salt
  - JWTs: HS256, HMAC-SHA256, 24h expiry
  - Tokens: invalidated server-side via jti deny-list
  - No raw passwords stored — ever
  - Constant-time comparison for all secret comparisons
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-USER-AUTH")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
AUTH_DIR   = BASE_DIR / "data" / "auth"
USERS_DB   = AUTH_DIR / "users.json"
TOKENS_DB  = AUTH_DIR / "active_tokens.json"

# ── Config ────────────────────────────────────────────────────────────────────
JWT_SECRET_ENV = "JWT_SECRET"
JWT_ALGO       = "HS256"
JWT_EXPIRY_H   = 24          # hours
PBKDF2_ITERS   = 260_000
PBKDF2_HASH    = "sha256"
SALT_BYTES     = 32

# ── FastAPI imports (graceful if missing) ─────────────────────────────────────
try:
    from fastapi import APIRouter, HTTPException, Header, Depends, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, EmailStr, field_validator
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False
    class APIRouter:
        def post(self, *a, **kw): return lambda f: f
        def get(self,  *a, **kw): return lambda f: f
    class BaseModel: pass
    def Header(default=None): return None

# ── Pydantic models ───────────────────────────────────────────────────────────
if _FASTAPI_OK:
    from pydantic import BaseModel as PM

    class RegisterRequest(PM):
        email:    str
        password: str
        name:     str = ""

    class LoginRequest(PM):
        email:    str
        password: str

    class APIKeyGenRequest(PM):
        tier:  str = "FREE"
        label: str = ""

# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_write(path: Path, data: Any) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.error(f"Write failed {path}: {e}")
        try: tmp.unlink(missing_ok=True)
        except Exception: pass
        return False


def _safe_load(path: Path, default: Any = None) -> Any:
    try:
        if path.exists() and path.stat().st_size > 0:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Load failed {path}: {e}")
    return default if default is not None else {}


def _get_jwt_secret() -> str:
    s = os.environ.get(JWT_SECRET_ENV, "")
    if not s:
        # Deterministic fallback from machine-specific entropy (dev only)
        s = hashlib.sha256(
            (str(BASE_DIR) + "cdb-sentinel-apex-jwt-fallback").encode()
        ).hexdigest()
    return s


def _hash_password(password: str) -> str:
    """PBKDF2-SHA256 with random salt. Returns 'salt:hash' both hex."""
    salt = secrets.token_hex(SALT_BYTES)
    dk   = hashlib.pbkdf2_hmac(PBKDF2_HASH, password.encode(), salt.encode(), PBKDF2_ITERS)
    return f"{salt}:{dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Constant-time password verification."""
    try:
        salt, expected = stored.split(":", 1)
        dk = hashlib.pbkdf2_hmac(PBKDF2_HASH, password.encode(), salt.encode(), PBKDF2_ITERS)
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False


def _validate_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email.strip().lower()))


def _validate_password(pw: str) -> Tuple[bool, str]:
    if len(pw) < 8:
        return False, "Password must be at least 8 characters"
    if len(pw) > 128:
        return False, "Password too long (max 128 chars)"
    return True, ""

# ── JWT (pure Python, no external lib) ───────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def create_jwt(user_id: str, email: str, tier: str = "FREE") -> str:
    """Create HS256 JWT token."""
    secret = _get_jwt_secret()
    now    = int(time.time())
    jti    = secrets.token_hex(16)
    header  = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "tier": tier,
        "iat": now,
        "exp": now + JWT_EXPIRY_H * 3600,
        "jti": jti,
    }
    h_enc = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_enc = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    msg   = f"{h_enc}.{p_enc}"
    sig   = hmac.new(secret.encode(), msg.encode(), "sha256").digest()
    return f"{msg}.{_b64url(sig)}"


def verify_jwt(token: str) -> Tuple[bool, Optional[Dict], str]:
    """Verify JWT. Returns (valid, payload, error_msg)."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return False, None, "malformed token"
        h_enc, p_enc, sig_enc = parts
        secret = _get_jwt_secret()
        msg    = f"{h_enc}.{p_enc}"
        expected_sig = hmac.new(secret.encode(), msg.encode(), "sha256").digest()
        if not hmac.compare_digest(_b64url_decode(sig_enc), expected_sig):
            return False, None, "invalid signature"
        payload = json.loads(_b64url_decode(p_enc))
        if payload.get("exp", 0) < time.time():
            return False, None, "token expired"
        # Check deny-list
        jti = payload.get("jti", "")
        deny = _safe_load(TOKENS_DB, {}).get("revoked", [])
        if jti in deny:
            return False, None, "token revoked"
        return True, payload, ""
    except Exception as e:
        return False, None, str(e)

# ── User Store ────────────────────────────────────────────────────────────────

def _load_users() -> Dict:
    return _safe_load(USERS_DB, {"users": {}, "by_email": {}})


def _save_users(db: Dict) -> bool:
    return _safe_write(USERS_DB, db)


def get_user_by_email(email: str) -> Optional[Dict]:
    db = _load_users()
    uid = db.get("by_email", {}).get(email.lower().strip())
    return db["users"].get(uid) if uid else None


def get_user_by_id(user_id: str) -> Optional[Dict]:
    return _load_users()["users"].get(user_id)


def register_user(email: str, password: str, name: str = "") -> Tuple[bool, str, Optional[Dict]]:
    """Register new user. Returns (success, message, user_record)."""
    email = email.lower().strip()
    if not _validate_email(email):
        return False, "Invalid email address", None
    ok, msg = _validate_password(password)
    if not ok:
        return False, msg, None

    db = _load_users()
    if email in db.get("by_email", {}):
        return False, "Email already registered", None

    user_id  = f"usr_{secrets.token_hex(12)}"
    pw_hash  = _hash_password(password)
    now      = datetime.now(timezone.utc).isoformat()
    record   = {
        "user_id":    user_id,
        "email":      email,
        "name":       (name or "").strip()[:80],
        "pw_hash":    pw_hash,
        "tier":       "FREE",
        "created_at": now,
        "last_login": None,
        "api_keys":   [],
        "active":     True,
    }
    db.setdefault("users", {})[user_id]       = record
    db.setdefault("by_email", {})[email]      = user_id
    if not _save_users(db):
        return False, "Storage error — please retry", None

    safe_record = {k: v for k, v in record.items() if k != "pw_hash"}
    logger.info(f"[REGISTER] New user: {email} ({user_id})")
    return True, "Account created", safe_record


def login_user(email: str, password: str) -> Tuple[bool, str, Optional[str], Optional[Dict]]:
    """Login. Returns (success, message, jwt_token, user_record)."""
    email = email.lower().strip()
    user  = get_user_by_email(email)
    if not user:
        # Constant-time fail — prevent user enumeration
        _verify_password(password, "dummy_salt:0000000000000000")
        return False, "Invalid credentials", None, None
    if not user.get("active", True):
        _verify_password(password, "dummy_salt:0000000000000000")
        return False, "Account disabled", None, None
    if not _verify_password(password, user.get("pw_hash", "")):
        return False, "Invalid credentials", None, None

    # Update last_login
    db = _load_users()
    db["users"][user["user_id"]]["last_login"] = datetime.now(timezone.utc).isoformat()
    _save_users(db)

    token = create_jwt(user["user_id"], email, user.get("tier", "FREE"))
    safe_user = {k: v for k, v in user.items() if k != "pw_hash"}
    logger.info(f"[LOGIN] {email}")
    return True, "Login successful", token, safe_user


def revoke_token(jti: str) -> None:
    """Add jti to deny-list."""
    db  = _safe_load(TOKENS_DB, {"revoked": []})
    rev = db.get("revoked", [])
    if jti not in rev:
        rev.append(jti)
        # Prune old entries (keep last 1000)
        db["revoked"] = rev[-1000:]
        _safe_write(TOKENS_DB, db)

# ── API Key self-service ──────────────────────────────────────────────────────

def add_api_key_to_user(user_id: str, raw_key: str, tier: str, label: str = "") -> bool:
    db = _load_users()
    user = db["users"].get(user_id)
    if not user:
        return False
    entry = {
        "key_prefix": raw_key[:20] + "..." if len(raw_key) > 20 else raw_key,
        "key_hash":   hashlib.sha256(raw_key.encode()).hexdigest()[:16],
        "tier":       tier,
        "label":      label,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    db["users"][user_id].setdefault("api_keys", []).append(entry)
    return _save_users(db)

# ── FastAPI Router ─────────────────────────────────────────────────────────────

if _FASTAPI_OK:
    auth_router = APIRouter(prefix="/auth", tags=["User Authentication"])

    def _get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict:
        """Dependency: extract + verify JWT from Authorization: Bearer <token>."""
        if not authorization:
            raise HTTPException(401, {"error": "Authorization header required", "login": "/auth/login"})
        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(401, {"error": "Bearer token required"})
        valid, payload, err = verify_jwt(parts[1])
        if not valid:
            raise HTTPException(401, {"error": f"Invalid token: {err}", "login": "/auth/login"})
        user = get_user_by_id(payload["sub"])
        if not user:
            raise HTTPException(401, {"error": "User not found"})
        return {**user, "_jwt_payload": payload}

    @auth_router.post("/register", summary="Create user account")
    async def register(req: RegisterRequest):
        ok, msg, user = register_user(req.email, req.password, req.name)
        if not ok:
            raise HTTPException(400, {"error": msg})
        return {
            "status":  "ok",
            "message": msg,
            "user_id": user["user_id"],
            "email":   user["email"],
            "tier":    user["tier"],
        }

    @auth_router.post("/login", summary="Login and get JWT token")
    async def login(req: LoginRequest):
        ok, msg, token, user = login_user(req.email, req.password)
        if not ok:
            raise HTTPException(401, {"error": msg})
        tier_info = {
            "FREE":       {"price": "$0/mo",    "advisories": 10,  "req_per_day": 100},
            "PRO":        {"price": "$49/mo",   "advisories": 100, "req_per_day": 5000},
            "ENTERPRISE": {"price": "$499/mo",  "advisories": 500, "req_per_day": 50000},
            "MSSP":       {"price": "$1999/mo", "advisories": "∞", "req_per_day": "∞"},
        }.get(user.get("tier", "FREE"), {})
        return {
            "status":      "ok",
            "token":       token,
            "token_type":  "bearer",
            "expires_in":  JWT_EXPIRY_H * 3600,
            "user": {
                "user_id":    user["user_id"],
                "email":      user["email"],
                "name":       user.get("name", ""),
                "tier":       user.get("tier", "FREE"),
                "tier_info":  tier_info,
                "api_keys":   user.get("api_keys", []),
                "created_at": user.get("created_at", ""),
                "last_login": user.get("last_login", ""),
            },
        }

    @auth_router.get("/me", summary="Current user profile + API keys")
    async def get_me(current_user: Dict = Depends(_get_current_user)):
        safe = {k: v for k, v in current_user.items() if k not in ("pw_hash", "_jwt_payload")}
        return {"status": "ok", "user": safe}

    @auth_router.post("/logout", summary="Invalidate current session")
    async def logout(current_user: Dict = Depends(_get_current_user)):
        jti = current_user.get("_jwt_payload", {}).get("jti", "")
        if jti:
            revoke_token(jti)
        return {"status": "ok", "message": "Logged out"}

    @auth_router.post("/apikey/generate", summary="Generate API key for current user")
    async def generate_key(req: APIKeyGenRequest, current_user: Dict = Depends(_get_current_user)):
        tier = req.tier.upper()
        if tier not in ("FREE", "PRO", "ENTERPRISE", "MSSP"):
            raise HTTPException(400, {"error": f"Invalid tier: {tier}"})

        # Import key manager from auth module
        try:
            from api.auth import get_key_manager
            mgr = get_key_manager()
        except ImportError:
            try:
                import sys
                sys.path.insert(0, str(BASE_DIR))
                from api.auth import get_key_manager
                mgr = get_key_manager()
            except Exception as e:
                raise HTTPException(500, {"error": f"Key manager unavailable: {e}"})

        raw_key = mgr.create_key(
            tier=tier,
            owner=current_user["email"],
            label=req.label or f"Self-service {tier} key",
        )
        # Attach to user record
        add_api_key_to_user(current_user["user_id"], raw_key, tier, req.label)

        masked = raw_key[:12] + "*" * (len(raw_key) - 16) + raw_key[-4:]
        tier_limits = {
            "FREE":       {"req_per_day": 100,    "advisories_per_req": 10},
            "PRO":        {"req_per_day": 5000,   "advisories_per_req": 100},
            "ENTERPRISE": {"req_per_day": 50000,  "advisories_per_req": 500},
            "MSSP":       {"req_per_day": -1,     "advisories_per_req": -1},
        }.get(tier, {})
        return {
            "status":       "ok",
            "api_key":      raw_key,        # show once, never again
            "api_key_masked": masked,
            "tier":         tier,
            "limits":       tier_limits,
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "warning":      "Save this key immediately — it will NOT be shown again",
            "docs":         "/api/docs",
        }

    @auth_router.post("/apikey/generate-free", summary="Generate free API key (no auth required)")
    async def generate_free_key():
        """Zero-friction free tier key — no registration required."""
        try:
            from api.auth import get_key_manager
        except ImportError:
            import sys
            sys.path.insert(0, str(BASE_DIR))
            from api.auth import get_key_manager

        mgr     = get_key_manager()
        raw_key, _ = mgr.create_key(tier="FREE", owner="anonymous", label="Self-service free key")
        masked  = raw_key[:12] + "..." + raw_key[-4:]
        return {
            "status":         "ok",
            "api_key":        raw_key,
            "api_key_masked": masked,
            "tier":           "FREE",
            "limits":         {"req_per_day": 100, "advisories_per_req": 10},
            "upgrade_url":    "https://tools.cyberdudebivash.com",
            "docs":           "/api/docs",
            "warning":        "Save this key — it will not be shown again",
        }
else:
    auth_router = None
