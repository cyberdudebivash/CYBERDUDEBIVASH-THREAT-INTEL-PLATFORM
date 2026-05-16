#!/usr/bin/env python3
"""
auth_v2.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
RS256 JWT AUTHENTICATION UPGRADE

Provides RS256 asymmetric JWT issuance and verification as an additive
upgrade over the existing HS256 auth module (agent/api/auth.py).

Key capabilities:
  - RS256 JWT issuance (private key) + verification (public key)
  - JWKS endpoint data for /.well-known/jwks.json (OIDC/SIEM federation)
  - 15-minute access tokens + refresh token metadata
  - Unique token IDs (jti) for revocation support
  - Full backward compatibility: HS256 tokens still verified during migration

Migration:
  Week 1-2: Deploy RS256 keys. New tokens issued in RS256. HS256 still accepted.
  Week 4:   Log warning on HS256 token usage. Notify API consumers.
  Week 8:   Disable HS256 JWT verification (API key auth unaffected).

Required env vars:
  CDB_JWT_PRIVATE_KEY   PEM-encoded RSA-2048+ private key (base64 or multiline)
  CDB_JWT_PUBLIC_KEY    PEM-encoded RSA public key (or auto-derived from private)

Rollback: unset CDB_JWT_PRIVATE_KEY → module degrades gracefully, falls back
  to HS256 auth handler for all operations.
"""

import os
import uuid
import time
import base64
import json
import logging
from typing import Optional, Dict, Tuple
from datetime import datetime, timezone, timedelta

import jwt  # pyjwt[crypto] — already in requirements.txt

logger = logging.getLogger("CDB-AUTH-V2")

# ─── Configuration ──────────────────────────────────────────────────────────
_PRIVATE_KEY_PEM   = os.environ.get("CDB_JWT_PRIVATE_KEY", "")
_PUBLIC_KEY_PEM    = os.environ.get("CDB_JWT_PUBLIC_KEY", "")
_ISSUER            = os.environ.get("CDB_API_BASE_URL", "https://api.cyberdudebivash.com")
_AUDIENCE          = os.environ.get("CDB_JWT_AUDIENCE", "cyberdudebivash.com")
_ACCESS_TOKEN_TTL  = int(os.environ.get("CDB_JWT_ACCESS_TTL_SECONDS",  "900"))    # 15 min
_REFRESH_TOKEN_TTL = int(os.environ.get("CDB_JWT_REFRESH_TTL_SECONDS", "604800"))  # 7 days
_KEY_ID            = "cdb-rs256-1"

# ─── Tier model (mirrors auth.py) ───────────────────────────────────────────
TIER_FREE       = "FREE"
TIER_STANDARD   = "STANDARD"
TIER_PREMIUM    = "PREMIUM"
TIER_ENTERPRISE = "ENTERPRISE"
TIER_MSSP       = "MSSP"


def _normalize_pem(raw: str) -> str:
    """Handle both raw PEM and base64-encoded PEM from env vars."""
    raw = raw.strip()
    if raw.startswith("-----"):
        return raw
    # Try base64 decode
    try:
        decoded = base64.b64decode(raw).decode("utf-8")
        if decoded.startswith("-----"):
            return decoded
    except Exception:
        pass
    return raw


class AuthHandlerV2:
    """
    RS256 JWT authentication handler.
    Additive upgrade over AuthHandler — same interface, stronger algorithm.
    """

    def __init__(self):
        self._private_key = None
        self._public_key  = None
        self._ready       = False
        self._init_keys()

    def _init_keys(self) -> None:
        if not _PRIVATE_KEY_PEM:
            logger.info("[AUTH-V2] No RSA private key — RS256 JWT issuance disabled (HS256 active)")
            return
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend

            priv_pem = _normalize_pem(_PRIVATE_KEY_PEM).encode()
            self._private_key = load_pem_private_key(priv_pem, password=None, backend=default_backend())

            if _PUBLIC_KEY_PEM:
                pub_pem = _normalize_pem(_PUBLIC_KEY_PEM).encode()
                self._public_key = load_pem_public_key(pub_pem, backend=default_backend())
            else:
                # Derive public key from private key
                self._public_key = self._private_key.public_key()

            self._ready = True
            logger.info("[AUTH-V2] RS256 key pair loaded — enterprise JWT active")

        except Exception as e:
            logger.error(f"[AUTH-V2] Key loading failed: {e} — RS256 disabled")

    @property
    def is_ready(self) -> bool:
        return self._ready

    # ─── Token Issuance ─────────────────────────────────────────────────────

    def issue_access_token(
        self,
        identity:    str,
        tier:        str,
        org_id:      Optional[str] = None,
        workspace_id: Optional[str] = None,
        scopes:      Optional[list] = None,
    ) -> Optional[str]:
        """
        Issue RS256 access token with 15-minute expiry.
        Returns None if RS256 keys not configured (HS256 fallback active).
        """
        if not self._ready:
            return None

        now = datetime.now(timezone.utc)
        jti = str(uuid.uuid4())
        payload = {
            "iss":   _ISSUER,
            "aud":   _AUDIENCE,
            "sub":   identity,
            "iat":   int(now.timestamp()),
            "exp":   int((now + timedelta(seconds=_ACCESS_TOKEN_TTL)).timestamp()),
            "nbf":   int(now.timestamp()),
            "jti":   jti,
            "tier":  tier,
            "type":  "access",
        }
        if org_id:
            payload["org"] = org_id
        if workspace_id:
            payload["ws"] = workspace_id
        if scopes:
            payload["scp"] = scopes

        try:
            token = jwt.encode(
                payload,
                self._private_key,
                algorithm="RS256",
                headers={"kid": _KEY_ID},
            )
            logger.debug(f"[AUTH-V2] Access token issued: jti={jti[:8]}… tier={tier}")
            return token
        except Exception as e:
            logger.error(f"[AUTH-V2] Token issuance failed: {e}")
            return None

    def issue_refresh_token(self, identity: str, tier: str, org_id: Optional[str] = None) -> Optional[str]:
        """Issue RS256 refresh token with 7-day expiry."""
        if not self._ready:
            return None

        now = datetime.now(timezone.utc)
        payload = {
            "iss":  _ISSUER,
            "aud":  _AUDIENCE,
            "sub":  identity,
            "iat":  int(now.timestamp()),
            "exp":  int((now + timedelta(seconds=_REFRESH_TOKEN_TTL)).timestamp()),
            "jti":  str(uuid.uuid4()),
            "tier": tier,
            "type": "refresh",
        }
        if org_id:
            payload["org"] = org_id

        try:
            return jwt.encode(payload, self._private_key, algorithm="RS256", headers={"kid": _KEY_ID})
        except Exception as e:
            logger.error(f"[AUTH-V2] Refresh token issuance failed: {e}")
            return None

    # ─── Token Verification ─────────────────────────────────────────────────

    def verify_token(self, token: str) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Verify RS256 JWT.
        Returns (payload_dict, None) on success or (None, error_message).
        Also attempts HS256 verification for migration window compatibility.
        """
        if not token:
            return None, "No token provided"

        # Try RS256 first
        if self._ready:
            try:
                payload = jwt.decode(
                    token,
                    self._public_key,
                    algorithms=["RS256"],
                    audience=_AUDIENCE,
                    issuer=_ISSUER,
                )
                return payload, None
            except jwt.ExpiredSignatureError:
                return None, "Token expired"
            except jwt.InvalidTokenError as e:
                pass  # Fall through to HS256 migration check

        # HS256 migration window: attempt legacy verification
        hs256_secret = os.environ.get("CDB_JWT_SECRET", "")
        if hs256_secret:
            try:
                payload = jwt.decode(token, hs256_secret, algorithms=["HS256"])
                logger.warning(f"[AUTH-V2] HS256 token accepted — migration window active. "
                               f"sub={payload.get('sub', '?')[:8]}…")
                return payload, None
            except jwt.ExpiredSignatureError:
                return None, "Token expired"
            except jwt.InvalidTokenError as e:
                return None, f"Invalid token: {e}"

        return None, "Token verification failed — no valid algorithm configured"

    # ─── JWKS Endpoint ──────────────────────────────────────────────────────

    def get_jwks(self) -> Dict:
        """
        Return JSON Web Key Set for /.well-known/jwks.json.
        Enables SIEM/IDP platforms (Splunk, Elastic, Okta, Azure AD) to verify
        our tokens without needing the private key.
        """
        if not self._ready:
            return {"keys": []}

        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
            pub_numbers = self._public_key.public_numbers()

            def _to_base64url(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return base64.urlsafe_b64encode(
                    n.to_bytes(length, "big")
                ).rstrip(b"=").decode("ascii")

            return {
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": _KEY_ID,
                    "n":   _to_base64url(pub_numbers.n),
                    "e":   _to_base64url(pub_numbers.e),
                }]
            }
        except Exception as e:
            logger.error(f"[AUTH-V2] JWKS generation failed: {e}")
            return {"keys": []}

    # ─── Introspection ──────────────────────────────────────────────────────

    def introspect(self, token: str) -> Dict:
        """RFC 7662 token introspection — returns active/inactive + claims."""
        payload, err = self.verify_token(token)
        if err or not payload:
            return {"active": False}
        return {
            "active":    True,
            "sub":       payload.get("sub"),
            "tier":      payload.get("tier"),
            "org":       payload.get("org"),
            "scope":     " ".join(payload.get("scp", [])),
            "iss":       payload.get("iss"),
            "exp":       payload.get("exp"),
            "iat":       payload.get("iat"),
            "jti":       payload.get("jti"),
            "token_type": payload.get("type", "access"),
        }


# Singleton
auth_handler_v2 = AuthHandlerV2()
