#!/usr/bin/env python3
"""
auth.py — CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
NEW MODULE: API Authentication & JWT Middleware

Provides:
  - API key validation for PRO / ENTERPRISE tiers
  - JWT bearer token validation (HS256)
  - Tier resolution from any credential type
  - Audit trail for auth events

Usage:
    from agent.api.auth import auth_handler
    tier, identity, err = auth_handler.resolve_tier(api_key=key, bearer=token)
"""
import os
import hmac
import hashlib
import base64
import json
import logging
import time
from typing import Optional, Tuple
from datetime import datetime, timezone, timedelta

from agent.config import (
    CDB_JWT_SECRET,
    CDB_STANDARD_API_KEYS,
    CDB_PREMIUM_API_KEYS,
    CDB_PRO_API_KEYS,
    CDB_ENTERPRISE_API_KEYS,
    AUDIT_LOG_ENABLED,
    AUDIT_LOG_PATH,
    AUDIT_MAX_ENTRIES,
)

logger = logging.getLogger("CDB-AUTH")

# ── Tier constants (4-tier model v1.0.0) ──
TIER_FREE       = "FREE"
TIER_STANDARD   = "STANDARD"
TIER_PREMIUM    = "PREMIUM"
TIER_PRO        = "PRO"        # legacy alias — treated as PREMIUM internally
TIER_ENTERPRISE = "ENTERPRISE"

JWT_ALGORITHM   = "HS256"
JWT_EXPIRY_SECS = 86400  # 24 hours


class AuthHandler:
    """
    API authentication engine supporting API keys and JWT bearer tokens.
    Tier hierarchy: ENTERPRISE > PRO > FREE
    """

    def resolve_tier(
        self,
        api_key: Optional[str] = None,
        bearer:  Optional[str] = None,
        remote_ip: str = "unknown",
    ) -> Tuple[str, str, Optional[str]]:
        """
        Resolve API tier from credentials.

        Returns:
            (tier: str, identity: str, error: Optional[str])
            error is None on success.
        """
        # 1. JWT Bearer token
        if bearer:
            tier, identity, err = self._validate_jwt(bearer)
            if not err:
                self._audit("JWT_AUTH_SUCCESS", identity, tier, remote_ip)
                return tier, identity, None
            logger.warning(f"JWT validation failed: {err}")

        # 2. API key
        if api_key:
            tier, identity = self._validate_api_key(api_key)
            if tier != TIER_FREE:
                self._audit("APIKEY_AUTH_SUCCESS", identity, tier, remote_ip)
                return tier, identity, None
            # Unknown key → still FREE but logged
            self._audit("APIKEY_UNKNOWN", api_key[:8] + "***", TIER_FREE, remote_ip)

        # 3. Default: FREE anonymous
        return TIER_FREE, f"anon:{remote_ip}", None

    def _validate_api_key(self, key: str) -> Tuple[str, str]:
        """Check key against all tier sets. Hierarchy: ENTERPRISE > PREMIUM > STANDARD > FREE."""
        key = key.strip()
        if key in CDB_ENTERPRISE_API_KEYS:
            return TIER_ENTERPRISE, f"ent:{key[:8]}"
        if key in CDB_PREMIUM_API_KEYS or key in CDB_PRO_API_KEYS:
            # CDB_PRO_API_KEYS is a legacy alias — treated as PREMIUM
            return TIER_PREMIUM, f"prm:{key[:8]}"
        if key in CDB_STANDARD_API_KEYS:
            return TIER_STANDARD, f"std:{key[:8]}"
        return TIER_FREE, f"unk:{key[:8]}"

    def generate_jwt(self, identity: str, tier: str, expiry_secs: int = JWT_EXPIRY_SECS) -> str:
        """
        Generate a signed JWT token (HS256).
        Format: base64url(header).base64url(payload).base64url(signature)
        """
        now = int(time.time())
        header  = {"alg": JWT_ALGORITHM, "typ": "JWT"}
        payload = {
            "sub":  identity,
            "tier": tier,
            "iat":  now,
            "exp":  now + expiry_secs,
            "iss":  "CDB-SENTINEL-APEX-v22",
        }
        h_enc = self._b64(json.dumps(header, separators=(',', ':')))
        p_enc = self._b64(json.dumps(payload, separators=(',', ':')))
        sig   = self._sign(f"{h_enc}.{p_enc}")
        return f"{h_enc}.{p_enc}.{sig}"

    def _validate_jwt(self, token: str) -> Tuple[str, str, Optional[str]]:
        """Validate JWT signature and expiry. Returns (tier, identity, error)."""
        try:
            parts = token.strip().split(".")
            if len(parts) != 3:
                return TIER_FREE, "invalid", "Malformed JWT"

            h_enc, p_enc, sig = parts
            expected_sig = self._sign(f"{h_enc}.{p_enc}")
            if not hmac.compare_digest(sig, expected_sig):
                return TIER_FREE, "invalid", "Invalid JWT signature"

            payload = json.loads(self._b64_decode(p_enc))
            now = int(time.time())
            if payload.get("exp", 0) < now:
                return TIER_FREE, "expired", "JWT expired"

            tier     = payload.get("tier", TIER_FREE)
            identity = payload.get("sub", "unknown")
            if tier not in (TIER_FREE, TIER_PRO, TIER_ENTERPRISE):
                return TIER_FREE, identity, f"Unknown tier: {tier}"

            return tier, identity, None

        except Exception as e:
            return TIER_FREE, "error", str(e)

    def _sign(self, message: str) -> str:
        sig_bytes = hmac.new(
            CDB_JWT_SECRET.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return self._b64(sig_bytes, is_bytes=True)

    def _b64(self, data, is_bytes: bool = False) -> str:
        if not is_bytes:
            data = data.encode("utf-8")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _b64_decode(self, data: str) -> str:
        # Add padding
        pad = 4 - len(data) % 4
        data += "=" * (pad % 4)
        return base64.urlsafe_b64decode(data).decode("utf-8")

    def tier_allows(self, tier: str, required: str) -> bool:
        """Check if a tier meets a minimum requirement (4-tier model)."""
        order = {
            TIER_FREE:       0,
            TIER_STANDARD:   1,
            TIER_PRO:        2,   # legacy — same level as PREMIUM
            TIER_PREMIUM:    2,
            TIER_ENTERPRISE: 3,
        }
        return order.get(tier, 0) >= order.get(required, 0)

    def _audit(self, event: str, identity: str, tier: str, remote_ip: str):
        if not AUDIT_LOG_ENABLED:
            return
        try:
            entry = {
                "ts":        datetime.now(timezone.utc).isoformat(),
                "event":     event,
                "identity":  identity,
                "tier":      tier,
                "remote_ip": remote_ip,
            }
            log = []
            if os.path.exists(AUDIT_LOG_PATH):
                try:
                    with open(AUDIT_LOG_PATH, "r") as f:
                        log = json.load(f)
                except Exception:
                    log = []
            log.append(entry)
            if len(log) > AUDIT_MAX_ENTRIES:
                log = log[-AUDIT_MAX_ENTRIES:]
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            with open(AUDIT_LOG_PATH, "w") as f:
                json.dump(log, f)
        except Exception as e:
            logger.debug(f"Auth audit write failed: {e}")


# Global singleton
auth_handler = AuthHandler()
