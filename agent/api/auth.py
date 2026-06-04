#!/usr/bin/env python3
"""
auth.py - CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
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

# -- Tier constants (v176.0 — 6-tier commercial model) --
TIER_FREE       = "FREE"
TIER_STANDARD   = "STANDARD"
TIER_PREMIUM    = "PREMIUM"
TIER_PRO        = "PRO"        # legacy alias — treated as PREMIUM internally
TIER_ENTERPRISE = "ENTERPRISE"
TIER_MSSP       = "MSSP"       # v176.0: MSSP commercial tier (500k calls/day)
TIER_TRIAL      = "TRIAL"      # v176.0: 7-day trial tier (500 calls/day)

# Tier hierarchy (higher index = higher privilege)
TIER_HIERARCHY = [TIER_FREE, TIER_STANDARD, TIER_TRIAL, TIER_PREMIUM, TIER_PRO, TIER_ENTERPRISE, TIER_MSSP]

JWT_ALGORITHM   = "HS256"
JWT_EXPIRY_SECS = 86400  # 24 hours

# Revocation registry path — keys listed here are IMMEDIATELY rejected regardless
# of tier, without requiring config reload or service restart.
_REVOCATION_REGISTRY_PATH = "data/security/revoked_keys.json"

# v176.0: Runtime key registry — keys issued via generate_key.py
# Loaded on every resolve_tier() call for zero-restart key activation
_ACTIVE_KEYS_PATH = "data/keys/active_keys.json"


def _load_active_key_registry() -> dict:
    """Load runtime key registry (data/keys/active_keys.json)."""
    try:
        if os.path.exists(_ACTIVE_KEYS_PATH):
            with open(_ACTIVE_KEYS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("keys", {})
    except Exception as e:
        logger.warning(f"[AUTH] Active key registry load failed: {e}")
    return {}


def _check_runtime_expiry(record: dict) -> bool:
    """Return True if the key record is still within its validity window."""
    try:
        expires_at = record.get("expires_at", "")
        if not expires_at:
            return True  # No expiry set — assume valid (legacy)
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) < exp_dt
    except Exception:
        return True  # Parse error — be permissive, log separately


def _load_revocation_registry() -> set:
    """Load the set of revoked API key hashes from the registry file."""
    try:
        if os.path.exists(_REVOCATION_REGISTRY_PATH):
            with open(_REVOCATION_REGISTRY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Store SHA-256 hashes of keys rather than keys themselves
            return set(data.get("revoked_hashes", []))
    except Exception as e:
        logger.warning(f"[AUTH] Revocation registry load failed: {e}")
    return set()


def _key_hash(key: str) -> str:
    import hashlib
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()


class AuthHandler:
    """
    API authentication engine supporting API keys and JWT bearer tokens.
    Tier hierarchy: ENTERPRISE > PRO > FREE

    v23.0 ENTERPRISE SECURITY ADDITIONS:
      - Revocation registry: API keys can be revoked at runtime without
        config reload by adding their SHA-256 hash to
        data/security/revoked_keys.json. The registry is reloaded on every
        resolve_tier() call so revocations take effect within one request cycle.
      - revoke_key() / unrevoke_key() helpers for ops tooling.
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
            # Unknown key -> still FREE but logged
            self._audit("APIKEY_UNKNOWN", api_key[:8] + "***", TIER_FREE, remote_ip)

        # 3. Default: FREE anonymous
        return TIER_FREE, f"anon:{remote_ip}", None

    def _validate_api_key(self, key: str) -> Tuple[str, str]:
        """
        Check key against all tier sets.
        Hierarchy (v176.0): MSSP > ENTERPRISE > PREMIUM/PRO > TRIAL > STANDARD > FREE

        Resolution order:
        1. Revocation check (immediate reject if revoked)
        2. Config-based keys (existing — no restart needed for config reload)
        3. Runtime key registry (data/keys/active_keys.json — no restart needed)

        Revocation check runs first - a revoked key is rejected regardless of tier.
        The revocation registry is reloaded on every call so runtime revocations
        (e.g., after a credential leak) take effect immediately.
        """
        key = key.strip()
        # Revocation guard — check registry before tier resolution
        revoked = _load_revocation_registry()
        if _key_hash(key) in revoked:
            logger.warning(f"[AUTH] REVOKED key attempted: {key[:8]}***")
            self._audit("APIKEY_REVOKED", f"rev:{key[:8]}", TIER_FREE, "revocation-check")
            return TIER_FREE, f"revoked:{key[:8]}"
        # ── 1. Config-based tier resolution (existing behaviour, no change) ──
        if key in CDB_ENTERPRISE_API_KEYS:
            return TIER_ENTERPRISE, f"ent:{key[:8]}"
        if key in CDB_PREMIUM_API_KEYS or key in CDB_PRO_API_KEYS:
            # CDB_PRO_API_KEYS is a legacy alias — treated as PREMIUM internally
            return TIER_PREMIUM, f"prm:{key[:8]}"
        if key in CDB_STANDARD_API_KEYS:
            return TIER_STANDARD, f"std:{key[:8]}"

        # ── 2. v176.0: Runtime key registry (data/keys/active_keys.json) ──
        # Enables zero-restart key provisioning via generate_key.py
        kh = _key_hash(key)
        registry = _load_active_key_registry()
        if kh in registry:
            record = registry[kh]
            # Check expiry before granting access
            if not _check_runtime_expiry(record):
                logger.info(f"[AUTH] Runtime key EXPIRED: {key[:8]}*** ref={record.get('reference_id','?')}")
                self._audit("APIKEY_EXPIRED", f"exp:{key[:8]}", TIER_FREE, "expiry-check")
                return TIER_FREE, f"expired:{key[:8]}"
            # Check record-level revocation status
            if record.get("status") == "revoked":
                self._audit("APIKEY_REVOKED", f"rev:{key[:8]}", TIER_FREE, "registry-revoked")
                return TIER_FREE, f"revoked:{key[:8]}"
            # Resolve tier from registry record
            tier = record.get("tier", TIER_FREE).upper()
            identity_prefix = {
                TIER_MSSP: "mssp", TIER_ENTERPRISE: "ent",
                TIER_PRO: "prm", TIER_PREMIUM: "prm",
                TIER_TRIAL: "trial", TIER_STANDARD: "std",
            }.get(tier, "reg")
            logger.debug(f"[AUTH] Runtime registry hit: {key[:8]}*** tier={tier}")
            self._audit("APIKEY_REGISTRY_HIT", f"reg:{key[:8]}", tier,
                        record.get("customer_email", "?"))
            return tier, f"{identity_prefix}:{key[:8]}"

        # ── 3. Unknown key — default to FREE ──
        return TIER_FREE, f"unk:{key[:8]}"

    # ── Revocation management ─────────────────────────────────────────────────

    def revoke_key(self, key: str, reason: str = "") -> bool:
        """Add a key to the revocation registry. Effective immediately on next request."""
        try:
            os.makedirs(os.path.dirname(_REVOCATION_REGISTRY_PATH), exist_ok=True)
            data: Dict = {}
            if os.path.exists(_REVOCATION_REGISTRY_PATH):
                with open(_REVOCATION_REGISTRY_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
            hashes: list = data.get("revoked_hashes", [])
            kh = _key_hash(key)
            if kh not in hashes:
                hashes.append(kh)
            data["revoked_hashes"] = hashes
            data.setdefault("revocation_log", []).append({
                "key_prefix": key[:8],
                "hash":       kh,
                "reason":     reason,
                "revoked_at": datetime.now(timezone.utc).isoformat(),
            })
            with open(_REVOCATION_REGISTRY_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info(f"[AUTH] Key revoked: {key[:8]}*** reason={reason!r}")
            return True
        except Exception as e:
            logger.error(f"[AUTH] Key revocation failed: {e}")
            return False

    def unrevoke_key(self, key: str) -> bool:
        """Remove a key from the revocation registry."""
        try:
            if not os.path.exists(_REVOCATION_REGISTRY_PATH):
                return True
            with open(_REVOCATION_REGISTRY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            kh = _key_hash(key)
            before = len(data.get("revoked_hashes", []))
            data["revoked_hashes"] = [h for h in data.get("revoked_hashes", []) if h != kh]
            with open(_REVOCATION_REGISTRY_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info(f"[AUTH] Key unrevoked: {key[:8]}*** (removed {before - len(data['revoked_hashes'])} entry)")
            return True
        except Exception as e:
            logger.error(f"[AUTH] Key unrevoke failed: {e}")
            return False

    def is_revoked(self, key: str) -> bool:
        """Check if a key is currently revoked."""
        return _key_hash(key) in _load_revocation_registry()

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
            TIER_PRO:        2,   # legacy - same level as PREMIUM
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
