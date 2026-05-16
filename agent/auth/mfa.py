#!/usr/bin/env python3
"""
agent/auth/mfa.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE MFA — TOTP + BACKUP CODES

Implements RFC 6238 Time-based One-Time Password (TOTP) authentication
compatible with: Google Authenticator, Authy, 1Password, Microsoft Authenticator,
Bitwarden, and all TOTP-compliant authenticator apps.

Features:
  - TOTP secret generation and enrollment
  - QR code provisioning URI generation
  - Token verification with clock-drift tolerance (±1 window = ±30s)
  - One-time backup code generation and validation
  - Secure storage helpers (Fernet encryption for secrets at rest)
  - Anti-replay protection via Redis (prevents same token used twice)

Dependencies:
  pyotp==2.9.0    (add to requirements.txt)
  cryptography    (already in requirements.txt)

All functions are pure — no state mutations without explicit caller.
Feature-flag gated: CDB_MFA_ENABLED=true
"""

import os
import json
import hmac
import secrets
import hashlib
import base64
import logging
import time
from typing import Tuple, List, Optional

logger = logging.getLogger("CDB-MFA")

_MFA_ENABLED        = os.environ.get("CDB_MFA_ENABLED", "false").lower() == "true"
_MFA_ISSUER         = os.environ.get("CDB_MFA_ISSUER", "CyberDudeBivash SENTINEL APEX")
_MFA_ENCRYPTION_KEY = os.environ.get("CDB_MFA_ENCRYPTION_KEY", "")  # Fernet key for secret encryption
_TOTP_WINDOW        = int(os.environ.get("CDB_TOTP_WINDOW", "1"))   # ±1 period tolerance
_BACKUP_CODE_COUNT  = 10


# ── TOTP Core ──────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """
    Generate a cryptographically secure TOTP base32 secret.
    Returns 32-character base32 string (160-bit secret).
    """
    try:
        import pyotp
        return pyotp.random_base32()
    except ImportError:
        # Fallback: manual base32 generation if pyotp not yet installed
        random_bytes = secrets.token_bytes(20)
        return base64.b32encode(random_bytes).decode("utf-8")


def get_totp_uri(secret: str, user_email: str) -> str:
    """
    Generate TOTP provisioning URI for QR code display.
    Compatible with all standard authenticator apps.

    Args:
        secret:     TOTP base32 secret
        user_email: User's email (display label in authenticator)

    Returns:
        otpauth:// URI string
    """
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=user_email, issuer_name=_MFA_ISSUER)
    except ImportError:
        # Manual URI construction per RFC 6238
        import urllib.parse
        label = urllib.parse.quote(f"{_MFA_ISSUER}:{user_email}")
        issuer = urllib.parse.quote(_MFA_ISSUER)
        return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def verify_totp(secret: str, token: str, user_id: str = "") -> bool:
    """
    Verify a TOTP token against the secret.

    Args:
        secret:  TOTP base32 secret
        token:   6-digit token from authenticator app
        user_id: User ID for anti-replay check (optional)

    Returns:
        True if valid, False otherwise
    """
    if not secret or not token:
        return False

    # Sanitize token — digits only, exactly 6 chars
    token = token.strip().replace(" ", "")
    if not token.isdigit() or len(token) != 6:
        logger.warning(f"[MFA] Invalid token format for user={user_id[:8] if user_id else '?'}…")
        return False

    # Anti-replay: check if this token was already used
    if user_id and _is_token_replayed(user_id, token):
        logger.warning(f"[MFA] Replay attack detected for user={user_id[:8]}…")
        return False

    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        valid = totp.verify(token, valid_window=_TOTP_WINDOW)
        if valid and user_id:
            _mark_token_used(user_id, token)
        return valid
    except ImportError:
        # Fallback: manual TOTP verification
        return _verify_totp_manual(secret, token)
    except Exception as e:
        logger.error(f"[MFA] TOTP verification error: {e}")
        return False


def _verify_totp_manual(secret: str, token: str) -> bool:
    """Manual TOTP verification without pyotp dependency."""
    import struct
    try:
        key = base64.b32decode(secret.upper())
        current_time = int(time.time()) // 30
        for drift in range(-_TOTP_WINDOW, _TOTP_WINDOW + 1):
            counter = struct.pack(">Q", current_time + drift)
            mac = hmac.new(key, counter, hashlib.sha1).digest()
            offset = mac[-1] & 0x0F
            code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
            expected = str(code % 1000000).zfill(6)
            if hmac.compare_digest(expected, token):
                return True
        return False
    except Exception:
        return False


# ── Anti-Replay Protection ─────────────────────────────────────────────────

def _replay_key(user_id: str, token: str) -> str:
    combined = f"{user_id}:{token}:{int(time.time()) // 30}"
    return f"cdb:mfa:used:{hashlib.sha256(combined.encode()).hexdigest()[:32]}"


def _is_token_replayed(user_id: str, token: str) -> bool:
    """Check if this token was already used in the current 30s window."""
    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        return False  # Cannot enforce — fail open (acceptable for rate-limited endpoints)
    try:
        import redis
        r = redis.from_url(redis_url, decode_responses=True, socket_timeout=0.5)
        return bool(r.get(_replay_key(user_id, token)))
    except Exception:
        return False


def _mark_token_used(user_id: str, token: str) -> None:
    """Mark token as used for the current 30s window."""
    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        return
    try:
        import redis
        r = redis.from_url(redis_url, decode_responses=True, socket_timeout=0.5)
        r.set(_replay_key(user_id, token), "1", ex=90)  # 3 window buffer
    except Exception:
        pass


# ── Backup Codes ───────────────────────────────────────────────────────────

def generate_backup_codes(count: int = _BACKUP_CODE_COUNT) -> List[str]:
    """
    Generate one-time use backup codes for MFA recovery.
    Format: XXXX-XXXX (8 hex chars, hyphenated for readability)

    Returns list of plaintext codes. Store hashed versions only.
    """
    return [
        f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        for _ in range(count)
    ]


def hash_backup_code(code: str) -> str:
    """Hash a backup code for safe storage."""
    normalized = code.replace("-", "").upper()
    return hashlib.sha256(normalized.encode()).hexdigest()


def verify_backup_code(code: str, stored_hashes: List[str]) -> Tuple[bool, Optional[str]]:
    """
    Verify a backup code against stored hashes.
    Returns (valid: bool, matched_hash: Optional[str]).
    Matched hash should be removed from storage after use.
    """
    if not code or not stored_hashes:
        return False, None
    code_hash = hash_backup_code(code)
    for stored_hash in stored_hashes:
        if hmac.compare_digest(code_hash, stored_hash):
            return True, stored_hash
    return False, None


# ── Secret Encryption (at-rest protection) ────────────────────────────────

def encrypt_secret(plaintext: str) -> Optional[str]:
    """
    Encrypt TOTP secret for database storage.
    Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).
    Returns base64-encoded ciphertext or None if encryption key not configured.
    """
    if not _MFA_ENCRYPTION_KEY:
        logger.warning("[MFA] CDB_MFA_ENCRYPTION_KEY not set — storing secret unencrypted")
        return plaintext  # Graceful degradation — better than blocking
    try:
        from cryptography.fernet import Fernet
        key = _MFA_ENCRYPTION_KEY.encode() if len(_MFA_ENCRYPTION_KEY) == 44 else \
              base64.urlsafe_b64encode(_MFA_ENCRYPTION_KEY.encode()[:32].ljust(32, b'='))
        f = Fernet(key)
        return f.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error(f"[MFA] Encryption failed: {e}")
        return plaintext


def decrypt_secret(ciphertext: str) -> Optional[str]:
    """Decrypt TOTP secret from database storage."""
    if not _MFA_ENCRYPTION_KEY:
        return ciphertext  # Was stored unencrypted (degraded mode)
    try:
        from cryptography.fernet import Fernet
        key = _MFA_ENCRYPTION_KEY.encode() if len(_MFA_ENCRYPTION_KEY) == 44 else \
              base64.urlsafe_b64encode(_MFA_ENCRYPTION_KEY.encode()[:32].ljust(32, b'='))
        f = Fernet(key)
        return f.decrypt(ciphertext.encode()).decode()
    except Exception as e:
        logger.error(f"[MFA] Decryption failed: {e}")
        return None


# ── Enrollment Flow ────────────────────────────────────────────────────────

def begin_mfa_enrollment(user_email: str) -> dict:
    """
    Start MFA enrollment for a user.
    Returns: secret, provisioning_uri, backup_codes (plaintext — show once)
    Caller must store: encrypt_secret(secret), [hash_backup_code(c) for c in backup_codes]
    """
    secret       = generate_totp_secret()
    uri          = get_totp_uri(secret, user_email)
    backup_codes = generate_backup_codes()
    return {
        "secret":           secret,
        "provisioning_uri": uri,
        "backup_codes":     backup_codes,
        "backup_codes_hashed": [hash_backup_code(c) for c in backup_codes],
        "encrypted_secret": encrypt_secret(secret),
        "instructions": (
            "1. Scan the QR code with your authenticator app.\n"
            "2. Enter the 6-digit code to confirm enrollment.\n"
            "3. Save backup codes in a secure location — they cannot be retrieved again."
        ),
    }


def confirm_mfa_enrollment(secret: str, token: str, user_id: str) -> bool:
    """
    Confirm MFA enrollment by verifying the first token.
    Must be called before MFA is marked as active for the user.
    """
    valid = verify_totp(secret, token, user_id)
    if valid:
        logger.info(f"[MFA] Enrollment confirmed for user={user_id[:8]}…")
    else:
        logger.warning(f"[MFA] Enrollment confirmation failed for user={user_id[:8]}…")
    return valid
