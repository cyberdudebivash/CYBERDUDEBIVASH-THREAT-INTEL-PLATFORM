"""
CYBERDUDEBIVASH® SENTINEL APEX — API Key Manager v1.0
======================================================
Production API key lifecycle: generate, validate, revoke, rotate.

KEY FORMAT:  cdb_<tier>_<32-hex-chars>
EXAMPLES:
  cdb_free_a1b2c3d4e5f6...   (free tier)
  cdb_pro_a1b2c3d4e5f6...    (pro tier — $49/mo)
  cdb_ent_a1b2c3d4e5f6...    (enterprise — $499/mo)
  cdb_msp_a1b2c3d4e5f6...    (mssp — $1999/mo)

STORAGE: data/monetization/api_keys.json
  {
    "cdb_pro_abc...": {
      "tier": "pro", "name": "Acme Corp",
      "email": "admin@acme.com", "created_at": "...",
      "status": "active", "stripe_sub_id": "sub_xxx",
      "requests_today": 0, "last_request": null
    }
  }

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations
import json, logging, os, re, secrets, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("CDB-KEY-MANAGER")

BASE_DIR      = Path(__file__).resolve().parent.parent.parent
KEYS_FILE     = BASE_DIR / "data" / "monetization" / "api_keys.json"
TIER_PREFIXES = {"free": "cdb_free_", "pro": "cdb_pro_", "enterprise": "cdb_ent_", "mssp": "cdb_msp_"}

# ── Rate limits per tier (requests/hour) ─────────────────────────────────────
RATE_LIMITS = {"free": 60, "pro": 1000, "enterprise": 10000, "mssp": 99999}

_KEY_PATTERN = re.compile(r"^cdb_(free|pro|ent|msp)_[0-9a-f]{32}$")


def _tier_from_prefix(key: str) -> str:
    if key.startswith("cdb_pro_"):   return "pro"
    if key.startswith("cdb_ent_"):   return "enterprise"
    if key.startswith("cdb_msp_"):   return "mssp"
    return "free"


def _load() -> Dict:
    try:
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not KEYS_FILE.exists(): return {}
        with open(KEYS_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return {}


def _save(keys: Dict) -> None:
    try:
        tmp = str(KEYS_FILE) + ".tmp"
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "wb") as f:
            f.write(json.dumps(keys, indent=2, default=str).encode())
        os.replace(tmp, KEYS_FILE)
    except Exception as e:
        logger.warning(f"[KEY-MGR] Save failed (non-fatal): {e}")


def generate_key(tier: str, name: str, email: str = "",
                 stripe_sub_id: str = "", notes: str = "") -> str:
    """
    Generate and persist a new API key for given tier.
    Returns the new key string.
    """
    tier = tier.lower()
    if tier not in TIER_PREFIXES:
        raise ValueError(f"Unknown tier: {tier}")
    prefix  = TIER_PREFIXES[tier]
    raw     = secrets.token_hex(16)          # 32 hex chars = 128-bit entropy
    api_key = f"{prefix}{raw}"
    keys    = _load()
    keys[api_key] = {
        "tier":           tier,
        "name":           name[:100],
        "email":          email[:200],
        "created_at":     datetime.now(timezone.utc).isoformat(),
        "status":         "active",
        "stripe_sub_id":  stripe_sub_id,
        "requests_today": 0,
        "last_request":   None,
        "notes":          notes[:200],
    }
    _save(keys)
    logger.info(f"[KEY-MGR] Generated {tier} key for '{name}' (email={email[:30]})")
    return api_key


def validate_key(api_key: str) -> Dict:
    """
    Validate API key and return tier info.
    Returns {"valid": bool, "tier": str, "name": str, "rate_limit": int, ...}
    Checks: exists, active, format valid.
    """
    if not api_key or not isinstance(api_key, str):
        return {"valid": False, "tier": "free", "name": "Anonymous",
                "rate_limit": RATE_LIMITS["free"], "reason": "no_key"}

    # Demo keys (backward compat — always work without DB lookup)
    _DEMO = {
        "demo-free-key-0000":       {"tier": "free",       "name": "Demo Free"},
        "demo-pro-key-1111":        {"tier": "pro",        "name": "Demo Pro"},
        "demo-enterprise-key-2222": {"tier": "enterprise", "name": "Demo Enterprise"},
    }
    if api_key in _DEMO:
        t = _DEMO[api_key]
        return {"valid": True, "tier": t["tier"], "name": t["name"],
                "rate_limit": RATE_LIMITS[t["tier"]], "source": "demo"}

    # Format validation
    if not _KEY_PATTERN.match(api_key):
        return {"valid": False, "tier": "free", "name": "Unknown",
                "rate_limit": RATE_LIMITS["free"], "reason": "bad_format"}

    keys = _load()
    rec  = keys.get(api_key)
    if not rec:
        return {"valid": False, "tier": "free", "name": "Unknown",
                "rate_limit": RATE_LIMITS["free"], "reason": "not_found"}

    if rec.get("status") != "active":
        return {"valid": False, "tier": rec.get("tier","free"),
                "name": rec.get("name",""), "rate_limit": 0,
                "reason": f"status:{rec.get('status')}"}

    tier = rec.get("tier", "free")
    return {
        "valid":      True,
        "tier":       tier,
        "name":       rec.get("name", ""),
        "email":      rec.get("email", ""),
        "rate_limit": RATE_LIMITS.get(tier, RATE_LIMITS["free"]),
        "source":     "db",
    }


def revoke_key(api_key: str, reason: str = "manual") -> bool:
    """Revoke a key by marking status=revoked."""
    keys = _load()
    if api_key not in keys:
        return False
    keys[api_key]["status"]    = "revoked"
    keys[api_key]["revoked_at"] = datetime.now(timezone.utc).isoformat()
    keys[api_key]["revoke_reason"] = reason
    _save(keys)
    logger.info(f"[KEY-MGR] Revoked key {api_key[:20]}... reason={reason}")
    return True


def rotate_key(old_key: str) -> Optional[str]:
    """Generate a new key for same subscriber, revoke the old one."""
    keys = _load()
    rec  = keys.get(old_key)
    if not rec or rec.get("status") != "active":
        return None
    new_key = generate_key(
        tier=rec["tier"], name=rec["name"],
        email=rec.get("email",""), stripe_sub_id=rec.get("stripe_sub_id",""),
        notes=f"Rotated from {old_key[:20]}...",
    )
    revoke_key(old_key, reason="rotated")
    logger.info(f"[KEY-MGR] Rotated key for {rec.get('name','')}")
    return new_key


def list_keys(tier: Optional[str] = None, active_only: bool = True) -> list:
    """List all keys, optionally filtered by tier and active status."""
    keys = _load()
    result = []
    for k, v in keys.items():
        if active_only and v.get("status") != "active":
            continue
        if tier and v.get("tier") != tier:
            continue
        result.append({"key_prefix": k[:20]+"...", **v})
    return result


def get_key_stats() -> Dict:
    """Return aggregate stats for admin dashboard."""
    keys  = _load()
    stats = {"total": len(keys), "active": 0, "by_tier": {}, "revenue_arr_est": 0}
    PRICES = {"free": 0, "pro": 49, "enterprise": 499, "mssp": 1999}
    for v in keys.values():
        tier = v.get("tier", "free")
        if v.get("status") == "active":
            stats["active"] += 1
            stats["by_tier"][tier] = stats["by_tier"].get(tier, 0) + 1
            stats["revenue_arr_est"] += PRICES.get(tier, 0) * 12
    return stats
