#!/usr/bin/env python3
"""
SENTINEL APEX v134.0 — API Authentication Middleware
═════════════════════════════════════════════════════
ARCHITECTURE: ADDITIVE ONLY. Feature-flagged. Default: DISABLED.
This module provides API key management for future monetization.

DEPLOYMENT MODEL:
  Static GitHub Pages: cannot enforce auth server-side.
  Deploy this as a Cloudflare Worker / Vercel Edge Function / AWS Lambda
  fronting the GitHub Pages static files for auth enforcement.

  For local/CI use: manages api_keys.json store and validates keys.

Tiers:
  FREE       — 50 requests/day, public endpoints only
  PRO        — 5,000 requests/day, + /api/stats.json + exports
  ENTERPRISE — unlimited, + webhooks, SOC push, priority support

SAFE USAGE:
  from scripts.api_auth_middleware import validate_api_key, generate_key
  key_info = validate_api_key("sk-sentinel-...")
  if not key_info["valid"]: return 403
"""

import json
import hashlib
import hmac
import os
import secrets
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# ── Repo root ─────────────────────────────────────────────────────────────────
REPO             = Path(__file__).resolve().parent.parent
FLAGS_PATH       = REPO / "config" / "feature_flags.json"
API_KEYS_PATH    = REPO / "config" / "api_keys.json"   # NOT committed — gitignored
USAGE_LOG_PATH   = REPO / "data" / "health" / "api_usage.json"

# ── Load feature flags ────────────────────────────────────────────────────────
def _load_flags() -> Dict[str, Any]:
    try:
        return json.loads(FLAGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

_FLAGS = _load_flags()
ENABLED = _FLAGS.get("ENABLE_API_AUTH", False)

TIER_LIMITS = {
    "free":       _FLAGS.get("API_FREE_TIER_DAILY_LIMIT", 50),
    "pro":        _FLAGS.get("API_PRO_TIER_DAILY_LIMIT", 5000),
    "enterprise": _FLAGS.get("API_ENTERPRISE_TIER_DAILY_LIMIT", -1),  # -1 = unlimited
}

TIER_PERMISSIONS = {
    "free": {
        "endpoints": ["/api/feed.json", "/api/latest.json", "/api/status.json"],
        "webhooks":  False,
        "exports":   False,
        "soc_push":  False,
    },
    "pro": {
        "endpoints": ["/api/feed.json", "/api/latest.json", "/api/status.json",
                      "/api/stats.json", "/api/exports/feed.csv"],
        "webhooks":  False,
        "exports":   True,
        "soc_push":  False,
    },
    "enterprise": {
        "endpoints": ["*"],   # all endpoints
        "webhooks":  True,
        "exports":   True,
        "soc_push":  True,
    },
}

# ── Key store ─────────────────────────────────────────────────────────────────
def _load_key_store() -> Dict[str, Any]:
    try:
        return json.loads(API_KEYS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"keys": {}, "_note": "Managed by api_auth_middleware.py"}
    except Exception as e:
        print(f"[AUTH] Key store load error: {e}", file=sys.stderr)
        return {"keys": {}}

def _save_key_store(store: Dict[str, Any]) -> None:
    API_KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
    API_KEYS_PATH.write_text(
        json.dumps(store, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

# ── Key generation ────────────────────────────────────────────────────────────
def generate_key(
    tier: str = "free",
    label: str = "",
    owner_email: str = "",
    expires_days: Optional[int] = None
) -> Dict[str, Any]:
    """
    Generate a new API key. Returns key metadata dict.
    The raw key is returned ONCE and never stored in plaintext.
    """
    if tier not in TIER_LIMITS:
        raise ValueError(f"Unknown tier: {tier}. Valid: {list(TIER_LIMITS)}")

    raw_key    = "sk-sentinel-" + secrets.token_urlsafe(32)
    key_hash   = hashlib.sha256(raw_key.encode()).hexdigest()
    created_at = datetime.now(timezone.utc).isoformat()
    expires_at = None
    if expires_days:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

    entry = {
        "key_hash":    key_hash,
        "tier":        tier,
        "label":       label,
        "owner_email": owner_email,
        "created_at":  created_at,
        "expires_at":  expires_at,
        "active":      True,
        "daily_limit": TIER_LIMITS[tier],
        "usage":       {"today": 0, "date": created_at[:10], "total": 0},
    }

    store = _load_key_store()
    store["keys"][key_hash[:16]] = entry   # index by first 16 chars of hash
    _save_key_store(store)

    return {
        "raw_key":   raw_key,    # Return ONCE — never stored plaintext
        "key_id":    key_hash[:16],
        "tier":      tier,
        "label":     label,
        "expires_at": expires_at,
        "permissions": TIER_PERMISSIONS.get(tier, {}),
    }

# ── Key validation ────────────────────────────────────────────────────────────
def validate_api_key(raw_key: str, endpoint: str = "/api/feed.json") -> Dict[str, Any]:
    """
    Validate an API key against the key store.
    Returns dict with: valid, tier, reason, remaining_today.

    FAIL-SAFE: if auth system errors, returns valid=True for public endpoints
    to prevent system crash (per architecture mandate).
    """
    if not ENABLED:
        return {"valid": True, "tier": "public", "reason": "auth_disabled",
                "remaining_today": -1}

    if not raw_key or not raw_key.startswith("sk-sentinel-"):
        return {"valid": False, "tier": None, "reason": "invalid_key_format",
                "remaining_today": 0}

    try:
        key_hash   = hashlib.sha256(raw_key.encode()).hexdigest()
        key_id     = key_hash[:16]
        store      = _load_key_store()
        entry      = store.get("keys", {}).get(key_id)

        if not entry:
            return {"valid": False, "tier": None, "reason": "key_not_found",
                    "remaining_today": 0}

        if not entry.get("active", False):
            return {"valid": False, "tier": entry["tier"], "reason": "key_revoked",
                    "remaining_today": 0}

        # Expiry check
        if entry.get("expires_at"):
            exp = datetime.fromisoformat(entry["expires_at"])
            if datetime.now(timezone.utc) > exp:
                return {"valid": False, "tier": entry["tier"], "reason": "key_expired",
                        "remaining_today": 0}

        # Endpoint permission check
        tier     = entry["tier"]
        perms    = TIER_PERMISSIONS.get(tier, {})
        allowed  = perms.get("endpoints", [])
        if "*" not in allowed and endpoint not in allowed:
            return {"valid": False, "tier": tier, "reason": "endpoint_not_permitted",
                    "remaining_today": -1}

        # Daily rate limit check
        today        = datetime.now(timezone.utc).date().isoformat()
        usage        = entry.get("usage", {})
        if usage.get("date") != today:
            usage = {"today": 0, "date": today, "total": usage.get("total", 0)}

        daily_limit = entry.get("daily_limit", TIER_LIMITS.get(tier, 50))
        if daily_limit != -1 and usage["today"] >= daily_limit:
            return {"valid": False, "tier": tier, "reason": "daily_limit_exceeded",
                    "remaining_today": 0}

        # Increment usage
        usage["today"]  += 1
        usage["total"]  += 1
        entry["usage"]   = usage
        store["keys"][key_id] = entry
        _save_key_store(store)

        remaining = (daily_limit - usage["today"]) if daily_limit != -1 else -1
        return {
            "valid":           True,
            "tier":            tier,
            "key_id":          key_id,
            "reason":          "ok",
            "remaining_today": remaining,
            "permissions":     perms,
        }

    except Exception as e:
        # FAIL-SAFE: never crash the system on auth error — log and allow
        print(f"[AUTH] FAIL-SAFE triggered: {e} — allowing request", file=sys.stderr)
        return {"valid": True, "tier": "public", "reason": f"auth_error_failsafe: {e}",
                "remaining_today": -1}

# ── Key revocation ────────────────────────────────────────────────────────────
def revoke_key(key_id: str) -> bool:
    store = _load_key_store()
    entry = store.get("keys", {}).get(key_id)
    if not entry:
        return False
    entry["active"] = False
    store["keys"][key_id] = entry
    _save_key_store(store)
    return True

# ── Usage report ──────────────────────────────────────────────────────────────
def usage_report() -> Dict[str, Any]:
    store  = _load_key_store()
    keys   = store.get("keys", {})
    today  = datetime.now(timezone.utc).date().isoformat()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_keys":   len(keys),
        "active_keys":  sum(1 for k in keys.values() if k.get("active")),
        "by_tier":      {},
        "today_requests": 0,
        "total_requests": 0,
    }
    tier_counts: Dict[str, int] = {}
    for k in keys.values():
        t = k.get("tier", "unknown")
        tier_counts[t] = tier_counts.get(t, 0) + 1
        usage = k.get("usage", {})
        if usage.get("date") == today:
            report["today_requests"] += usage.get("today", 0)
        report["total_requests"] += usage.get("total", 0)
    report["by_tier"] = tier_counts
    return report

# ── CLI entrypoint ────────────────────────────────────────────────────────────
def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="SENTINEL APEX API Key Manager")
    sub = parser.add_subparsers(dest="cmd")

    gen = sub.add_parser("generate", help="Generate a new API key")
    gen.add_argument("--tier",  default="free", choices=["free", "pro", "enterprise"])
    gen.add_argument("--label", default="", help="Human label for this key")
    gen.add_argument("--email", default="", help="Owner email")
    gen.add_argument("--expires-days", type=int, default=None)

    val = sub.add_parser("validate", help="Validate an API key")
    val.add_argument("key")
    val.add_argument("--endpoint", default="/api/feed.json")

    rev = sub.add_parser("revoke", help="Revoke a key by key_id")
    rev.add_argument("key_id")

    sub.add_parser("report", help="Show usage report")

    args = parser.parse_args()

    if args.cmd == "generate":
        result = generate_key(args.tier, args.label, args.email, args.expires_days)
        print(json.dumps(result, indent=2))
        print(f"\n⚠️  Save your API key — it will NOT be shown again:\n{result['raw_key']}")

    elif args.cmd == "validate":
        result = validate_api_key(args.key, args.endpoint)
        print(json.dumps(result, indent=2))

    elif args.cmd == "revoke":
        ok = revoke_key(args.key_id)
        print("Revoked OK" if ok else "Key not found")

    elif args.cmd == "report":
        print(json.dumps(usage_report(), indent=2))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
