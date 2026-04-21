#!/usr/bin/env python3
"""
scripts/subscription_manager.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Subscription Manager CLI v1.0
==================================================================
Production CLI for managing API keys and subscriptions.

Features:
  create_api_key   -- Create new API key (FREE/PRO/ENTERPRISE/MSSP)
  revoke_api_key   -- Revoke an existing key by key prefix or owner
  validate_key     -- Validate a key and show tier/quota status
  list_keys        -- List all keys with status
  usage_report     -- Show usage summary across all keys
  gumroad_sync     -- Sync Gumroad purchases to subscriptions (if token set)

Modes:
  Mock mode (default) -- manual key creation, no payment integration
  Gumroad mode        -- reads GUMROAD_ACCESS_TOKEN, auto-provisions keys

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Bootstrap paths
REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT / "api"), str(REPO_ROOT / "scripts"), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [sub-manager] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("sentinel.subscription_manager")


# ---------------------------------------------------------------------------
# Core operations (wrapping api/auth.py APIKeyManager)
# ---------------------------------------------------------------------------

def create_api_key(
    tier: str,
    owner: str,
    label: str = "",
    expires_days: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Create a new API key for the given tier.
    Returns dict with raw_key (shown ONCE) and key metadata.
    """
    from api.auth import APIKeyManager, TIERS

    tier = tier.upper()
    if tier not in TIERS:
        raise ValueError(f"Unknown tier '{tier}'. Valid: {list(TIERS.keys())}")

    expires_at = None
    if expires_days:
        exp = datetime.now(timezone.utc) + timedelta(days=expires_days)
        expires_at = exp.isoformat(timespec="seconds")

    mgr = APIKeyManager()
    raw_key, record = mgr.create_key(
        tier=tier,
        owner=owner,
        label=label or f"{tier} key for {owner}",
        expires_at=expires_at,
    )

    return {
        "raw_key":    raw_key,
        "tier":       record.get("tier"),
        "owner":      record.get("owner"),
        "label":      record.get("label"),
        "created_at": record.get("created_at"),
        "expires_at": record.get("expires_at"),
        "active":     record.get("active"),
    }


def revoke_api_key(raw_key: str) -> bool:
    """Revoke an API key by its raw value."""
    from api.auth import APIKeyManager
    mgr = APIKeyManager()
    ok  = mgr.revoke_key(raw_key)
    if ok:
        log.info("Key revoked: %s...", raw_key[:20])
    else:
        log.warning("Key not found: %s...", raw_key[:20])
    return ok


def validate_key(raw_key: str) -> Dict[str, Any]:
    """
    Validate an API key and return tier/quota status.
    Constant-time safe — does not reveal key details on failure.
    """
    from api.auth import APIKeyManager, TIERS

    mgr = APIKeyManager()
    valid, record, reason = mgr.validate_key(raw_key)

    if not valid:
        return {
            "valid":  False,
            "reason": reason,
            "tier":   None,
        }

    tier     = record.get("tier", "FREE")
    tier_def = TIERS.get(tier, TIERS["FREE"])
    within_quota, quota_reason = mgr.check_rate_limit(record)
    daily_limit = tier_def.get("requests_per_day", 100)
    used_today  = record.get("requests_today", 0)

    return {
        "valid":          True,
        "tier":           tier,
        "owner":          record.get("owner"),
        "label":          record.get("label"),
        "active":         record.get("active"),
        "within_quota":   within_quota,
        "requests_today": used_today,
        "daily_limit":    daily_limit if daily_limit != -1 else "unlimited",
        "remaining":      max(0, daily_limit - used_today) if daily_limit != -1 else "unlimited",
        "total_requests": record.get("total_requests", 0),
        "last_used":      record.get("last_used"),
        "expires_at":     record.get("expires_at"),
        "features":       tier_def.get("features", {}),
    }


def list_keys(owner: Optional[str] = None) -> List[Dict]:
    """List all API keys (admin use). Raw keys never returned."""
    from api.auth import APIKeyManager
    mgr = APIKeyManager()
    return mgr.list_keys(owner=owner)


def usage_report_all() -> Dict[str, Any]:
    """Generate usage report across all keys."""
    from api.auth import APIKeyManager
    mgr   = APIKeyManager()
    keys  = mgr.list_keys()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    total_today = 0
    total_all   = 0
    by_tier: Dict[str, Dict[str, int]] = {}

    for key in keys:
        tier = key.get("tier", "FREE")
        if tier not in by_tier:
            by_tier[tier] = {"count": 0, "active": 0, "today": 0, "total": 0}
        by_tier[tier]["count"] += 1
        if key.get("active"):
            by_tier[tier]["active"] += 1
        if key.get("quota_reset_date") == today:
            rt = key.get("requests_today", 0)
        else:
            rt = 0
        by_tier[tier]["today"] += rt
        by_tier[tier]["total"] += key.get("total_requests", 0)
        total_today += rt
        total_all   += key.get("total_requests", 0)

    return {
        "generated_at":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_keys":     len(keys),
        "active_keys":    sum(1 for k in keys if k.get("active")),
        "requests_today": total_today,
        "total_requests": total_all,
        "by_tier":        by_tier,
    }


# ---------------------------------------------------------------------------
# Gumroad integration (optional)
# ---------------------------------------------------------------------------

def gumroad_sync() -> Dict[str, Any]:
    """
    Sync Gumroad purchases to API keys.
    Requires GUMROAD_ACCESS_TOKEN env var.
    Maps Gumroad product names to tiers.
    """
    token = os.getenv("GUMROAD_ACCESS_TOKEN", "")
    if not token:
        return {"error": "GUMROAD_ACCESS_TOKEN not set. Set env var to enable sync."}

    try:
        import urllib.request
        import urllib.parse

        url = "https://api.gumroad.com/v2/sales"
        req = urllib.request.Request(
            f"{url}?access_token={token}&page=1",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        sales   = data.get("sales", [])
        synced  = 0
        skipped = 0
        errors  = 0
        details = []

        # Map Gumroad product names to tiers
        PRODUCT_TIER_MAP = {
            "pro":        "PRO",
            "enterprise": "ENTERPRISE",
            "mssp":       "MSSP",
        }

        for sale in sales:
            product_name = sale.get("product_name", "").lower()
            email        = sale.get("email", "")
            tier         = next(
                (v for k, v in PRODUCT_TIER_MAP.items() if k in product_name),
                None,
            )
            if not tier or not email:
                skipped += 1
                continue

            try:
                result = create_api_key(
                    tier=tier,
                    owner=sale.get("full_name", email),
                    label=f"Gumroad: {sale.get('product_name')} | {sale.get('sale_id', '')}",
                )
                synced += 1
                details.append({
                    "email": email,
                    "tier":  tier,
                    "key_prefix": result["raw_key"][:20] + "...",
                })
                log.info("Gumroad sync: created %s key for %s", tier, email)
            except Exception as e:
                errors += 1
                log.warning("Gumroad sync error for %s: %s", email, e)

        return {
            "synced":  synced,
            "skipped": skipped,
            "errors":  errors,
            "details": details[:10],  # limit output
            "total_sales": len(sales),
        }

    except Exception as e:
        return {"error": f"Gumroad sync failed: {e}"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Subscription Manager v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # create
    p_create = sub.add_parser("create", help="Create a new API key")
    p_create.add_argument("--tier",   required=True, choices=["FREE", "PRO", "ENTERPRISE", "MSSP"])
    p_create.add_argument("--owner",  required=True, help="Owner name / org")
    p_create.add_argument("--label",  default="",    help="Human-readable label")
    p_create.add_argument("--expires-days", type=int, default=None,
                          help="Days until expiry (omit for no expiry)")

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke an API key")
    p_revoke.add_argument("key", help="Raw API key to revoke")

    # validate
    p_val = sub.add_parser("validate", help="Validate an API key")
    p_val.add_argument("key", help="Raw API key to validate")

    # list
    p_list = sub.add_parser("list", help="List all API keys")
    p_list.add_argument("--owner", default=None, help="Filter by owner")

    # report
    sub.add_parser("report", help="Usage report across all keys")

    # gumroad
    sub.add_parser("gumroad-sync", help="Sync Gumroad purchases to API keys")

    args = parser.parse_args()

    try:
        if args.cmd == "create":
            result = create_api_key(
                tier=args.tier,
                owner=args.owner,
                label=args.label,
                expires_days=args.expires_days,
            )
            raw_key = result.pop("raw_key")
            _print_json(result)
            print(f"\n{'='*60}")
            print(f"  API KEY (shown ONCE -- store securely):")
            print(f"  {raw_key}")
            print(f"{'='*60}\n")

        elif args.cmd == "revoke":
            ok = revoke_api_key(args.key)
            print("REVOKED" if ok else "NOT FOUND")
            return 0 if ok else 1

        elif args.cmd == "validate":
            result = validate_key(args.key)
            _print_json(result)
            return 0 if result.get("valid") else 1

        elif args.cmd == "list":
            keys = list_keys(owner=args.owner)
            print(f"\n{'PREFIX':<25} {'TIER':<12} {'OWNER':<25} {'ACTIVE':<8} {'TODAY':>8} {'TOTAL':>10}")
            print("-" * 95)
            for k in keys:
                pfx  = k.get("key_prefix", "")[:24]
                tier = k.get("tier", "")
                own  = k.get("owner", "")[:24]
                act  = "YES" if k.get("active") else "NO"
                tod  = k.get("requests_today", 0)
                tot  = k.get("total_requests", 0)
                print(f"{pfx:<25} {tier:<12} {own:<25} {act:<8} {tod:>8} {tot:>10}")
            print(f"\nTotal: {len(keys)} keys")

        elif args.cmd == "report":
            _print_json(usage_report_all())

        elif args.cmd == "gumroad-sync":
            result = gumroad_sync()
            _print_json(result)
            return 0 if "error" not in result else 1

        return 0

    except Exception as e:
        log.error("Command failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
