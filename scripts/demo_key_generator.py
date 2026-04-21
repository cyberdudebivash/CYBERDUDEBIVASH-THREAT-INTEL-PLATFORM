#!/usr/bin/env python3
"""
scripts/demo_key_generator.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Demo Key Generator v1.0
=======================================================================
Generates short-lived ENTERPRISE-tier demo API keys for sales demos,
prospect evaluations, and partner trials.

Default behavior:
  - Tier:    ENTERPRISE
  - Expiry:  24 hours
  - Rate:    500 req/day (same as ENTERPRISE, but rate-limited per minute)
  - Label:   "DEMO - expires in 24h"

Usage:
  python scripts/demo_key_generator.py
  python scripts/demo_key_generator.py --owner "Prospect Corp" --hours 48
  python scripts/demo_key_generator.py --owner "ACME" --tier PRO --hours 72 --output demo_key.txt

Exit codes:
  0 -- key generated successfully
  1 -- error (see stderr)

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

# Bootstrap path
REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT / "api"), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [demo-key-gen] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("sentinel.demo_key_gen")

# Demo rate limits (lower than full ENTERPRISE to prevent abuse)
DEMO_RATE_OVERRIDES = {
    "ENTERPRISE": {"requests_per_day": 500,  "rate_limit_per_minute": 30},
    "PRO":        {"requests_per_day": 200,  "rate_limit_per_minute": 20},
    "FREE":       {"requests_per_day": 50,   "rate_limit_per_minute": 10},
}

# Default demo parameters
DEFAULT_TIER     = "ENTERPRISE"
DEFAULT_HOURS    = 24
DEFAULT_MAX_DAYS = 30  # hard cap on demo duration


def generate_demo_key(
    owner: str = "Demo Prospect",
    tier: str = DEFAULT_TIER,
    hours: int = DEFAULT_HOURS,
    label: str = "",
    output_file: Optional[str] = None,
) -> dict:
    """
    Generate a time-limited demo API key.

    Args:
        owner:       Organization name (for audit trail)
        tier:        Tier to grant (ENTERPRISE recommended for demos)
        hours:       Validity in hours (max DEFAULT_MAX_DAYS * 24)
        label:       Human-readable label for this key
        output_file: If set, write key to this file (one key per line)

    Returns:
        dict with: raw_key, key_prefix, tier, expires_at, label, owner
    """
    from api.auth import APIKeyManager, TIERS

    tier = tier.upper()
    if tier not in TIERS:
        log.error("Unknown tier '%s'. Valid: %s", tier, list(TIERS.keys()))
        sys.exit(1)

    # Cap hours
    hours = max(1, min(hours, DEFAULT_MAX_DAYS * 24))
    now   = datetime.now(timezone.utc)
    exp   = (now + timedelta(hours=hours)).isoformat(timespec="seconds")

    # Build label
    if not label:
        label = f"DEMO [{tier}] - expires {exp[:10]} | {owner}"

    # Apply demo rate overrides as metadata
    rate_overrides = DEMO_RATE_OVERRIDES.get(tier, {})

    mgr = APIKeyManager()
    raw_key, record = mgr.create_key(
        tier=tier,
        owner=owner,
        label=label,
        expires_at=exp,
    )

    result = {
        "raw_key":        raw_key,
        "key_prefix":     raw_key[:25] + "...",
        "tier":           tier,
        "owner":          owner,
        "label":          label,
        "created_at":     now.isoformat(timespec="seconds"),
        "expires_at":     exp,
        "valid_for_hours": hours,
        "rate_limits": {
            **TIERS[tier],
            **rate_overrides,
        },
        "demo_instructions": {
            "authentication": "Pass key as: Authorization: Bearer <key>  OR  X-API-Key: <key>",
            "feed_endpoint":  "GET https://intel.cyberdudebivash.com/api/feed.json",
            "health_endpoint":"GET https://intel.cyberdudebivash.com/api/health",
            "docs_url":       "https://intel.cyberdudebivash.com/api",
            "warning":        f"This demo key expires in {hours}h. Contact enterprise@cyberdudebivash.in to upgrade.",
        },
    }

    # Write to output file if requested
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        log.info("Demo key written to %s", out_path)

    # Also save to data/auth/demo_keys.jsonl for audit
    _log_demo_key(result)

    return result


def _log_demo_key(result: dict) -> None:
    """Append demo key record to audit log (no raw key stored)."""
    log_path = REPO_ROOT / "data" / "auth" / "demo_keys.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    audit = {k: v for k, v in result.items() if k != "raw_key"}
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(audit, default=str) + "\n")
    except Exception as e:
        log.warning("Could not write demo key audit log: %s", e)


def list_demo_keys() -> None:
    """List all generated demo keys from audit log."""
    log_path = REPO_ROOT / "data" / "auth" / "demo_keys.jsonl"
    if not log_path.exists():
        print("No demo keys generated yet.")
        return
    lines = [l.strip() for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    now   = datetime.now(timezone.utc)
    active, expired = 0, 0

    print(f"\n{'KEY PREFIX':<28} {'TIER':<12} {'OWNER':<25} {'EXPIRES':<22} {'STATUS'}")
    print("-" * 110)
    for line in lines:
        try:
            rec   = json.loads(line)
            exp   = rec.get("expires_at", "")
            owner = rec.get("owner", "")[:24]
            tier  = rec.get("tier", "")
            pfx   = rec.get("key_prefix", "")[:27]
            try:
                status = "ACTIVE " if datetime.fromisoformat(exp) > now else "EXPIRED"
            except Exception:
                status = "UNKNOWN"
            if status == "ACTIVE ":
                active += 1
            else:
                expired += 1
            print(f"{pfx:<28} {tier:<12} {owner:<25} {exp[:19]:<22} {status}")
        except Exception:
            continue

    print("-" * 110)
    print(f"Total: {len(lines)} | Active: {active} | Expired: {expired}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
from typing import Optional  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Enterprise Demo Key Generator v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--owner",  default="Demo Prospect", help="Organization name (default: 'Demo Prospect')")
    parser.add_argument("--tier",   default=DEFAULT_TIER, choices=["FREE", "PRO", "ENTERPRISE", "MSSP"],
                        help=f"API tier (default: {DEFAULT_TIER})")
    parser.add_argument("--hours",  type=int, default=DEFAULT_HOURS,
                        help=f"Validity in hours (default: {DEFAULT_HOURS}, max: {DEFAULT_MAX_DAYS * 24})")
    parser.add_argument("--label",  default="", help="Custom label for this key")
    parser.add_argument("--output", default=None, metavar="FILE",
                        help="Write key JSON to this file")
    parser.add_argument("--list",   action="store_true", help="List all generated demo keys")
    args = parser.parse_args()

    if args.list:
        list_demo_keys()
        return 0

    try:
        result = generate_demo_key(
            owner=args.owner,
            tier=args.tier,
            hours=args.hours,
            label=args.label,
            output_file=args.output,
        )

        print("\n" + "=" * 70)
        print("  SENTINEL APEX -- ENTERPRISE DEMO KEY GENERATED")
        print("=" * 70)
        print(f"  Tier      : {result['tier']}")
        print(f"  Owner     : {result['owner']}")
        print(f"  Valid for : {result['valid_for_hours']} hours")
        print(f"  Expires   : {result['expires_at']}")
        print(f"  Label     : {result['label']}")
        print("=" * 70)
        print(f"\n  API KEY (shown ONCE -- store securely):\n")
        print(f"  {result['raw_key']}")
        print("\n" + "=" * 70)
        print(f"\n  Usage:  Authorization: Bearer {result['key_prefix']}")
        print(f"  Docs:   {result['demo_instructions']['docs_url']}")
        print(f"  Feeds:  {result['demo_instructions']['feed_endpoint']}")
        print(f"\n  {result['demo_instructions']['warning']}")
        print()

        if args.output:
            print(f"  Key details saved to: {args.output}")

        return 0

    except SystemExit as e:
        return int(e.code or 1)
    except Exception as e:
        log.error("Demo key generation failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
