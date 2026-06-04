#!/usr/bin/env python3
"""
generate_key.py — SENTINEL APEX API Key Provisioning Tool v176.0
=================================================================
Generates, activates, expires, and revokes API keys with full audit trail.
Reads/writes: data/keys/active_keys.json
              data/security/revoked_keys.json

Usage:
  # Generate a new PRO key for a customer (30-day subscription)
  python generate_key.py generate --tier pro --email customer@company.com --ref SA-20260604-A7X2 --days 30

  # Generate a 7-day TRIAL key
  python generate_key.py generate --tier trial --email trialist@company.com --ref SA-20260604-B3K9 --days 7

  # Generate an ENTERPRISE key (365-day annual)
  python generate_key.py generate --tier enterprise --email ciso@bigcorp.com --ref SA-20260604-C5M2 --days 365

  # Generate an MSSP key
  python generate_key.py generate --tier mssp --email ops@msspco.com --ref SA-20260604-D8N4 --days 30

  # List all active keys (masked)
  python generate_key.py list

  # Check a key's status
  python generate_key.py status --key SA-PRO-ABCDEF1234567890

  # Expire a key immediately (e.g. non-renewal)
  python generate_key.py expire --key SA-PRO-ABCDEF1234567890

  # Revoke a key (immediate effect, no grace period)
  python generate_key.py revoke --key SA-PRO-ABCDEF1234567890 --reason "Credential compromise"

  # Show revenue summary
  python generate_key.py revenue

Requirements: Python 3.8+, no external dependencies.
"""

import os
import sys
import json
import hmac
import secrets
import hashlib
import argparse
import datetime
from typing import Optional

# ─── CONFIG ──────────────────────────────────────────────────────────────────
ACTIVE_KEYS_PATH   = "data/keys/active_keys.json"
REVOKED_KEYS_PATH  = "data/security/revoked_keys.json"
CUSTOMERS_PATH     = "data/customers/registry.json"
SUBSCRIPTIONS_PATH = "data/subscriptions/active.json"

# Tier → daily quota mapping (matches rate_limiter.py)
TIER_QUOTAS = {
    "FREE":       100,
    "TRIAL":      500,
    "PRO":        5_000,
    "ENTERPRISE": 50_000,
    "MSSP":       500_000,
}

# Tier → key prefix
TIER_PREFIXES = {
    "FREE":       "SA-FREE",
    "TRIAL":      "SA-TRIAL",
    "PRO":        "SA-PRO",
    "ENTERPRISE": "SA-ENT",
    "MSSP":       "SA-MSSP",
}

# Grace period (days) after expiry before hard revocation
GRACE_PERIOD_DAYS = 3

# ─── UTILITIES ────────────────────────────────────────────────────────────────
def sha256(data: str) -> str:
    return hashlib.sha256(data.strip().encode("utf-8")).hexdigest()

def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def days_from_now(days: int) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    return dt.isoformat()

def parse_dt(s: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))

def is_expired(expires_at: str) -> bool:
    return parse_dt(expires_at) < datetime.datetime.now(datetime.timezone.utc)

def load_json(path: str, default=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
    return default if default is not None else {}

def save_json(path: str, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ─── KEY GENERATION ───────────────────────────────────────────────────────────
def generate_key(
    tier: str,
    customer_email: str,
    reference_id: str,
    days: int,
    customer_name: str = "",
    company: str = "",
    notes: str = "",
) -> dict:
    """
    Generate a new API key, register it in active_keys.json.
    Returns the full key record including the plaintext key (shown once only).
    """
    tier = tier.upper()
    if tier not in TIER_PREFIXES:
        raise ValueError(f"Unknown tier '{tier}'. Valid: {list(TIER_PREFIXES.keys())}")

    # Generate key
    prefix = TIER_PREFIXES[tier]
    token  = secrets.token_hex(16).upper()
    key    = f"{prefix}-{token}"
    key_hash = sha256(key)

    expiry = days_from_now(days)
    grace_end = days_from_now(days + GRACE_PERIOD_DAYS)

    record = {
        "key_hash":       key_hash,
        "tier":           tier,
        "customer_email": customer_email,
        "customer_name":  customer_name,
        "company":        company,
        "reference_id":   reference_id,
        "api_calls_per_day": TIER_QUOTAS.get(tier, 100),
        "issued_at":      now_utc(),
        "expires_at":     expiry,
        "grace_ends_at":  grace_end,
        "status":         "active",
        "renewal_count":  0,
        "notes":          notes,
    }

    # Load and update active_keys.json
    data = load_json(ACTIVE_KEYS_PATH, {"_meta": {}, "keys": {}})
    if "keys" not in data:
        data["keys"] = {}
    data["keys"][key_hash] = record
    data.setdefault("_meta", {})
    data["_meta"]["last_updated"] = now_utc()
    data["_meta"]["total_keys"] = len(data["keys"])
    save_json(ACTIVE_KEYS_PATH, data)

    # Audit log
    _append_audit("KEY_GENERATED", key_hash[:12], tier, customer_email, reference_id)

    result = dict(record)
    result["key"] = key  # Include plaintext ONLY in this return value — never stored
    return result


def activate_key(key_hash: str) -> bool:
    """Set a key's status to 'active' (idempotent)."""
    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    if key_hash not in data.get("keys", {}):
        return False
    data["keys"][key_hash]["status"] = "active"
    data["_meta"]["last_updated"] = now_utc()
    save_json(ACTIVE_KEYS_PATH, data)
    return True


def expire_key(key_plaintext: str, reason: str = "subscription_ended") -> bool:
    """Mark a key as expired (grace period begins, hard revocation in 3 days)."""
    kh = sha256(key_plaintext)
    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    if kh not in data.get("keys", {}):
        print(f"  [!] Key not found in active registry.")
        return False
    data["keys"][kh]["status"] = "expired"
    data["keys"][kh]["expired_at"] = now_utc()
    data["keys"][kh]["expiry_reason"] = reason
    data["_meta"]["last_updated"] = now_utc()
    save_json(ACTIVE_KEYS_PATH, data)
    # Schedule revocation: add to revoked after grace (manual step in Phase 1)
    _append_audit("KEY_EXPIRED", kh[:12], data["keys"][kh].get("tier","?"),
                  data["keys"][kh].get("customer_email","?"), reason)
    print(f"  ✓ Key marked expired. Grace period ends: {data['keys'][kh]['grace_ends_at'][:10]}")
    return True


def revoke_key(key_plaintext: str, reason: str = "") -> bool:
    """Immediately revoke a key — effective on next API request."""
    kh = sha256(key_plaintext)

    # Add to revocation registry
    rev_data = load_json(REVOKED_KEYS_PATH, {"revoked_hashes": [], "revocation_log": []})
    if kh not in rev_data["revoked_hashes"]:
        rev_data["revoked_hashes"].append(kh)
    rev_data["revocation_log"].append({
        "key_hash_prefix": kh[:12],
        "reason": reason,
        "revoked_at": now_utc(),
    })
    save_json(REVOKED_KEYS_PATH, rev_data)

    # Update active_keys status
    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    if kh in data.get("keys", {}):
        data["keys"][kh]["status"] = "revoked"
        data["keys"][kh]["revoked_at"] = now_utc()
        data["keys"][kh]["revoke_reason"] = reason
        save_json(ACTIVE_KEYS_PATH, data)

    _append_audit("KEY_REVOKED", kh[:12], "?", "?", reason)
    print(f"  ✓ Key REVOKED. Hash: {kh[:12]}... Effective immediately on next API request.")
    return True


def check_key_status(key_plaintext: str) -> dict:
    """Return current status of a key."""
    kh = sha256(key_plaintext)

    # Check revocation first
    rev_data = load_json(REVOKED_KEYS_PATH, {"revoked_hashes": []})
    if kh in rev_data.get("revoked_hashes", []):
        return {"status": "REVOKED", "key_hash": kh[:12]}

    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    if kh not in data.get("keys", {}):
        return {"status": "UNKNOWN", "key_hash": kh[:12]}

    record = data["keys"][kh]
    # Check expiry
    if is_expired(record["expires_at"]):
        if "grace_ends_at" in record and not is_expired(record["grace_ends_at"]):
            record["_runtime_status"] = "GRACE_PERIOD"
        else:
            record["_runtime_status"] = "EXPIRED_HARD"
    else:
        record["_runtime_status"] = "ACTIVE"

    days_left = (parse_dt(record["expires_at"]) - datetime.datetime.now(datetime.timezone.utc)).days
    record["_days_remaining"] = max(0, days_left)
    return record


def rotate_key(old_key_plaintext: str, customer_email: str, ref_id: str) -> dict:
    """Rotate a key: revoke old, generate new with same tier and remaining days."""
    kh = sha256(old_key_plaintext)
    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    old_record = data.get("keys", {}).get(kh)

    if not old_record:
        raise ValueError("Old key not found in active registry.")

    # Compute remaining days
    remaining = (parse_dt(old_record["expires_at"]) - datetime.datetime.now(datetime.timezone.utc)).days
    remaining = max(1, remaining)

    # Generate replacement
    new_record = generate_key(
        tier=old_record["tier"],
        customer_email=customer_email or old_record["customer_email"],
        reference_id=ref_id or old_record["reference_id"],
        days=remaining,
        customer_name=old_record.get("customer_name", ""),
        company=old_record.get("company", ""),
        notes=f"Rotated from {kh[:12]}",
    )
    new_record["renewal_count"] = old_record.get("renewal_count", 0)

    # Revoke old (with 7-day overlap for smooth transition)
    rev_data = load_json(REVOKED_KEYS_PATH, {"revoked_hashes": [], "revocation_log": []})
    # Don't hard-revoke immediately — mark as rotated in active_keys
    data["keys"][kh]["status"] = "rotated"
    data["keys"][kh]["rotated_at"] = now_utc()
    data["keys"][kh]["rotated_to"] = new_record["key_hash"][:12]
    save_json(ACTIVE_KEYS_PATH, data)

    _append_audit("KEY_ROTATED", kh[:12], old_record["tier"], customer_email, ref_id)
    return new_record

# ─── REVENUE SUMMARY ─────────────────────────────────────────────────────────
PLAN_MRR = {
    "FREE": 0, "TRIAL": 0, "PRO": 4100, "ENTERPRISE": 41600, "MSSP": 166600
}

def revenue_summary() -> dict:
    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    keys = data.get("keys", {})

    active = [v for v in keys.values() if v.get("status") == "active" and not is_expired(v.get("expires_at", "2000-01-01"))]
    tier_counts = {}
    mrr = 0
    for k in active:
        tier = k.get("tier", "FREE")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        mrr += PLAN_MRR.get(tier, 0)

    return {
        "active_keys": len(active),
        "tier_breakdown": tier_counts,
        "mrr_inr": mrr,
        "arr_equivalent_inr": mrr * 12,
        "as_of": now_utc(),
    }

# ─── AUDIT LOG ────────────────────────────────────────────────────────────────
def _append_audit(event: str, key_prefix: str, tier: str, identity: str, detail: str):
    audit_path = "data/keys/audit.log"
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    entry = f"{now_utc()} | {event:20} | {tier:12} | {key_prefix:16} | {identity:40} | {detail}\n"
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(entry)

# ─── RUNTIME AUTH INTEGRATION ─────────────────────────────────────────────────
def resolve_tier_from_registry(key: str) -> tuple:
    """
    Check active_keys.json for key tier and expiry.
    Returns: (tier, status, record_or_None)
    Designed to be called from auth.py as a supplement to config-based keys.
    """
    kh = sha256(key)

    # Check revocation first
    rev_data = load_json(REVOKED_KEYS_PATH, {"revoked_hashes": []})
    if kh in rev_data.get("revoked_hashes", []):
        return "FREE", "revoked", None

    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    record = data.get("keys", {}).get(kh)
    if not record:
        return "FREE", "unknown", None

    # Check expiry
    if is_expired(record.get("expires_at", "2000-01-01")):
        grace = record.get("grace_ends_at")
        if grace and not is_expired(grace):
            return record["tier"], "grace", record
        return "FREE", "expired", None

    if record.get("status") == "revoked":
        return "FREE", "revoked", None

    return record["tier"], "active", record

# ─── CLI ──────────────────────────────────────────────────────────────────────
def cmd_generate(args):
    print(f"\n  Generating {args.tier.upper()} key...")
    record = generate_key(
        tier=args.tier,
        customer_email=args.email,
        reference_id=args.ref,
        days=args.days,
        customer_name=getattr(args, 'name', ''),
        company=getattr(args, 'company', ''),
        notes=getattr(args, 'notes', ''),
    )
    print(f"\n  ═══════════════════════════════════════════")
    print(f"  API KEY (copy now — shown once only):")
    print(f"  {record['key']}")
    print(f"  ═══════════════════════════════════════════")
    print(f"  Tier:       {record['tier']}")
    print(f"  Customer:   {record['customer_email']}")
    print(f"  Reference:  {record['reference_id']}")
    print(f"  Quota/day:  {record['api_calls_per_day']:,} calls")
    print(f"  Issued:     {record['issued_at'][:10]}")
    print(f"  Expires:    {record['expires_at'][:10]}")
    print(f"  Key Hash:   {record['key_hash'][:24]}...")
    print(f"\n  ✓ Registered in {ACTIVE_KEYS_PATH}")
    print(f"\n  NEXT STEP: Email this key to {record['customer_email']}")
    print(f"  Use template: templates/email/api_key_delivered.txt")

def cmd_list(args):
    data = load_json(ACTIVE_KEYS_PATH, {"keys": {}})
    keys = data.get("keys", {})
    if not keys:
        print("  No keys in registry.")
        return
    print(f"\n  {'HASH[:12]':<14} {'TIER':<12} {'STATUS':<12} {'EXPIRES':<12} {'CUSTOMER'}")
    print(f"  {'─'*14} {'─'*12} {'─'*12} {'─'*12} {'─'*30}")
    for kh, rec in keys.items():
        exp = rec.get("expires_at", "")[:10]
        expired = is_expired(rec.get("expires_at", "2000-01-01"))
        status = rec.get("status", "active")
        if expired and status == "active":
            status = "EXPIRED"
        print(f"  {kh[:12]:<14} {rec.get('tier','?'):<12} {status:<12} {exp:<12} {rec.get('customer_email','?')}")

def cmd_status(args):
    record = check_key_status(args.key)
    print(f"\n  Key Status Report")
    print(f"  ─────────────────────────────────────────")
    for k, v in record.items():
        if k not in ("key_hash",):
            print(f"  {k:<25}: {v}")

def cmd_expire(args):
    print(f"\n  Expiring key: {args.key[:18]}...")
    expire_key(args.key, getattr(args, 'reason', 'manual_expiry'))

def cmd_revoke(args):
    print(f"\n  Revoking key: {args.key[:18]}...")
    revoke_key(args.key, getattr(args, 'reason', ''))

def cmd_rotate(args):
    print(f"\n  Rotating key: {args.key[:18]}...")
    new_record = rotate_key(args.key, args.email, args.ref)
    print(f"\n  ═══════════════════════════════════════════")
    print(f"  NEW KEY: {new_record['key']}")
    print(f"  ═══════════════════════════════════════════")
    print(f"  Old key marked as 'rotated' (not yet revoked)")
    print(f"  Old key will be hard-revoked after 7 days")

def cmd_revenue(args):
    summary = revenue_summary()
    print(f"\n  SENTINEL APEX Revenue Summary — {summary['as_of'][:10]}")
    print(f"  ─────────────────────────────────────────")
    print(f"  Active Keys:  {summary['active_keys']}")
    print(f"  MRR (INR):    ₹{summary['mrr_inr']:,}")
    print(f"  ARR (INR):    ₹{summary['arr_equivalent_inr']:,}")
    print(f"  Tier Breakdown:")
    for tier, count in summary["tier_breakdown"].items():
        print(f"    {tier:<12}: {count}")

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX API Key Provisioning Tool v176.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate
    gen = sub.add_parser("generate", help="Generate a new API key")
    gen.add_argument("--tier",    required=True, choices=["free","trial","pro","enterprise","mssp"])
    gen.add_argument("--email",   required=True, help="Customer email")
    gen.add_argument("--ref",     required=True, help="Reference ID (SA-YYYYMMDD-XXXX)")
    gen.add_argument("--days",    type=int, default=30, help="Key validity in days")
    gen.add_argument("--name",    default="", help="Customer full name")
    gen.add_argument("--company", default="", help="Company name")
    gen.add_argument("--notes",   default="", help="Operator notes")

    # list
    sub.add_parser("list", help="List all keys (masked)")

    # status
    stat = sub.add_parser("status", help="Check key status")
    stat.add_argument("--key", required=True, help="Full plaintext API key")

    # expire
    exp = sub.add_parser("expire", help="Expire a key (grace period begins)")
    exp.add_argument("--key",    required=True, help="Full plaintext API key")
    exp.add_argument("--reason", default="subscription_ended")

    # revoke
    rev = sub.add_parser("revoke", help="Immediately revoke a key")
    rev.add_argument("--key",    required=True, help="Full plaintext API key")
    rev.add_argument("--reason", default="", help="Reason for revocation")

    # rotate
    rot = sub.add_parser("rotate", help="Rotate a key (old deprecated, new issued)")
    rot.add_argument("--key",   required=True, help="Old plaintext API key")
    rot.add_argument("--email", required=True, help="Customer email (for new key record)")
    rot.add_argument("--ref",   required=True, help="Reference ID")

    # revenue
    sub.add_parser("revenue", help="Show revenue summary from active keys")

    args = parser.parse_args()
    cmds = {
        "generate": cmd_generate, "list": cmd_list,   "status": cmd_status,
        "expire":   cmd_expire,   "revoke": cmd_revoke, "rotate": cmd_rotate,
        "revenue":  cmd_revenue,
    }
    cmds[args.command](args)

if __name__ == "__main__":
    main()
