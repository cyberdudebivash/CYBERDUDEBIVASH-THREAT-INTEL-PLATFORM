#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Quota Enforcement Engine
=============================================================
Enterprise Monetization: Phase 5

Enforces per-tier API quotas, request limits, and feature gates.
Integrates with the Cloudflare Worker / static API layer.

TIER DEFINITIONS:
  FREE        50 req/day  | 1,000 req/month  | Public feed only
  PRO        500 req/day  | 15,000 req/month  | + IOC + STIX + reports
  ENTERPRISE  unlimited   |  unlimited        | + AI enrichment + webhooks
  MSSP        unlimited   |  unlimited        | + multi-tenant + white-label

FEATURE GATES:
  Feature               FREE    PRO   ENTERPRISE  MSSP
  --------              ----    ---   ----------  ----
  /api/preview          YES     YES      YES      YES
  /api/feed             YES     YES      YES      YES
  /api/latest           YES     YES      YES      YES
  /api/v1/ioc/*         NO      YES      YES      YES
  /api/v1/stix/*        NO      YES      YES      YES
  /api/v1/reports/*     NO      YES      YES      YES
  /api/v1/ai/*          NO      NO       YES      YES
  /api/v1/webhooks/*    NO      NO       YES      YES
  /api/v1/multi-tenant  NO      NO       NO       YES
  CSV export            NO      YES      YES      YES
  PDF reports           NO      NO       YES      YES
  Priority support      NO      NO       YES      YES

Usage:
  python3 scripts/quota_enforcer.py validate <api_key>
  python3 scripts/quota_enforcer.py report
  python3 scripts/quota_enforcer.py reset-daily
  python3 scripts/quota_enforcer.py check-gate <api_key> <feature>
"""

import argparse
import datetime
import json
import pathlib
import sys
import hashlib
import hmac
from typing import Dict, Any, List, Optional, Tuple

# ============================================================
# TIER DEFINITIONS
# ============================================================
TIER_QUOTAS: Dict[str, Dict] = {
    "FREE": {
        "daily_limit":    50,
        "monthly_limit":  1_000,
        "rate_per_minute": 5,
        "burst_limit":    10,
        "price_usd":      0.0,
        "features":       ["preview", "feed", "latest", "health"],
    },
    "PRO": {
        "daily_limit":    500,
        "monthly_limit":  15_000,
        "rate_per_minute": 60,
        "burst_limit":    100,
        "price_usd":      49.0,
        "features":       ["preview", "feed", "latest", "health",
                           "ioc", "stix", "reports", "csv_export"],
    },
    "ENTERPRISE": {
        "daily_limit":    -1,      # -1 = unlimited
        "monthly_limit":  -1,
        "rate_per_minute": 300,
        "burst_limit":    500,
        "price_usd":      299.0,
        "features":       ["preview", "feed", "latest", "health",
                           "ioc", "stix", "reports", "csv_export",
                           "ai_enrichment", "webhooks", "pdf_reports",
                           "priority_support"],
    },
    "MSSP": {
        "daily_limit":    -1,
        "monthly_limit":  -1,
        "rate_per_minute": -1,     # -1 = unlimited
        "burst_limit":    -1,
        "price_usd":      999.0,
        "features":       ["preview", "feed", "latest", "health",
                           "ioc", "stix", "reports", "csv_export",
                           "ai_enrichment", "webhooks", "pdf_reports",
                           "priority_support", "multi_tenant", "white_label",
                           "sla_contract"],
    },
}

# Feature → minimum tier required
FEATURE_MIN_TIER: Dict[str, str] = {
    "preview":          "FREE",
    "feed":             "FREE",
    "latest":           "FREE",
    "health":           "FREE",
    "ioc":              "PRO",
    "stix":             "PRO",
    "reports":          "PRO",
    "csv_export":       "PRO",
    "ai_enrichment":    "ENTERPRISE",
    "webhooks":         "ENTERPRISE",
    "pdf_reports":      "ENTERPRISE",
    "priority_support": "ENTERPRISE",
    "multi_tenant":     "MSSP",
    "white_label":      "MSSP",
    "sla_contract":     "MSSP",
}

TIER_RANK = {"FREE": 0, "PRO": 1, "ENTERPRISE": 2, "MSSP": 3}

# ============================================================
# PATHS
# ============================================================
AUTH_PATH   = pathlib.Path("data/auth/api_keys.json")
USAGE_PATH  = pathlib.Path("data/monetization/usage_log.json")
QUOTA_PATH  = pathlib.Path("data/monetization/quota_status.json")


# ============================================================
# KEY LOADER
# ============================================================
def _load_keys() -> Dict[str, Dict]:
    """Load API keys dict. Returns {hash: key_record}."""
    if not AUTH_PATH.exists():
        return {}
    try:
        raw = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
        keys_raw = raw.get("keys", {})
        if isinstance(keys_raw, dict):
            return keys_raw
        # list format
        return {k["key_hash"]: k for k in keys_raw if isinstance(k, dict) and "key_hash" in k}
    except Exception:
        return {}


def _save_keys(keys: Dict[str, Dict]) -> None:
    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if AUTH_PATH.exists():
        try:
            existing = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing["keys"] = keys
    existing["version"] = existing.get("version", "1.0")
    existing["last_updated"] = datetime.datetime.utcnow().isoformat()
    AUTH_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


# ============================================================
# QUOTA VALIDATION
# ============================================================
def _today() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")


def _this_month() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")


def validate_key(api_key: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    Validate an API key. Returns (is_valid, reason, key_record).
    """
    if not api_key or not api_key.startswith("cdb_"):
        return False, "Invalid key format (must start with cdb_)", None

    key_hash = _hash_key(api_key)
    keys     = _load_keys()

    record = keys.get(key_hash)
    if not record:
        return False, "API key not found", None

    if not record.get("active", True):
        return False, "API key is revoked", record

    # Expiry check
    expires = record.get("expires_at")
    if expires:
        try:
            exp_ts = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if exp_ts.tzinfo is None:
                exp_ts = exp_ts.replace(tzinfo=datetime.timezone.utc)
            if datetime.datetime.now(datetime.timezone.utc) > exp_ts:
                return False, f"API key expired at {expires}", record
        except Exception:
            pass

    # Daily quota check
    tier       = record.get("tier", "FREE")
    quota_info = TIER_QUOTAS.get(tier, TIER_QUOTAS["FREE"])
    daily_lim  = quota_info["daily_limit"]
    today      = _today()

    if daily_lim != -1:
        # Reset counter if day changed
        if record.get("quota_reset_date", "") != today:
            record["requests_today"] = 0
            record["quota_reset_date"] = today

        if record.get("requests_today", 0) >= daily_lim:
            return False, f"Daily quota exceeded ({daily_lim} req/day for {tier})", record

    return True, "OK", record


def check_feature_gate(api_key: str, feature: str) -> Tuple[bool, str]:
    """
    Check if an API key has access to a feature.
    Returns (allowed, reason).
    """
    is_valid, reason, record = validate_key(api_key)
    if not is_valid:
        return False, reason

    tier        = record.get("tier", "FREE")
    tier_rank   = TIER_RANK.get(tier, 0)
    min_tier    = FEATURE_MIN_TIER.get(feature, "ENTERPRISE")
    min_rank    = TIER_RANK.get(min_tier, 2)

    if tier_rank < min_rank:
        return False, f"Feature '{feature}' requires {min_tier} tier (current: {tier})"

    return True, "OK"


def increment_usage(api_key: str) -> bool:
    """
    Increment request counter for a key. Returns False if over quota.
    """
    key_hash = _hash_key(api_key)
    keys     = _load_keys()
    record   = keys.get(key_hash)
    if not record:
        return False

    today = _today()
    if record.get("quota_reset_date", "") != today:
        record["requests_today"] = 0
        record["quota_reset_date"] = today

    record["requests_today"] = record.get("requests_today", 0) + 1
    record["total_requests"] = record.get("total_requests", 0) + 1
    record["last_used"]      = datetime.datetime.utcnow().isoformat()

    keys[key_hash] = record
    _save_keys(keys)

    tier      = record.get("tier", "FREE")
    daily_lim = TIER_QUOTAS.get(tier, TIER_QUOTAS["FREE"])["daily_limit"]
    if daily_lim != -1 and record["requests_today"] > daily_lim:
        return False

    return True


# ============================================================
# DAILY RESET
# ============================================================
def reset_daily_quotas() -> int:
    """Reset all daily counters for a new day. Returns number of keys reset."""
    keys  = _load_keys()
    today = _today()
    count = 0
    for key_hash, record in keys.items():
        if record.get("quota_reset_date", "") != today:
            record["requests_today"]  = 0
            record["quota_reset_date"] = today
            count += 1
    _save_keys(keys)
    return count


# ============================================================
# QUOTA STATUS REPORT
# ============================================================
def generate_quota_report() -> Dict:
    keys = _load_keys()

    tier_summary: Dict[str, Dict] = {}
    key_statuses = []

    for key_hash, record in keys.items():
        tier      = record.get("tier", "FREE")
        q         = TIER_QUOTAS.get(tier, TIER_QUOTAS["FREE"])
        daily_lim = q["daily_limit"]
        req_today = record.get("requests_today", 0)
        pct_used  = round(req_today / daily_lim * 100, 1) if daily_lim > 0 else 0

        if tier not in tier_summary:
            tier_summary[tier] = {
                "tier": tier,
                "key_count": 0,
                "active_count": 0,
                "total_requests_today": 0,
                "daily_limit": daily_lim,
                "price_usd": q["price_usd"],
            }
        tier_summary[tier]["key_count"] += 1
        if record.get("active", True):
            tier_summary[tier]["active_count"] += 1
        tier_summary[tier]["total_requests_today"] += req_today

        key_statuses.append({
            "prefix":         record.get("key_prefix", key_hash[:16]),
            "tier":           tier,
            "owner":          record.get("owner", "unknown"),
            "active":         record.get("active", True),
            "requests_today": req_today,
            "daily_limit":    daily_lim,
            "pct_used":       pct_used,
            "total_requests": record.get("total_requests", 0),
            "last_used":      record.get("last_used"),
        })

    total_revenue = sum(
        v["active_count"] * TIER_QUOTAS.get(t, {}).get("price_usd", 0)
        for t, v in tier_summary.items()
    )

    report = {
        "generated_at":    datetime.datetime.utcnow().isoformat(),
        "schema":          "sentinel_apex_quota_status_v1",
        "total_keys":      len(keys),
        "active_keys":     sum(1 for r in keys.values() if r.get("active", True)),
        "mrr_usd":         round(total_revenue, 2),
        "tier_summary":    list(tier_summary.values()),
        "key_statuses":    sorted(key_statuses, key=lambda x: TIER_RANK.get(x["tier"], 0), reverse=True),
    }

    QUOTA_PATH.parent.mkdir(parents=True, exist_ok=True)
    QUOTA_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


# ============================================================
# REPORT PRINTER
# ============================================================
def print_report(report: Dict) -> None:
    print("\n" + "=" * 68)
    print("SENTINEL APEX QUOTA ENFORCEMENT REPORT")
    print(f"Generated: {report['generated_at']}")
    print("=" * 68)
    print(f"  Total keys:    {report['total_keys']}")
    print(f"  Active keys:   {report['active_keys']}")
    print(f"  Est. MRR:      ${report['mrr_usd']:,.2f}/mo")
    print()
    print("  TIER BREAKDOWN:")
    for t in sorted(report["tier_summary"], key=lambda x: TIER_RANK.get(x["tier"], 0), reverse=True):
        price = TIER_QUOTAS.get(t["tier"], {}).get("price_usd", 0)
        print(f"    {t['tier']:<12} {t['active_count']:>3} active keys  "
              f"${price:>7.0f}/mo  "
              f"{t['total_requests_today']:>6} req today")
    print()
    print("  KEY STATUS:")
    for k in report["key_statuses"]:
        lim_str = str(k["daily_limit"]) if k["daily_limit"] != -1 else "unlimited"
        status  = "ACTIVE" if k["active"] else "REVOKED"
        bar_len = min(20, int(k["pct_used"] * 0.2)) if k["daily_limit"] != -1 else 0
        bar     = "#" * bar_len
        print(f"    {k['prefix']:<28} {k['tier']:<12} {status:<8} "
              f"{k['requests_today']:>5}/{lim_str:<12} {bar}")
    print()
    print("  FEATURE GATE MATRIX:")
    print(f"    {'Feature':<20} {'FREE':<8} {'PRO':<8} {'ENTERPRISE':<12} {'MSSP'}")
    for feature, min_tier in sorted(FEATURE_MIN_TIER.items()):
        min_rank = TIER_RANK.get(min_tier, 0)
        cells = []
        for tier in ["FREE", "PRO", "ENTERPRISE", "MSSP"]:
            cells.append("YES" if TIER_RANK.get(tier, 0) >= min_rank else "no")
        print(f"    {feature:<20} {cells[0]:<8} {cells[1]:<8} {cells[2]:<12} {cells[3]}")
    print("=" * 68)


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL APEX Quota Enforcement Engine")
    sub = parser.add_subparsers(dest="command")

    p_validate = sub.add_parser("validate", help="Validate an API key")
    p_validate.add_argument("api_key")

    p_gate = sub.add_parser("check-gate", help="Check feature gate for key")
    p_gate.add_argument("api_key")
    p_gate.add_argument("feature")

    sub.add_parser("report",      help="Generate quota status report")
    sub.add_parser("reset-daily", help="Reset daily quota counters")

    args = parser.parse_args()

    if args.command == "validate":
        valid, reason, record = validate_key(args.api_key)
        tier = record.get("tier", "?") if record else "?"
        print(f"[QUOTA] Valid={valid} | Tier={tier} | {reason}")
        sys.exit(0 if valid else 1)

    elif args.command == "check-gate":
        allowed, reason = check_feature_gate(args.api_key, args.feature)
        print(f"[QUOTA] Feature={args.feature} | Allowed={allowed} | {reason}")
        sys.exit(0 if allowed else 1)

    elif args.command == "reset-daily":
        n = reset_daily_quotas()
        print(f"[QUOTA] Reset daily counters for {n} keys")

    else:  # report (default)
        report = generate_quota_report()
        print_report(report)
        print(f"[QUOTA] Written: {QUOTA_PATH}")
