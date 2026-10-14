#!/usr/bin/env python3
"""Offline, read-only release gate for one Cloudflare account shared by 10 platforms.

This tool NEVER calls Cloudflare or mutates live resources. An operator must
provide a RECENT, account-wide, reviewed usage/plan snapshot. Unknown metrics,
quotas, forecasts and billing-product coverage FAIL CLOSED. Does not imply
Cloudflare enforces a hard spending cap: unexpected public traffic can still
consume metered resources after the snapshot.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config/cloudflare_shared_account_zero_overage.json"


class ReleaseBlocked(ValueError):
    pass


def number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, str, float)):
        raise ReleaseBlocked(f"{label}: numeric value required")
    try:
        value = Decimal(str(value))
    except InvalidOperation as exc:
        raise ReleaseBlocked(f"{label}: invalid numeric value") from exc
    if not value.is_finite() or value < 0:
        raise ReleaseBlocked(f"{label}: nonnegative finite value required")
    return value


def instant(value, label):
    if not isinstance(value, str):
        raise ReleaseBlocked(f"{label}: ISO UTC date-time required")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseBlocked(f"{label}: invalid ISO date-time") from exc
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        raise ReleaseBlocked(f"{label}: must explicitly use UTC")
    return dt.astimezone(timezone.utc)


def validate_policy(policy):
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ReleaseBlocked("Zero-overage policy missing or version not supported")
    if policy.get("mode") != "STRICT_ZERO_CLOUDFLARE_OVERAGE":
        raise ReleaseBlocked("Zero-overage policy disabled")
    if policy.get("platform_count") != 10:
        raise ReleaseBlocked("Shared-account platform inventory is not ten")
    if number(policy.get("max_usage_based_overage_usd"), "max overage") != 0:
        raise ReleaseBlocked("Zero-overage limit must remain zero")
    reserve = number(policy.get("minimum_unallocated_headroom_percent"), "reserve")
    if not 10 <= reserve <= 50:
        raise ReleaseBlocked("Mandatory safety reserve must remain between 10 and 50 percent")
    age = number(policy.get("max_attestation_age_minutes"), "age")
    if not 0 < age <= 360:
        raise ReleaseBlocked("Account attestation must be refreshed within six hours")
    metrics = policy.get("minimum_required_metrics")
    if not isinstance(metrics, list) or len(metrics) < 12:
        raise ReleaseBlocked("Required metered-resource inventory missing")
    if not all(isinstance(x, str) and x and x.strip() == x for x in metrics):
        raise ReleaseBlocked("Invalid metric identifiers")
    if len(metrics) != len(set(metrics)):
        raise ReleaseBlocked("Duplicate resource metric")
    controls = policy.get("controls")
    if not isinstance(controls, dict):
        raise ReleaseBlocked("Cost controls missing")
    for name in ("allow_plan_upgrade", "allow_new_paid_resources",
                 "allow_new_cron_triggers", "allow_unbounded_r2_sync",
                 "allow_manual_bypass"):
        if controls.get(name) is not False:
            raise ReleaseBlocked(f"Disallowed cost control: {name}")
    if controls.get("default_when_unverified") != "BLOCK_NEW_OR_EXPANDED_METERED_WORKLOAD":
        raise ReleaseBlocked("Unverified usage must block new metered workloads")
    return policy


def certify(policy, record, *, now=None):
    """Return bounded headroom figures; raises on any unknown or unsafe input."""
    validate_policy(policy)
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        raise ReleaseBlocked("Account usage attestation missing")
    if record.get("source") != "cloudflare_account_billing_and_analytics":
        raise ReleaseBlocked("Actual Cloudflare account metrics required")
    if record.get("owner_verified") is not True:
        raise ReleaseBlocked("Owner verification required")
    if record.get("current_account_plan_verified") is not True:
        raise ReleaseBlocked("Current Cloudflare account plan not verified")
    if record.get("all_billing_products_accounted_for") is not True:
        raise ReleaseBlocked("Billing product inventory incomplete")
    if record.get("all_platforms_accounted_for") is not True:
        raise ReleaseBlocked("Ten-platform account aggregation not verified")
    platforms = record.get("platform_ids")
    if (not isinstance(platforms, list) or len(platforms) != policy["platform_count"]
        or len(set(str(x) for x in platforms)) != len(platforms)
        or any(not isinstance(x, str) or not x.strip() for x in platforms)):
        raise ReleaseBlocked("Exactly ten distinct platform identifiers required")
    for key in ("plan_change", "new_paid_resource", "new_cron_trigger",
                "unbounded_r2_sync", "manual_override"):
        if record.get(key) is not False:
            raise ReleaseBlocked(f"{key}: explicitly prohibited")

    now = now or datetime.now(timezone.utc)
    as_of = instant(record.get("as_of_utc"), "as_of_utc")
    if as_of > now + timedelta(minutes=5):
        raise ReleaseBlocked("Cloudflare snapshot is future dated")
    if now - as_of > timedelta(minutes=float(policy["max_attestation_age_minutes"])):
        raise ReleaseBlocked("Cloudflare snapshot too old")

    if number(record.get("usage_based_overage_usd"), "billed usage overage") != 0:
        raise ReleaseBlocked("Account already accrued usage overage")
    if number(record.get("projected_usage_overage_usd"), "forecast overage") != 0:
        raise ReleaseBlocked("Account projected to incur usage overage")

    metrics = record.get("metrics")
    if not isinstance(metrics, dict):
        raise ReleaseBlocked("Account metrics missing")
    missing = set(policy["minimum_required_metrics"]) - set(metrics)
    if missing:
        raise ReleaseBlocked(f"Account metrics missing: {', '.join(sorted(missing))}")
    if not metrics:
        raise ReleaseBlocked("No account metrics supplied")

    reserve = number(policy["minimum_unallocated_headroom_percent"], "reserve") / 100
    out = {}
    for key, entry in metrics.items():
        if not isinstance(key, str) or not key or not isinstance(entry, dict):
            raise ReleaseBlocked("Malformed billing metric entry")
        start = instant(entry.get("window_start_utc"), key + ".window_start_utc")
        end = instant(entry.get("window_end_utc"), key + ".window_end_utc")
        if start > as_of or end <= as_of or end <= now:
            raise ReleaseBlocked(key + ": expired or invalid quota window")
        if end - start > timedelta(days=36):
            raise ReleaseBlocked(key + ": billing quota window exceeds 36 days")
        included = number(entry.get("included"), key + ".included")
        used = number(entry.get("used_account_wide"), key + ".used_account_wide")
        committed = number(entry.get("forecast_all_platforms_until_reset"), key + ".forecast")
        delta = number(entry.get("proposed_increment_until_reset"), key + ".proposed_increment")
        unit = entry.get("unit")
        if not isinstance(unit, str) or not unit.strip() or len(unit) > 80:
            raise ReleaseBlocked(key + ": Cloudflare billing unit missing or invalid")
        if included == 0 and (used > 0 or committed > 0 or delta > 0):
            raise ReleaseBlocked(key + ": metric has no included allowance and would be billed")
        # Deliberately reserve headroom even for already-deployed traffic.
        # This is conservative forecasting, NOT Cloudflare's own hard cap.
        budget = included * (1 - reserve)
        remaining = budget - used - committed - delta
        if remaining < 0:
            raise ReleaseBlocked(key + ": would exceed 80%-or-lower account safety envelope")
        out[key] = {"included": str(included), "account_used": str(used),
                    "existing_forecast": str(committed), "proposal": str(delta),
                    "unallocated_after_forecast": str(remaining), "unit": entry.get("unit")}
    return {"verdict": "CONDITIONAL_ALLOW_ON_REVIEWED_SNAPSHOT",
            "account_scope": "10 platforms / 1 Cloudflare account",
            "snapshot_as_of_utc": as_of.isoformat(),
            "metrics": out,
            "qualification": "Offline account-owner evidence, NOT a live Cloudflare spending cap"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-policy", action="store_true")
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--policy", type=Path, default=POLICY)
    args = parser.parse_args(argv)
    try:
        policy = validate_policy(json.loads(args.policy.read_text(encoding="utf-8")))
        if args.validate_policy:
            if args.attestation:
                raise ReleaseBlocked("Choose policy-only check OR an attestation evaluation")
            print("PASS: strict account-wide zero-overage policy is structurally valid.")
            print("NOT CERTIFIED: live shared-account Cloudflare usage was not checked.")
            return 0
        if args.attestation is None:
            raise ReleaseBlocked("Missing verified account-wide Cloudflare usage attestation")
        result = certify(policy, json.loads(args.attestation.read_text(encoding="utf-8")))
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"BLOCK: new or expanded Cloudflare-metered workload forbidden: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
