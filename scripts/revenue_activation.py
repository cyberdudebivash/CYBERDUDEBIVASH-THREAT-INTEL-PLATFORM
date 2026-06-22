#!/usr/bin/env python3
"""
revenue_activation.py — SENTINEL APEX Subscription Activation Engine v185.0

Provisions a paid subscription immediately after payment confirmation.
Updates active.json, customers.json, revenue_log.json, and pipeline.json.

Usage:
  python scripts/revenue_activation.py \
    --email customer@company.com \
    --plan enterprise \
    --payment-id PAY-RZP-ABC123 \
    --amount-usd 499 \
    --order-id ORD-ABC123

Plans: pro ($49) | enterprise ($499) | mssp ($1999)
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
ACTIVE_JSON    = ROOT / "data" / "subscriptions" / "active.json"
CUSTOMERS_JSON = ROOT / "data" / "billing" / "customers.json"
REVENUE_LOG    = ROOT / "data" / "revenue_log.json"
PIPELINE_JSON  = ROOT / "data" / "leads" / "pipeline.json"
PAYMENT_AUDIT  = ROOT / "data" / "payment_audit.jsonl"

# ─── Plan definitions ──────────────────────────────────────────────────────────
PLANS = {
    "pro": {
        "name": "PRO Defense",
        "monthly_usd": 49,
        "annual_usd": 470,
        "tier": "PRO",
        "api_calls_day": 10000,
        "ioc_limit": 50000,
        "seats": 3,
    },
    "enterprise": {
        "name": "Enterprise SOC",
        "monthly_usd": 499,
        "annual_usd": 4788,
        "tier": "ENTERPRISE",
        "api_calls_day": 100000,
        "ioc_limit": 1000000,
        "seats": 25,
    },
    "mssp": {
        "name": "MSSP / White-Label",
        "monthly_usd": 1999,
        "annual_usd": 19188,
        "tier": "MSSP",
        "api_calls_day": -1,  # unlimited
        "ioc_limit": -1,
        "seats": -1,
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  ✓ Written: {path.relative_to(ROOT)}")


def generate_api_key(email: str, tier: str) -> tuple[str, str]:
    """Return (plaintext_key, sha256_hash). Plaintext shown once then discarded."""
    raw = f"APEX-{tier}-{secrets.token_hex(16).upper()}"
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def activate_subscription(
    email: str,
    plan_id: str,
    payment_id: str,
    amount_usd: float,
    order_id: str,
    billing: str = "monthly",
    notes: str = "",
) -> dict:
    plan = PLANS.get(plan_id)
    if not plan:
        print(f"ERROR: Unknown plan '{plan_id}'. Valid: {list(PLANS.keys())}", file=sys.stderr)
        sys.exit(1)

    now      = _now_iso()
    sub_id   = "sub_" + uuid.uuid4().hex[:12]
    cus_id   = "cus_" + hashlib.sha256(email.lower().encode()).hexdigest()[:12]
    api_key, api_key_hash = generate_api_key(email, plan["tier"])

    period_days = 30 if billing == "monthly" else 365
    period_end  = (datetime.now(timezone.utc) + timedelta(days=period_days)).isoformat().replace("+00:00", "Z")

    subscription = {
        "sub_id": sub_id,
        "customer_id": cus_id,
        "email": email,
        "plan_id": plan_id,
        "tier": plan["tier"],
        "plan_name": plan["name"],
        "billing": billing,
        "amount_usd": amount_usd,
        "status": "ACTIVE",
        "trial": False,
        "payment_id": payment_id,
        "order_id": order_id,
        "api_key_hash": api_key_hash,
        "api_calls_day_limit": plan["api_calls_day"],
        "ioc_limit": plan["ioc_limit"],
        "seats": plan["seats"],
        "activated_at": now,
        "current_period_start": now,
        "current_period_end": period_end,
        "renewal_count": 0,
        "notes": notes,
    }

    # ── 1. Update active.json ──────────────────────────────────────────────────
    active = _load_json(ACTIVE_JSON)
    if "_meta" not in active:
        active["_meta"] = {}
    if "subscriptions" not in active:
        active["subscriptions"] = []

    # Remove stale entry for same email if exists
    active["subscriptions"] = [s for s in active["subscriptions"] if s.get("email") != email]
    active["subscriptions"].append(subscription)

    # Recompute meta
    subs = active["subscriptions"]
    tier_counts = {t: sum(1 for s in subs if s.get("tier") == t) for t in ["FREE", "TRIAL", "PRO", "ENTERPRISE", "MSSP"]}
    mrr_usd = sum(
        PLANS.get(s.get("plan_id", ""), {}).get("monthly_usd", 0)
        for s in subs if s.get("status") == "ACTIVE"
    )
    active["_meta"].update({
        "schema_version": "1.0",
        "description": "SENTINEL APEX Active Subscriptions Registry",
        "last_updated": now,
        "active_count": len(subs),
        "mrr_usd": mrr_usd,
        "mrr_inr": round(mrr_usd * 83.5),
        "arr_equivalent_usd": mrr_usd * 12,
        "arr_equivalent_inr": round(mrr_usd * 83.5 * 12),
        "tier_breakdown": tier_counts,
    })
    _save_json(ACTIVE_JSON, active)

    # ── 2. Update customers.json ───────────────────────────────────────────────
    customers = _load_json(CUSTOMERS_JSON)
    if "customers" not in customers:
        customers["customers"] = {}
    customers["customers"][email] = {
        "customer_id": cus_id,
        "subscription_id": sub_id,
        "tier": plan["tier"],
        "plan_id": plan_id,
        "plan_name": plan["name"],
        "amount_usd": amount_usd,
        "billing": billing,
        "payment_id": payment_id,
        "order_id": order_id,
        "status": "active",
        "activated_at": now,
        "api_key_hash": api_key_hash,
    }
    _save_json(CUSTOMERS_JSON, customers)

    # ── 3. Append to revenue_log.json ─────────────────────────────────────────
    rev_log = _load_json(REVENUE_LOG)
    if "events" not in rev_log:
        rev_log["events"] = []
    rev_log["events"].append({
        "event": "subscription_activated",
        "timestamp": now,
        "email": email,
        "plan_id": plan_id,
        "tier": plan["tier"],
        "amount_usd": amount_usd,
        "billing": billing,
        "payment_id": payment_id,
        "order_id": order_id,
        "sub_id": sub_id,
    })
    rev_log["last_updated"] = now
    rev_log["total_events"] = len(rev_log["events"])
    _save_json(REVENUE_LOG, rev_log)

    # ── 4. Append to payment_audit.jsonl ──────────────────────────────────────
    audit_entry = json.dumps({
        "ts": now,
        "event": "payment_verified_activation",
        "email": email,
        "plan": plan_id,
        "amount_usd": amount_usd,
        "payment_id": payment_id,
        "order_id": order_id,
        "sub_id": sub_id,
    })
    PAYMENT_AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with open(PAYMENT_AUDIT, "a") as f:
        f.write(audit_entry + "\n")
    print(f"  ✓ Audit log appended: {PAYMENT_AUDIT.relative_to(ROOT)}")

    # ── 5. Mark lead as converted in pipeline.json ────────────────────────────
    pipeline = _load_json(PIPELINE_JSON)
    if "_meta" in pipeline:
        pipeline["_meta"]["paying_customers"] = pipeline["_meta"].get("paying_customers", 0) + 1
        pipeline["_meta"]["last_updated"] = now
        pipeline["_meta"]["mrr_attributed_usd"] = pipeline["_meta"].get("mrr_attributed_usd", 0) + amount_usd
    if "leads" not in pipeline:
        pipeline["leads"] = []
    pipeline["leads"].append({
        "email": email,
        "stage": "active_subscriber",
        "plan": plan_id,
        "amount_usd": amount_usd,
        "converted_at": now,
        "sub_id": sub_id,
    })
    _save_json(PIPELINE_JSON, pipeline)

    return {
        "status": "SUCCESS",
        "sub_id": sub_id,
        "customer_id": cus_id,
        "plan": plan["name"],
        "tier": plan["tier"],
        "api_key": api_key,
        "api_key_hash": api_key_hash,
        "amount_usd": amount_usd,
        "activated_at": now,
        "period_end": period_end,
    }


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Revenue Activation Engine v185.0")
    parser.add_argument("--email",      required=True,  help="Customer email address")
    parser.add_argument("--plan",       required=True,  choices=["pro", "enterprise", "mssp"], help="Plan ID")
    parser.add_argument("--payment-id", required=True,  dest="payment_id", help="Payment reference (Razorpay/UPI/PayPal)")
    parser.add_argument("--amount-usd", required=False, dest="amount_usd", type=float, help="Verified payment amount in USD")
    parser.add_argument("--order-id",   required=False, dest="order_id",   default=None, help="Order ID from upgrade.html")
    parser.add_argument("--billing",    required=False, default="monthly", choices=["monthly", "annual"])
    parser.add_argument("--notes",      required=False, default="", help="Internal notes")
    args = parser.parse_args()

    plan  = PLANS[args.plan]
    amount = args.amount_usd if args.amount_usd else plan["monthly_usd"]
    order  = args.order_id or ("ORD-" + uuid.uuid4().hex[:8].upper())

    print(f"\n{'='*60}")
    print(f"  SENTINEL APEX — SUBSCRIPTION ACTIVATION ENGINE v185.0")
    print(f"{'='*60}")
    print(f"  Email:      {args.email}")
    print(f"  Plan:       {plan['name']} ({args.plan})")
    print(f"  Amount:     ${amount} USD / billing: {args.billing}")
    print(f"  Payment ID: {args.payment_id}")
    print(f"  Order ID:   {order}")
    print(f"{'='*60}\n")

    result = activate_subscription(
        email=args.email,
        plan_id=args.plan,
        payment_id=args.payment_id,
        amount_usd=amount,
        order_id=order,
        billing=args.billing,
        notes=args.notes,
    )

    print(f"\n{'='*60}")
    print(f"  ACTIVATION COMPLETE")
    print(f"{'='*60}")
    print(f"  Sub ID:       {result['sub_id']}")
    print(f"  Customer ID:  {result['customer_id']}")
    print(f"  Tier:         {result['tier']}")
    print(f"  API Key:      {result['api_key']}")
    print(f"  Activated:    {result['activated_at']}")
    print(f"  Period End:   {result['period_end']}")
    print(f"\n  IMPORTANT: Deliver API key to customer NOW.")
    print(f"  WhatsApp: +91 8179881447 or email: support@cyberdudebivash.com")
    print(f"{'='*60}\n")

    # Write activation summary for CI/CD consumption
    summary_path = ROOT / "data" / "subscriptions" / f"activation_{result['sub_id']}.json"
    _save_json(summary_path, result)


if __name__ == "__main__":
    main()
