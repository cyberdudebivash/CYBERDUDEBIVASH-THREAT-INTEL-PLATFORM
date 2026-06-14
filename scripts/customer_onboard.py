#!/usr/bin/env python3
"""
customer_onboard.py — SENTINEL APEX Customer Provisioning Tool v177.0
======================================================================
End-to-end operator script to onboard a new international subscriber:
  1. Validates customer details and jurisdiction compliance
  2. Generates API key (reuses generate_key.py core logic)
  3. Registers customer in data/customers/registry.json
  4. Creates subscription record in data/subscriptions/active.json
  5. Writes audit entry to data/payment_audit.jsonl
  6. Outputs a printable welcome package

Usage:
  python scripts/customer_onboard.py provision \\
      --name "Alice Smith" \\
      --email alice@company.com \\
      --company "Acme Corp" \\
      --country US \\
      --tier pro \\
      --days 30 \\
      --ref SA-20260613-XXXX \\
      --payment-ref "STRIPE-PI-XXXXXX"

  python scripts/customer_onboard.py list
  python scripts/customer_onboard.py revenue

Supported country codes: US, UK, DE, UAE, IN (and any ISO-3166-1 alpha-2)
"""

import os
import sys
import json
import secrets
import hashlib
import argparse
import datetime
import textwrap

# ─── PATH: allow import from agent/tools ─────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "agent", "tools"))
import generate_key as _gk

# ─── FILE PATHS ──────────────────────────────────────────────────────────────
CUSTOMERS_PATH     = os.path.join(_ROOT, "data", "customers", "registry.json")
SUBSCRIPTIONS_PATH = os.path.join(_ROOT, "data", "subscriptions", "active.json")
PAYMENT_AUDIT_PATH = os.path.join(_ROOT, "data", "payment_audit.jsonl")
WELCOME_PKG_DIR    = os.path.join(_ROOT, "data", "welcome_packages")

# ─── JURISDICTION MAP ────────────────────────────────────────────────────────
# country_code -> (region_label, aws_region, dpa_framework, supervisory_authority)
JURISDICTION = {
    "US":  ("North America", "us-east-1",  "CCPA/CPRA",         "N/A (California AG for CA residents)"),
    "UK":  ("UK",            "eu-west-1",  "UK GDPR + DPA 2018","Information Commissioner's Office (ICO)"),
    "DE":  ("EU / Germany",  "eu-west-1",  "EU GDPR + BDSG",    "BfDI / Landesbeauftragter"),
    "UAE": ("APAC / UAE",    "ap-south-1", "UAE PDPL (2021)",    "TDRA — Telecommunications & Digital Gov. Regulatory Authority"),
    "IN":  ("South Asia",    "ap-south-1", "DPDP Act 2023",      "Data Protection Board of India"),
    "SG":  ("APAC",          "ap-southeast-1","PDPA Singapore",  "Personal Data Protection Commission (PDPC)"),
    "AU":  ("APAC",          "ap-southeast-2","Privacy Act 1988","Office of the Australian Information Commissioner (OAIC)"),
    "CA":  ("North America", "us-east-1",  "PIPEDA / Law 25",   "Office of the Privacy Commissioner of Canada"),
}
DEFAULT_JURISDICTION = ("Global", "us-east-1", "Applicable local law", "Local DPA")

# ─── TIER PRICING (INR monthly) ──────────────────────────────────────────────
TIER_PRICING_INR = {"FREE": 0, "TRIAL": 0, "PRO": 4100, "ENTERPRISE": 41600, "MSSP": 166600}
TIER_PRICING_USD = {"FREE": 0, "TRIAL": 0, "PRO": 49,   "ENTERPRISE": 499,   "MSSP": 1999}

# ─── UTILITIES ────────────────────────────────────────────────────────────────
def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def today_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

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

def append_jsonl(path: str, record: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def gen_customer_id() -> str:
    return "C-" + secrets.token_hex(4).upper()

def gen_sub_id() -> str:
    return "SUB-" + secrets.token_hex(5).upper()

def normalize_country(code: str) -> str:
    return code.upper().strip()

# ─── CUSTOMER REGISTRY ────────────────────────────────────────────────────────
def register_customer(
    customer_id: str,
    name: str,
    email: str,
    company: str,
    country: str,
    tier: str,
    ref_id: str,
    key_hash_prefix: str,
) -> dict:
    data = load_json(CUSTOMERS_PATH, {
        "_meta": {"schema_version": "1.0", "total_customers": 0, "active_customers": 0,
                  "mrr_inr": 0, "arr_inr": 0, "created": today_str(), "last_updated": today_str()},
        "customers": []
    })

    juri = JURISDICTION.get(normalize_country(country), DEFAULT_JURISDICTION)
    record = {
        "customer_id":           customer_id,
        "name":                  name,
        "email":                 email,
        "company":               company,
        "country":               normalize_country(country),
        "jurisdiction":          juri[0],
        "data_residency_region": juri[1],
        "compliance_framework":  juri[2],
        "supervisory_authority": juri[3],
        "tier":                  tier.upper(),
        "reference_id":          ref_id,
        "api_key_hash_prefix":   key_hash_prefix,
        "status":                "active",
        "onboarded_at":          now_utc(),
        "dpa_version":           "177.0.0",
        "dpa_accepted":          False,
        "notes":                 "",
    }

    customers = data.get("customers", [])
    customers.append(record)
    data["customers"] = customers

    meta = data.setdefault("_meta", {})
    meta["last_updated"] = today_str()
    meta["total_customers"] = len(customers)
    meta["active_customers"] = sum(1 for c in customers if c.get("status") == "active")

    # Recompute MRR
    mrr = sum(TIER_PRICING_INR.get(c.get("tier", "FREE"), 0)
              for c in customers if c.get("status") == "active")
    meta["mrr_inr"] = mrr
    meta["arr_inr"] = mrr * 12

    save_json(CUSTOMERS_PATH, data)
    return record


# ─── SUBSCRIPTION REGISTRY ───────────────────────────────────────────────────
def register_subscription(
    sub_id: str,
    customer_id: str,
    email: str,
    tier: str,
    days: int,
    ref_id: str,
    payment_ref: str,
    key_hash_prefix: str,
) -> dict:
    data = load_json(SUBSCRIPTIONS_PATH, {
        "_meta": {"schema_version": "1.0", "active_count": 0, "mrr_inr": 0,
                  "arr_equivalent_inr": 0,
                  "tier_breakdown": {"FREE": 0, "TRIAL": 0, "PRO": 0, "ENTERPRISE": 0, "MSSP": 0},
                  "created": today_str(), "last_updated": today_str()},
        "subscriptions": []
    })

    tier_up = tier.upper()
    start = datetime.datetime.now(datetime.timezone.utc)
    end   = start + datetime.timedelta(days=days)

    record = {
        "sub_id":              sub_id,
        "customer_id":         customer_id,
        "customer_email":      email,
        "tier":                tier_up,
        "status":              "active",
        "billing_cycle_days":  days,
        "started_at":          start.isoformat(),
        "current_period_end":  end.isoformat(),
        "payment_ref":         payment_ref,
        "reference_id":        ref_id,
        "api_key_hash_prefix": key_hash_prefix,
        "price_usd":           TIER_PRICING_USD.get(tier_up, 0),
        "price_inr":           TIER_PRICING_INR.get(tier_up, 0),
        "auto_renew":          True,
        "created_at":          now_utc(),
    }

    subs = data.get("subscriptions", [])
    subs.append(record)
    data["subscriptions"] = subs

    meta = data.setdefault("_meta", {})
    meta["last_updated"] = today_str()
    meta["active_count"] = sum(1 for s in subs if s.get("status") == "active")

    breakdown = meta.setdefault("tier_breakdown", {t: 0 for t in ["FREE","TRIAL","PRO","ENTERPRISE","MSSP"]})
    breakdown[tier_up] = breakdown.get(tier_up, 0) + 1

    mrr = sum(TIER_PRICING_INR.get(s.get("tier","FREE"), 0)
              for s in subs if s.get("status") == "active")
    meta["mrr_inr"] = mrr
    meta["arr_equivalent_inr"] = mrr * 12

    save_json(SUBSCRIPTIONS_PATH, data)
    return record


# ─── PAYMENT AUDIT ───────────────────────────────────────────────────────────
def write_payment_audit(
    event: str,
    customer_id: str,
    email: str,
    tier: str,
    ref_id: str,
    payment_ref: str,
    amount_inr: int,
    country: str,
):
    append_jsonl(PAYMENT_AUDIT_PATH, {
        "event":       event,
        "timestamp":   now_utc(),
        "customer_id": customer_id,
        "email":       email,
        "tier":        tier.upper(),
        "ref_id":      ref_id,
        "payment_ref": payment_ref,
        "amount_inr":  amount_inr,
        "country":     normalize_country(country),
        "operator":    "customer_onboard.py v177.0",
    })


# ─── WELCOME PACKAGE ─────────────────────────────────────────────────────────
def generate_welcome_package(
    key_record: dict,
    customer_record: dict,
    sub_record: dict,
) -> str:
    juri  = JURISDICTION.get(customer_record["country"], DEFAULT_JURISDICTION)
    tier  = key_record["tier"]
    quota = key_record["api_calls_per_day"]
    quota_str = "Unlimited" if quota < 0 else f"{quota:,}"

    pkg = textwrap.dedent(f"""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║         CYBERDUDEBIVASH® SENTINEL APEX — WELCOME PACKAGE           ║
    ║                    CONFIDENTIAL — OPERATOR COPY                     ║
    ╚══════════════════════════════════════════════════════════════════════╝

    CUSTOMER DETAILS
    ─────────────────────────────────────────────────────────────────────
    Customer ID  : {customer_record['customer_id']}
    Name         : {customer_record['name']}
    Email        : {customer_record['email']}
    Company      : {customer_record['company']}
    Country      : {customer_record['country']} ({customer_record['jurisdiction']})
    Subscription : {sub_record['sub_id']}
    Tier         : {tier}
    Period Start : {sub_record['started_at'][:10]}
    Period End   : {sub_record['current_period_end'][:10]}
    Payment Ref  : {sub_record['payment_ref']}

    API CREDENTIALS (SHOWN ONCE — COPY IMMEDIATELY)
    ─────────────────────────────────────────────────────────────────────
    API KEY      : {key_record['key']}
    Daily Quota  : {quota_str} API calls/day
    Expires      : {key_record['expires_at'][:10]}
    Key Hash     : {key_record['key_hash'][:24]}...

    QUICK START
    ─────────────────────────────────────────────────────────────────────
    Base URL     : https://intel.cyberdudebivash.com/api/v1
    Auth header  : Authorization: Bearer <YOUR_API_KEY>

    Test your key:
      curl -H "Authorization: Bearer {key_record['key']}" \\
           https://intel.cyberdudebivash.com/api/v1/ping

    DATA RESIDENCY & COMPLIANCE
    ─────────────────────────────────────────────────────────────────────
    AWS Region   : {juri[1]}
    Framework    : {juri[2]}
    DPA Version  : {customer_record['dpa_version']}
    Supervisory  : {juri[3]}
    DPA Request  : privacy@cyberdudebivash.com

    SUPPORT CONTACTS
    ─────────────────────────────────────────────────────────────────────
    Platform     : https://intel.cyberdudebivash.com
    API Docs     : https://intel.cyberdudebivash.com/api-docs.html
    Support      : intelligence@cyberdudebivash.com
    Privacy      : privacy@cyberdudebivash.com
    Billing      : iambivash.bn@gmail.com

    ─────────────────────────────────────────────────────────────────────
    SENTINEL APEX v177.0 | Generated: {now_utc()[:19]}Z | TLP:RED (operator only)
    """).strip()
    return pkg


# ─── MAIN PROVISION COMMAND ──────────────────────────────────────────────────
def cmd_provision(args):
    tier     = args.tier.upper()
    country  = normalize_country(args.country)
    ref_id   = args.ref or f"SA-{today_str().replace('-','')}-{secrets.token_hex(2).upper()}"
    pay_ref  = args.payment_ref or "MANUAL-" + secrets.token_hex(3).upper()
    days     = args.days

    print(f"\n  SENTINEL APEX — Customer Provisioning")
    print(f"  ══════════════════════════════════════")
    print(f"  Customer : {args.name} <{args.email}>")
    print(f"  Company  : {args.company}")
    print(f"  Country  : {country}")
    print(f"  Tier     : {tier}  |  Days: {days}")
    print(f"  Ref ID   : {ref_id}")
    print()

    # Step 1: Generate API key
    print("  [1/5] Generating API key...")
    key_record = _gk.generate_key(
        tier=tier,
        customer_email=args.email,
        reference_id=ref_id,
        days=days,
        customer_name=args.name,
        company=args.company,
        notes=f"Onboarded via customer_onboard.py | country={country}",
    )
    key_hash_prefix = key_record["key_hash"][:16]
    print(f"         Key: {key_record['key'][:20]}...")

    # Step 2: Register customer
    print("  [2/5] Registering customer...")
    customer_id = gen_customer_id()
    customer_record = register_customer(
        customer_id=customer_id,
        name=args.name,
        email=args.email,
        company=args.company,
        country=country,
        tier=tier,
        ref_id=ref_id,
        key_hash_prefix=key_hash_prefix,
    )
    print(f"         Customer ID: {customer_id}")

    # Step 3: Create subscription
    print("  [3/5] Creating subscription record...")
    sub_id = gen_sub_id()
    sub_record = register_subscription(
        sub_id=sub_id,
        customer_id=customer_id,
        email=args.email,
        tier=tier,
        days=days,
        ref_id=ref_id,
        payment_ref=pay_ref,
        key_hash_prefix=key_hash_prefix,
    )
    print(f"         Sub ID: {sub_id}")

    # Step 4: Payment audit
    print("  [4/5] Writing payment audit entry...")
    write_payment_audit(
        event="CUSTOMER_ONBOARDED",
        customer_id=customer_id,
        email=args.email,
        tier=tier,
        ref_id=ref_id,
        payment_ref=pay_ref,
        amount_inr=TIER_PRICING_INR.get(tier, 0),
        country=country,
    )

    # Step 5: Welcome package
    print("  [5/5] Generating welcome package...")
    pkg = generate_welcome_package(key_record, customer_record, sub_record)

    os.makedirs(WELCOME_PKG_DIR, exist_ok=True)
    pkg_file = os.path.join(WELCOME_PKG_DIR, f"{customer_id}_{args.email.split('@')[0]}.txt")
    with open(pkg_file, "w", encoding="utf-8") as f:
        f.write(pkg)
    print(f"         Saved: {pkg_file}")

    print()
    print(pkg)
    print()
    print(f"  ✓ Onboarding complete.")
    print(f"  ✓ Key stored in: data/keys/active_keys.json (hash only)")
    print(f"  ✓ Customer in:   data/customers/registry.json")
    print(f"  ✓ Subscription:  data/subscriptions/active.json")
    print(f"  ✓ Audit entry:   data/payment_audit.jsonl")
    print(f"  ✓ Welcome pkg:   {pkg_file}")
    print()
    print(f"  NEXT: Email the API key to {args.email}")
    print(f"        Use: templates/email/03_api_key_delivered.txt")


# ─── LIST COMMAND ────────────────────────────────────────────────────────────
def cmd_list(args):
    data = load_json(CUSTOMERS_PATH, {"customers": []})
    customers = data.get("customers", [])
    if not customers:
        print("  No customers registered yet.")
        return
    print(f"\n  {'ID':<12} {'NAME':<22} {'EMAIL':<32} {'COUNTRY':<8} {'TIER':<12} {'STATUS'}")
    print(f"  {'─'*12} {'─'*22} {'─'*32} {'─'*8} {'─'*12} {'─'*8}")
    for c in customers:
        print(f"  {c['customer_id']:<12} {c['name'][:20]:<22} {c['email'][:30]:<32} "
              f"{c['country']:<8} {c['tier']:<12} {c.get('status','?')}")
    meta = data.get("_meta", {})
    print(f"\n  Total: {meta.get('total_customers',0)} | Active: {meta.get('active_customers',0)} "
          f"| MRR: ₹{meta.get('mrr_inr',0):,}/mo")


# ─── REVENUE COMMAND ─────────────────────────────────────────────────────────
def cmd_revenue(args):
    summary = _gk.revenue_summary()
    sub_data = load_json(SUBSCRIPTIONS_PATH, {"_meta": {}})
    meta = sub_data.get("_meta", {})
    print(f"\n  SENTINEL APEX Revenue Dashboard — {summary['as_of'][:10]}")
    print(f"  ─────────────────────────────────────────")
    print(f"  Active API Keys : {summary['active_keys']}")
    print(f"  Active Subs     : {meta.get('active_count', '?')}")
    print(f"  MRR (INR)       : ₹{summary['mrr_inr']:,}")
    print(f"  ARR (INR)       : ₹{summary['arr_equivalent_inr']:,}")
    print(f"  Tier Breakdown:")
    for tier, count in summary["tier_breakdown"].items():
        print(f"    {tier:<14}: {count}")


# ─── CLI ENTRY POINT ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Customer Provisioning Tool v177.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    prov = sub.add_parser("provision", help="Provision a new customer end-to-end")
    prov.add_argument("--name",        required=True, help="Customer full name")
    prov.add_argument("--email",       required=True, help="Customer email address")
    prov.add_argument("--company",     required=True, help="Company / organisation name")
    prov.add_argument("--country",     required=True, help="Country code: US, UK, DE, UAE, IN, etc.")
    prov.add_argument("--tier",        required=True, choices=["free","trial","pro","enterprise","mssp"],
                      help="Subscription tier")
    prov.add_argument("--days",        type=int, default=30, help="Subscription length in days (default: 30)")
    prov.add_argument("--ref",         default="", help="Reference ID (auto-generated if omitted)")
    prov.add_argument("--payment-ref", default="", dest="payment_ref",
                      help="Payment reference (Stripe PI, Gumroad TX, UPI Ref, etc.)")

    sub.add_parser("list",    help="List all registered customers")
    sub.add_parser("revenue", help="Revenue and subscription summary")

    args = parser.parse_args()
    dispatch = {"provision": cmd_provision, "list": cmd_list, "revenue": cmd_revenue}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
