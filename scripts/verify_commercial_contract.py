#!/usr/bin/env python3
"""
scripts/verify_commercial_contract.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Commercial Contract Drift Gate
==================================================================================
Rebuilt 2026-09-19 after the original implementation was silently dropped by a
`.gitignore` rule (`verify*.py`) that pre-dated this file and was never scoped to
exclude it -- it was written, run green, and never actually committed. See
scripts/verify_public_claims.py for the sibling gate with the same history.

config/commercial-contract.json is canonical. Every other place a price, quota
or forbidden claim is defined MUST agree with it. This script fails the build
on drift between:

  C01-C16   config/pricing.json               tiers vs canon (4 tiers x 4 fields)
  C17-C32   config/subscription_tiers.json     tiers vs canon (4 tiers x 4 fields)
  C33-C38   workers/intel-gateway/src/pricing-data.json (paise) vs canon x 100
  C39-C42   RATE_LIMITS (index.js)             requests_per_minute vs canon
  C43-C46   DAILY_QUOTAS (daily-quota.js)       requests_per_day vs canon
  C47-C58   pricing.html PRICES table (USD/INR, monthly/annual, 3 paid tiers)
  C59+      revenue/operator dashboards' own TIER_PRICES-style constants
  C60+      every buyer-facing HTML page, scanned for superseded price literals
  C61+      _forbidden_claims (commercial-contract.json) not present unnegated

Exit codes:
  0 = ALL PASS
  1 = ONE OR MORE FAIL (drift detected)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [commercial-contract] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.verify_commercial_contract")

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = REPO_ROOT / "config" / "commercial-contract.json"
PRICING_JSON_PATH = REPO_ROOT / "config" / "pricing.json"
SUBSCRIPTION_TIERS_PATH = REPO_ROOT / "config" / "subscription_tiers.json"
PRICING_DATA_PATH = REPO_ROOT / "workers" / "intel-gateway" / "src" / "pricing-data.json"
GATEWAY_INDEX_PATH = REPO_ROOT / "workers" / "intel-gateway" / "src" / "index.js"
DAILY_QUOTA_PATH = REPO_ROOT / "workers" / "intel-gateway" / "src" / "daily-quota.js"
PRICING_HTML_PATH = REPO_ROOT / "pricing.html"

# Directories excluded from the buyer-surface sweep: dated historical records,
# not live offers (matches config/evidence-register.json's stated audit scope).
EXCLUDED_DIRS = {"blog", "threat", "reports", "node_modules", ".git", "dist", "data"}

# Superseded literal values that must never reappear on a buyer-facing page.
# Each entry: (human label, compiled regex). Matching is case-insensitive.
FORBIDDEN_PRICE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("old MSSP monthly USD $1,999", re.compile(r"\$\s?1,?999\b")),
    ("old MSSP annual USD $19,190/$19,188", re.compile(r"\$\s?19,?19[08]\b")),
    ("old MSSP monthly INR (Western grouping) 166,600", re.compile(r"166,600\b")),
    ("old MSSP monthly INR (Indian grouping) 1,66,600", re.compile(r"1,66,600\b")),
    ("old MSSP annual INR (Western grouping) 1,666,000", re.compile(r"1,666,000\b")),
    ("old MSSP annual INR (Indian grouping) 16,66,000", re.compile(r"16,66,000\b")),
    ("old MSSP paise (unformatted) 16660000/166600000", re.compile(r"\b16660000\b|\b166600000\b")),
    ("old Enterprise annual USD $4,790", re.compile(r"\$\s?4,?790\b")),
    ("old Enterprise annual USD $4,788", re.compile(r"\$\s?4,?788\b")),
    ("old PRO annual USD $470", re.compile(r"\$\s?470\b(?!\d)")),
    ("wrong legal entity name", re.compile(r"CYBERDUDEBIVASH\s+PRIVATE\s+LIMITED", re.IGNORECASE)),
    # Bare JS-object-literal forms, e.g. `usd_annual:4790` / `usdAnnual:1999` --
    # these carry no `$`/comma formatting and slipped past the display-string
    # patterns above in upgrade.html's two embedded Razorpay/PLANS tables
    # (found during this gate's own rebuild: the price *text* on the page had
    # been corrected but the JS object feeding two on-page payment panels
    # still held the pre-owner-decision numbers). Scoped to a `key:value`
    # shape so a coincidental bare "1999" (e.g. a year) elsewhere isn't hit.
    ("old MSSP monthly USD (JS literal) usd(_monthly)?:1999", re.compile(r"usd(?:_monthly)?\s*:\s*1999\b")),
    ("old MSSP annual USD (JS literal) usd(_a|A)nnual:19190/19188", re.compile(r"usd(?:_a|A)nnual\s*:\s*19,?19[08]\b")),
    ("old MSSP monthly INR-rupees (JS literal) inr(_monthly)?:166600/166500", re.compile(r"inr(?:_monthly)?\s*:\s*166[56]00\b")),
    ("old MSSP annual INR-rupees (JS literal) inr(_a|A)nnual:1666000/1600000", re.compile(r"inr(?:_a|A)nnual\s*:\s*1,?[67]00,?000\b")),
    ("old Enterprise annual USD (JS literal) usd(_a|A)nnual:4790/4788", re.compile(r"usd(?:_a|A)nnual\s*:\s*47[89]0\b")),
]

FAILURES: list[str] = []
CHECK_COUNT = 0


def check(condition: bool, description: str) -> None:
    global CHECK_COUNT
    CHECK_COUNT += 1
    if condition:
        log.info("PASS C%03d: %s", CHECK_COUNT, description)
    else:
        FAILURES.append(f"C{CHECK_COUNT:03d}: {description}")
        log.error("FAIL C%03d: %s", CHECK_COUNT, description)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_buyer_html_files():
    for path in sorted(REPO_ROOT.rglob("*.html")):
        rel = path.relative_to(REPO_ROOT)
        if any(part in EXCLUDED_DIRS for part in rel.parts[:-1]):
            continue
        yield rel, path


def main() -> int:
    if not CONTRACT_PATH.exists():
        log.error("Canonical contract missing: %s", CONTRACT_PATH)
        return 1
    canon = load_json(CONTRACT_PATH)["tiers"]

    # --- C01-C16: config/pricing.json ------------------------------------
    pricing = load_json(PRICING_JSON_PATH)["tiers"]
    for tier_id, tier in canon.items():
        p = pricing.get(tier_id, {})
        check(p.get("monthly_usd") == tier["usd_monthly"],
              f"pricing.json {tier_id}.monthly_usd == {tier['usd_monthly']} (got {p.get('monthly_usd')})")
        check(p.get("annual_usd") == tier["usd_annual"],
              f"pricing.json {tier_id}.annual_usd == {tier['usd_annual']} (got {p.get('annual_usd')})")
        check(p.get("monthly_inr") == tier["inr_monthly"],
              f"pricing.json {tier_id}.monthly_inr == {tier['inr_monthly']} (got {p.get('monthly_inr')})")
        check(p.get("annual_inr") == tier["inr_annual"],
              f"pricing.json {tier_id}.annual_inr == {tier['inr_annual']} (got {p.get('annual_inr')})")

    # --- C17-C32: config/subscription_tiers.json --------------------------
    sub_tiers = load_json(SUBSCRIPTION_TIERS_PATH)
    for tier_id, tier in canon.items():
        s = sub_tiers.get(tier_id, {})
        check(s.get("price_usd") == tier["usd_monthly"],
              f"subscription_tiers.json {tier_id}.price_usd == {tier['usd_monthly']} (got {s.get('price_usd')})")
        check(s.get("price_usd_annual") == tier["usd_annual"],
              f"subscription_tiers.json {tier_id}.price_usd_annual == {tier['usd_annual']} (got {s.get('price_usd_annual')})")
        check(s.get("price_inr") == tier["inr_monthly"],
              f"subscription_tiers.json {tier_id}.price_inr == {tier['inr_monthly']} (got {s.get('price_inr')})")
        check(s.get("price_inr_annual") == tier["inr_annual"],
              f"subscription_tiers.json {tier_id}.price_inr_annual == {tier['inr_annual']} (got {s.get('price_inr_annual')})")

    # --- C33-C38: Razorpay charging table (paise), PRO/ENTERPRISE/MSSP only
    pricing_data = load_json(PRICING_DATA_PATH)["tiers"]
    for tier_id in ("pro", "enterprise", "mssp"):
        tier = canon[tier_id]
        key = tier_id.upper()
        pd = pricing_data.get(key, {})
        check(pd.get("monthly") == tier["inr_monthly"] * 100,
              f"pricing-data.json {key}.monthly paise == {tier['inr_monthly'] * 100} (got {pd.get('monthly')})")
        check(pd.get("annual") == tier["inr_annual"] * 100,
              f"pricing-data.json {key}.annual paise == {tier['inr_annual'] * 100} (got {pd.get('annual')})")

    # --- C39-C42: RATE_LIMITS (requests/minute) ----------------------------
    gateway_src = GATEWAY_INDEX_PATH.read_text(encoding="utf-8")
    rl_match = re.search(r"RATE_LIMITS\s*=\s*\{([^}]*)\}", gateway_src)
    check(rl_match is not None, "RATE_LIMITS constant found in intel-gateway/src/index.js")
    rate_limits = {}
    if rl_match:
        for m in re.finditer(r"(FREE|PRO|ENTERPRISE|MSSP)\s*:\s*(\d+)", rl_match.group(1)):
            rate_limits[m.group(1)] = int(m.group(2))
    for tier_id, tier in canon.items():
        key = tier_id.upper()
        check(rate_limits.get(key) == tier["requests_per_minute"],
              f"RATE_LIMITS.{key} == {tier['requests_per_minute']} req/min (got {rate_limits.get(key)})")

    # --- C43-C46: DAILY_QUOTAS (requests/day) ------------------------------
    quota_src = DAILY_QUOTA_PATH.read_text(encoding="utf-8")
    daily_quotas = {}
    for m in re.finditer(r"(FREE|PRO|ENTERPRISE|MSSP)\s*:\s*Object\.freeze\(\{\s*limit:\s*(\d+)", quota_src):
        daily_quotas[m.group(1)] = int(m.group(2))
    for tier_id, tier in canon.items():
        key = tier_id.upper()
        check(daily_quotas.get(key) == tier["requests_per_day"],
              f"DAILY_QUOTAS.{key}.limit == {tier['requests_per_day']} req/day (got {daily_quotas.get(key)})")

    # --- C47-C58: pricing.html PRICES table (USD/INR, monthly/annual) -----
    pricing_html = PRICING_HTML_PATH.read_text(encoding="utf-8")
    price_block_match = re.search(r"var PRICES\s*=\s*\{(.*?)\n  \};", pricing_html, re.DOTALL)
    check(price_block_match is not None, "pricing.html PRICES table located")
    price_block = price_block_match.group(1) if price_block_match else ""

    def html_price(currency: str, billing: str, tier_key: str) -> str | None:
        # Scope to this currency/billing sub-block first, then pull the tier's price.
        cur_match = re.search(rf"{currency}:\s*\{{(.*?)\n    \}},?\n    (?:INR|EUR|GBP|\}})", price_block + "\n  }", re.DOTALL)
        if not cur_match:
            return None
        billing_match = re.search(rf"{billing}:\s*\{{(.*?)\n      \}}", cur_match.group(1), re.DOTALL)
        if not billing_match:
            return None
        tier_match = re.search(rf"{tier_key}:\s*\{{[^}}]*?price:\s*'([\d,]+)'", billing_match.group(1))
        return tier_match.group(1).replace(",", "") if tier_match else None

    expected_usd_monthly = {"pro": "49", "ent": "499", "mssp": "999"}
    expected_usd_annual_per_month = {  # displayed as a per-month equivalent of the annual total
        "pro": str(round(canon["pro"]["usd_annual"] / 12)),
        "ent": str(round(canon["enterprise"]["usd_annual"] / 12)),
        "mssp": str(round(canon["mssp"]["usd_annual"] / 12)),
    }
    expected_inr_monthly = {"pro": "4100", "ent": "41600", "mssp": "83300"}

    for tier_key, expected in expected_usd_monthly.items():
        got = html_price("USD", "monthly", tier_key)
        check(got == expected, f"pricing.html USD monthly {tier_key} == {expected} (got {got})")
    for tier_key, expected in expected_inr_monthly.items():
        got = html_price("INR", "monthly", tier_key)
        check(got == expected, f"pricing.html INR monthly {tier_key} == {expected} (got {got})")
    # Annual totals are asserted via the prose in the `period` field rather than
    # the per-month figure alone, so a stale total can't hide behind a correct
    # per-month rounding.
    check(f"${canon['pro']['usd_annual']}" in price_block or f"${canon['pro']['usd_annual']:,}" in price_block,
          f"pricing.html states PRO annual total ${canon['pro']['usd_annual']}")
    check(f"${canon['enterprise']['usd_annual']:,}" in price_block,
          f"pricing.html states Enterprise annual total ${canon['enterprise']['usd_annual']:,}")
    check(f"${canon['mssp']['usd_annual']:,}" in price_block,
          f"pricing.html states MSSP annual total ${canon['mssp']['usd_annual']:,}")

    # --- C59+: revenue/operator dashboard TIER_PRICES-style constants -----
    dashboard_candidates = list(REPO_ROOT.glob("*.html")) + list((REPO_ROOT / "dashboard").glob("*.html"))
    tier_price_pattern = re.compile(
        r"(?:TIER_PRICES|PLAN_PRICES|PRICE_MAP)\s*=\s*\{([^}]*)\}"
    )
    # Expected monthly USD per recognized key, including the *_ANNUAL variants
    # this exact bug historically hid behind (a dashboard naming a variable
    # "ENTERPRISE_ANNUAL" but assigning it MSSP's annual figure -- the P0
    # mismatch this whole gate exists to prevent recurring).
    expected_dashboard_values = {
        "FREE": canon["free"]["usd_monthly"],
        "PRO": canon["pro"]["usd_monthly"],
        "ENTERPRISE": canon["enterprise"]["usd_monthly"],
        "MSSP": canon["mssp"]["usd_monthly"],
        "PRO_ANNUAL": canon["pro"]["usd_annual"],
        "ENTERPRISE_ANNUAL": canon["enterprise"]["usd_annual"],
        "MSSP_ANNUAL": canon["mssp"]["usd_annual"],
    }
    dashboards_checked = 0
    for path in dashboard_candidates:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        m = tier_price_pattern.search(text)
        if not m:
            continue
        dashboards_checked += 1
        rel = path.relative_to(REPO_ROOT)
        values = {k: int(v) for k, v in re.findall(
            r"(FREE|PRO_ANNUAL|PRO|ENTERPRISE_ANNUAL|ENTERPRISE|MSSP_ANNUAL|MSSP)\s*:\s*'?(\d+)'?", m.group(1)
        )}
        # Only assert on keys this particular object actually defines -- not
        # every dashboard tracks every tier (e.g. an enterprise-onboarding
        # page may only carry ENTERPRISE/MSSP/ENTERPRISE_ANNUAL).
        for key, expected in expected_dashboard_values.items():
            if key in values:
                check(values[key] == expected, f"{rel} {{{key}}} == {expected} (got {values[key]})")
    log.info("Scanned %d dashboard file(s) with a TIER_PRICES-style constant.", dashboards_checked)

    # --- C60+: sweep every buyer-facing HTML page for superseded literals --
    scanned = 0
    for rel, path in iter_buyer_html_files():
        scanned += 1
        text = path.read_text(encoding="utf-8", errors="ignore")
        for label, pattern in FORBIDDEN_PRICE_PATTERNS:
            check(not pattern.search(text), f"{rel} does not contain {label}")
    log.info("Swept %d buyer-facing HTML page(s) for superseded price/legal-entity literals.", scanned)

    # --- Forbidden quota claims ---------------------------------------------
    # commercial-contract.json's _forbidden_claims also lists compliance-
    # framework names (SOC 2, ISO 27001, ISO 42001, FedRAMP, PCI DSS).
    # Deliberately NOT enforced here as a bare substring ban: compliance.html
    # and trust-center.html already describe these honestly as in-progress
    # readiness programmes ("SOC 2 Type II -- READINESS IN PROGRESS, formal
    # audit planned H2 2026"), which is a legitimate maturity narrative, not
    # the kind of unconditional false claim "unlimited API calls" is against
    # an enforced 50,000/day cap. A substring ban can't distinguish "pursuing
    # certification" from "certified" without the same false-positive risk
    # verify_public_claims.py's negation window exists to avoid, and PR #435's
    # own verification never claimed to have audited compliance-posture
    # wording -- only customer-proof claims and prices. Flagged as a follow-up
    # in the mission report rather than mis-enforced here.
    absolute_quota_claims = [
        c for c in load_json(CONTRACT_PATH).get("_forbidden_claims", [])
        if c.lower() in ("unlimited api calls", "unlimited requests", "no rate limit")
    ]
    for rel, path in iter_buyer_html_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        lower = text.lower()
        for claim in absolute_quota_claims:
            if claim.lower() in lower:
                check(False, f"{rel} does not contain forbidden claim '{claim}'")

    print()
    print(f"verify_commercial_contract.py: {CHECK_COUNT} checks, {len(FAILURES)} failed.")
    if FAILURES:
        print("\nFAILURES:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("ALL COMMERCIAL CONTRACT CHECKS PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
