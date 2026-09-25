"""
Phase 2B funnel-truth regression: T01–T15.

Static + extracted-JS checks. No network payment. No create-order POST.

Run: pytest tests/test_funnel_truth.py -v
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
UPGRADE = REPO / "upgrade.html"
PRICING = REPO / "pricing.html"
GETKEY = REPO / "get-api-key.html"
INDEX = REPO / "index.html"
TRIAL = REPO / "trial-center.html"
LEAD = REPO / "lead-capture.html"

PAID_PATH_FILES = (UPGRADE, PRICING, GETKEY, INDEX, TRIAL, LEAD)

FALSE_TRIAL_CTAS = (
    "START FREE TRIAL",
    "Start Free Trial",
    "FREE 7-DAY TRIAL",
    "Start 7-Day Free Trial",
    "Start free 14-day trial",
    "FREE TRIAL →",
    "No credit card. No commitment.",
)


def _read(path: Path) -> str:
    assert path.exists(), f"missing {path}"
    return path.read_text(encoding="utf-8")


def _extract_resolve_js() -> str:
    src = _read(UPGRADE)
    m = re.search(
        r"BEGIN resolveCheckoutPlan \*/\s*(function resolveCheckoutPlan\b.*?\n\})\s*/\* END resolveCheckoutPlan",
        src,
        re.S,
    )
    assert m, "resolveCheckoutPlan not found between BEGIN/END markers in upgrade.html"
    return m.group(1)


def _node_resolve(query: str) -> dict:
    fn = _extract_resolve_js()
    script = (
        fn
        + "\nconst r = resolveCheckoutPlan("
        + json.dumps(query)
        + ");\nprocess.stdout.write(JSON.stringify(r));\n"
    )
    result = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# T01 — false trial CTAs gone from customer-facing paid paths
# ---------------------------------------------------------------------------
def test_t01_paid_paths_have_no_false_trial_ctas():
    for path in PAID_PATH_FILES:
        text = _read(path)
        for needle in FALSE_TRIAL_CTAS:
            assert needle not in text, f"{path.name} still contains false-trial CTA {needle!r}"


# ---------------------------------------------------------------------------
# T02 — Community / Free may still say no credit card
# ---------------------------------------------------------------------------
def test_t02_community_no_credit_card_retained():
    pricing = _read(PRICING)
    getkey = _read(GETKEY)
    upgrade = _read(UPGRADE)
    assert "No credit card" in pricing
    assert "No credit card" in getkey
    assert "No credit card" in upgrade
    assert "REQUEST FREE ACCESS" in getkey
    assert "get-api-key.html?plan=community" in upgrade


# ---------------------------------------------------------------------------
# T03 — genuine 7-day money-back refund copy is allowed
# ---------------------------------------------------------------------------
def test_t03_money_back_refund_copy_retained():
    # Owner commercial policy (2026-09-24): the 7-day guarantee is kept, but
    # only as a qualified, merchant-approved guarantee on eligible first
    # purchases, with no pro-rata refunds after it (terms.html#refunds).
    upgrade = _read(UPGRADE)
    pricing = _read(PRICING)
    terms = _read(REPO / "terms.html")
    assert "7-Day Money-Back Guarantee on eligible first purchases" in upgrade
    assert "7-day money-back on eligible first purchases" in pricing
    for src in (upgrade, pricing):
        assert "/terms.html#refunds" in src
        assert "No pro-rata refunds" in src or "no pro-rata refunds" in src
    assert 'id="refunds"' in terms
    assert "pro-rated refund for unused" not in terms
    assert "no partial or pro-rata refunds" in terms


# ---------------------------------------------------------------------------
# T04–T09 — parser HARD CONTRACT (extracted JS, no browser)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "query,expected_plan,expected_annual",
    [
        ("", "free", False),                       # T07 missing
        ("plan=free", "free", False),              # T04
        ("plan=FREE", "free", False),              # T06 lowercase
        ("plan=community", "free", False),         # T05 alias
        ("plan=unknown", "free", False),           # T07 unknown
        ("plan=", "free", False),                  # T07 empty
        ("plan=%00", "free", False),               # T07 malformed
        ("plan=pro&plan=enterprise", "free", False),  # T08 no elevate
        ("plan=free&plan=pro", "free", False),     # T08 free wins / no elevate
        ("plan=pro", "pro", False),                # T09
        ("plan=enterprise", "enterprise", False),  # T09
        ("plan=mssp", "mssp", False),
        ("plan=pro-annual", "pro", True),
        ("plan=PRO-ANNUAL", "pro", True),
    ],
)
def test_t04_t09_resolve_checkout_plan_contract(query, expected_plan, expected_annual):
    result = _node_resolve(query)
    assert result["plan"] == expected_plan, (query, result)
    assert result["annual"] is expected_annual, (query, result)


def test_t04_source_never_defaults_unknown_to_pro():
    src = _read(UPGRADE)
    assert "function resolveCheckoutPlan" in src
    assert "selectPlan(resolvedPlan.plan)" in src
    assert "['pro','enterprise','mssp'].includes(basePlan) ? basePlan : 'pro'" not in src
    assert "var currentPlan = 'free';" in src


# ---------------------------------------------------------------------------
# T10 — selectPlan('free') hides Gumroad and Razorpay
# ---------------------------------------------------------------------------
def test_t10_free_hides_paid_widgets():
    src = _read(UPGRADE)
    assert "panel.style.display = isFree ? 'none' : ''" in src
    assert "rzpSection.style.display = isFree ? 'none' : ''" in src
    assert 'id="gumroad-panel"' in src
    assert 'id="section-payment-methods"' in src
    assert 'id="free-plan-panel"' in src


# ---------------------------------------------------------------------------
# T11 — get-api-key PRO CTA is GET PRO ACCESS (do not regress)
# ---------------------------------------------------------------------------
def test_t11_get_api_key_pro_cta_is_get_pro_access():
    src = _read(GETKEY)
    assert "submitLabel: 'GET PRO ACCESS →'" in src
    assert "START FREE TRIAL" not in src


# ---------------------------------------------------------------------------
# T12 — Gumroad Pro/Ent permalinks, 30-day Pro CTA, prices frozen
# ---------------------------------------------------------------------------
def test_t12_gumroad_pro_ent_permalinks_and_30day_cta():
    src = _read(UPGRADE)
    assert "https://cyberdudebivash.gumroad.com/l/pxyfcb" in src
    assert "https://cyberdudebivash.gumroad.com/l/cdedlo" in src
    assert "GET 30-DAY PRO ACCESS — $49" in src
    assert "usd:49" in src
    assert "usd:499" in src


# ---------------------------------------------------------------------------
# T13 — Razorpay display ₹4,100; charge paise unchanged 410000; no 3999
# ---------------------------------------------------------------------------
def test_t13_razorpay_display_aligned_charge_unchanged():
    src = _read(UPGRADE)
    assert "inr_monthly:410000" in src
    assert "usd_monthly:49" in src
    assert 'id="rzp-display-inr">&#x20B9;4,100</div>' in src or 'id="rzp-display-inr">₹4,100</div>' in src
    assert "3,999" not in src
    assert "399900" not in src
    # Owner commercial policy (2026-09-24): Razorpay checkout IS a recurring
    # subscription now (Gumroad: membership or a labelled one-time grant), so the
    # Razorpay button must say so; it previously had to avoid the word.
    btn = re.search(r'id="rzp-pay-btn"[^>]*>([\s\S]*?)</button>', src)
    assert btn, "rzp-pay-btn missing"
    assert "SUBSCRIBE" in btn.group(1).upper()
    assert "Renews monthly" in src


# ---------------------------------------------------------------------------
# T14 — JSON-LD parses; no P1M on monthly Gumroad-shaped offers; prices 49/499
# ---------------------------------------------------------------------------
def test_t14_pricing_jsonld_no_p1m_parses():
    src = _read(PRICING)
    m = re.search(
        r'<script type="application/ld\+json">\s*(\{.*?\})\s*</script>',
        src,
        re.S,
    )
    assert m, "pricing.html JSON-LD missing"
    data = json.loads(m.group(1))
    assert data.get("@type") == "SoftwareApplication"
    offers = data["offers"]
    assert isinstance(offers, list)
    by_name = {o["name"]: o for o in offers}
    assert by_name["PRO / SOC"]["price"] == "49"
    assert by_name["Enterprise SOC"]["price"] == "499"
    assert by_name["MSSP / Sovereign"]["price"] == "1999"
    assert by_name["Free Tier"]["price"] == "0"
    for name in ("PRO / SOC", "Enterprise SOC", "MSSP / Sovereign"):
        assert "billingDuration" not in by_name[name], name
        assert "P1M" not in json.dumps(by_name[name])
    assert "P1M" not in src


# ---------------------------------------------------------------------------
# T15 — frozen prices / permalinks / GST / seller untouched
# ---------------------------------------------------------------------------
def test_t15_frozen_prices_and_annual_permalinks_unchanged():
    upgrade = _read(UPGRADE)
    pricing = _read(PRICING)
    assert "pxyfcb" in upgrade and "cdedlo" in upgrade
    assert "/l/xtnzu" in upgrade and "/l/vxoczs" in upgrade
    assert "$1,999" in upgrade and "$1,999" in pricing
    assert "usd:1999" in upgrade or "usd:1999" in upgrade.replace(" ", "")
    assert "GSTIN: 21ARKPN8270G1ZP" in upgrade
    assert "21ARKPN8270G1ZP" in pricing
    # RAZORPAY charge figures frozen
    assert "inr_monthly:410000" in upgrade
    assert "inr_monthly:4160000" in upgrade
    assert "inr_monthly:16660000" in upgrade


def test_lead_modal_paid_destination_is_obvious():
    src = _read(INDEX)
    assert "CONTINUE TO PRO" in src
    assert "upgrade.html?plan=pro" in src
    assert "not a free trial" in src.lower()
    assert "apexLeadSubmit" in src
    assert "utm_source=lead-modal" in src
