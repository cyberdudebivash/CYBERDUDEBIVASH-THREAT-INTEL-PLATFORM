"""Checkout P0 (2026-10-01): one automated primary path, a gated secondary,
an assisted note that is not a checkout, and copy the platform can back.

Owner decision: Razorpay is the primary checkout, Gumroad the secondary,
and assisted payments (crypto, Paytm, PayPal, UPI, Amazon Pay, bank NEFT)
are one low-prominence contact note. Before this change the checkout page
listed wallet brands Razorpay subscriptions do not take, sold Gumroad while
production could not provision a Gumroad sale (F21), told buyers their key
was emailed (the revenue engine never sends that email, F22), offered MSSP
by email from the checkout panel, and reported failures in alert() boxes;
get-api-key.html took paid-plan "requests" promising a key by email within
2 hours. render-test/verify_upgrade_checkout.js drives the page in a real
browser; this file pins the same contract statically, plus the server-side
pieces, so a regression fails without a browser. Local files only.
"""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
UPGRADE = (REPO / "upgrade.html").read_text(encoding="utf-8")
CONTRACT = json.loads((REPO / "config/commercial-contract.json").read_text(encoding="utf-8"))["tiers"]
ASSISTED = ("Need an alternative payment method? Assisted payments via crypto, Paytm, PayPal, UPI, Amazon Pay or bank NEFT "
            "may be arranged by contacting contact@cyberdudebivash.in or bivash@cyberdudebivash.com. "
            "Access is provisioned only after payment verification.")

CREDENTIALS = re.compile(
    r"\b[\w.-]+@(?:upi|ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|ibl|axl)\b"   # UPI handles
    r"|\b[A-Z]{4}0[A-Z0-9]{6}\b"                                               # IFSC
    r"|\b(?:a/c|account)\s*(?:no\.?|number)?\s*[:#]?\s*\d{9,18}\b"            # bank account numbers
    r"|\b0x[0-9a-fA-F]{40}\b|\bbc1q[0-9a-z]{20,}|\bT[1-9A-HJ-NP-Za-km-z]{33}\b"  # crypto addresses
    r"|upi://|paypal\.me/", re.I)
WALLET_BADGE = re.compile(r">(?:&#x[0-9A-Fa-f]+;\s*)?(?:Paytm|AmazonPay|Amazon Pay|PhonePe|BHIM(?: UPI)?|GPay(?: / UPI)?)</span>")


def _scripts(html):
    return "\n".join(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>", html, re.I))


def _visible(fragment):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment)).replace(" .", ".").strip()


def _element(html, element_id):
    m = re.search(r'<(\w+)[^>]*\bid="%s"[^>]*>' % re.escape(element_id), html)
    assert m, element_id
    tag, depth, pos = m.group(1), 1, m.end()
    for t in re.finditer(r"<(/?)%s\b[^>]*>" % tag, html[pos:]):
        depth += -1 if t.group(1) else 1
        if depth == 0:
            return html[m.start():pos + t.end()]
    raise AssertionError(f"unclosed #{element_id}")


def _shipped_pages():
    import importlib.util
    spec = importlib.util.spec_from_file_location("bda_checkout", REPO / "scripts" / "build_dist_artifact.py")
    bda = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bda)
    pages = [p for p in sorted(REPO.glob("*.html")) if not bda.is_excluded_html(p.name)]
    for d in ("dashboard", "customer"):
        excluded = set(bda.INCLUDE_DIR_FILE_EXCLUDES.get(d, ()))
        pages += [p for p in sorted((REPO / d).glob("*.html")) if p.name not in excluded]
    return pages


# ── the assisted note ──────────────────────────────────────────────────────

def test_assisted_note_is_verbatim_with_both_contacts_and_no_controls():
    note = _element(UPGRADE, "assisted-payments")
    first_paragraph = re.search(r"<p>([\s\S]*?)</p>", note).group(1)
    assert _visible(first_paragraph) == ASSISTED
    assert re.findall(r'href="(mailto:[^"]+)"', note) == ["mailto:contact@cyberdudebivash.in", "mailto:bivash@cyberdudebivash.com"]
    assert "not part of the automated checkout" in note
    assert not re.search(r"<(button|input|form|select|textarea)\b", note), "the note is information, not a checkout"


def test_assisted_note_sits_below_both_automated_checkouts():
    rzp, gumroad, note = (UPGRADE.index('id="rzp-pay-btn"'), UPGRADE.index('id="gumroad-btn"'),
                          UPGRADE.index('id="assisted-payments"'))
    assert rzp < gumroad < note


# ── no manual payment mechanism, no published credentials ─────────────────

def test_checkout_page_has_no_manual_payment_mechanism():
    assert not CREDENTIALS.search(UPGRADE), CREDENTIALS.search(UPGRADE)
    assert not re.search(r'<input[^>]+type="file"', UPGRADE)
    assert not re.search(r'id="[^"]*(utr|proof|screenshot|transaction)[^"]*"', UPGRADE, re.I)
    assert not re.search(r"\bUTR\b|\bQR\b|qr[_-]?code|upi[_-]?id|ifsc|formspree", UPGRADE, re.I)
    assert "mailto:" not in re.search(r"var GUMROAD_URLS = \{([\s\S]*?)\n\};", UPGRADE).group(1), "no email-to-buy in checkout"
    assert not re.search(r"\balert\s*\(", _scripts(UPGRADE)), "failures are inline, never alert()"


def test_negative_controls_the_guards_are_not_blind():
    for sample in ("pay to someone@okaxis", "IFSC UTIB0000052", "A/C No. 915010024617260",
                   "0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796", "upi://pay?pa=x", "paypal.me/someone"):
        assert CREDENTIALS.search(sample), sample
    old_badge = '<span style="color:#00baf2;">Paytm</span><span>&#x1F6D2; AmazonPay</span>'
    assert len(WALLET_BADGE.findall(old_badge)) == 2


# ── one primary path, a gated secondary ───────────────────────────────────

def test_razorpay_is_the_one_primary_cta_and_gumroad_the_secondary():
    pay = _element(UPGRADE, "section-payment-methods")
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*id="([^"]+)"', pay) == ["rzp-pay-btn"]
    button = _element(UPGRADE, "rzp-pay-btn")
    assert "Continue with Razorpay" in button and "Subscribe" in button
    assert "<strong>Secure automated checkout</strong>" in pay
    gumroad = re.search(r'<a [^>]*id="gumroad-btn"[^>]*>([^<]*)</a>', pay)
    assert gumroad and gumroad.group(1) == "Continue with Gumroad"
    assert "<strong>Secondary automated checkout</strong>" in pay
    assert "Prefer another checkout?" in pay


def test_gumroad_is_hidden_until_the_gateway_confirms_it_fail_closed():
    tag = re.search(r'<a [^>]*id="gumroad-btn"[^>]*>', UPGRADE).group(0)
    assert " hidden" in tag and "href=" not in tag, "without JS or availability there is no Gumroad link"
    assert "var CHECKOUT_AVAILABILITY = { gumroad: null };" in UPGRADE
    assert "if (CHECKOUT_AVAILABILITY.gumroad !== true) {" in UPGRADE
    assert "CHECKOUT_AVAILABILITY.gumroad = !!(g && g.available === true);" in UPGRADE
    gateway = (REPO / "workers/intel-gateway/src/checkout-providers.js").read_text(encoding="utf-8")
    assert "GUMROAD_WEBHOOK_SECRET" in gateway and "RESEND_API_KEY" in gateway
    index_js = (REPO / "workers/intel-gateway/src/index.js").read_text(encoding="utf-8")
    assert "return jsonResp({ ...getPricingSnapshot(), checkout: checkoutProviderAvailability(env) });" in index_js


# ── what you get = the contract ───────────────────────────────────────────

def test_plan_terms_equal_the_commercial_contract():
    block = re.search(r"var PLAN_TERMS = \{([\s\S]*?)\n\};", UPGRADE).group(1)
    for plan in ("free", "pro", "enterprise", "mssp"):
        row = re.search(r"\b%s:\s*\{([^}]*)\}" % plan, block).group(1)
        get = lambda k: re.search(r"\b%s:\s*('([^']*)'|[\w.]+)" % k, row)
        c = CONTRACT[plan]
        assert int(get("rpm").group(1)) == c["requests_per_minute"], plan
        assert int(get("rpd").group(1)) == c["requests_per_day"], plan
        assert int(get("keys").group(1)) == c["api_keys"], plan
        assert int(get("seats").group(1)) == c["seats"], plan
        assert get("uptime").group(2) == c["uptime_commitment"], plan
        assert ("white_label:true" in row.replace(" ", "")) == c["white_label"], plan
        if plan != "free":
            assert get("support").group(2) == c["support"].rstrip("."), plan


def test_static_plan_cards_quote_contract_quotas_and_prices():
    for plan in ("pro", "enterprise", "mssp"):
        card = _element(UPGRADE, f"plan-{plan}")
        c = CONTRACT[plan]
        text = _visible(card)
        assert f"{c['requests_per_minute']:,} requests/min" in text, (plan, text)
        assert f"{c['requests_per_day']:,}/day" in text, (plan, text)
        assert f"{c['api_keys']} API keys" in text, (plan, text)
        assert f"${c['usd_monthly']:,}" in text, (plan, text)
        assert f"&#x20B9;{c['inr_monthly']:,}" in card, (plan, card)


# ── server side ───────────────────────────────────────────────────────────

def test_revenue_engine_refuses_a_second_payment_and_keeps_provider_errors_server_side():
    se = (REPO / "workers/revenue-engine/src/subscription-engine.js").read_text(encoding="utf-8")
    assert 'const PAID_CHECKOUT_LINK_STATUSES = Object.freeze(["authenticated", "active"]);' in se
    assert 'error: "checkout_in_progress"' in se
    assert "detail: errText" not in se


# ── the rest of the funnel says the same thing ─────────────────────────────

def test_no_shipped_page_shows_wallet_brand_payment_badges():
    hits = {str(p.relative_to(REPO)): WALLET_BADGE.findall(p.read_text(encoding="utf-8", errors="ignore")) for p in _shipped_pages()}
    assert not {k: v for k, v in hits.items() if v}, hits


def test_paid_plan_requests_go_to_checkout_not_an_emailed_key():
    page = (REPO / "get-api-key.html").read_text(encoding="utf-8")
    for claim in ("within 2 hours", "within 2 hrs", "Key within", "assisted activation", "INSTANT PROVISIONING", "urgent activation"):
        assert claim.lower() not in page.lower(), claim
    assert "No API key is issued from this form" in page
    assert "var payUrl = '/upgrade.html?plan=' + upgradePlan;" in page, "no email address in the checkout URL"


def test_billing_copy_matches_the_implementation():
    trial = (REPO / "trial-center.html").read_text(encoding="utf-8")
    assert "no automated recurring billing" not in trial.lower()
    assert "+ 18% GST" not in trial and "No recurring billing until" not in trial
    assert "Razorpay subscriptions renew automatically each billing period" in trial
    assert "The INR price includes GST" in trial
    pricing = (REPO / "pricing.html").read_text(encoding="utf-8")
    assert "enterprise bank transfer is available only against" not in pricing, "contradicted the assisted-payment note"
    assert "Assisted payments are arranged only by contacting us" in pricing
    assert "GET 30-DAY PRO ACCESS" not in pricing
    ep = (REPO / "enterprise-pricing.html").read_text(encoding="utf-8")
    assert "EMI" not in _visible(ep) and "issued automatically for every paid plan" not in ep


# P0 (2026-10-16): the checkout seller/legal sidebar, support contact,
# public marketing pages and API documentation must use the current inbox.
def test_customer_facing_seller_contact_is_canonical_across_shipped_pages():
    current = "contact@cyberdudebivash.in"
    retired = "enterprise" + "@cyberdudebivash.com"
    seller = re.search(r'<div class="contact-card">([\\s\\S]*?)</div>', UPGRADE)
    assert seller and "Seller" in seller.group(1)
    assert f'href="mailto:{current}"' in seller.group(1)
    assert retired not in UPGRADE
    assert UPGRADE.count(f"mailto:{current}") >= 3
    for path in _shipped_pages():
        page = path.read_text(encoding="utf-8", errors="replace")
        assert retired not in page, f"Retired customer-facing inbox in {path.relative_to(REPO)}"
    for path in (REPO / "docs").rglob("*.html"):
        assert retired not in path.read_text(encoding="utf-8", errors="replace"), str(path)
