"""
Regression tests for the Razorpay + Gumroad dual-checkout system.

The live Razorpay/Gumroad checkout implementation lives in
workers/intel-gateway/src/index.js (handleWebhookGumroad, handleWebhookRazorpay,
provisionApiKey) and upgrade.html (the single checkout page for both
gateways) -- see workers/intel-gateway/src/gumroad-lifecycle.js's header
comment for why this is one system, not a second parallel one.

Two test styles, matching this repo's existing conventions:

  1. Real-execution style -- subprocess-runs the actual Node unit test file
     (gumroad-lifecycle.test.js) and the actual monetization CI gate
     (scripts/validate_monetization.py), asserting they pass. This reuses
     those checks rather than re-deriving them in Python (Principle 4).
  2. Static-analysis style (tests/test_enterprise_pricing.py,
     tests/test_developer_portal.py convention) -- regex/string assertions
     against the real source files for wiring this repo's Node ESM loader
     can't otherwise unit-test (KV writes, ctx.waitUntil, the Workers
     runtime), and against the frontend pages for the required markers.

Run with: pytest tests/test_gumroad_and_razorpay.py -v
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from scripts.homepage_source import read_homepage_source  # index.html + extracted css/js

REPO_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_SRC = REPO_ROOT / "workers" / "intel-gateway" / "src" / "index.js"
GUMROAD_LIFECYCLE_SRC = REPO_ROOT / "workers" / "intel-gateway" / "src" / "gumroad-lifecycle.js"
GUMROAD_LIFECYCLE_TEST = REPO_ROOT / "workers" / "intel-gateway" / "src" / "__tests__" / "gumroad-lifecycle.test.js"
VALIDATE_MONETIZATION = REPO_ROOT / "scripts" / "validate_monetization.py"
INDEX_HTML = REPO_ROOT / "index.html"
UPGRADE_HTML = REPO_ROOT / "upgrade.html"
WELCOME_HTML = REPO_ROOT / "welcome.html"


def _node_available() -> bool:
    try:
        return subprocess.run(["node", "--version"], capture_output=True, timeout=5).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _html_references_host(html_text: str, host: str) -> bool:
    """True if any src=/href= URL in the page has `host` as its exact
    hostname (or a subdomain of it). Deliberately does not use a raw
    `host in html_text` substring check: that form is flagged by CodeQL
    (py/incomplete-url-substring-sanitization) because it doesn't verify
    the domain's position -- "evil.com/checkout.razorpay.com" would also
    match. Parsing each URL and comparing the hostname is the precise
    check the query recommends instead.
    """
    for url in re.findall(r'(?:src|href)=["\']([^"\']+)["\']', html_text):
        hostname = urlsplit(url).hostname or ""
        if hostname == host or hostname.endswith("." + host):
            return True
    return False


needs_node = pytest.mark.skipif(not _node_available(), reason="node not available in this environment")


def _extract_function(src: str, name: str) -> str:
    """Extract one top-level `async function <name>(...) { ... }` body,
    matching the pattern already used by scripts/validate_monetization.py's
    validate_worker_api_auth_enforcement() for the same purpose.
    """
    match = re.search(
        rf"async function {re.escape(name)}\s*\(.*?\)\s*\{{(.*?)(?=\n(?:async function|export default))",
        src, re.DOTALL,
    )
    assert match, f"could not locate async function {name}() in {GATEWAY_SRC.name}"
    return match.group(1)


@pytest.fixture(scope="module")
def gateway_src() -> str:
    assert GATEWAY_SRC.exists(), f"{GATEWAY_SRC} not found"
    return GATEWAY_SRC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def gumroad_webhook_body(gateway_src: str) -> str:
    return _extract_function(gateway_src, "handleWebhookGumroad")


@pytest.fixture(scope="module")
def gumroad_lifecycle_src() -> str:
    assert GUMROAD_LIFECYCLE_SRC.exists(), f"{GUMROAD_LIFECYCLE_SRC} not found"
    return GUMROAD_LIFECYCLE_SRC.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Real-execution: the actual Node unit tests and the actual CI gate
# ---------------------------------------------------------------------------

@needs_node
def test_gumroad_lifecycle_node_unit_tests_pass():
    assert GUMROAD_LIFECYCLE_TEST.exists(), f"{GUMROAD_LIFECYCLE_TEST} not found"
    result = subprocess.run(
        ["node", "--test", str(GUMROAD_LIFECYCLE_TEST)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"gumroad-lifecycle.test.js failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_monetization_integrity_gate_passes():
    """Reuses the real, already-live CI gate rather than re-deriving its
    Razorpay/Gumroad marker and manual-payment-absence checks here."""
    result = subprocess.run(
        [sys.executable, str(VALIDATE_MONETIZATION)],
        capture_output=True, text=True, timeout=60, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, (
        f"validate_monetization.py gate failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# 2. Static analysis: Gumroad webhook wiring (KV writes, cancellation, email)
# ---------------------------------------------------------------------------

def test_gumroad_webhook_requires_shared_secret_auth(gumroad_webhook_body: str):
    assert "GUMROAD_WEBHOOK_SECRET" in gumroad_webhook_body
    assert "timingSafeEqual" in gumroad_webhook_body


def test_gumroad_webhook_handles_cancellation_event(gumroad_webhook_body: str, gumroad_lifecycle_src: str):
    # 2026-09-25 (Gumroad memberships): the handler routes on
    # classifyGumroadPing(), whose "cancellation" kind IS
    # isGumroadCancellationEvent() -- same guarantee, one classifier.
    classifies = ('classifyGumroadPing(formData)' in gumroad_webhook_body
                  and 'pingKind === "cancellation"' in gumroad_webhook_body
                  and 'if (isGumroadCancellationEvent(formData)) return "cancellation";' in gumroad_lifecycle_src)
    assert "isGumroadCancellationEvent" in gumroad_webhook_body or classifies, (
        "handleWebhookGumroad must check isGumroadCancellationEvent() -- "
        "a Gumroad subscription cancellation/end ping must not be treated as a new sale"
    )
    assert "gumroad_sub_key_map:" in gumroad_webhook_body, (
        "cancellation handling needs a subscription_id -> apiKey lookup"
    )
    assert 'applySubscriptionStatusChange(env, ctx, mappedKey, "cancelled"' in gumroad_webhook_body, (
        "cancellation must reuse applySubscriptionStatusChange() (single source of truth "
        "for subscription_status transitions), not a second ad-hoc KV write"
    )


def test_gumroad_webhook_does_not_revoke_on_cancel_intent_alone(gumroad_webhook_body: str):
    """cancelled:"true" alone means auto-renewal was turned off -- the buyer
    already paid for the current period, so access must not be revoked
    until ended:"true" (the period actually finishing) arrives. Revoking
    immediately on cancelled:"true" would cut off access a customer already
    paid for."""
    assert "isGumroadAccessRevokingEvent" in gumroad_webhook_body, (
        "must gate the actual revoke on a separate, stricter check than "
        "isGumroadCancellationEvent (which is also true for cancel-intent-only pings)"
    )
    assert "cancellation_recorded" in gumroad_webhook_body, (
        "a cancel-intent-only ping must return a distinct status, not silently "
        "no-op or be indistinguishable from an actual revoke"
    )


def test_gumroad_webhook_alerts_on_activation_email_failure(gumroad_webhook_body: str):
    """sendActivationEmail() fails closed (returns false, never throws) --
    the webhook must check that return value and raise visibility when it's
    false, since the customer has a valid key with no way to learn it
    otherwise. A bare try/catch around the call (ignoring the return value)
    is not enough."""
    assert "emailSent" in gumroad_webhook_body
    assert "GUMROAD ACTIVATION EMAIL FAILED" in gumroad_webhook_body


def test_gumroad_webhook_provisioning_writes_subscription_map(gumroad_webhook_body: str):
    assert "gumroad_sub_key_map:${subscription_id}" in gumroad_webhook_body.replace(" ", ""), (
        "a new recurring sale must record subscription_id -> apiKey so a later "
        "cancellation/end ping (which carries no apiKey) can find the key"
    )


def test_gumroad_webhook_sends_activation_email(gumroad_webhook_body: str):
    assert "sendActivationEmail(env, email, tier, apiKey)" in gumroad_webhook_body, (
        "Gumroad checkout happens entirely on Gumroad's hosted page -- there is no "
        "client-side callback into this app, so email is the only delivery channel "
        "for the API key; this must call the existing sendActivationEmail(), not "
        "reimplement email delivery"
    )


def test_gumroad_webhook_reuses_pure_tier_inference(gumroad_webhook_body: str):
    assert "inferGumroadTier(product_name, variants)" in gumroad_webhook_body


def test_index_js_reexports_gumroad_lifecycle_functions(gateway_src: str):
    assert "from './gumroad-lifecycle.js'" in gateway_src
    assert "inferGumroadTier" in gateway_src
    assert "isGumroadCancellationEvent" in gateway_src


# ---------------------------------------------------------------------------
# 3. Static analysis: tier-inference bug fix stays fixed
# ---------------------------------------------------------------------------

def test_gumroad_tier_inference_does_not_false_positive_on_sentinel(gumroad_lifecycle_src: str):
    """Regression guard: the original inline check was `pnl.includes("ent")`,
    which matches the substring "ent" inside "Sentinel" -- every product here
    is branded "...SENTINEL APEX...", so that check misclassified every PRO
    sale as ENTERPRISE. Must never come back."""
    assert 'includes("ent")' not in gumroad_lifecycle_src
    assert 'includes(\'ent\')' not in gumroad_lifecycle_src


# ---------------------------------------------------------------------------
# 4. Static analysis: frontend paywall + checkout pages
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def index_html_text() -> str:
    assert INDEX_HTML.exists()
    return read_homepage_source()


@pytest.fixture(scope="module")
def upgrade_html_text() -> str:
    assert UPGRADE_HTML.exists()
    return UPGRADE_HTML.read_text(encoding="utf-8")


def test_index_html_ioc_paywall_applies_blur_styling(index_html_text: str):
    style_match = re.search(r"\.cdb-ioc-lock-blur\s*\{([^}]*)\}", index_html_text)
    assert style_match, "expected .cdb-ioc-lock-blur rule in index.html"
    assert "blur(" in style_match.group(1), "gated IOC fields must be visually blurred for free tier"


def test_index_html_ioc_total_is_numeric_coerced_before_innerhtml(index_html_text: str):
    """Regression guard (CodeRabbit finding): _iocTotal feeds into
    grid.innerHTML via the paywall's title/sub text, so a non-numeric
    ioc_count/ioc_counts value from upstream feed data must be coerced to a
    finite number, never interpolated raw."""
    assert "Number(item.ioc_count)" in index_html_text
    assert "Number.isFinite" in index_html_text


def test_index_html_ioc_paywall_has_dual_gateway_ctas(index_html_text: str):
    assert "cdb-ioc-unlock-group" in index_html_text
    assert "gateway=razorpay" in index_html_text, "paywall must offer a Razorpay CTA"
    assert "gateway=gumroad" in index_html_text, "paywall must offer a Gumroad CTA"
    # Both CTAs must route through the one real checkout page, not a new one
    assert "/upgrade.html?plan=pro&utm_source=ioc-blur&gateway=razorpay" in index_html_text
    assert "/upgrade.html?plan=pro&utm_source=ioc-blur&gateway=gumroad" in index_html_text


def test_upgrade_html_still_has_automated_checkout_markers(upgrade_html_text: str):
    """Anti-regression: same markers scripts/validate_monetization.py enforces --
    duplicated here so this test file stands on its own."""
    assert _html_references_host(upgrade_html_text, "checkout.razorpay.com")
    assert "initiateRazorpayCheckout" in upgrade_html_text
    assert _html_references_host(upgrade_html_text, "gumroad.com")


def test_upgrade_html_handles_gateway_hint(upgrade_html_text: str):
    assert "_gatewayHint" in upgrade_html_text
    assert "gumroad-panel" in upgrade_html_text
    assert "section-payment-methods" in upgrade_html_text


@needs_node
def test_upgrade_html_inline_js_syntax_valid():
    """Same node --check technique scripts/validate_monetization.py uses."""
    data = UPGRADE_HTML.read_text(encoding="utf-8")
    # </script[^>]*> (not </script\s*> or bare </script>): a real HTML5
    # parser closes a <script> element on "</script" followed by ANY
    # characters up to the next ">" (not just whitespace) -- CodeQL's
    # py/bad-tag-filter confirmed a whitespace-only allowance still misses
    # a real closing tag like "</script foo>". Mirrors the same [^>]*
    # already used for the opening tag above.
    scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script[^>]*>", data, re.IGNORECASE)
    assert scripts, "expected inline <script> blocks in upgrade.html"
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False, encoding="utf-8") as f:
        f.write("\n".join(scripts))
        tmp_path = f.name
    result = subprocess.run(["node", "--check", tmp_path], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, f"upgrade.html inline JS syntax error: {result.stderr}"


# ---------------------------------------------------------------------------
# 5. welcome.html -- Gumroad post-checkout confirmation page
# ---------------------------------------------------------------------------

def test_welcome_html_exists_and_handles_gumroad_redirect():
    assert WELCOME_HTML.exists(), (
        "welcome.html is the landing page a merchant-configured Gumroad "
        "post-purchase redirect (?email=...&gateway=gumroad) points to"
    )
    data = WELCOME_HTML.read_text(encoding="utf-8")
    assert not data.startswith("﻿"), "welcome.html: BOM detected"
    assert "gateway" in data
    assert "gumroad-panel" in data


def test_welcome_html_never_reads_api_key_from_url(index_html_text: str, upgrade_html_text: str):
    """Regression guard: a live API key must never be read from or echoed
    into this page via a URL query parameter -- it can leak through browser
    history, referrer headers, and access logs. Gumroad delivers the key by
    email; Razorpay's checkout page already shows it inline server-side."""
    data = WELCOME_HTML.read_text(encoding="utf-8")
    # "YOUR_API_KEY" placeholder text in the quickstart snippets is fine --
    # what must never come back is code reading a live key out of the URL.
    assert "params.get('api_key')" not in data
    assert 'params.get("api_key")' not in data
    # welcome.html must not be linked to with a live key in the query string either
    assert "welcome.html?api_key=" not in index_html_text
    assert "welcome.html?api_key=" not in upgrade_html_text


@needs_node
def test_welcome_html_inline_js_syntax_valid():
    data = WELCOME_HTML.read_text(encoding="utf-8")
    # </script[^>]*> (not </script\s*> or bare </script>): a real HTML5
    # parser closes a <script> element on "</script" followed by ANY
    # characters up to the next ">" (not just whitespace) -- CodeQL's
    # py/bad-tag-filter confirmed a whitespace-only allowance still misses
    # a real closing tag like "</script foo>". Mirrors the same [^>]*
    # already used for the opening tag above.
    scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script[^>]*>", data, re.IGNORECASE)
    assert scripts
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False, encoding="utf-8") as f:
        f.write("\n".join(scripts))
        tmp_path = f.name
    result = subprocess.run(["node", "--check", tmp_path], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, f"welcome.html inline JS syntax error: {result.stderr}"


# ---------------------------------------------------------------------------
# 6. Gumroad billing-cycle expansion (issue #287)
# ---------------------------------------------------------------------------

def test_provision_api_key_has_cycle_days_for_every_gumroad_recurrence(gateway_src: str, gumroad_lifecycle_src: str):
    """provisionApiKey()'s cycleDays used to be a binary
    `billingCycle === "annual" ? 365 : 30`, silently giving any other value
    (Gumroad's quarterly/biannual/every_two_years) only 30 days. Regression
    guard: every bucket inferGumroadBillingCycle() can return must have a
    real entry here, not fall through to the 30-day default."""
    # 2026-09-25: the table is the shared BILLING_CYCLE_DAYS (gumroad-lifecycle.js,
    # also used for membership renewals); provisionApiKey() must read it.
    assert "BILLING_CYCLE_DAYS[billingCycle]" in gateway_src, "provisionApiKey() must use BILLING_CYCLE_DAYS"
    match = re.search(r"export const BILLING_CYCLE_DAYS = Object\.freeze\(\{([^}]*)\}\)", gumroad_lifecycle_src)
    assert match, "expected the BILLING_CYCLE_DAYS mapping in gumroad-lifecycle.js"
    cycle_days_body = match.group(1)
    for bucket in ("monthly", "quarterly", "biannual", "annual", "every_two_years"):
        assert f"{bucket}:" in cycle_days_body, f"CYCLE_DAYS is missing a '{bucket}' entry"


def test_gumroad_lifecycle_preserves_all_recurrence_buckets(gumroad_lifecycle_src: str):
    assert 'r === "quarterly"' in gumroad_lifecycle_src
    assert 'r === "biannually"' in gumroad_lifecycle_src
    assert 'r === "every_two_years"' in gumroad_lifecycle_src
