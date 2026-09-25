"""Commercial copy truth (P0 go-live, 2026-09-25).

Public manual payment proof is retired (docs/COMMERCIAL_POLICY_V1.md): no
customer page may ask for a payment screenshot, a UPI/NEFT/crypto proof or a
transaction hash, publish crypto addresses, promise "instant" or manual
activation, or claim a SOC 2 / ISO 27001 certification the platform does not
hold (config/commercial-contract.json: _attestation_status).
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUBLIC_PAGES = sorted(p for p in REPO.glob("*.html"))

FORBIDDEN = [
    (r"payment\s+screenshot", "asks for a payment screenshot"),
    (r"send\s+(us\s+)?(the\s+|your\s+)?(payment|transaction)\s+(screenshot|proof)", "asks for payment proof"),
    (r"(upi|neft|imps|bank)\s+(payment\s+)?proof(?!s are not accepted)", "asks for UPI/NEFT/bank proof"),
    (r"transaction\s+hash\s+to\s+verify", "crypto transaction verification"),
    (r"/api/payment/verify-bsc", "calls the non-existent crypto verifier"),
    (r"\bbc1q[0-9a-z]{6,}|\bT[1-9A-HJ-NP-Za-km-z]{33}\b", "publishes a crypto address"),
    (r"manual\s+activation", "promises manual activation"),
    (r"instant\s+activation(?!, valid for 1 year)", "promises instant activation of a paid plan"),
    (r"(soc\s*2|iso\s*27001)[^.<]{0,20}\bcertified\b", "claims a certification"),
]


def _visible(src: str) -> str:
    src = re.sub(r"<!--.*?-->", " ", src, flags=re.S)
    return src


def test_public_pages_exist():
    assert len(PUBLIC_PAGES) > 50


def test_no_retired_manual_payment_or_overclaim_copy_on_public_pages():
    hits = []
    for page in PUBLIC_PAGES:
        text = _visible(page.read_text(encoding="utf-8", errors="replace"))
        for pattern, why in FORBIDDEN:
            for m in re.finditer(pattern, text, flags=re.I):
                ctx = text[max(0, m.start() - 40):m.end() + 2].lower()
                # "aligned, not certified" and "Are you ... certified?" are the
                # honest disclaimer and an FAQ question, not a claim.
                if why == "claims a certification" and ("not certified" in ctx or text[m.end():m.end() + 1] == "?"):
                    continue
                hits.append(f"{page.name}: {why}: ...{text[max(0, m.start()-40):m.end()+40]!r}...")
    assert not hits, "\n".join(hits)


def test_checkout_support_wording_is_sales_and_checkout_support():
    upgrade = (REPO / "upgrade.html").read_text(encoding="utf-8")
    assert "Sales &amp; checkout support" in upgrade
    assert "API access activates automatically after payment confirmation" in upgrade


def test_recurring_checkout_never_calls_one_time_orders():
    # Stage 24: PRO / Enterprise / MSSP are subscription-only.
    upgrade = (REPO / "upgrade.html").read_text(encoding="utf-8")
    assert "/api/payment/razorpay/create-order" not in upgrade
    assert "/api/payment/razorpay/verify" not in upgrade
    assert "/api/v2/billing/subscriptions/create" in upgrade
