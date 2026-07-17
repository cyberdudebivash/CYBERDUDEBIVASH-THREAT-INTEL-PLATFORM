"""
Regression tests for platform/services/billing-engine/main.py.

Context: this service previously fabricated data on five endpoints —
hardcoded MRR/usage figures with no data source, a Stripe webhook handler
that accepted any payload without verifying its signature, a subscription
endpoint that returned "status": "active" without ever calling Stripe or
persisting anything, and an OEM license check that returned valid=True for
any license_id (a fail-open authorization bypass). None of that was caught
by existing tests because none existed for this service. These tests pin
the corrected behavior: real endpoints fail loudly (503/501/400) instead of
returning invented data, and the one authorization-relevant check fails
closed (valid: false) rather than open.
"""
import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# platform/services/billing-engine/main.py isn't an importable package (no
# __init__.py, and "billing-engine" isn't a valid Python identifier), so it's
# loaded directly by file path rather than via a normal import statement.
_MAIN_PATH = Path(__file__).resolve().parents[2] / "platform" / "services" / "billing-engine" / "main.py"
_spec = importlib.util.spec_from_file_location("billing_engine_main", _MAIN_PATH)
main = importlib.util.module_from_spec(_spec)
sys.modules["billing_engine_main"] = main
_spec.loader.exec_module(main)

client = TestClient(main.app)


def test_health_still_works():
    """Sanity check the app loads and the untouched route is unaffected."""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_tiers_still_returns_real_pricing_data():
    """/tiers was never fabricated (it echoes the real TIER_LIMITS constant)
    and must keep working exactly as before."""
    r = client.get("/tiers")
    assert r.status_code == 200
    assert r.json()["tiers"]["pro"]["price_monthly_usd"] == 499


def test_mrr_no_longer_returns_fabricated_numbers():
    r = client.get("/revenue/mrr")
    assert r.status_code == 503
    body = r.json()
    assert "284" not in str(body)  # the old fabricated $284,750 MRR must not appear anywhere
    assert "not implemented" in body["detail"].lower()


def test_usage_summary_no_longer_returns_mock_numbers():
    r = client.get("/usage/some-tenant/summary")
    assert r.status_code == 503
    assert "47832" not in str(r.json())  # the old mock api_calls figure must not appear


def test_subscription_creation_no_longer_fakes_success():
    r = client.post("/subscriptions", json={
        "tenant_id": "acme-corp", "tier": "pro", "billing_email": "billing@acme.example",
    })
    assert r.status_code == 501
    assert r.json()["detail"]  # must explain why, not just fail silently


def test_oem_license_fails_closed_for_arbitrary_input():
    """The core authorization-bypass fix: any string used to previously
    validate as a real OEM license with full feature access."""
    r = client.get("/licensing/oem/totally-made-up-license-id-12345")
    assert r.status_code == 200  # a license *check* correctly returning "not valid" is a 200, not an error
    body = r.json()
    assert body["valid"] is False
    assert body["features"] == []


def test_webhook_rejects_missing_signature():
    r = client.post("/webhooks/stripe", content=b'{"type":"customer.subscription.created"}')
    assert r.status_code in (400, 503)  # 503 if STRIPE_WEBHOOK_SECRET unset in this env, 400 if set but header missing


def test_webhook_rejects_forged_signature_when_secret_is_configured(monkeypatch):
    monkeypatch.setattr(main, "STRIPE_WEBHOOK_SECRET", "whsec_test_fake_secret_for_this_test_only")
    r = client.post(
        "/webhooks/stripe",
        content=b'{"type":"customer.subscription.created"}',
        headers={"stripe-signature": "t=1,v1=not_a_real_signature"},
    )
    assert r.status_code == 400
    assert "invalid signature" in r.json()["detail"].lower()
