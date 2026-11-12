"""Catalog-value reporting must follow the canonical pricing contract, not old estimates."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

spec = importlib.util.spec_from_file_location(
    "key_catalog_value", Path(__file__).resolve().parents[1] / "agent/tools/generate_key.py"
)
keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(keys)


class KeyCatalogValueTests(unittest.TestCase):
    def test_uses_exact_owner_canonical_prices(self):
        prices = keys.canonical_catalog_monthly_prices()
        self.assertEqual(prices, {
            "FREE": 0, "TRIAL": 0, "PRO": 4100,
            "ENTERPRISE": 41600, "MSSP": 83300,
        })
        self.assertNotEqual(prices["MSSP"], 166600)

    def test_rejects_missing_or_invalid_contract_without_guessing_prices(self):
        with TemporaryDirectory() as root:
            path = Path(root) / "commercial-contract.json"
            with self.assertRaises(OSError):
                keys.canonical_catalog_monthly_prices(path)
            path.write_text(json.dumps({
                "currency_primary": "USD", "tiers": {},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CATALOG_CURRENCY_NOT_INR"):
                keys.canonical_catalog_monthly_prices(path)
            path.write_text(json.dumps({
                "currency_primary": "INR",
                "tiers": {
                    "pro": {"inr_monthly": 4100},
                    "enterprise": {"inr_monthly": 41600},
                    "mssp": {"inr_monthly": "83300"},
                },
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CATALOG_PRICE_INVALID_MSSP"):
                keys.canonical_catalog_monthly_prices(path)

    def test_qualifying_keys_are_only_provisional_catalog_value_not_cash(self):
        data = {"keys": {
            "mssp1": {"tier": "MSSP", "status": "active", "expires_at": "2099-01-01"},
            "mssp2": {"tier": "mssp", "status": "active", "expires_at": "2099-01-01"},
            "pro": {"tier": "PRO", "status": "active", "expires_at": "2099-01-01"},
            "expired": {"tier": "ENTERPRISE", "status": "active", "expires_at": "2000-01-01"},
            "revoked": {"tier": "ENTERPRISE", "status": "revoked", "expires_at": "2099-01-01"},
        }}
        with patch.object(keys, "load_json", return_value=data):
            summary = keys.revenue_summary()
        self.assertEqual(summary["active_keys"], 3)
        self.assertEqual(summary["estimated_monthly_catalog_value_inr"], 170700)
        self.assertEqual(summary["estimated_annual_catalog_value_inr"], 2048400)
        self.assertIsNone(summary["mrr_inr"])
        self.assertIsNone(summary["arr_equivalent_inr"])
        self.assertEqual(summary["revenue_status"], "unverified_no_payment_ledger")
        self.assertEqual(summary["catalog_pricing_status"], "canonical_contract_verified")

    def test_missing_price_contract_is_not_silently_assumed_to_be_zero(self):
        with patch.object(keys, "load_json", return_value={"keys": {
            "x": {"status": "active", "tier": "MSSP", "expires_at": "2099-01-01"},
        }}), patch.object(keys, "canonical_catalog_monthly_prices", side_effect=OSError("offline")):
            summary = keys.revenue_summary()
        self.assertEqual(summary["catalog_pricing_status"], "unavailable")
        self.assertIsNone(summary["estimated_monthly_catalog_value_inr"])
        self.assertIsNone(summary["estimated_annual_catalog_value_inr"])
        self.assertIsNone(summary["mrr_inr"])

    def test_unknown_active_tier_cannot_inflate_or_understate_catalog_value(self):
        with patch.object(keys, "load_json", return_value={"keys": {
            "x": {"status": "active", "tier": "UNMAPPED", "expires_at": "2099-01-01"},
        }}):
            summary = keys.revenue_summary()
        self.assertEqual(summary["catalog_pricing_status"], "unavailable")
        self.assertIsNone(summary["estimated_monthly_catalog_value_inr"])

    def test_cli_handles_unavailable_catalog_value_without_claiming_revenue(self):
        with patch.object(keys, "revenue_summary", return_value={
            "as_of": "2026-11-12T00:00:00+00:00",
            "active_keys": 1, "tier_breakdown": {"MSSP": 1},
            "estimated_monthly_catalog_value_inr": None,
        }):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                keys.cmd_revenue(None)
        self.assertIn("Verified MRR: unavailable", out.getvalue())
        self.assertIn("Catalog value: unavailable", out.getvalue())


if __name__ == "__main__":
    unittest.main()
