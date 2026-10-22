"""Regression tests for the PHP2Shell public-feed gate (offline, no network)."""
import importlib.util
import unittest
from datetime import datetime, timezone

from pathlib import Path
spec = importlib.util.spec_from_file_location("gate", Path(__file__).resolve().parents[1] / "scripts" / "php2shell_coverage_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
NOW = datetime(2026, 10, 23, tzinfo=timezone.utc)

def payload():
    return {"generated_at": "2026-10-22T23:00:00Z", "items": [
        {"cve_id": c, "references": [{"url": "https://www.php.net/archive/2026.php"}]}
        for c in sorted(gate.REQUIRED)]}

class CoverageGateTests(unittest.TestCase):
    def test_complete_verified_feed(self):
        self.assertEqual(gate.check(payload(), now=NOW), [])
    def test_missing_cve_fails(self):
        p = payload()
        p["items"].pop()
        self.assertTrue(any("not_verified" in e for e in gate.check(p, now=NOW)))
    def test_untrusted_reference_fails(self):
        p = payload()
        p["items"][0]["references"] = ["https://php.net.evil.example/advisory"]
        self.assertTrue(any("missing_authoritative_source" in e for e in gate.check(p, now=NOW)))
    def test_stale_feed_fails(self):
        p = payload()
        p["generated_at"] = "2026-10-21T00:00:00Z"
        self.assertIn("feed_timestamp_outside_freshness_contract", gate.check(p, now=NOW))
    def test_future_timestamp_fails(self):
        p = payload()
        p["generated_at"] = "2026-10-24T00:00:00Z"
        self.assertIn("feed_timestamp_outside_freshness_contract", gate.check(p, now=NOW))
    def test_projected_public_schema(self):
        p = payload()
        for item in p["items"]:
            item["source_url"] = "https://www.php.net/archive/2026.php"
            item.pop("references")
            item["cve_ids"] = [item.pop("cve_id")]
        self.assertEqual(gate.check(p, now=NOW), [])
    def test_non_authoritative_github_reference(self):
        p = payload()
        p["items"][0]["references"] = ["https://github.com/unknown/example"]
        self.assertTrue(any("missing_authoritative_source" in e for e in gate.check(p, now=NOW)))
    def test_wrong_production_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            gate._read(url="https://intel.cyberdudebivash.com/api/admin/health")
    def test_querystring_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            gate._read(url="https://intel.cyberdudebivash.com/api/v1/intel/latest.json?debug=1")
    def test_no_items_fails(self):
        self.assertIn("missing_items_array", gate.check({"generated_at": "2026-10-22T23:00:00Z"}, now=NOW))
if __name__ == "__main__":
    unittest.main()
