"""Regression tests for the PHP2Shell public-feed gate (offline, no network)."""
import importlib.util
import unittest
from datetime import datetime, timezone

from pathlib import Path
spec = importlib.util.spec_from_file_location("gate", Path(__file__).resolve().parents[1] / "scripts" / "php2shell_coverage_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
NOW = datetime(2026, 10, 23, tzinfo=timezone.utc)
projection_spec = importlib.util.spec_from_file_location(
    "public_api_sanitizer",
    Path(__file__).resolve().parents[1] / "scripts" / "public_api_sanitizer.py",
)
projection = importlib.util.module_from_spec(projection_spec)
projection_spec.loader.exec_module(projection)

_PHP_NEWS_URL = (
    "https://www.bleepingcomputer.com/news/security/"
    "php-ships-emergency-patches-for-critical-php2shell-flaws/"
)
_PHP_VENDOR_URL = "https://www.php.net/archive/2026.php#2026-10-21-5"


def _curated_source_item():
    return {
        "title": "PHP ships emergency patches for critical PHP2Shell flaws",
        "tlp": "TLP:CLEAR",
        "source": "BleepingComputer",
        "source_url": _PHP_NEWS_URL,
        "cve_id": "CVE-2026-109619",
        "cve_ids": ["CVE-2026-109619", "CVE-2026-109618"],
    }

def payload():
    return {"generated_at": "2026-10-22T23:00:00Z", "items": [
        {"cve_id": c, "references": [{"url": "https://www.php.net/archive/2026.php#2026-10-21-5"}]}
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
            item["source_url"] = "https://www.php.net/archive/2026.php#2026-10-21-5"
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
    def test_generic_php_archive_not_accepted(self):
        p = payload()
        p["items"][0]["references"] = ["https://www.php.net/archive/2026.php"]
        self.assertTrue(any("missing_authoritative_source" in e for e in gate.check(p, now=NOW)))

    def test_mismatched_nvd_cve_not_accepted(self):
        p = payload()
        p["items"][0]["references"] = ["https://nvd.nist.gov/vuln/detail/CVE-2026-109619"]
        self.assertTrue(any("missing_authoritative_source" in e for e in gate.check(p, now=NOW)))

    def test_cve_specific_nvd_reference(self):
        p = payload()
        for item in p["items"]:
            item["references"] = [f"https://nvd.nist.gov/vuln/detail/{item['cve_id']}"]
        self.assertEqual(gate.check(p, now=NOW), [])

    def test_wrong_php_anchor_rejected(self):
        p = payload()
        p["items"][0]["references"] = ["https://www.php.net/archive/2026.php#2026-10-21-999"]
        self.assertTrue(any("missing_authoritative_source" in e for e in gate.check(p, now=NOW)))

    def test_no_items_fails(self):
        self.assertIn("missing_items_array", gate.check({"generated_at": "2026-10-22T23:00:00Z"}, now=NOW))
    def test_exact_reviewed_vendor_reference_survives_public_projection(self):
        item = _curated_source_item()
        item["references"] = [
            {"url": "https://private.example/internal", "internal_report_url": "classified"}
        ]
        item["report_url"] = "https://private.example/paywalled"
        projected = projection.project_for_public_latest(item)
        self.assertEqual(projected["source"], "BleepingComputer")
        self.assertEqual(projected["source_url"], _PHP_NEWS_URL)
        self.assertEqual(projected["references"], [{
            "url": _PHP_VENDOR_URL, "type": "vendor_advisory",
            "publisher": "PHP Security Team",
            "cve_ids": ["CVE-2026-109618", "CVE-2026-109619"],
        }])
        self.assertNotIn("report_url", projected)
        self.assertNotIn("internal_report_url", str(projected))
        self.assertNotIn("private.example", str(projected))
        self.assertEqual(gate.check({
            "generated_at": "2026-10-22T23:00:00Z", "items": [projected],
        }, now=NOW), [])

    def test_curated_reference_never_attached_to_unreviewed_source(self):
        for url in (
            "https://attacker.invalid/fake-php-advisory",
            "https://www.bleepingcomputer.com/news/security/different-story/",
            "http://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/",
            "https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/?other=1",
        ):
            with self.subTest(url=url):
                item = _curated_source_item()
                item["source_url"] = url
                item["references"] = ["https://www.php.net/archive/2026.php#2026-10-21-5"]
                self.assertNotIn("references", projection.project_for_public_latest(item))

    def test_curated_reference_requires_both_structured_cve_identifiers(self):
        samples = (
            {"cve_ids": ["CVE-2026-109618"], "cve_id": ""},
            {"cve_ids": ["CVE-2026-109619"], "cve_id": ""},
            {"cve_ids": "CVE-2026-109618 CVE-2026-109619", "cve_id": ""},
            {"cve_ids": [], "cve_id": ""},
            {"cve_ids": ["CVE-2026-109618", "CVE-2026-109617"], "cve_id": ""},
            {"cve_ids": ["CVE-2026-109618", "CVE-2026-109619"] * 20, "cve_id": ""},
        )
        for values in samples:
            with self.subTest(values=values):
                item = _curated_source_item()
                item.update(values)
                # Free-text title is never treated as validated CVE identity.
                self.assertNotIn("references", projection.project_for_public_latest(item))

    def test_curated_reference_only_tlp_clear(self):
        for label in (None, "TLP:RED", "TLP:AMBER", "TLP:GREEN", "", "CLEAR"):
            with self.subTest(tlp=label):
                item = _curated_source_item()
                item["tlp"] = label
                self.assertNotIn("references", projection.project_for_public_latest(item))

    def test_unrelated_items_remain_unchanged_and_raw_references_are_not_published(self):
        item = {
            "title": "Unrelated source", "tlp": "TLP:CLEAR",
            "source_url": "https://example.com/advisory",
            "cve_ids": ["CVE-2026-109618", "CVE-2026-109619"],
            "references": [{"url": "https://internal.example/private", "secret": "hidden"}],
            "report_url": "https://paywall.invalid/report",
        }
        projected = projection.project_for_public_latest(item)
        self.assertEqual(projected, {
            "title": "Unrelated source", "tlp": "TLP:CLEAR",
            "source_url": "https://example.com/advisory",
            "cve_ids": ["CVE-2026-109618", "CVE-2026-109619"],
        })

    def test_unrelated_non_advisory_records_never_gain_curated_metadata(self):
        item = {
            "id": "intel--generic", "title": "Ordinary threat",
            "cve_id": "CVE-2026-999999", "tlp": "TLP:CLEAR",
            "source_url": _PHP_NEWS_URL,
        }
        self.assertNotIn("references", projection.project_for_public_latest(item))

if __name__ == "__main__":
    unittest.main()
