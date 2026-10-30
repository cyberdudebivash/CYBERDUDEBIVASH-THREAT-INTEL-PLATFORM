"""Offline negative controls: no Pages release on inconsistent catalog/manifest."""
import json
from contextlib import redirect_stdout
from io import StringIO
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from p0_pages_report_parity_preflight import preflight, main  # noqa: E402

BASE = "https://intel.cyberdudebivash.com"


def report(letter="a", timestamp="2025-10-02T00:00:00Z"):
    slug = "intel--" + letter * 24
    path = "/reports/2025/10/" + slug + ".html"
    return {"id": slug, "path": path, "url": BASE + path, "timestamp": timestamp}


class PreflightTests(unittest.TestCase):
    def check(self, catalog, manifest):
        with tempfile.TemporaryDirectory() as d:
            c, m = Path(d) / "catalog.json", Path(d) / "manifest.json"
            c.write_text(json.dumps(catalog), encoding="utf-8")
            m.write_text(json.dumps(manifest), encoding="utf-8")
            with redirect_stdout(StringIO()):
                code = main(["--catalog", str(c), "--manifest", str(m)])
            return preflight(c, m), code

    def test_valid_pages_parity_is_only_precheck(self):
        item = report()
        result, code = self.check({"reports": [item]}, {"files": {item["path"].lstrip("/"): {}}})
        self.assertEqual(code, 0)
        self.assertEqual(result["verdict"], "PARITY_PRECHECK_ONLY")
        self.assertFalse(result["delivery_certified"])
        self.assertEqual(result["selected_probes"], 1)

    def test_missing_pages_report_blocks_before_deployment(self):
        first, second = report("a"), report("b", "2025-10-03T00:00:00Z")
        result, code = self.check({"reports": [first, second]},
                                  {"files": {first["path"].lstrip("/"): {}}})
        self.assertEqual(code, 2)
        self.assertEqual(result["reason_code"], "PAGES_MANIFEST_REPORT_MISMATCH")
        self.assertNotIn("intel--", json.dumps(result))

    def test_naive_timestamp_blocks(self):
        item = report(timestamp="2025-10-02T00:00:00")
        result, code = self.check({"reports": [item]}, {"files": {}})
        self.assertEqual(code, 2)
        self.assertEqual(result["reason_code"], "CATALOG_TIMESTAMP_NOT_EXPLICIT_UTC")

    def test_invalid_manifest_files_blocks(self):
        result, code = self.check({"reports": [report()]}, {"files": []})
        self.assertEqual(code, 2)
        self.assertEqual(result["reason_code"], "PAGES_MANIFEST_INVALID")

    def test_empty_catalog_blocks(self):
        result, code = self.check({"reports": []}, {"files": {}})
        self.assertEqual(code, 2)
        self.assertEqual(result["reason_code"], "CATALOG_EMPTY")

    def test_missing_files_block(self):
        with tempfile.TemporaryDirectory() as d:
            result = preflight(Path(d) / "absent-catalog", Path(d) / "absent-manifest")
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertFalse(result["delivery_certified"])

    def test_r2_first_empty_pages_manifest_is_not_delivery_proof(self):
        result, code = self.check({"reports": [report()]}, {"files": {}})
        self.assertEqual(code, 0)
        self.assertFalse(result["delivery_certified"])
        self.assertTrue(any("R2/Pages" in x for x in result["remaining_gates"]))

    def test_no_untrusted_report_details_leak(self):
        item = report(timestamp="SECRET_PRIVATE_REPORT_MARKER")
        item["title"] = "SECRET_PRIVATE_REPORT_MARKER"
        result, code = self.check({"reports": [item]}, {"files": {}})
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET_PRIVATE_REPORT_MARKER", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
