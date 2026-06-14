#!/usr/bin/env python3
"""
tests/test_generate_intel_reports_manifest_formats.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Report Generator Manifest-Format Regression Test

P0 REGRESSION GUARD: run_pipeline.py STAGE 3.6 invokes
scripts/generate_intel_reports.py twice:
  1. --manifest data/stix/feed_manifest.json  (top-level JSON object {"advisories": [...]})
  2. --manifest api/feed.json                 (top-level JSON ARRAY -- "ID format
     migration pass", allow_fail=True)

Prior to the fix, main() unconditionally called data.get("advisories"), which
raised `AttributeError: 'list' object has no attribute 'get'` for pass #2.
Because that pass is allow_fail=True, the crash was silently swallowed every
run -- items in api/feed.json never received a report_url, producing permanent
404s on /reports/<yyyy>/<mm>/<id>.html on the live dashboard.

This test locks in support for BOTH manifest shapes so this cannot regress.
"""
import json
import sys
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "generate_intel_reports.py"

_BASE_ITEM = {
    "title": "Regression Test Advisory -- Manifest Format Guard",
    "description": (
        "Synthetic advisory used by "
        "tests/test_generate_intel_reports_manifest_formats.py to verify "
        "scripts/generate_intel_reports.py handles both list- and dict-shaped "
        "manifests without crashing."
    ),
    "source": "TEST-FIXTURE",
    "severity": "LOW",
    "timestamp": "2026-06-01T00:00:00Z",
    "processed_at": "2026-06-01T00:00:00Z",
}


def _run_generator(manifest_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, str(SCRIPT),
            "--manifest", str(manifest_path),
            "--public-prefix", "https://intel.cyberdudebivash.com",
            "--limit", "0",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _cleanup_reports(*item_ids):
    for item_id in item_ids:
        for p in (REPO_ROOT / "reports").rglob(f"{item_id}.html*"):
            p.unlink(missing_ok=True)


class TestGenerateIntelReportsManifestFormats(unittest.TestCase):
    """Both api/feed.json (list) and feed_manifest.json (dict) shapes must work."""

    def test_list_manifest_does_not_crash(self):
        """api/feed.json is a top-level JSON array."""
        item_id = "intel--testfixture0000000a01"
        item = dict(_BASE_ITEM, id=item_id)

        with __import__("tempfile").TemporaryDirectory() as td:
            manifest = Path(td) / "feed.json"
            manifest.write_text(json.dumps([item]), encoding="utf-8")

            try:
                result = _run_generator(manifest)
                self.assertEqual(
                    result.returncode, 0,
                    f"generator crashed on list-format manifest:\n"
                    f"stdout={result.stdout}\nstderr={result.stderr}",
                )
                self.assertNotIn("AttributeError", result.stderr)

                data = json.loads(manifest.read_text(encoding="utf-8"))
                self.assertIsInstance(
                    data, list,
                    "list-format manifest must remain a top-level JSON array",
                )
                self.assertEqual(len(data), 1)

                report_path = REPO_ROOT / "reports" / "2026" / "06" / f"{item_id}.html"
                self.assertTrue(
                    report_path.exists(),
                    f"expected HTML report generated for list-format item at {report_path}",
                )
                self.assertGreater(report_path.stat().st_size, 1024)
            finally:
                _cleanup_reports(item_id)

    def test_dict_manifest_still_works(self):
        """data/stix/feed_manifest.json is {"advisories": [...], ...}."""
        item_id = "intel--testfixture0000000a02"
        item = dict(_BASE_ITEM, id=item_id)

        with __import__("tempfile").TemporaryDirectory() as td:
            manifest = Path(td) / "feed_manifest.json"
            manifest.write_text(
                json.dumps({"advisories": [item], "generated_at": "2026-06-01T00:00:00Z"}),
                encoding="utf-8",
            )

            try:
                result = _run_generator(manifest)
                self.assertEqual(
                    result.returncode, 0,
                    f"generator failed on dict-format manifest:\n"
                    f"stdout={result.stdout}\nstderr={result.stderr}",
                )

                data = json.loads(manifest.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)
                self.assertIn("advisories", data)
                self.assertEqual(len(data["advisories"]), 1)
                self.assertEqual(data.get("generated_at"), "2026-06-01T00:00:00Z")

                report_path = REPO_ROOT / "reports" / "2026" / "06" / f"{item_id}.html"
                self.assertTrue(
                    report_path.exists(),
                    f"expected HTML report generated for dict-format item at {report_path}",
                )
                self.assertGreater(report_path.stat().st_size, 1024)
            finally:
                _cleanup_reports(item_id)


if __name__ == "__main__":
    unittest.main()
