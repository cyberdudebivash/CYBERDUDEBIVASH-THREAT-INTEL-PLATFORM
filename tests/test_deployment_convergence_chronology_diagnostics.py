"""P0 negative controls: chronology diagnostic codes cannot bypass publication gate."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scripts import deployment_convergence_validator as validator  # noqa: E402


def report(digest, when):
    path = f"/reports/2026/10/intel--{digest}.html"
    return {"id": f"intel--{digest}", "path": path,
            "url": "https://intel.cyberdudebivash.com" + path,
            "timestamp": when}


class ChronologyDiagnosticsTest(unittest.TestCase):
    def _check_failed_precheck(self, data, manifest, code):
        with tempfile.TemporaryDirectory() as temp:
            catalog = Path(temp) / "index.json"
            catalog.write_text(data, encoding="utf-8")
            with patch.object(validator, "REPORTS_CATALOG_PATH", catalog):
                with self.assertLogs(validator.log, "ERROR") as logs:
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "P0 canonical chronology blocked convergence certification",
                    ) as error:
                        validator._extract_report_urls([], {"files": manifest})
        self.assertEqual(type(error.exception.__cause__).__name__, "ReportSelectionBlocked"
                         if code != "CATALOG_JSON_INVALID" else "JSONDecodeError")
        self.assertTrue(any(f"reason_code={code}" in line for line in logs.output))
        self.assertNotIn("https://intel.cyberdudebivash.com/reports/", " ".join(logs.output))
        self.assertNotIn("SECRET_CATALOG_MARKER", " ".join(logs.output))

    def test_naive_timestamp_fails_closed_with_actionable_category(self):
        row = report("a" * 16, "2026-10-24T19:00:00")
        row["title"] = "SECRET_CATALOG_MARKER"
        self._check_failed_precheck(
            json.dumps({"reports": [row]}), {}, "CATALOG_TIMESTAMP_NOT_EXPLICIT_UTC"
        )

    def test_manifest_catalog_mismatch_fails_closed(self):
        first = report("a" * 16, "2026-10-24T19:00:00Z")
        second = report("b" * 16, "2026-10-24T19:05:00Z")
        self._check_failed_precheck(
            json.dumps({"reports": [first, second]}),
            {first["path"].lstrip("/"): {}}, "PAGES_MANIFEST_REPORT_MISMATCH"
        )

    def test_bad_json_fails_closed(self):
        self._check_failed_precheck("{bad JSON", {}, "CATALOG_JSON_INVALID")

    def test_never_log_unrecognized_exception_values(self):
        code = validator._chronology_block_reason(
            ValueError("UNKNOWN: SECRET_CATALOG_MARKER")
        )
        self.assertEqual(code, "CATALOG_INTEGRITY_UNCLASSIFIED")


if __name__ == "__main__":
    unittest.main()
