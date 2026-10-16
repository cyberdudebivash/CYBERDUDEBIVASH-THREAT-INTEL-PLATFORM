"""
tests/test_export_stix_single_writer.py

RX-PUB-A0.4 Phase 3 regression tests: agent/export_stix.py's brand-new-item
ingestion path (STIXExporter._update_manifest, called from
agent/sentinel_blogger.py's "Stage 2" per
.github/workflows/sentinel-apex.yml's own architecture comment) must no
longer synchronously invoke report_generator.py's secondary rendering
engine ("Writer B" in docs/REPORT_WRITER_OWNERSHIP_MATRIX.md). It must
still produce a manifest entry with the correct prospective report_url so
generate_intel_reports.py's later "Zero-skip" pass in the same pipeline run
(Stage 3.6 html_reports) picks it up, and workers/intel-gateway/src/index.js's
live-render fallback (PR #182) covers the narrow gap in between -- without
either of those being a second canonical writer.
"""
import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


class TestExportStixDoesNotCallSecondaryRenderer(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="export_stix_test_")
        self._orig_cwd = os.getcwd()
        os.chdir(self.tmp)
        os.makedirs("data/stix", exist_ok=True)
        self._orig_jwt = os.environ.get("CDB_JWT_SECRET")
        os.environ["CDB_JWT_SECRET"] = "test-secret-for-unit-tests-only-not-real"

    def tearDown(self):
        os.chdir(self._orig_cwd)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)
        if self._orig_jwt is None:
            os.environ.pop("CDB_JWT_SECRET", None)
        else:
            os.environ["CDB_JWT_SECRET"] = self._orig_jwt

    def _make_exporter(self):
        from agent.export_stix import STIXExporter
        return STIXExporter(output_dir="data/stix")

    def test_new_item_manifest_entry_written_without_any_html_file_existing(self):
        """No secondary renderer means: this must succeed with ZERO html files
        on disk anywhere -- proving nothing tried to generate/verify one."""
        exp = self._make_exporter()
        self.assertFalse(
            os.path.isdir("reports"),
            "sanity check: no reports/ directory should exist before this call"
        )

        exp._update_manifest(
            title="Test Advisory — New Item Ingestion",
            stix_id="intel--newitemtest0000001",
            risk_score=7.5,
            blog_url="",
            severity="HIGH",
            confidence=0.8,
            tlp_label="TLP:CLEAR",
            ioc_counts={},
            actor_tag="UNC-TEST",
            mitre_tactics=[],
            feed_source="TEST-SOURCE",
            indicator_count=0,
            stix_file="",
        )

        self.assertFalse(
            os.path.isdir("reports"),
            "no reports/ directory should have been created -- this path must "
            "never write HTML itself, only the manifest entry"
        )

        with open("data/stix/feed_manifest.json", encoding="utf-8") as f:
            data = json.load(f)
        entries = data if isinstance(data, list) else data.get("advisories", data.get("items", []))
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["id"], "intel--newitemtest0000001")
        import re
        self.assertRegex(
            entry["report_url"],
            r"^/reports/\d{4}/\d{2}/intel--newitemtest0000001\.html$",
            "report_url must be the prospective canonical path, computed "
            "without needing the file to exist"
        )
        self.assertEqual(entry["internal_report_url"], entry["report_url"])
        self.assertEqual(
            entry["validation_status"], "pending",
            "must be 'pending' (not the old hardcoded 'valid') since no file "
            "has actually been generated at this point -- update_validation_status.py "
            "(STAGE 3.3.5) is the mechanism that later flips this to 'valid'"
        )
        self.assertIsNone(entry["validated_at"])

    def test_report_generator_is_not_imported_by_export_stix_module(self):
        """Static guard: report_generator (Writer B's engine) must not be
        reachable from this module at all -- not just unused at runtime."""
        source_path = os.path.join(REPO_ROOT, "agent", "export_stix.py")
        with open(source_path, encoding="utf-8") as f:
            source = f.read()
        self.assertNotIn(
            "from report_generator import", source,
            "agent/export_stix.py must not import report_generator -- it is "
            "no longer this module's job to invoke a rendering engine at all "
            "(RX-PUB-A0.4 Phase 3)."
        )
        self.assertNotIn("_gen_report(", source)

    def test_multiple_new_items_all_get_pending_state_no_exceptions(self):
        """Proves this is not a one-off -- a realistic burst of new items
        (e.g. a source with several new advisories in one ingestion pass)
        all succeed without any of them needing a rendered file to exist."""
        exp = self._make_exporter()
        for i in range(5):
            exp._update_manifest(
                title=f"Test Advisory {i}",
                stix_id=f"intel--burst{i:020d}",
                risk_score=5.0,
                blog_url="",
                severity="MEDIUM",
                confidence=0.5,
                tlp_label="TLP:CLEAR",
                ioc_counts={},
                actor_tag="UNC-TEST",
                mitre_tactics=[],
                feed_source="TEST-SOURCE",
                indicator_count=0,
                stix_file="",
            )

        with open("data/stix/feed_manifest.json", encoding="utf-8") as f:
            data = json.load(f)
        entries = data if isinstance(data, list) else data.get("advisories", data.get("items", []))
        self.assertEqual(len(entries), 5)
        for entry in entries:
            self.assertEqual(entry["validation_status"], "pending")
            self.assertTrue(entry["report_url"].startswith("/reports/"))


if __name__ == "__main__":
    unittest.main()
