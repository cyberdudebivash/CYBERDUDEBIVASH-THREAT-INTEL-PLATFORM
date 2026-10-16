"""
tests/test_validate_reports_window_deferral.py

P0 regression coverage for the Report Validation Gate (scripts/
validate_reports.py, STAGE 3.3) root-cause fix.

CONFIRMED PRODUCTION FAILURE (forensic evidence from the actual CI logs of
sentinel-apex.yml runs #2244 and #2245 -- the first two natural runs
after PR #369/#370 landed): STAGE 3.3 hard-failed with ~1,394 "RULE 3 FAIL:
report file NOT FOUND" errors, 100% of them advisories OUTSIDE the rolling
REPORT_WINDOW_HOURS publish window that PR #369 introduced to stop the
whole-corpus R2 cost incident. Root cause: reports/ is gitignored and never
persisted across CI runs, and PR #369 correctly bounded report (re)generation
to a rolling window for R2 cost reasons -- but this validator still required
EVERY manifest entry, including thousands of historical ones outside that
window, to have a physical local file. That assumption held only under the
pre-#369 architecture where every report was regenerated every run.

These tests reproduce that exact scenario against the fixed validator and
prove: an in-window missing report still hard-fails (the gate's real safety
guarantee is preserved), while an out-of-window or confirmed-published
missing report is deferred, not failed -- restoring the pipeline's ability
to progress past STAGE 3.3 without weakening what the gate actually protects
against (a genuinely broken, in-scope customer-facing report link).

Tests use only local temp files -- no real R2/network access.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validate_reports as vr  # noqa: E402


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


class _ChdirFixture(unittest.TestCase):
    """Runs each test in a throwaway CWD so relative reports/ paths (and
    validate_reports.py's own MANIFEST_PATH/REPORTS_BASE defaults) never
    touch the real repository tree."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_cwd = os.getcwd()
        os.chdir(self._tmpdir.name)
        self.now = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        os.chdir(self._orig_cwd)
        self._tmpdir.cleanup()

    def _write_report(self, rel_path: str, size: int = 90_000) -> None:
        p = Path(rel_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("<!doctype html>\n" + ("x" * size), encoding="utf-8")


class TestInWindowMissingStillFails(_ChdirFixture):
    """GATE A: the gate's real safety guarantee -- a report this run was
    actually responsible for producing, but didn't -- is preserved."""

    def test_in_window_missing_report_is_fail(self):
        entry = {
            "id": "intel--freshmissing", "tlp": "TLP:CLEAR",  # P0 #721: an unlabelled advisory is policy-withheld, not "missing"
            "report_url": "/reports/2026/09/intel--freshmissing.html",
            "processed_at": _iso(self.now - timedelta(hours=1)),  # 1h old, well inside 24h window
        }
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(disposition, "FAIL")
        self.assertTrue(any("RULE 3 FAIL" in f for f in failures))

    def test_exactly_at_window_boundary_still_treated_as_in_window(self):
        entry = {
            "id": "intel--boundary", "tlp": "TLP:CLEAR",
            "report_url": "/reports/2026/09/intel--boundary.html",
            "processed_at": _iso(self.now - timedelta(hours=24)),  # exactly at the boundary
        }
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(disposition, "FAIL")


class TestOutOfWindowMissingIsDeferredNotFailed(_ChdirFixture):
    """This is the exact production defect: reproduces runs #2244/#2245's
    ~1,394 false-positive RULE 3 failures and proves they no longer occur."""

    def test_out_of_window_missing_report_is_deferred(self):
        entry = {
            "id": "intel--legacyitem",
            "report_url": "/reports/2026/06/intel--legacyitem.html",
            "processed_at": _iso(self.now - timedelta(days=60)),  # far outside 24h window
        }
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(disposition, "DEFERRED")
        self.assertEqual(failures, [])

    def test_unparseable_timestamp_missing_report_is_deferred_not_assumed_fresh(self):
        # r2_report_publisher.py's own build_publish_candidates() excludes
        # unparseable timestamps from the publish window entirely -- this
        # validator must treat that the same way (never "assume fresh").
        entry = {
            "id": "intel--badtimestamp",
            "report_url": "/reports/2026/09/intel--badtimestamp.html",
            "processed_at": "not-a-real-timestamp",
        }
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(disposition, "DEFERRED")
        self.assertEqual(failures, [])

    def test_confirmed_published_via_r2_state_is_deferred_regardless_of_age(self):
        entry = {
            "id": "intel--confirmedpub",
            "report_url": "/reports/2026/01/intel--confirmedpub.html",
            "processed_at": _iso(self.now - timedelta(days=200)),
        }
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24,
            published_ids={"intel--confirmedpub"},
        )
        self.assertEqual(disposition, "DEFERRED")
        self.assertEqual(failures, [])

    def test_out_of_window_external_url_still_fails_rule_2(self):
        """Deferral narrows RULE 3's scope only -- RULE 2 (no external URLs)
        must still apply unconditionally, in-window or not."""
        entry = {
            "id": "intel--externalold",
            "report_url": "https://evil.example.com/phish.html",
            "processed_at": _iso(self.now - timedelta(days=60)),
        }
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(disposition, "FAIL")
        self.assertTrue(any("RULE 2 FAIL" in f for f in failures))


class TestPassAndSkipDispositionsUnaffected(_ChdirFixture):
    def test_present_valid_report_is_pass(self):
        self._write_report("reports/2026/09/intel--present.html")
        entry = {
            "id": "intel--present",
            "report_url": "/reports/2026/09/intel--present.html",
            "processed_at": _iso(self.now - timedelta(hours=1)),
        }
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(disposition, "PASS")
        self.assertEqual(failures, [])

    def test_stix_bundle_only_entry_is_skip(self):
        entry = {"id": "bundle--abc123"}  # no report_url/internal_report_url at all
        failures, disposition = vr._validate_one(
            entry, 0, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(disposition, "SKIP")
        self.assertEqual(failures, [])


class TestValidateAllReportsEndToEnd(_ChdirFixture):
    """Reproduces the actual runs #2244/#2245 shape at the validate_all_reports()
    level: a manifest overwhelmingly made of out-of-window, locally-missing
    legacy advisories must no longer hard-fail the whole gate."""

    def _write_manifest(self, advisories):
        Path("data/stix").mkdir(parents=True, exist_ok=True)
        Path("data/stix/feed_manifest.json").write_text(
            json.dumps(advisories), encoding="utf-8"
        )

    def test_manifest_of_only_legacy_out_of_window_items_passes_the_gate(self):
        advisories = [
            {
                "id": f"intel--legacy{i}",
                "report_url": f"/reports/2026/06/intel--legacy{i}.html",
                "processed_at": _iso(datetime.now(timezone.utc) - timedelta(days=60)),
            }
            for i in range(50)
        ]
        self._write_manifest(advisories)
        with patch.object(vr, "load_publish_state", return_value={"items": {}}):
            ok = vr.validate_all_reports(
                manifest_path=Path("data/stix/feed_manifest.json"),
                reports_base=Path("reports"),
            )
        self.assertTrue(
            ok,
            "A manifest made entirely of out-of-window legacy advisories with "
            "no local report files must PASS the gate (deferred, not failed) -- "
            "this is the exact shape of the confirmed production failure in "
            "sentinel-apex.yml runs #2244/#2245.",
        )

    def test_one_in_window_missing_report_still_blocks_the_whole_gate(self):
        advisories = [
            {
                "id": "intel--legacy0",
                "report_url": "/reports/2026/06/intel--legacy0.html",
                "processed_at": _iso(datetime.now(timezone.utc) - timedelta(days=60)),
            },
            {
                "id": "intel--freshmissing", "tlp": "TLP:CLEAR",  # P0 #721: labelled, so a missing report is a real defect
                "report_url": "/reports/2026/09/intel--freshmissing.html",
                "processed_at": _iso(datetime.now(timezone.utc) - timedelta(hours=1)),
            },
        ]
        self._write_manifest(advisories)
        with patch.object(vr, "load_publish_state", return_value={"items": {}}):
            ok = vr.validate_all_reports(
                manifest_path=Path("data/stix/feed_manifest.json"),
                reports_base=Path("reports"),
            )
        self.assertFalse(
            ok,
            "A genuinely missing IN-WINDOW report must still hard-fail the "
            "gate -- deferral must never mask a real regression in this "
            "run's own report generation.",
        )


if __name__ == "__main__":
    unittest.main()
