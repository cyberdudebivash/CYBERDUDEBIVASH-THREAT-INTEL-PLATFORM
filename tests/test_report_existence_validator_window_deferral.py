"""
tests/test_report_existence_validator_window_deferral.py

P0 regression coverage for scripts/report_existence_validator.py (STAGE 5.4.1)
root-cause fix.

CONFIRMED PRODUCTION FAILURE: once PR #375 unblocked STAGE 3.3 (Report
Validation Gate), the very same natural sentinel-apex.yml run (#2249)
progressed further and then hard-failed at STAGE 5.4.1 instead -- skipping
GitHub Pages deployment for the rest of that run. This is the identical
architectural mismatch #375 already fixed in scripts/validate_reports.py,
just in a sibling validator #375 did not touch: PR #369 bounded report
(re)generation to a rolling REPORT_WINDOW_HOURS window to stop the
whole-corpus R2 cost incident, but reports/ is gitignored and never
persisted across CI runs, so a fresh runner has zero local files for any
manifest entry outside that window -- including the historical entries in
data/stix/feed_manifest.json this validator also checks.

These tests reproduce that scenario and prove: an in-window missing report
still hard-fails (the gate's real safety guarantee -- catching a report this
run was actually responsible for producing but didn't), while an
out-of-window or confirmed-durably-published missing report is deferred, not
failed. A malformed report_url (BAD_PREFIX -- real schema drift, unrelated to
the windowed-generation architecture) is never deferred, regardless of age.

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

import report_existence_validator as rev  # noqa: E402


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


class _ChdirFixture(unittest.TestCase):
    """Runs each test in a throwaway CWD so relative /reports/ paths never
    touch the real repository tree."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_cwd = os.getcwd()
        os.chdir(self._tmpdir.name)
        self.now = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
        self.repo = Path(self._tmpdir.name)

    def tearDown(self):
        os.chdir(self._orig_cwd)
        self._tmpdir.cleanup()

    def _write_report(self, rel_path: str) -> None:
        p = self.repo / rel_path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("<!doctype html>\n<html></html>", encoding="utf-8")

    def _write_feed(self, filename: str, advisories: list) -> Path:
        p = self.repo / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(advisories), encoding="utf-8")
        return p


class TestInWindowMissingStillFails(_ChdirFixture):
    """GATE A: the gate's real safety guarantee is preserved."""

    def test_in_window_missing_report_is_counted_as_missing(self):
        feed = self._write_feed("feed.json", [{
            "id": "intel--freshmissing",
            "report_url": "/reports/2026/09/intel--freshmissing.html",
            "processed_at": _iso(self.now - timedelta(hours=1)),  # inside 24h window
        }])
        checked, n_missing, missing, deferred = rev.validate(
            feed, self.repo, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(n_missing, 1)
        self.assertEqual(deferred, [])
        self.assertTrue(any("[MISSING]" in m for m in missing))


class TestOutOfWindowMissingIsDeferredNotFailed(_ChdirFixture):
    """Reproduces the exact production defect: run #2249's STAGE 5.4.1
    failure, caused by thousands of historical, out-of-window manifest
    entries with no local file on a fresh CI runner."""

    def test_out_of_window_missing_report_is_deferred(self):
        feed = self._write_feed("feed.json", [{
            "id": "intel--legacyitem",
            "report_url": "/reports/2026/06/intel--legacyitem.html",
            "processed_at": _iso(self.now - timedelta(days=60)),  # far outside 24h window
        }])
        checked, n_missing, missing, deferred = rev.validate(
            feed, self.repo, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(n_missing, 0)
        self.assertEqual(len(deferred), 1)
        self.assertTrue(any("[DEFERRED:out-of-window]" in d for d in deferred))

    def test_unparseable_timestamp_missing_report_is_deferred_not_assumed_fresh(self):
        feed = self._write_feed("feed.json", [{
            "id": "intel--badtimestamp",
            "report_url": "/reports/2026/09/intel--badtimestamp.html",
            "processed_at": "not-a-real-timestamp",
        }])
        checked, n_missing, missing, deferred = rev.validate(
            feed, self.repo, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(n_missing, 0)
        self.assertEqual(len(deferred), 1)

    def test_confirmed_published_via_r2_state_is_deferred_regardless_of_age(self):
        feed = self._write_feed("feed.json", [{
            "id": "intel--confirmedpub",
            "report_url": "/reports/2026/01/intel--confirmedpub.html",
            "processed_at": _iso(self.now - timedelta(days=200)),
        }])
        checked, n_missing, missing, deferred = rev.validate(
            feed, self.repo, now=self.now, window_hours=24,
            published_ids={"intel--confirmedpub"},
        )
        self.assertEqual(n_missing, 0)
        self.assertTrue(any("[DEFERRED:published]" in d for d in deferred))

    def test_out_of_window_bad_prefix_still_counted_as_missing(self):
        """Deferral narrows the 'no local file' case only -- a malformed
        report_url is real schema drift regardless of age, so BAD_PREFIX
        must never be deferred."""
        feed = self._write_feed("feed.json", [{
            "id": "intel--badprefix",
            "report_url": "reports/2026/06/intel--badprefix.html",  # missing leading /
            "processed_at": _iso(self.now - timedelta(days=60)),
        }])
        checked, n_missing, missing, deferred = rev.validate(
            feed, self.repo, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(n_missing, 1)
        self.assertEqual(deferred, [])
        self.assertTrue(any("[BAD_PREFIX]" in m for m in missing))

    def test_external_url_still_skipped_regardless_of_age(self):
        feed = self._write_feed("feed.json", [{
            "id": "intel--externalold",
            "report_url": "https://intel.cyberdudebivash.com/reports/2026/06/x.html",
            "processed_at": _iso(self.now - timedelta(days=60)),
        }])
        checked, n_missing, missing, deferred = rev.validate(
            feed, self.repo, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(checked, 0)
        self.assertEqual(n_missing, 0)
        self.assertEqual(deferred, [])


class TestPresentReportsUnaffected(_ChdirFixture):
    def test_present_report_is_not_missing_or_deferred(self):
        self._write_report("/reports/2026/09/intel--present.html")
        feed = self._write_feed("feed.json", [{
            "id": "intel--present",
            "report_url": "/reports/2026/09/intel--present.html",
            "processed_at": _iso(self.now - timedelta(hours=1)),
        }])
        checked, n_missing, missing, deferred = rev.validate(
            feed, self.repo, now=self.now, window_hours=24, published_ids=set(),
        )
        self.assertEqual(checked, 1)
        self.assertEqual(n_missing, 0)
        self.assertEqual(deferred, [])


class TestMainEndToEnd(_ChdirFixture):
    """Reproduces run #2249's STAGE 5.4.1 shape at the main()/exit-code
    level: a manifest overwhelmingly made of out-of-window, locally-missing
    legacy advisories must no longer hard-fail this gate."""

    def test_manifest_of_only_legacy_out_of_window_items_exits_zero(self):
        advisories = [
            {
                "id": f"intel--legacy{i}",
                "report_url": f"/reports/2026/06/intel--legacy{i}.html",
                "processed_at": _iso(datetime.now(timezone.utc) - timedelta(days=60)),
            }
            for i in range(50)
        ]
        self._write_feed("api/feed.json", advisories)
        with patch.object(rev, "REPO_ROOT", self.repo), \
             patch.object(rev, "load_publish_state", return_value={"items": {}}), \
             patch.object(sys, "argv", ["report_existence_validator.py"]):
            exit_code = rev.main()
        self.assertEqual(
            exit_code, 0,
            "A manifest made entirely of out-of-window legacy advisories with "
            "no local report files must exit 0 (deferred, not failed) -- this "
            "is the exact shape of run #2249's confirmed STAGE 5.4.1 failure.",
        )

    def test_one_in_window_missing_report_still_blocks_the_gate(self):
        advisories = [
            {
                "id": "intel--legacy0",
                "report_url": "/reports/2026/06/intel--legacy0.html",
                "processed_at": _iso(datetime.now(timezone.utc) - timedelta(days=60)),
            },
            {
                "id": "intel--freshmissing",
                "report_url": "/reports/2026/09/intel--freshmissing.html",
                "processed_at": _iso(datetime.now(timezone.utc) - timedelta(hours=1)),
            },
        ]
        self._write_feed("api/feed.json", advisories)
        with patch.object(rev, "REPO_ROOT", self.repo), \
             patch.object(rev, "load_publish_state", return_value={"items": {}}), \
             patch.object(sys, "argv", ["report_existence_validator.py"]):
            exit_code = rev.main()
        self.assertEqual(
            exit_code, 1,
            "A genuinely missing IN-WINDOW report must still hard-fail this "
            "gate -- deferral must never mask a real regression in this run's "
            "own report generation.",
        )


if __name__ == "__main__":
    unittest.main()
