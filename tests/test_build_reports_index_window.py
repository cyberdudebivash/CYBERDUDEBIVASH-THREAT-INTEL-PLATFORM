#!/usr/bin/env python3
"""
tests/test_build_reports_index_window.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- P0 R2 Cost Incident: dashboard report
index 24h-window regression guard. See docs/P0_R2_COST_CONTAINMENT.md.

scripts/build_reports_index.py used to sort/include reports by filesystem
mtime -- unreliable in this repo (bulk-seeded history, reset on fresh
checkouts; see scripts/report_archive_manager.py's own documented finding
of the same problem). It now uses each report's CANONICAL intelligence
timestamp (via its api/feed.json entry), bounded to the rolling
REPORT_WINDOW_HOURS window. These tests lock in:
  1. A report whose feed item is >24h old is excluded from the index.
  2. A report whose feed item is <24h old is included.
  3. A report with no feed_map match at all is excluded (fail safe --
     cannot prove it belongs in the hot window).
  4. index.json/latest.json/stats.json are ALWAYS written, even when the
     window is genuinely empty, with an explicit empty_state_message
     (never omitted, never silently stale).
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_reports_index as bri  # noqa: E402


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class _IsolatedRepoTestCase(unittest.TestCase):
    """Monkey-patches build_reports_index's module-level path constants to
    a throwaway temp directory for the duration of the test, so main() can
    be called directly (no subprocess overhead) without ever touching this
    repo's real reports/ or api/reports/ files."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self._orig = (bri.REPORTS_ROOT, bri.API_FEED, bri.API_REPORTS)
        bri.REPORTS_ROOT = root / "reports"
        bri.API_FEED = root / "api" / "feed.json"
        bri.API_REPORTS = root / "api" / "reports"
        bri.REPORTS_ROOT.mkdir(parents=True)
        bri.API_FEED.parent.mkdir(parents=True)

    def tearDown(self):
        bri.REPORTS_ROOT, bri.API_FEED, bri.API_REPORTS = self._orig
        self._tmp.cleanup()

    def _write_feed(self, items: list[dict]) -> None:
        bri.API_FEED.write_text(json.dumps(items))

    def _write_report(self, item_id: str, year: str, month: str, size_padding: int = 600) -> None:
        d = bri.REPORTS_ROOT / year / month
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{item_id}.html").write_text("<html>" + ("x" * size_padding) + "</html>")


class TestEndToEndIndexBuild(_IsolatedRepoTestCase):
    def test_report_older_than_window_excluded(self):
        now = datetime.now(timezone.utc)
        old_id = "intel--bri-old0001"
        self._write_feed([{"id": old_id, "timestamp": _iso(now - timedelta(hours=48))}])
        self._write_report(old_id, "2026", "01")

        rc = bri.main()
        self.assertEqual(rc, 0)
        index = json.loads((bri.API_REPORTS / "index.json").read_text())
        self.assertEqual(index["reports"], [])
        self.assertEqual(index["total_reports"], 0)
        self.assertIn("empty_state_message", index)

    def test_report_within_window_included(self):
        now = datetime.now(timezone.utc)
        fresh_id = "intel--bri-fresh0001"
        self._write_feed([{"id": fresh_id, "timestamp": _iso(now - timedelta(hours=2)), "title": "Fresh One", "severity": "HIGH"}])
        self._write_report(fresh_id, now.strftime("%Y"), now.strftime("%m"))

        rc = bri.main()
        self.assertEqual(rc, 0)
        index = json.loads((bri.API_REPORTS / "index.json").read_text())
        self.assertEqual(len(index["reports"]), 1)
        self.assertEqual(index["reports"][0]["id"], fresh_id)
        self.assertNotIn("empty_state_message", index)

    def test_report_with_no_feed_match_excluded_fail_safe(self):
        """A file on disk whose id has no api/feed.json entry at all cannot
        have its age proven -- must be excluded, never included via a
        mtime or other fallback."""
        now = datetime.now(timezone.utc)
        orphan_id = "intel--bri-orphan0001"
        self._write_feed([])  # empty feed -- orphan_id has no match
        self._write_report(orphan_id, now.strftime("%Y"), now.strftime("%m"))

        rc = bri.main()
        self.assertEqual(rc, 0)
        index = json.loads((bri.API_REPORTS / "index.json").read_text())
        self.assertEqual(index["reports"], [])

    def test_mixed_batch_only_fresh_included(self):
        now = datetime.now(timezone.utc)
        fresh_id = "intel--bri-mix-fresh"
        old_id = "intel--bri-mix-old"
        self._write_feed([
            {"id": fresh_id, "timestamp": _iso(now - timedelta(hours=1)), "title": "Fresh"},
            {"id": old_id, "timestamp": _iso(now - timedelta(days=90)), "title": "Old"},
        ])
        self._write_report(fresh_id, now.strftime("%Y"), now.strftime("%m"))
        self._write_report(old_id, "2020", "01")

        rc = bri.main()
        self.assertEqual(rc, 0)
        index = json.loads((bri.API_REPORTS / "index.json").read_text())
        ids = {r["id"] for r in index["reports"]}
        self.assertEqual(ids, {fresh_id})

    def test_cross_month_report_is_withheld_from_all_catalog_artifacts(self):
        """A fresh feed timestamp cannot authorize an older-month report path."""
        now = datetime.now(timezone.utc)
        ts = now - timedelta(minutes=2)
        wrong_month = (ts.replace(day=1) - timedelta(days=1))
        report_id = "intel--aabbccddeeff0011"
        self._write_report(report_id, wrong_month.strftime("%Y"),
                           wrong_month.strftime("%m"))
        self._write_feed([{"id": report_id, "timestamp": _iso(ts),
                           "title": "Cross-month record"}])
        self.assertEqual(bri.main(), 0)
        for name in ("index.json", "latest.json"):
            payload = json.loads((bri.API_REPORTS / name).read_text())
            self.assertEqual(payload["reports"], [])
            self.assertEqual(payload["total_reports"], 0)
        stats = json.loads((bri.API_REPORTS / "stats.json").read_text())
        self.assertEqual(stats["total_reports"], 0)

    def test_valid_and_mismatched_months_preserve_valid_catalog(self):
        """Never silently relabel the invalid report or drop valid siblings."""
        now = datetime.now(timezone.utc)
        ts = now - timedelta(minutes=2)
        wrong_month = ts.replace(day=1) - timedelta(days=1)
        good = "intel--1122334455667788"
        bad = "intel--8899aabbccddeeff"
        self._write_report(good, ts.strftime("%Y"), ts.strftime("%m"))
        self._write_report(bad, wrong_month.strftime("%Y"),
                           wrong_month.strftime("%m"))
        self._write_feed([
            {"id": good, "timestamp": _iso(ts), "severity": "HIGH"},
            {"id": bad, "timestamp": _iso(ts), "severity": "HIGH"},
        ])
        self.assertEqual(bri.main(), 0)
        index = json.loads((bri.API_REPORTS / "index.json").read_text())
        latest = json.loads((bri.API_REPORTS / "latest.json").read_text())
        stats = json.loads((bri.API_REPORTS / "stats.json").read_text())
        self.assertEqual([r["id"] for r in index["reports"]], [good])
        self.assertEqual(latest["reports"], index["reports"])
        self.assertEqual(index["total_reports"], 1)
        self.assertEqual(stats["total_reports"], 1)
        self.assertEqual(stats["by_severity"]["HIGH"], 1)

    def test_empty_window_writes_valid_json_all_three_files_with_message(self):
        """No reports at all -- must still write valid, non-omitted
        index.json / latest.json / stats.json, each carrying the exact
        required empty-state message, never a 404/missing file and never a
        stale historical list shown to paper over the empty state."""
        bri.API_FEED.write_text(json.dumps([]))
        rc = bri.main()
        self.assertEqual(rc, 0)
        for fname in ("index.json", "latest.json", "stats.json"):
            payload = json.loads((bri.API_REPORTS / fname).read_text())
            self.assertEqual(payload.get("total_reports"), 0)
            self.assertEqual(payload.get("empty_state_message"),
                              "No intelligence reports generated during the last 24 hours.")

    def test_window_hours_field_present_and_matches_env(self):
        import os
        old_env = os.environ.get("REPORT_WINDOW_HOURS")
        os.environ["REPORT_WINDOW_HOURS"] = "24"
        try:
            import importlib
            importlib.reload(bri)
            # re-apply isolation after reload (reload resets module globals)
            root = Path(self._tmp.name)
            bri.REPORTS_ROOT = root / "reports"
            bri.API_FEED = root / "api" / "feed.json"
            bri.API_REPORTS = root / "api" / "reports"
            bri.API_FEED.write_text(json.dumps([]))
            rc = bri.main()
            self.assertEqual(rc, 0)
            index = json.loads((bri.API_REPORTS / "index.json").read_text())
            self.assertEqual(index["window_hours"], 24.0)
        finally:
            if old_env is None:
                os.environ.pop("REPORT_WINDOW_HOURS", None)
            else:
                os.environ["REPORT_WINDOW_HOURS"] = old_env
            importlib.reload(bri)


if __name__ == "__main__":
    unittest.main()
