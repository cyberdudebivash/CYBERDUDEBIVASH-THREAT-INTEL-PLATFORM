"""
tests/test_report_url_canary_window_deferral.py

P0 regression coverage for scripts/report_url_canary.py's --local gate
(STAGE 5.8.1b) root-cause fix.

CONFIRMED PRODUCTION FAILURE: sentinel-apex.yml run #2250 -- the same
natural production run whose STAGE 3.3 and STAGE 5.4.1 gates both passed
cleanly for the first time (after PRs #375/#376 fixed the identical
architectural mismatch in scripts/validate_reports.py and
scripts/report_existence_validator.py), and which then went on to succeed
at STAGE 5 (Deploy to GitHub Pages) -- progressed one stage further and
hard-failed at STAGE 5.8.1b instead:
  "LOCAL GATE: 214 ok / 184 missing / 0 invalid (of 398)"
  "P0 FAIL-CLOSED: 184 report_url(s) would publish without a valid artifact."

This is the exact same rolling-window mismatch already fixed twice in this
codebase, in a THIRD, previously-unfixed sibling gate: PR #369 bounded
report (re)generation to a rolling REPORT_WINDOW_HOURS window, and reports/
is gitignored (never persisted across CI runs), so a fresh runner has zero
local file for a CURRENT-feed report_url whose id was rendered/published in
an earlier run and is still legitimately current (in-window, or already
durably published to R2 per r2_report_publisher.py's own state) but wasn't
re-rendered THIS run.

These tests reproduce that scenario at both the local_artifact_check() unit
level and the --local main() end-to-end level, and prove: a genuinely
missing IN-WINDOW report still hard-fails (the gate's real safety
guarantee -- catching a report this run was actually responsible for
producing but didn't), while an out-of-window or confirmed-durably-
published missing report is deferred, not failed. A body-invalid
(soft-404) artifact is never deferred regardless of age, and a report_url
with no recoverable item metadata (deployment_manifest.json fallback path)
is conservatively never deferred either.

Tests use only local temp files -- no real R2/network access.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import report_url_canary as canary  # noqa: E402

_PADDING = "x" * 600  # keeps bodies >= MIN_REPORT_BYTES (512)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


class _TempTreeFixture(unittest.TestCase):
    """Points canary's module-level path constants at a throwaway tree so
    tests never touch the real repository's reports/ or api/feed.json."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmpdir.name)
        self.now = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
        self._patches = [
            patch.object(canary, "REPO_ROOT", self.repo),
            patch.object(canary, "REPORTS_DIR", self.repo / "reports"),
            patch.object(canary, "DIST_REPORTS_DIR", self.repo / "dist" / "reports"),
            patch.object(canary, "FEED_PATHS", [self.repo / "api" / "feed.json", self.repo / "feed.json"]),
            patch.object(canary, "MANIFEST_PATH", self.repo / "dist" / "deployment_manifest.json"),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmpdir.cleanup()

    def _write_report(self, rel_path: str, body: str = None) -> None:
        p = self.repo / rel_path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body or f"<!doctype html>\n<html><body>{_PADDING}</body></html>", encoding="utf-8")

    def _write_feed(self, advisories: list) -> None:
        p = self.repo / "api" / "feed.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(advisories), encoding="utf-8")


class TestInWindowMissingStillFails(_TempTreeFixture):
    """The gate's real safety guarantee is preserved: a report this run was
    actually responsible for producing, but didn't, must still hard-fail."""

    def test_in_window_missing_report_hard_fails(self):
        path_to_item = canary.build_path_to_item([{
            "id": "intel--freshmissing",
            "report_url": "/reports/2026/09/intel--freshmissing.html",
            "processed_at": _iso(self.now - timedelta(hours=1)),
        }])
        with self.assertLogs(canary.log, level="ERROR") as cm:
            exit_code = canary.local_artifact_check(
                ["/reports/2026/09/intel--freshmissing.html"],
                path_to_item, self.now, 24, set(),
            )
        self.assertEqual(exit_code, 1)
        self.assertTrue(any("[MISSING]" in m for m in cm.output))


class TestOutOfWindowMissingIsDeferredNotFailed(_TempTreeFixture):
    """Reproduces the exact production defect: run #2250's STAGE 5.8.1b
    failure, caused by historical, out-of-window (or already-published)
    current-feed entries with no local file on a fresh CI runner."""

    def test_out_of_window_missing_report_is_deferred(self):
        path_to_item = canary.build_path_to_item([{
            "id": "intel--legacyitem",
            "report_url": "/reports/2026/06/intel--legacyitem.html",
            "processed_at": _iso(self.now - timedelta(days=60)),
        }])
        with self.assertLogs(canary.log, level="INFO") as cm:
            exit_code = canary.local_artifact_check(
                ["/reports/2026/06/intel--legacyitem.html"],
                path_to_item, self.now, 24, set(),
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(any("[DEFERRED:out-of-window]" in m for m in cm.output))

    def test_unparseable_timestamp_missing_report_is_deferred_not_assumed_fresh(self):
        path_to_item = canary.build_path_to_item([{
            "id": "intel--badtimestamp",
            "report_url": "/reports/2026/09/intel--badtimestamp.html",
            "processed_at": "not-a-real-timestamp",
        }])
        exit_code = canary.local_artifact_check(
            ["/reports/2026/09/intel--badtimestamp.html"],
            path_to_item, self.now, 24, set(),
        )
        self.assertEqual(exit_code, 0)

    def test_confirmed_published_via_r2_state_is_deferred_regardless_of_age(self):
        path_to_item = canary.build_path_to_item([{
            "id": "intel--confirmedpub",
            "report_url": "/reports/2026/01/intel--confirmedpub.html",
            "processed_at": _iso(self.now - timedelta(days=200)),
        }])
        with self.assertLogs(canary.log, level="INFO") as cm:
            exit_code = canary.local_artifact_check(
                ["/reports/2026/01/intel--confirmedpub.html"],
                path_to_item, self.now, 24, {"intel--confirmedpub"},
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(any("[DEFERRED:published]" in m for m in cm.output))

    def test_path_with_no_item_metadata_is_never_deferred(self):
        """A report_url sourced from the deployment_manifest.json fallback
        (no matching feed item) carries no id/timestamp to defer with, so it
        must fail closed exactly like before this fix."""
        with self.assertLogs(canary.log, level="ERROR") as cm:
            exit_code = canary.local_artifact_check(
                ["/reports/2026/06/intel--nometadata.html"], {}, self.now, 24, set(),
            )
        self.assertEqual(exit_code, 1)
        self.assertTrue(any("[MISSING]" in m for m in cm.output))


class TestInvalidBodyNeverDeferred(_TempTreeFixture):
    """Deferral narrows the 'no local file' case only -- a soft-404 body on
    an artifact that DOES exist is a real defect regardless of age."""

    def test_soft_404_body_out_of_window_still_fails(self):
        self._write_report(
            "/reports/2026/06/intel--soft404.html",
            body="<html>report_not_found" + _PADDING + "</html>",
        )
        path_to_item = canary.build_path_to_item([{
            "id": "intel--soft404",
            "report_url": "/reports/2026/06/intel--soft404.html",
            "processed_at": _iso(self.now - timedelta(days=60)),
        }])
        exit_code = canary.local_artifact_check(
            ["/reports/2026/06/intel--soft404.html"],
            path_to_item, self.now, 24, set(),
        )
        self.assertEqual(exit_code, 1)


class TestPresentReportsUnaffected(_TempTreeFixture):
    def test_present_in_window_report_passes(self):
        self._write_report("/reports/2026/09/intel--present.html")
        path_to_item = canary.build_path_to_item([{
            "id": "intel--present",
            "report_url": "/reports/2026/09/intel--present.html",
            "processed_at": _iso(self.now - timedelta(hours=1)),
        }])
        exit_code = canary.local_artifact_check(
            ["/reports/2026/09/intel--present.html"],
            path_to_item, self.now, 24, set(),
        )
        self.assertEqual(exit_code, 0)

    def test_present_report_found_in_dist_reports_fallback(self):
        p = self.repo / "dist" / "reports" / "2026" / "09" / "intel--distonly.html"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"<!doctype html>\n<html><body>{_PADDING}</body></html>", encoding="utf-8")
        path_to_item = canary.build_path_to_item([{
            "id": "intel--distonly",
            "report_url": "/reports/2026/09/intel--distonly.html",
            "processed_at": _iso(self.now - timedelta(hours=1)),
        }])
        exit_code = canary.local_artifact_check(
            ["/reports/2026/09/intel--distonly.html"],
            path_to_item, self.now, 24, set(),
        )
        self.assertEqual(exit_code, 0)


class TestMainLocalEndToEnd(_TempTreeFixture):
    """Reproduces run #2250's STAGE 5.8.1b shape at the --local main()/
    exit-code level: a feed overwhelmingly made of out-of-window,
    locally-missing legacy entries must no longer hard-fail this gate."""

    def test_feed_of_only_legacy_out_of_window_items_exits_zero(self):
        advisories = [
            {
                "id": f"intel--legacy{i}",
                "report_url": f"/reports/2026/06/intel--legacy{i}.html",
                "processed_at": _iso(datetime.now(timezone.utc) - timedelta(days=60)),
            }
            for i in range(50)
        ]
        self._write_feed(advisories)
        with patch.object(canary, "load_publish_state", return_value={"items": {}}), \
             patch.object(sys, "argv", ["report_url_canary.py", "--local"]):
            exit_code = canary.main()
        self.assertEqual(
            exit_code, 0,
            "A feed made entirely of out-of-window legacy report_url entries with "
            "no local report files must exit 0 (deferred, not failed) -- this is "
            "the exact shape of run #2250's confirmed STAGE 5.8.1b failure.",
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
        self._write_feed(advisories)
        with patch.object(canary, "load_publish_state", return_value={"items": {}}), \
             patch.object(sys, "argv", ["report_url_canary.py", "--local"]):
            exit_code = canary.main()
        self.assertEqual(
            exit_code, 1,
            "A genuinely missing IN-WINDOW report must still hard-fail this gate -- "
            "deferral must never mask a real regression in this run's own report "
            "generation.",
        )


if __name__ == "__main__":
    unittest.main()
