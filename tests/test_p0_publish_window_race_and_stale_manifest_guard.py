#!/usr/bin/env python3
"""
tests/test_p0_publish_window_race_and_stale_manifest_guard.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- regression guards for two production
defects confirmed on sentinel-blogger run 35867879014 (2026-09-23).

1. STAGE 3.3 WINDOW RACE
   generate_intel_reports.py (13:58:05Z) excluded 2 items as outside the
   24h window; validate_reports.py (STAGE 3.3, 14:02:47Z) then classified
   the same items as inside it and hard-failed the run on missing report
   files. Both evaluate `age = now - canonical_ts` against their OWN now();
   a timestamp in (T_render, T_verify] is future-dated for the renderer and
   current for the verifier. Producers (renderer + publisher) now accept a
   bounded future skew; verifiers stay strict, so a verifier's window is
   always a subset of what was rendered.

2. STALE-MANIFEST ROLLBACK
   The same run's STAGE 4.1 (r2_resync_manifests.py) uploaded the stale
   git-checkout api/v1/intel/latest.json (generated_at 2026-08-26, 109
   items) over the fresh 273-item object the previous run published,
   rolling every customer feed endpoint back four weeks. Manifests whose
   generated_at is provably old are now never uploaded.
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import generate_intel_reports as gen  # noqa: E402
import r2_report_publisher as pub  # noqa: E402
import r2_resync_manifests as resync  # noqa: E402
import r2_upload  # noqa: E402


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _strict_verifier_in_window(item: dict, now: datetime, window_hours: int = 24) -> bool:
    """Exactly the predicate validate_reports.py (STAGE 3.3) applies before
    it hard-fails a missing report: canonical_age() + strict 0 <= age <= W."""
    _ts, age = pub.canonical_age(item, now)
    return age is not None and 0 <= age <= window_hours


class TestWindowRace(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ, {}, clear=False)
        self._env.start()
        os.environ.pop("REPORT_FUTURE_SKEW_HOURS", None)
        self.t_render = datetime(2026, 9, 23, 13, 58, 5, tzinfo=timezone.utc)
        self.t_verify = datetime(2026, 9, 23, 14, 2, 47, tzinfo=timezone.utc)

    def tearDown(self):
        self._env.stop()

    def test_incident_reproduction_verifier_window_is_subset_of_render_window(self):
        """The exact 2026-09-23 interleaving: timestamp between render and
        verify. Before the fix the renderer excluded it and STAGE 3.3 failed."""
        item = {"id": "intel--race", "timestamp": "2026-09-23T14:00:00Z"}
        self.assertTrue(_strict_verifier_in_window(item, self.t_verify))
        self.assertTrue(gen._within_report_window(item, 24.0, self.t_render),
                        "renderer must render anything a later strict verifier will require")
        self.assertEqual(len(pub.build_publish_candidates([item], 24, self.t_render)), 1,
                         "publisher must accept anything the renderer rendered")

    def test_subset_holds_across_whole_job_duration(self):
        """For every timestamp a strict verifier would require at any point
        up to the 130-minute job timeout after rendering, the renderer at
        T_render must have included it."""
        for verify_delay_min in (0, 5, 30, 60, 129):
            t_verify = self.t_render + timedelta(minutes=verify_delay_min)
            for offset_min in range(-24 * 60, verify_delay_min + 1, 7):
                item = {"id": "x", "timestamp": _iso(self.t_render + timedelta(minutes=offset_min))}
                if _strict_verifier_in_window(item, t_verify):
                    self.assertTrue(
                        gen._within_report_window(item, 24.0, self.t_render),
                        f"verify +{verify_delay_min}m requires ts offset {offset_min}m but renderer excluded it",
                    )

    def test_far_future_timestamp_still_excluded(self):
        item = {"id": "intel--2099", "timestamp": "2099-01-01T00:00:00Z"}
        self.assertFalse(gen._within_report_window(item, 24.0, self.t_render))
        self.assertEqual(pub.build_publish_candidates([item], 24, self.t_render), [])

    def test_beyond_tolerance_excluded_within_tolerance_included(self):
        inside = {"id": "a", "timestamp": _iso(self.t_render + timedelta(hours=2, minutes=59))}
        outside = {"id": "b", "timestamp": _iso(self.t_render + timedelta(hours=3, minutes=1))}
        self.assertTrue(gen._within_report_window(inside, 24.0, self.t_render))
        self.assertFalse(gen._within_report_window(outside, 24.0, self.t_render))

    def test_upper_bound_unchanged(self):
        stale = {"id": "old", "timestamp": _iso(self.t_render - timedelta(hours=24, seconds=5))}
        self.assertFalse(gen._within_report_window(stale, 24.0, self.t_render))

    def test_unbounded_mode_unchanged(self):
        self.assertTrue(gen._within_report_window({"id": "x"}, None, self.t_render))

    def test_missing_timestamp_still_fail_safe(self):
        self.assertFalse(gen._within_report_window({"id": "x"}, 24.0, self.t_render))

    def test_env_override_and_invalid_values(self):
        with mock.patch.dict(os.environ, {"REPORT_FUTURE_SKEW_HOURS": "0"}):
            self.assertEqual(gen.report_future_skew_hours(), 0.0)
            future = {"id": "f", "timestamp": _iso(self.t_render + timedelta(minutes=1))}
            self.assertFalse(gen._within_report_window(future, 24.0, self.t_render))
        for bad in ("abc", "-1"):
            with mock.patch.dict(os.environ, {"REPORT_FUTURE_SKEW_HOURS": bad}):
                self.assertEqual(gen.report_future_skew_hours(), gen.DEFAULT_REPORT_FUTURE_SKEW_HOURS)

    def test_verifiers_remain_strict(self):
        """Tolerance is producer-only: STAGE 3.3 must never start requiring
        (or excusing) future-dated reports."""
        future = {"id": "f", "timestamp": _iso(self.t_verify + timedelta(minutes=10))}
        self.assertFalse(_strict_verifier_in_window(future, self.t_verify))


class TestStaleManifestGuard(unittest.TestCase):
    NOW = datetime(2026, 9, 23, 14, 7, 28, tzinfo=timezone.utc)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        os.environ.pop("MAX_PUBLIC_MANIFEST_AGE_HOURS", None)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel: str, payload) -> Path:
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    def test_incident_git_checkout_copy_is_refused(self):
        p = self._write("latest.json", {"generated_at": "2026-08-26T09:55:27Z", "count": 109, "items": []})
        reason = r2_upload.stale_manifest_reason(p, now=self.NOW)
        self.assertIsNotNone(reason)
        self.assertIn("2026-08-26T09:55:27Z", reason)

    def test_fresh_manifest_allowed(self):
        p = self._write("latest.json", {"generated_at": _iso(self.NOW - timedelta(minutes=40)), "items": []})
        self.assertIsNone(r2_upload.stale_manifest_reason(p, now=self.NOW))

    def test_non_provable_cases_keep_existing_behaviour(self):
        cases = {
            "list.json": [{"id": "a"}],
            "nostamp.json": {"items": []},
            "badstamp.json": {"generated_at": "not-a-date"},
        }
        for name, payload in cases.items():
            self.assertIsNone(r2_upload.stale_manifest_reason(self._write(name, payload), now=self.NOW), name)
        broken = self.dir / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        self.assertIsNone(r2_upload.stale_manifest_reason(broken, now=self.NOW))

    def test_age_limit_env_override(self):
        p = self._write("m.json", {"generated_at": _iso(self.NOW - timedelta(hours=2))})
        with mock.patch.dict(os.environ, {"MAX_PUBLIC_MANIFEST_AGE_HOURS": "1"}):
            self.assertIsNotNone(r2_upload.stale_manifest_reason(p, now=self.NOW))
        with mock.patch.dict(os.environ, {"MAX_PUBLIC_MANIFEST_AGE_HOURS": "junk"}):
            self.assertIsNone(r2_upload.stale_manifest_reason(p, now=self.NOW))

    def test_default_limit_exceeds_job_timeout(self):
        self.assertGreater(r2_upload.DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS * 60, 130)

    def _run_resync(self, files: dict) -> list[str]:
        for rel, payload in files.items():
            self._write(rel, payload)
        uploaded: list[str] = []

        def fake_cp(src, bucket, key, endpoint, cache_control="x"):
            uploaded.append(key)
            return True

        env = {"CF_ACCOUNT_ID": "acct", "AWS_ACCESS_KEY_ID": "k", "AWS_SECRET_ACCESS_KEY": "s"}
        with mock.patch.object(resync, "REPO_ROOT", self.dir), \
             mock.patch.object(resync, "s3_cp", side_effect=fake_cp), \
             mock.patch.dict(os.environ, env), \
             mock.patch("os.chdir"):
            with self.assertRaises(SystemExit) as ctx:
                resync.main()
        self.assertEqual(ctx.exception.code, 0)
        return uploaded

    def test_stage_4_1_after_failed_run_does_not_roll_back_r2(self):
        """Run 35867879014: STAGE 3.93 skipped -> only the git checkout is on
        disk. STAGE 4.1 must upload the run's own fresh feed, never the stale
        manifests."""
        fresh = _iso(datetime.now(timezone.utc) - timedelta(minutes=5))
        uploaded = self._run_resync({
            "api/feed.json": [{"id": "fresh-1"}],
            "api/v1/intel/latest.json": {"generated_at": "2026-08-26T09:55:27Z", "items": []},
            "api/v1/intel/apex.json": {"generated_at": "2026-08-26T09:55:27Z", "items": []},
            "api/v1/intel/top10.json": {"generated_at": fresh, "items": []},
        })
        self.assertIn("api/feed.json", uploaded)
        self.assertIn("api/v1/intel/top10.json", uploaded)
        self.assertNotIn("api/v1/intel/latest.json", uploaded)
        self.assertNotIn("api/v1/intel/apex.json", uploaded)

    def test_stage_3_5_plan_excludes_stale_intel_manifests(self):
        fresh = _iso(datetime.now(timezone.utc) - timedelta(minutes=5))
        self._write("api/v1/intel/latest.json", {"generated_at": "2026-08-26T09:55:27Z"})
        self._write("api/v1/intel/latest_pro.json", {"generated_at": "2026-08-26T09:55:27Z"})
        self._write("api/reports/index.json", {"generated_at": fresh, "reports": []})
        with mock.patch.object(r2_upload, "REPO_ROOT", self.dir):
            keys = {dst for _src, dst in r2_upload.build_upload_plan()}
        self.assertNotIn("api/v1/intel/latest.json", keys)
        self.assertNotIn("api/v1/intel/latest_pro.json", keys)
        self.assertIn("api/reports/index.json", keys)

    def test_resync_logger_prefix_preserved(self):
        """Importing r2_upload must not hijack r2_resync's log format."""
        self.assertEqual(resync.log.name, "sentinel.r2_resync")


if __name__ == "__main__":
    unittest.main()
