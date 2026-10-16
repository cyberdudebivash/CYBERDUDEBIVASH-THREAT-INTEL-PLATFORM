"""
tests/test_r2_state_sync.py

Regression tests for scripts/r2_state_sync.py, the P0 fix that moves
data/cache/feed_state.json, data/processed_intel.json and
data/stix/feed_manifest.json from a direct `git push origin main` (rejected
on every run since main started requiring PRs -- see
tests/test_git_publish_no_silent_push_failure.py) onto Cloudflare R2 as the
cross-run, cross-workflow authority, matching the pattern already reviewed
and approved for issue #274 / PR #293.

These tests mock subprocess.run (the underlying `aws s3 cp` invocation) so
they exercise the real download()/upload()/s3_get() code paths without any
network access or real R2 credentials. time.sleep is also mocked -- the
retry-exhaustion tests would otherwise take 90-150 real seconds each.
"""
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import r2_state_sync as rs  # noqa: E402
import r2_upload  # noqa: E402
import r2_report_publisher as rrp  # noqa: E402


def _proc(returncode=0, stdout="", stderr=""):
    p = MagicMock()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


def _parse_cp_cmd(cmd):
    """Both s3_get (download) and s3_cp (upload) build an
    ["aws", "s3", "cp", <src>, <dst>, ...] command -- the only way to tell
    them apart is which of <src>/<dst> (cmd[3]/cmd[4]) starts with "s3://".
    Returns (is_download, local_path, r2_key)."""
    if cmd[3].startswith("s3://"):
        s3_url, local_path = cmd[3], cmd[4]
        is_download = True
    else:
        local_path, s3_url = cmd[3], cmd[4]
        is_download = False
    r2_key = s3_url.split("/", 3)[-1]  # strip "s3://<bucket>/"
    return is_download, local_path, r2_key


class TestS3GetOutcomeClassification(unittest.TestCase):
    """s3_get() must distinguish OK / NOT_FOUND / ERROR -- callers rely on
    this three-way split to know when it's safe to bootstrap vs. when it
    must hard-fail."""

    def test_success_returns_ok(self):
        with patch.object(r2_upload.subprocess, "run", return_value=_proc(0)):
            self.assertEqual(r2_upload.s3_get("/tmp/x.json", "b", "k", "https://e"), "OK")

    def test_404_in_stderr_returns_not_found(self):
        with patch.object(r2_upload.subprocess, "run",
                           return_value=_proc(1, stderr="fatal error: An error occurred (404) when calling the HeadObject operation: Not Found")):
            self.assertEqual(r2_upload.s3_get("/tmp/x.json", "b", "k", "https://e"), "NOT_FOUND")

    def test_nosuchkey_returns_not_found(self):
        with patch.object(r2_upload.subprocess, "run",
                           return_value=_proc(1, stderr="An error occurred (NoSuchKey) when calling the GetObject operation")):
            self.assertEqual(r2_upload.s3_get("/tmp/x.json", "b", "k", "https://e"), "NOT_FOUND")

    def test_auth_failure_returns_error_not_not_found(self):
        with patch.object(r2_upload.subprocess, "run",
                           return_value=_proc(1, stderr="An error occurred (InvalidAccessKeyId) when calling the HeadObject operation")):
            self.assertEqual(r2_upload.s3_get("/tmp/x.json", "b", "k", "https://e"), "ERROR")

    def test_network_timeout_returns_error(self):
        with patch.object(r2_upload.subprocess, "run",
                           return_value=_proc(1, stderr="Connection timed out")):
            self.assertEqual(r2_upload.s3_get("/tmp/x.json", "b", "k", "https://e"), "ERROR")

    def test_nosuchbucket_returns_error_not_not_found(self):
        """CodeRabbit review finding (verified, not taken on faith): AWS's
        actual NoSuchBucket message is "An error occurred (NoSuchBucket)
        when calling the HeadObject operation: The specified bucket does
        not exist" -- which contains "does not exist", one of the generic
        NOT_FOUND substrings this function already matched on. A wrong or
        misconfigured bucket name would have been silently misclassified as
        "this object simply hasn't been created yet" and treated as a safe
        bootstrap case instead of the configuration error it actually is."""
        with patch.object(r2_upload.subprocess, "run",
                           return_value=_proc(1, stderr="An error occurred (NoSuchBucket) when calling the HeadObject operation: The specified bucket does not exist")):
            self.assertEqual(r2_upload.s3_get("/tmp/x.json", "b", "k", "https://e"), "ERROR")


class TestStateFilesManifest(unittest.TestCase):
    """STATE_FILES is the single source of truth other tests (download/
    upload/wiring) drive off of via len()/iteration -- these tests pin its
    actual expected contents directly, so a future accidental removal of an
    entry doesn't silently pass just because the generic tests adapted to
    the shorter list."""

    def test_exactly_twenty_three_files_migrated(self):
        """P0 R2 COST AUDIT FIX: was 9 -- data/cache/r2_report_publish_state.json
        (scripts/r2_report_publisher.py's own cross-run incremental-publish
        state) was added after a post-merge forensic audit of PR #369 found
        it was never staged anywhere in safe_git_commit.py, so it silently
        reverted to empty on every fresh CI checkout -- same git-push-
        rejection root cause this module's docstring documents for the
        other 9 entries, fixed the same way rather than re-attempting
        git-based persistence for this file too.

        Was 10 -- P0 production-architecture-transformation mission
        (2026-09-08): data/cache/intel_index.json (intel_dedup_engine.py's
        dedup primary index, sibling to feed_state.json, same atomic write
        contract and same "committed to git, persists forever" assumption
        that caused the 2026-08-26 staleness incident) had NO persistence
        path at all -- not git-staged (safe_git_commit.py never listed it),
        not R2-synced. Added as the 11th entry rather than left with zero
        durability.

        Was 11 -- post-merge verification of PR #388/#389 (2026-09-09) found
        the AI plane persisting through ai-predictions.yml's `git push origin
        main`, i.e. the same rejected-since-2026-08-26 path this whole module
        exists to replace, with the failure swallowed by that workflow's own
        retry loop. Verified empirically: zero runtime commits on main in that
        window. Four entries added -- sector_history.json (bidirectional
        cross-run state; without it the forecast's 35-observed-day threshold
        is unreachable forever) plus anomalies/forecasts/anomaly_radar, which
        ai_brain_publisher.py consumes from a DIFFERENT workflow and so must
        survive the hand-off. predictions_summary.json and
        apex_forecast_latest.json were deliberately NOT added (no consumer /
        orphaned producer) -- see the rationale block in r2_state_sync.py.

        Was 15 -- P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10):
        genesis-powerhouse.yml and sovereign-platform.yml persisted via
        `git push origin main`, rejected every run since ~2026-08-26 and
        swallowed by `|| echo "... cycle complete"` / a push-retry loop that
        still exits 0. Seven entries added, traced to real consumers by an
        exhaustive producer/consumer pass: nexus_output.json,
        cortex_output.json, quantum_output.json, sovereign_output.json and
        genesis_output.json are exactly index.html's ENGINE_URLS set for
        these five engines (the customer dashboard's current-state read);
        cortex/stream_events.json feeds agent/sdk/cdb_apex_streamer.py;
        genesis/detection_pack.json feeds agent/product_factory/
        detection_pack_builder.py's sellable detection ZIP. Every other
        NEXUS/CORTEX/QUANTUM/SOVEREIGN sub-file was confirmed same-run-only
        (no cross-run or cross-workflow reader) and deliberately NOT added;
        neither was data/sovereign/tenants.json (customer-shaped API-key
        values -- see NEVER_PERSIST_PATHS) nor the billing-adjacent
        mrr_report.json/invoices.json/stripe_config.json (pre-existing,
        out-of-scope duplicate-writer with scripts/stripe_webhook.py).

        This count is a FinOps tripwire, not bookkeeping: every entry costs a
        GET on each download pass and a PUT on each upload pass across four
        workflows. The +4 here was measured at 2,160 Class A + 2,160 Class B
        per month = 0.216% of R2's 1M Class A allowance. The +7 here was
        measured against the exact 2 new call sites (not all four workflows,
        since both new download/upload steps use --only to scope to just
        their own files) at 840 Class A + 240 Class B per month = 0.084% /
        0.0024% of the respective allowances. Any future increase must be
        justified the same way before this number is changed.

        Was 22 -- F26 (2026-10-02): api/feed.baseline.json, the premium
        baseline behind the four Enterprise/MSSP premium feeds, was persisted
        only by STAGE 4's rejected git push, so every publisher run read the
        26 August copy back and the premium feeds served August items. One
        owner-only entry (broad sweeps skip it), downloaded and uploaded with
        --only around sentinel-apex.yml's STAGE 3.1.19. Computed from the
        observed run count (at most 14 publisher runs/day): worst case 1,680
        Class A + 1,260 Class B per month = 0.168% / 0.0126% of R2's
        allowances; no LIST."""
        self.assertEqual(len(rs.STATE_FILES), 23)

    def test_premium_baseline_is_owner_only_under_the_private_prefix(self):
        """F26: the key stays under premium/ (served by no route) and no
        broad sweep may download or re-publish it."""
        self.assertIn(("api/feed.baseline.json", "premium/state/feed.baseline.json"), rs.STATE_FILES)
        self.assertIn("api/feed.baseline.json", rs.BROAD_SWEEP_EXCLUDED_PATHS)

    def test_p0_runtime_intelligence_plane_is_r2_persisted(self):
        """The 5 customer dashboard aggregate files plus the 2 sub-files with
        a real non-dashboard consumer must be R2-persisted, path-mirrored
        keys (this migration's established convention for genuinely new R2
        objects -- see data/stix/feed_manifest.json's own comment for the
        one pre-existing exception)."""
        for entry in (
            ("data/nexus/nexus_output.json", "data/nexus/nexus_output.json"),
            ("data/cortex/cortex_output.json", "data/cortex/cortex_output.json"),
            ("data/cortex/stream_events.json", "data/cortex/stream_events.json"),
            ("data/quantum/quantum_output.json", "data/quantum/quantum_output.json"),
            ("data/sovereign/sovereign_output.json", "data/sovereign/sovereign_output.json"),
            ("data/genesis/genesis_output.json", "data/genesis/genesis_output.json"),
            ("data/genesis/detection_pack.json", "data/genesis/detection_pack.json"),
        ):
            self.assertIn(entry, rs.STATE_FILES)

    def test_sovereign_tenant_secrets_never_added_to_state_files(self):
        """Regression guard for the mission's explicit secret-safety
        requirement: data/sovereign/tenants.json holds customer-shaped
        API-key values (SEC-2026-07-25/2026-08-28 incidents) and must never
        be persisted to R2, no matter how this module's STATE_FILES list is
        edited in the future. This does not depend on remembering to keep
        this test in sync -- r2_state_sync.py's own NEVER_PERSIST_PATHS
        module-level assertion enforces the same invariant at import time."""
        local_paths = [local for local, _ in rs.STATE_FILES]
        self.assertNotIn("data/sovereign/tenants.json", local_paths)
        self.assertIn("data/sovereign/tenants.json", rs.NEVER_PERSIST_PATHS)

    def test_sovereign_billing_state_deliberately_not_added(self):
        """Guards the scope decision above: these are billing-adjacent state
        with a pre-existing, independent duplicate-writer (stripe_webhook.py)
        outside this mission's scope, and are not read by any customer
        intelligence panel this mission targets. Re-adding any of these needs
        a fresh justification, not a casual directory-level sync."""
        local_paths = [local for local, _ in rs.STATE_FILES]
        for f in (
            "data/sovereign/mrr_report.json",
            "data/sovereign/invoices.json",
            "data/sovereign/stripe_config.json",
            "data/sovereign/onboarding_flow.json",
            "data/sovereign/whitelabel_config.json",
            "data/sovereign/soc2_report.json",
            "data/sovereign/nist_csf_report.json",
        ):
            self.assertNotIn(f, local_paths)

    def test_ai_plane_state_is_r2_persisted(self):
        """The AI plane's cross-run state must not regress onto the git path.

        sector_history.json is load-bearing: sector_forecast_model.py needs 35
        observed days before it will publish a forecast, and the store can only
        reach that by accumulating across runs. On the git path it accumulated
        nothing at all, silently."""
        for entry in (
            ("data/ai_predictions/sector_history.json", "data/ai_predictions/sector_history.json"),
            ("data/ai_predictions/anomalies.json", "data/ai_predictions/anomalies.json"),
            ("data/ai_predictions/forecasts.json", "data/ai_predictions/forecasts.json"),
            ("data/ai/anomaly_radar.json", "data/ai/anomaly_radar.json"),
        ):
            self.assertIn(entry, rs.STATE_FILES)

    def test_no_consumerless_ai_artifacts_added(self):
        """Guards the cost decision above: these two were traced to no live
        consumer / an orphaned producer, so syncing them would spend ops for
        nothing. Re-adding either needs a fresh justification."""
        local_paths = [local for local, _ in rs.STATE_FILES]
        self.assertNotIn("data/ai_predictions/predictions_summary.json", local_paths)
        self.assertNotIn("data/ai_predictions/apex_forecast_latest.json", local_paths)

    def test_report_publish_state_is_present_with_path_mirrored_key(self):
        self.assertIn(
            ("data/cache/r2_report_publish_state.json", "data/cache/r2_report_publish_state.json"),
            rs.STATE_FILES,
        )

    def test_all_five_intelligence_repository_registry_files_present(self):
        """CodeRabbit review finding on this migration (verified, not taken
        on faith): these 5 files were still on multi-source-intel.yml's
        doomed-to-fail git push after the 4 files above were pulled off it."""
        local_paths = [local for local, _ in rs.STATE_FILES]
        for f in (
            "data/intelligence_repository/intelligence_index.json",
            "data/intelligence_repository/advisory_registry.json",
            "data/intelligence_repository/intel_retention_registry.json",
            "data/intelligence_repository/intel_lifecycle_registry.json",
            "data/intelligence_repository/historical_feed_registry.json",
        ):
            self.assertIn(f, local_paths)

    def test_top_level_feed_manifest_is_present_with_path_mirrored_key(self):
        self.assertIn(
            ("data/feed_manifest.json", "data/feed_manifest.json"),
            rs.STATE_FILES,
        )

    def test_top_level_and_stix_feed_manifest_are_distinct_entries(self):
        """These are two different files (the EII-enriched manifest vs. the
        raw STIX ingestion bundle) -- must never collapse onto the same
        local path or the same R2 key."""
        local_paths = [local for local, _ in rs.STATE_FILES]
        r2_keys = [key for _, key in rs.STATE_FILES]
        self.assertIn("data/feed_manifest.json", local_paths)
        self.assertIn("data/stix/feed_manifest.json", local_paths)
        self.assertEqual(len(local_paths), len(set(local_paths)))
        self.assertEqual(len(r2_keys), len(set(r2_keys)))


class TestDownload(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_dl_"))
        # STATE_DIRS uses a different (sync, not cp) subprocess command shape
        # than the STATE_FILES tests below fake -- these tests are about
        # STATE_FILES semantics specifically, so STATE_DIRS is neutralized
        # to a trivial success here. TestStateDirs below covers its own
        # behavior directly.
        patcher = patch.object(rs, "s3_sync_download", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mock_run_for(self, outcomes: dict):
        """outcomes: {r2_key: 'OK'|'NOT_FOUND'|'ERROR'} -- fakes `aws s3 cp` per key."""
        def _fake_run(cmd, **kwargs):
            _is_download, local_path, r2_key = _parse_cp_cmd(cmd)
            outcome = outcomes.get(r2_key, "ERROR")
            if outcome == "OK":
                pathlib.Path(local_path).write_text(json.dumps({"ok": True}), encoding="utf-8")
                return _proc(0)
            if outcome == "NOT_FOUND":
                return _proc(1, stderr="An error occurred (404) when calling the HeadObject operation: Not Found")
            return _proc(1, stderr="Connection timed out")
        return _fake_run

    def test_all_ok_populates_every_local_file_except_broad_sweep_excluded(self):
        """P0 mission follow-up (2026-09-10): a broad (no --only) download
        must skip BROAD_SWEEP_EXCLUDED_PATHS entirely -- see that set's own
        comment in r2_state_sync.py for why (a stale snapshot downloaded here
        would otherwise sit untouched for the rest of a long-running caller's
        job and get blindly re-published by that same job's later broad
        upload, reverting a newer write sovereign-platform.yml/
        genesis-powerhouse.yml made to the same R2 keys in the meantime)."""
        with patch.object(r2_upload.subprocess, "run",
                           side_effect=self._mock_run_for({k: "OK" for _, k in rs.STATE_FILES})):
            rc = rs.download(self.tmp, "https://e")
        self.assertEqual(rc, 0)
        for local_rel, _ in rs.STATE_FILES:
            if local_rel in rs.BROAD_SWEEP_EXCLUDED_PATHS:
                self.assertFalse((self.tmp / local_rel).exists())
            else:
                self.assertTrue((self.tmp / local_rel).exists())

    def test_not_found_keeps_existing_local_bootstrap_copy(self):
        local_rel, r2_key = rs.STATE_FILES[0]
        local_path = self.tmp / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text('{"bootstrap": true}', encoding="utf-8")

        outcomes = {k: "NOT_FOUND" for _, k in rs.STATE_FILES}
        with patch.object(r2_upload.subprocess, "run", side_effect=self._mock_run_for(outcomes)):
            rc = rs.download(self.tmp, "https://e")

        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(local_path.read_text()), {"bootstrap": True})

    def test_not_found_with_no_local_copy_is_not_an_error(self):
        outcomes = {k: "NOT_FOUND" for _, k in rs.STATE_FILES}
        with patch.object(r2_upload.subprocess, "run", side_effect=self._mock_run_for(outcomes)):
            rc = rs.download(self.tmp, "https://e")
        self.assertEqual(rc, 0)
        for local_rel, _ in rs.STATE_FILES:
            self.assertFalse((self.tmp / local_rel).exists())

    def test_error_hard_fails_even_with_existing_local_copy(self):
        """The dangerous case: a transient R2 outage must NOT be silently
        treated the same as 'this object has never existed'."""
        local_rel, r2_key = rs.STATE_FILES[0]
        local_path = self.tmp / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text('{"real_history": "must_not_be_discarded"}', encoding="utf-8")

        outcomes = {k: "ERROR" for _, k in rs.STATE_FILES}
        with patch.object(r2_upload.subprocess, "run", side_effect=self._mock_run_for(outcomes)):
            rc = rs.download(self.tmp, "https://e")

        self.assertEqual(rc, 1)
        # And the existing (real) local copy must be left untouched, not wiped.
        self.assertEqual(json.loads(local_path.read_text()), {"real_history": "must_not_be_discarded"})

    def test_one_file_error_does_not_abort_processing_the_others(self):
        keys = [k for _, k in rs.STATE_FILES]
        outcomes = {keys[0]: "ERROR", keys[1]: "OK", keys[2]: "OK"}
        with patch.object(r2_upload.subprocess, "run", side_effect=self._mock_run_for(outcomes)):
            rc = rs.download(self.tmp, "https://e")
        self.assertEqual(rc, 1)  # overall failure reported...
        # ...but the other two files were still downloaded.
        self.assertTrue((self.tmp / rs.STATE_FILES[1][0]).exists())
        self.assertTrue((self.tmp / rs.STATE_FILES[2][0]).exists())

    def test_malformed_json_after_successful_download_is_fatal(self):
        def _fake_run(cmd, **kwargs):
            _is_download, local_path, _r2_key = _parse_cp_cmd(cmd)
            pathlib.Path(local_path).write_text("{not valid json", encoding="utf-8")
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            rc = rs.download(self.tmp, "https://e")
        self.assertEqual(rc, 1)

    def test_malformed_json_after_download_preserves_existing_local_copy(self):
        """PRODUCTION-VERIFICATION HARDENING (2026-09-02): s3_get() used to
        write straight to local_path, so a malformed download had already
        overwritten a good local copy by the time this function's own
        validation ran -- correctly reported as fatal (rc=1), but the file
        on disk was left corrupt, not restored. download() now stages into
        a .tmp sibling first and only promotes it on successful validation,
        so a real pre-existing local copy must survive a malformed download
        completely unchanged, not just get an accurate error code."""
        local_rel, r2_key = rs.STATE_FILES[0]
        local_path = self.tmp / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text('{"real_history": "must_not_be_discarded"}', encoding="utf-8")

        def _fake_run(cmd, **kwargs):
            _is_download, dst, key = _parse_cp_cmd(cmd)
            if key == r2_key:
                pathlib.Path(dst).write_text("{not valid json", encoding="utf-8")
            else:
                pathlib.Path(dst).write_text(json.dumps({"ok": True}), encoding="utf-8")
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            rc = rs.download(self.tmp, "https://e")

        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(local_path.read_text()), {"real_history": "must_not_be_discarded"})
        # No leftover .tmp sibling, success or rejection.
        self.assertFalse((self.tmp / (local_rel + ".r2sync.tmp")).exists())

    def test_wrong_shape_json_is_rejected_and_preserves_existing_local_copy(self):
        """Section 19 Case C of the P0 R2 hardening mandate: valid JSON that
        is not the expected shape (here, a bare string instead of a list/
        object) must be rejected the same as malformed JSON, not silently
        accepted just because json.loads() succeeds."""
        local_rel, r2_key = rs.STATE_FILES[0]
        local_path = self.tmp / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text('{"real_history": "must_not_be_discarded"}', encoding="utf-8")

        def _fake_run(cmd, **kwargs):
            _is_download, dst, key = _parse_cp_cmd(cmd)
            if key == r2_key:
                pathlib.Path(dst).write_text(json.dumps("just a string, not a list or object"), encoding="utf-8")
            else:
                pathlib.Path(dst).write_text(json.dumps({"ok": True}), encoding="utf-8")
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            rc = rs.download(self.tmp, "https://e")

        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(local_path.read_text()), {"real_history": "must_not_be_discarded"})

    def test_valid_correctly_shaped_download_replaces_existing_local_copy(self):
        """Sanity counterpart to the two rejection tests above: a valid,
        correctly-shaped download must still replace an existing local file
        (the hardening must reject bad content, not everything)."""
        local_rel, r2_key = rs.STATE_FILES[0]
        local_path = self.tmp / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text('{"stale": true}', encoding="utf-8")

        outcomes = {k: "OK" for _, k in rs.STATE_FILES}
        with patch.object(r2_upload.subprocess, "run", side_effect=self._mock_run_for(outcomes)):
            rc = rs.download(self.tmp, "https://e")

        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(local_path.read_text()), {"ok": True})

    def test_replace_failure_after_valid_download_preserves_existing_local_copy(self):
        """The atomic-replace promotion itself can fail (disk full, a
        cross-device tmp dir, a permission error) even after the downloaded
        content has already passed validation. That failure must be reported
        (not swallowed) and must not destroy whatever was already at
        local_path -- the same guarantee the malformed/wrong-shape cases
        above provide, now covering the promotion step itself."""
        local_rel, r2_key = rs.STATE_FILES[0]
        local_path = self.tmp / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text('{"real_history": "must_not_be_discarded"}', encoding="utf-8")

        outcomes = {k: "OK" for _, k in rs.STATE_FILES}
        real_replace = pathlib.Path.replace

        def _fake_replace(self_path, target):
            if self_path.name == local_path.name + ".r2sync.tmp" and self_path.parent == local_path.parent:
                raise OSError("simulated: cross-device link")
            return real_replace(self_path, target)

        with patch.object(r2_upload.subprocess, "run", side_effect=self._mock_run_for(outcomes)), \
             patch.object(pathlib.Path, "replace", _fake_replace):
            rc = rs.download(self.tmp, "https://e")

        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(local_path.read_text()), {"real_history": "must_not_be_discarded"})


class TestUpload(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_ul_"))
        for local_rel, _ in rs.STATE_FILES:
            p = self.tmp / local_rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"file": local_rel}), encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_success_on_first_attempt(self):
        with patch.object(r2_upload.subprocess, "run", return_value=_proc(0)) as m:
            with patch.object(rs.time, "sleep") as sleep_mock:
                rc = rs.upload(self.tmp, "https://e")
        self.assertEqual(rc, 0)
        sleep_mock.assert_not_called()
        # P0 mission follow-up (2026-09-10): a broad (no --only) upload must
        # skip BROAD_SWEEP_EXCLUDED_PATHS even though setUp gave every
        # STATE_FILES entry a local copy -- see that set's own comment for
        # why a broad upload must never touch these paths.
        self.assertEqual(m.call_count, len(rs.STATE_FILES) - len(rs.BROAD_SWEEP_EXCLUDED_PATHS))

    def test_succeeds_after_retries(self):
        attempts_for_first_file = {"n": 0}

        def _fake_run(cmd, **kwargs):
            _is_download, local_path, _r2_key = _parse_cp_cmd(cmd)
            if "feed_state.json" in local_path:
                attempts_for_first_file["n"] += 1
                if attempts_for_first_file["n"] <= 2:
                    return _proc(1, stderr="503 Slow Down")
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            with patch.object(rs.time, "sleep") as sleep_mock:
                rc = rs.upload(self.tmp, "https://e")
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(sleep_mock.call_count, 2)

    def test_exhausted_retries_is_fatal(self):
        with patch.object(r2_upload.subprocess, "run", return_value=_proc(1, stderr="500 Internal Error")):
            with patch.object(rs.time, "sleep"):
                rc = rs.upload(self.tmp, "https://e")
        self.assertEqual(rc, 1)

    def test_missing_local_file_is_skipped_not_an_error(self):
        empty_dir = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_ul_empty_"))
        try:
            with patch.object(r2_upload.subprocess, "run") as m:
                rc = rs.upload(empty_dir, "https://e")
            self.assertEqual(rc, 0)
            m.assert_not_called()
        finally:
            import shutil
            shutil.rmtree(empty_dir, ignore_errors=True)

    def test_one_file_exhaustion_does_not_abort_the_others(self):
        keys = [k for _, k in rs.STATE_FILES]
        uploaded_keys = []

        def _fake_run(cmd, **kwargs):
            _is_download, _local_path, r2_key = _parse_cp_cmd(cmd)
            if r2_key == keys[0]:
                return _proc(1, stderr="500 Internal Error")
            uploaded_keys.append(r2_key)
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            with patch.object(rs.time, "sleep"):
                rc = rs.upload(self.tmp, "https://e")
        self.assertEqual(rc, 1)
        self.assertIn(keys[1], uploaded_keys)
        self.assertIn(keys[2], uploaded_keys)


class TestStateDirs(unittest.TestCase):
    """STATE_DIRS (data/intelligence_repository/advisories/) uses sync, not
    cp, semantics -- these tests exercise that path directly rather than
    relying on TestDownload/TestUpload's STATE_FILES-shaped mocking."""

    def test_exactly_one_dir_migrated(self):
        self.assertEqual(len(rs.STATE_DIRS), 1)
        self.assertIn(
            ("data/intelligence_repository/advisories", "data/intelligence_repository/advisories"),
            rs.STATE_DIRS,
        )

    def test_download_calls_sync_for_each_configured_dir(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_dirs_dl_"))
        try:
            with patch.object(rs, "s3_sync_download", return_value=True) as m:
                with patch.object(rs, "s3_get", return_value="NOT_FOUND"):
                    rc = rs.download(tmp, "https://e")
            self.assertEqual(rc, 0)
            self.assertEqual(m.call_count, len(rs.STATE_DIRS))
            for local_rel, r2_prefix in rs.STATE_DIRS:
                m.assert_any_call(str(tmp / local_rel), rs.BUCKET_DATA, r2_prefix, "https://e")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_download_sync_failure_is_an_error_not_silently_ignored(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_dirs_dl_"))
        try:
            with patch.object(rs, "s3_sync_download", return_value=False):
                with patch.object(rs, "s3_get", return_value="NOT_FOUND"):
                    rc = rs.download(tmp, "https://e")
            self.assertEqual(rc, 1)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_upload_skips_missing_or_empty_dir_not_an_error(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_dirs_ul_empty_"))
        try:
            with patch.object(r2_upload.subprocess, "run") as m:
                rc = rs.upload(tmp, "https://e")
            self.assertEqual(rc, 0)
            m.assert_not_called()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_upload_syncs_dir_with_content(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_dirs_ul_"))
        try:
            local_rel, _ = rs.STATE_DIRS[0]
            adv_dir = tmp / local_rel
            adv_dir.mkdir(parents=True, exist_ok=True)
            (adv_dir / "registry_202609.json").write_text('{"items": []}', encoding="utf-8")

            with patch.object(rs, "s3_sync", return_value=True) as m:
                rc = rs.upload(tmp, "https://e")
            self.assertEqual(rc, 0)
            m.assert_called_once()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_upload_sync_exhaustion_is_fatal_and_reported_as_mixed_state_when_partial(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_dirs_ul_"))
        try:
            local_rel, _ = rs.STATE_DIRS[0]
            adv_dir = tmp / local_rel
            adv_dir.mkdir(parents=True, exist_ok=True)
            (adv_dir / "registry_202609.json").write_text('{"items": []}', encoding="utf-8")
            for f, _ in rs.STATE_FILES:
                p = tmp / f
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("{}", encoding="utf-8")

            with patch.object(rs, "s3_sync", return_value=False):
                with patch.object(rs, "s3_cp", return_value=True):
                    with patch.object(rs.time, "sleep"):
                        with self.assertLogs("r2-state-sync", level="ERROR") as cm:
                            rc = rs.upload(tmp, "https://e")
            self.assertEqual(rc, 1)
            self.assertTrue([line for line in cm.output if "MIXED STATE" in line])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestMixedStateVisibility(unittest.TestCase):
    """CodeRabbit review finding on PR #332: R2 has no cross-object
    transactions, so a run where some of the 4 STATE_FILES upload
    successfully and others exhaust their retries leaves R2 in a genuinely
    inconsistent mix -- and the original per-file-only error message
    ('this run's state was NOT persisted') was misleading in exactly that
    case, since some of it *had* been. These tests assert the partial
    failure is loudly, distinctly diagnosable rather than indistinguishable
    from a total failure."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_mixed_"))
        for local_rel, _ in rs.STATE_FILES:
            p = self.tmp / local_rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"file": local_rel}), encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_partial_failure_logs_mixed_state_warning(self):
        keys = [k for _, k in rs.STATE_FILES]

        def _fake_run(cmd, **kwargs):
            _is_download, _local_path, r2_key = _parse_cp_cmd(cmd)
            if r2_key == keys[0]:
                return _proc(1, stderr="500 Internal Error")
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            with patch.object(rs.time, "sleep"):
                with self.assertLogs("r2-state-sync", level="ERROR") as cm:
                    rc = rs.upload(self.tmp, "https://e")

        self.assertEqual(rc, 1)
        mixed_state_lines = [line for line in cm.output if "MIXED STATE" in line]
        self.assertTrue(mixed_state_lines, "expected a MIXED STATE warning when some files "
                                            "succeeded and others failed")
        # Names both the stale (failed) and fresh (succeeded) files, not just a count.
        self.assertIn(keys[0], mixed_state_lines[0])
        # P0 mission follow-up (2026-09-10): BROAD_SWEEP_EXCLUDED_PATHS' own
        # r2_keys are skipped entirely on a broad upload (this test never
        # passes --only), so they're neither "succeeded" nor "failed" here --
        # excluded from this loop rather than asserted as succeeded.
        excluded_keys = {r2_key for local_rel, r2_key in rs.STATE_FILES if local_rel in rs.BROAD_SWEEP_EXCLUDED_PATHS}
        for k in keys[1:]:
            if k in excluded_keys:
                continue
            self.assertIn(k, mixed_state_lines[0])

    def test_total_failure_does_not_log_mixed_state_warning(self):
        """All 4 files failing is not 'mixed' -- it's uniformly stale, same
        as before this fix. The MIXED STATE signal must be reserved for the
        genuinely partial case so it isn't cried wolf on every outage."""
        with patch.object(r2_upload.subprocess, "run", return_value=_proc(1, stderr="500 Internal Error")):
            with patch.object(rs.time, "sleep"):
                with self.assertLogs("r2-state-sync", level="ERROR") as cm:
                    rc = rs.upload(self.tmp, "https://e")

        self.assertEqual(rc, 1)
        self.assertFalse([line for line in cm.output if "MIXED STATE" in line])

    def test_total_success_does_not_log_mixed_state_warning(self):
        with patch.object(r2_upload.subprocess, "run", return_value=_proc(0)):
            rc = rs.upload(self.tmp, "https://e")
        self.assertEqual(rc, 0)

    def test_single_file_failure_message_does_not_overclaim_whole_run_lost(self):
        """The original wording implied the entire run's state was lost even
        when only one of several files failed -- must now scope the claim to
        the file it actually describes."""
        keys = [k for _, k in rs.STATE_FILES]

        def _fake_run(cmd, **kwargs):
            _is_download, _local_path, r2_key = _parse_cp_cmd(cmd)
            if r2_key == keys[0]:
                return _proc(1, stderr="500 Internal Error")
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            with patch.object(rs.time, "sleep"):
                with self.assertLogs("r2-state-sync", level="ERROR") as cm:
                    rs.upload(self.tmp, "https://e")

        per_file_failure = [line for line in cm.output if keys[0] in line and "MIXED STATE" not in line]
        self.assertTrue(per_file_failure)
        self.assertNotIn("this run's state was NOT persisted", per_file_failure[0])


class TestRoundTripFidelity(unittest.TestCase):
    """The script must be a byte-transparent pass-through: whatever gets
    uploaded is exactly what a later download returns -- no silent mutation
    of dedup fingerprints or manifest content."""

    def test_upload_then_download_round_trips_exact_content(self):
        src_dir = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_rt_src_"))
        dst_dir = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_rt_dst_"))
        fake_bucket: dict[str, bytes] = {}
        try:
            local_rel, r2_key = rs.STATE_FILES[2]  # feed_manifest.json
            payload = {"items": [{"id": "intel--abc123", "title": "Real advisory"}]}
            src_path = src_dir / local_rel
            src_path.parent.mkdir(parents=True, exist_ok=True)
            src_path.write_text(json.dumps(payload), encoding="utf-8")

            def _fake_run(cmd, **kwargs):
                is_download, local_path, key = _parse_cp_cmd(cmd)
                if not is_download:
                    fake_bucket[key] = pathlib.Path(local_path).read_bytes()
                    return _proc(0)
                if key not in fake_bucket:
                    return _proc(1, stderr="An error occurred (404) Not Found")
                pathlib.Path(local_path).write_bytes(fake_bucket[key])
                return _proc(0)

            (dst_dir / local_rel).parent.mkdir(parents=True, exist_ok=True)
            with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
                self.assertEqual(r2_upload.s3_cp(str(src_path), r2_upload.BUCKET_DATA, r2_key, "https://e"), True)
                outcome = r2_upload.s3_get(str(dst_dir / local_rel), r2_upload.BUCKET_DATA, r2_key, "https://e")

            self.assertEqual(outcome, "OK")
            self.assertEqual(json.loads((dst_dir / local_rel).read_text()), payload)
        finally:
            import shutil
            shutil.rmtree(src_dir, ignore_errors=True)
            shutil.rmtree(dst_dir, ignore_errors=True)


class TestTopLevelFeedManifestRoundTrip(unittest.TestCase):
    """Same round-trip guarantee as TestRoundTripFidelity above, specifically
    for data/feed_manifest.json (STATE_FILES[3]) -- the EII-enriched
    manifest, not the STIX one already covered by that test. Written by
    apex_quality_field_backfill.py / cve_id_backfill.py / etc. in place, so
    an upload that silently truncated or reordered its content would corrupt
    accumulated enrichment history, not just fail to add new items."""

    def test_upload_then_download_round_trips_exact_content(self):
        src_dir = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_rt2_src_"))
        dst_dir = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_rt2_dst_"))
        fake_bucket: dict[str, bytes] = {}
        try:
            local_rel, r2_key = next(
                (local, key) for local, key in rs.STATE_FILES if local == "data/feed_manifest.json"
            )
            payload = {
                "version": "70.0",
                "advisories": [{"id": "intel--abc123", "cve_id": "CVE-2026-4075", "apex_risk": 91.2}],
            }
            src_path = src_dir / local_rel
            src_path.parent.mkdir(parents=True, exist_ok=True)
            src_path.write_text(json.dumps(payload), encoding="utf-8")

            def _fake_run(cmd, **kwargs):
                is_download, local_path, key = _parse_cp_cmd(cmd)
                if not is_download:
                    fake_bucket[key] = pathlib.Path(local_path).read_bytes()
                    return _proc(0)
                if key not in fake_bucket:
                    return _proc(1, stderr="An error occurred (404) Not Found")
                pathlib.Path(local_path).write_bytes(fake_bucket[key])
                return _proc(0)

            (dst_dir / local_rel).parent.mkdir(parents=True, exist_ok=True)
            with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
                self.assertEqual(r2_upload.s3_cp(str(src_path), r2_upload.BUCKET_DATA, r2_key, "https://e"), True)
                outcome = r2_upload.s3_get(str(dst_dir / local_rel), r2_upload.BUCKET_DATA, r2_key, "https://e")

            self.assertEqual(outcome, "OK")
            self.assertEqual(json.loads((dst_dir / local_rel).read_text()), payload)
        finally:
            import shutil
            shutil.rmtree(src_dir, ignore_errors=True)
            shutil.rmtree(dst_dir, ignore_errors=True)


class TestReportPublishStateRoundTrip(unittest.TestCase):
    """P0 R2 COST AUDIT FIX: proves scripts/r2_report_publisher.py's
    incremental-publish state actually survives the real cross-run lifecycle
    that mechanism depends on -- pipeline run -> publisher writes state ->
    upload() -> [next scheduled run's fresh checkout, simulated here by a
    brand-new tmp root with no local copy at all] -> download() -> publisher
    reads state back. Exercises rs.download()/rs.upload() themselves (the
    actual functions the workflow's download/upload steps call), not just
    the s3_cp/s3_get primitives TestRoundTripFidelity above already covers,
    and confirms the recovered file is genuinely usable by
    r2_report_publisher.py's own load_publish_state() -- closing the loop
    between the two modules a unit test of either one in isolation cannot.

    This is the correct analog to "survives a commit+push+checkout cycle"
    for this specific file: it does NOT go through git at all (confirmed:
    absent from safe_git_commit.py's staging lists in the original PR), and
    r2_state_sync.py's own module docstring documents why a git-based fix
    would be the wrong one here -- main's branch ruleset rejects direct
    pushes for this exact class of cross-run state file."""

    def test_state_survives_upload_then_fresh_checkout_then_download(self):
        run1_root = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_pubstate_run1_"))
        run2_root = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_pubstate_run2_"))
        fake_bucket: dict[str, bytes] = {}
        try:
            local_rel, r2_key = next(
                (local, key) for local, key in rs.STATE_FILES
                if local == "data/cache/r2_report_publish_state.json"
            )

            def _fake_run(cmd, **kwargs):
                is_download, local_path, key = _parse_cp_cmd(cmd)
                if not is_download:
                    fake_bucket[key] = pathlib.Path(local_path).read_bytes()
                    return _proc(0)
                if key not in fake_bucket:
                    return _proc(1, stderr="An error occurred (404) Not Found")
                pathlib.Path(local_path).write_bytes(fake_bucket[key])
                return _proc(0)

            # STATE_DIRS (data/intelligence_repository/advisories) uses a
            # different (sync, not cp) subprocess command shape than
            # _fake_run/_parse_cp_cmd understand -- this test is about the
            # STATE_FILES entry for the publisher's state, so STATE_DIRS is
            # neutralized the same way TestDownload's setUp() already does.
            with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run), \
                 patch.object(rs, "s3_sync_download", return_value=True), \
                 patch.object(rs, "s3_sync", return_value=True):
                # "Run 1", start of pipeline: genuinely first-ever run --
                # nothing in R2 yet, nothing on local disk either.
                rc = rs.download(run1_root, "https://e")
                self.assertEqual(rc, 0)
                self.assertFalse((run1_root / local_rel).exists())

                # "Run 1": the publisher runs and writes its state (simulating
                # r2_report_publisher.py's own save_publish_state()).
                published_state = {
                    "schema_version": "1.0",
                    "items": {
                        "intel--roundtriptest01": {
                            "canonical_ts": "2026-09-04T12:00:00Z",
                            "html_key": "reports/2026/09/intel--roundtriptest01.html",
                            "html_sha256": "a" * 64,
                        },
                    },
                }
                state_path = run1_root / local_rel
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(json.dumps(published_state), encoding="utf-8")

                # "Run 1", end of pipeline: STAGE 4.1 uploads it to R2.
                rc = rs.upload(run1_root, "https://e")
                self.assertEqual(rc, 0)
                self.assertIn(r2_key, fake_bucket, "upload() must actually publish this file to R2")

                # "Next scheduled execution": a brand-new ephemeral container,
                # fresh git checkout -- run2_root has NO local copy of
                # anything. This file is not staged by safe_git_commit.py, so
                # a real fresh checkout would never restore it from git
                # either -- the ONLY way it can reappear is via this download.
                self.assertFalse((run2_root / local_rel).exists())
                rc = rs.download(run2_root, "https://e")
                self.assertEqual(rc, 0)

            recovered_path = run2_root / local_rel
            self.assertTrue(recovered_path.exists(), "state must be recovered by download() on the next run")
            recovered = json.loads(recovered_path.read_text())
            self.assertEqual(recovered, published_state, "recovered state must be byte-for-byte equivalent, not just 'a file exists'")

            # Closes the loop with the OTHER module: the recovered file must
            # be genuinely usable by r2_report_publisher.py's own state
            # loader, not just byte-identical JSON.
            with patch.object(rrp, "STATE_PATH", recovered_path):
                loaded = rrp.load_publish_state()
            self.assertEqual(loaded["items"], published_state["items"])
            self.assertEqual(
                loaded["items"]["intel--roundtriptest01"]["html_sha256"], "a" * 64,
                "if this incremental-publish fingerprint is lost, the publisher "
                "would re-PUT unchanged content as if it were new -- exactly "
                "the defect this fix closes"
            )
        finally:
            import shutil
            shutil.rmtree(run1_root, ignore_errors=True)
            shutil.rmtree(run2_root, ignore_errors=True)

    def test_missing_state_across_a_genuinely_first_run_bootstraps_safely(self):
        """The other half of the lifecycle: if R2 has never seen this file
        (a genuinely first-ever run, or the object was somehow lost from R2
        too), download() must not error, and the publisher must safely
        bootstrap to an empty state rather than crashing or fail-opening
        into an unsafe operation."""
        root = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_pubstate_bootstrap_"))
        try:
            def _fake_run(cmd, **kwargs):
                is_download, _local_path, _key = _parse_cp_cmd(cmd)
                if is_download:
                    return _proc(1, stderr="An error occurred (404) Not Found")
                return _proc(0)

            with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run), \
                 patch.object(rs, "s3_sync_download", return_value=True):
                rc = rs.download(root, "https://e")
            self.assertEqual(rc, 0, "a not-found state file is a safe bootstrap, not an error")

            local_rel, _ = next(
                (local, key) for local, key in rs.STATE_FILES
                if local == "data/cache/r2_report_publish_state.json"
            )
            state_path = root / local_rel
            self.assertFalse(state_path.exists())

            with patch.object(rrp, "STATE_PATH", state_path):
                loaded = rrp.load_publish_state()
            self.assertEqual(loaded, {"schema_version": "1.0", "items": {}})
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


class TestCli(unittest.TestCase):
    def test_download_and_upload_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            with patch.object(sys, "argv", ["r2_state_sync.py", "--download", "--upload"]):
                rs.main()

    def test_one_mode_is_required(self):
        with self.assertRaises(SystemExit):
            with patch.object(sys, "argv", ["r2_state_sync.py"]):
                rs.main()

    def test_only_with_unknown_path_is_rejected(self):
        """A typo'd --only value would otherwise silently download/upload
        nothing (an empty intersection with STATE_FILES/STATE_DIRS) --
        exactly the class of silent-failure this whole module exists to
        eliminate. Must fail loudly at argument-parsing time instead."""
        with patch.object(rs, "get_credentials", return_value=("acct", "k", "s")), \
             patch.object(rs, "install_awscli"), \
             patch.object(sys, "argv", ["r2_state_sync.py", "--download", "--only", "data/typo/not_a_real_path.json"]):
            with self.assertRaises(SystemExit):
                rs.main()

    def test_only_filters_to_the_given_subset(self):
        """--only reaches download()/upload() as the exact frozenset named,
        not silently ignored or expanded back to everything."""
        target = "data/stix/feed_manifest.json"
        with patch.object(rs, "get_credentials", return_value=("acct", "k", "s")), \
             patch.object(rs, "install_awscli"), \
             patch.object(rs, "download", return_value=0) as mock_download, \
             patch.object(sys, "argv", ["r2_state_sync.py", "--download", "--only", target]):
            rs.main()
        mock_download.assert_called_once()
        _, kwargs = mock_download.call_args
        self.assertEqual(kwargs["only"], frozenset({target}))

    def test_only_omitted_preserves_original_unfiltered_behavior(self):
        """Every pre-existing caller (ai-predictions.yml, multi-source-intel.yml,
        sentinel-apex.yml, ...) omits --only and must see the exact same
        None passed through as before this flag existed."""
        with patch.object(rs, "get_credentials", return_value=("acct", "k", "s")), \
             patch.object(rs, "install_awscli"), \
             patch.object(rs, "upload", return_value=0) as mock_upload, \
             patch.object(sys, "argv", ["r2_state_sync.py", "--upload"]):
            rs.main()
        _, kwargs = mock_upload.call_args
        self.assertIsNone(kwargs["only"])


class TestBroadSweepExcludedPathsExplicitOnlyStillWorks(unittest.TestCase):
    """P0 mission follow-up (2026-09-10): BROAD_SWEEP_EXCLUDED_PATHS'
    entries must be untouchable by a broad sweep (covered above) but fully
    reachable via an explicit `--only` naming them -- exactly what
    sovereign-platform.yml/genesis-powerhouse.yml's own real invocations do.
    An excluded-but-unreachable path would be as broken as an
    excluded-but-still-swept one, just in the opposite direction."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="r2sync_excl_only_"))
        patcher = patch.object(rs, "s3_sync_download", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_explicit_only_download_still_reaches_a_broad_sweep_excluded_path(self):
        target = next(iter(rs.BROAD_SWEEP_EXCLUDED_PATHS))

        def _fake_run(cmd, **kwargs):
            _is_download, local_path, _r2_key = _parse_cp_cmd(cmd)
            pathlib.Path(local_path).write_text(json.dumps({"ok": True}), encoding="utf-8")
            return _proc(0)

        with patch.object(r2_upload.subprocess, "run", side_effect=_fake_run):
            rc = rs.download(self.tmp, "https://e", only=frozenset({target}))
        self.assertEqual(rc, 0)
        self.assertTrue((self.tmp / target).exists())

    def test_explicit_only_upload_still_reaches_a_broad_sweep_excluded_path(self):
        target = next(iter(rs.BROAD_SWEEP_EXCLUDED_PATHS))
        local_path = self.tmp / target
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(json.dumps({"file": target}), encoding="utf-8")

        with patch.object(r2_upload.subprocess, "run", return_value=_proc(0)) as m:
            with patch.object(rs.time, "sleep"):
                rc = rs.upload(self.tmp, "https://e", only=frozenset({target}))
        self.assertEqual(rc, 0)
        self.assertEqual(m.call_count, 1)


if __name__ == "__main__":
    unittest.main()
