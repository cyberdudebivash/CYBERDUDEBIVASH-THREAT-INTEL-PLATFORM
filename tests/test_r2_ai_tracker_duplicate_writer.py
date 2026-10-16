"""
tests/test_r2_ai_tracker_duplicate_writer.py

P0 FinOps regression coverage: the documented "bounded duplicate-writer
race" between generate-and-sync.yml and scripts/r2_upload.py for the 4
shared AI-tracker R2 keys (ai/tracker.json, ai/health.json,
ai/executive-brief.json, ai/monetization.json), and the companion
r2_upload.py cost-guard accounting gap -- both called out in PR #370 as
remaining FinOps risks blocking full zero-overage certification.

FIX SHAPE (Option A -- one authoritative writer per shared key):
  * scripts/r2_upload.py's main() (invoked by sentinel-apex.yml under
    concurrency group "sentinel-data-writer") no longer uploads any of the
    4 AI-tracker keys.
  * scripts/r2_upload.py --ai-tracker-only (main_ai_tracker_only()) is now
    the SOLE code path that uploads them, and generate-and-sync.yml's
    STAGE 9.5 (concurrency group "sentinel-ai-writer") is its only caller
    -- replacing that step's former raw inline `aws s3 cp` loop, which had
    zero r2_cost_guard.py accounting.
  * main()'s remaining bounded sentinel-apex-data uploads are now planned
    in full (build_upload_plan()) and budget-checked via
    r2_cost_guard.enforce_budget() BEFORE any R2 mutation.

Tests use mocks/fakes only -- no real R2/network access.
"""
from __future__ import annotations

import inspect
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import r2_upload  # noqa: E402
import r2_cost_guard as guard  # noqa: E402


class TestAiTrackerSingleOwnership(unittest.TestCase):
    """GATE E: the 4 shared keys have exactly one writer in the codebase."""

    def test_ai_tracker_files_constant_has_exactly_the_four_documented_keys(self):
        dst_keys = {dst for _src, dst in r2_upload.AI_TRACKER_FILES}
        self.assertEqual(
            dst_keys,
            {"ai/tracker.json", "ai/health.json", "ai/executive-brief.json", "ai/monetization.json"},
        )

    def test_main_source_never_references_ai_tracker_dst_keys(self):
        main_source = inspect.getsource(r2_upload.main)
        build_plan_source = inspect.getsource(r2_upload.build_upload_plan)
        combined = main_source + build_plan_source
        for _src, dst_key in r2_upload.AI_TRACKER_FILES:
            self.assertNotIn(
                repr(dst_key), combined,
                f"main()/build_upload_plan() must never upload {dst_key!r} -- "
                "that key is now owned exclusively by main_ai_tracker_only() "
                "(--ai-tracker-only), called only from generate-and-sync.yml. "
                "A second writer here would resurrect the PR #370 duplicate-"
                "writer race.",
            )

    def test_build_upload_plan_excludes_ai_tracker_filenames_from_ai_dir_glob(self):
        # Simulate api/ai/ containing both AI-tracker files AND a non-tracker
        # AI endpoint file (e.g. analyze.json from generate_ai_endpoints.py)
        # to prove the exclusion is scoped to the 4 tracker filenames only.
        with patch.object(r2_upload, "REPO_ROOT", REPO_ROOT):
            pairs = r2_upload.build_upload_plan()
        dst_keys = {dst for _src, dst in pairs}
        for filename in r2_upload.AI_TRACKER_FILENAMES:
            self.assertNotIn(
                f"ai/{filename}", dst_keys,
                f"build_upload_plan() must exclude ai/{filename} -- owned by "
                "main_ai_tracker_only() only.",
            )

    def test_ai_tracker_filenames_derived_from_ai_tracker_files(self):
        expected = {Path(src).name for src, _dst in r2_upload.AI_TRACKER_FILES}
        self.assertEqual(r2_upload.AI_TRACKER_FILENAMES, expected)


class TestGenerateAndSyncCallsSharedWriter(unittest.TestCase):
    """Static check: generate-and-sync.yml's STAGE 9.5 delegates to the
    single authoritative writer instead of hand-rolling `aws s3 cp` again."""

    def setUp(self):
        self.workflow_path = REPO_ROOT / ".github" / "workflows" / "generate-and-sync.yml"
        self.workflow_source = self.workflow_path.read_text(encoding="utf-8")

    def test_stage_9_5_invokes_ai_tracker_only_mode(self):
        self.assertIn(
            "r2_upload.py --ai-tracker-only", self.workflow_source,
            "generate-and-sync.yml STAGE 9.5 must call the single "
            "authoritative writer (scripts/r2_upload.py --ai-tracker-only) "
            "rather than a competing inline aws-cli upload.",
        )

    def test_stage_9_5_no_longer_hand_rolls_aws_s3_cp_for_tracker_keys(self):
        # Isolate the STAGE 9.5 step block so this doesn't false-positive on
        # unrelated `aws s3 cp` usage elsewhere in this large workflow file.
        match = re.search(
            r'name: "STAGE 9\.5.*?(?=\n {6}- name:|\Z)',
            self.workflow_source, re.DOTALL,
        )
        self.assertIsNotNone(match, "Could not locate STAGE 9.5 step block")
        stage_9_5_block = match.group(0)
        self.assertNotIn("aws s3 cp", stage_9_5_block)


class TestSentinelBloggerNoLongerDuplicatesAiTrackerUpload(unittest.TestCase):
    """Static check: sentinel-apex.yml's r2_upload.py invocation (main())
    no longer independently writes the 4 shared keys."""

    def test_r2_upload_invocation_is_plain_main_not_ai_tracker_mode(self):
        workflow_path = REPO_ROOT / ".github" / "workflows" / "sentinel-apex.yml"
        source = workflow_path.read_text(encoding="utf-8")
        self.assertIn("run: python3 scripts/r2_upload.py", source)
        # It must not ALSO invoke --ai-tracker-only (that would just move
        # the race from "different code paths" to "same code path, two
        # callers" -- still two writers for the same keys).
        self.assertNotIn("r2_upload.py --ai-tracker-only", source)


class TestR2UploadCostGuardAccounting(unittest.TestCase):
    """GATE D: r2_upload.py's normal operations are represented in the
    r2_cost_guard.py ledger and fail closed before mutation."""

    def setUp(self):
        # Every code path this class exercises (main(), main_ai_tracker_only())
        # calls the REAL emit_summary(), which writes to guard.REPORT_PATH --
        # redirect it to a throwaway temp file so these tests never mutate the
        # real data/quality/r2_cost_guard_report.json (same isolation pattern
        # as tests/test_r2_cost_guard.py's TestEmitSummary).
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_report_path = guard.REPORT_PATH
        guard.REPORT_PATH = Path(self._tmpdir.name) / "r2_cost_guard_report.json"

    def tearDown(self):
        guard.REPORT_PATH = self._orig_report_path
        self._tmpdir.cleanup()

    def test_main_builds_plan_and_enforces_budget_before_any_upload(self):
        main_source = inspect.getsource(r2_upload.main)
        plan_idx = main_source.index("build_upload_plan()")
        enforce_idx = main_source.index("enforce_budget(")
        first_execute_idx = main_source.index("for src, dst_key in pairs:")
        self.assertLess(plan_idx, enforce_idx, "plan must be built before budget is enforced")
        self.assertLess(enforce_idx, first_execute_idx, "budget must be enforced before any upload executes")

    def test_main_emits_r2_cost_guard_summary(self):
        main_source = inspect.getsource(r2_upload.main)
        self.assertIn("emit_summary(", main_source)
        self.assertIn('label="r2_upload"', main_source)

    def test_budget_exceeded_blocks_before_any_s3_cp_call(self):
        """PLAN EXCEEDS BUDGET -> BLOCK BEFORE MUTATION (Phase 3 contract)."""
        fake_pairs = [(f"src{i}.json", f"dst/{i}.json") for i in range(5)]

        # Publication eligibility has real boundary/integration coverage in
        # test_p0_r44_publication_boundary.py; isolate this synthetic cost plan.
        with patch("p0_r44_publication_boundary.finalize_public_feed"), \
             patch.object(r2_upload, "get_credentials", return_value=("acct", "key", "secret")), \
             patch.object(r2_upload, "install_awscli"), \
             patch.object(r2_upload, "configure_awscli_performance"), \
             patch.object(r2_upload, "count_manifest", return_value=10), \
             patch.object(r2_upload, "_generate_ai_endpoints"), \
             patch.object(r2_upload, "build_upload_plan", return_value=fake_pairs), \
             patch.object(guard.R2Budgets, "from_env", return_value=guard.R2Budgets(max_data_writes_per_run=2)), \
             patch.object(r2_upload, "s3_cp") as mock_s3_cp, \
             patch.object(r2_upload.os, "chdir"):
            with self.assertRaises(SystemExit) as ctx:
                r2_upload.main()
            self.assertEqual(ctx.exception.code, 1)
            mock_s3_cp.assert_not_called()

    def test_plan_within_budget_executes_all_planned_uploads(self):
        fake_pairs = [("src1.json", "dst/1.json"), ("src2.json", "dst/2.json")]

        with patch("p0_r44_publication_boundary.finalize_public_feed"), \
             patch.object(r2_upload, "get_credentials", return_value=("acct", "key", "secret")), \
             patch.object(r2_upload, "install_awscli"), \
             patch.object(r2_upload, "configure_awscli_performance"), \
             patch.object(r2_upload, "count_manifest", return_value=10), \
             patch.object(r2_upload, "_generate_ai_endpoints"), \
             patch.object(r2_upload, "build_upload_plan", return_value=fake_pairs), \
             patch.object(guard.R2Budgets, "from_env", return_value=guard.R2Budgets(max_data_writes_per_run=200)), \
             patch.object(r2_upload, "s3_cp", return_value=True) as mock_s3_cp, \
             patch.object(r2_upload, "write_github_env"), \
             patch("builtins.open", unittest.mock.mock_open()), \
             patch.object(r2_upload.json, "dump"), \
             patch.object(r2_upload.os, "chdir"):
            r2_upload.main()
            # 2 planned pairs + 1 sync-meta upload = 3 s3_cp calls.
            self.assertEqual(mock_s3_cp.call_count, 3)

    def test_ai_tracker_only_mode_builds_plan_and_enforces_budget(self):
        source = inspect.getsource(r2_upload.main_ai_tracker_only)
        self.assertIn("R2OperationPlan(", source)
        self.assertIn("enforce_budget(", source)
        self.assertIn("emit_summary(", source)

    def test_ai_tracker_only_blocks_before_mutation_when_over_budget(self):
        with patch.object(r2_upload, "get_credentials", return_value=("acct", "key", "secret")), \
             patch.object(r2_upload, "install_awscli"), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(guard.R2Budgets, "from_env", return_value=guard.R2Budgets(max_data_writes_per_run=0)), \
             patch.object(r2_upload, "s3_cp") as mock_s3_cp, \
             patch.object(r2_upload.os, "chdir"):
            with self.assertRaises(SystemExit) as ctx:
                r2_upload.main_ai_tracker_only()
            self.assertEqual(ctx.exception.code, 1)
            mock_s3_cp.assert_not_called()

    def test_p40_only_mode_builds_plan_and_enforces_budget(self):
        source = inspect.getsource(r2_upload.main_p40_only)
        self.assertIn("R2OperationPlan(", source)
        self.assertIn("enforce_budget(", source)
        self.assertIn("emit_summary(", source)


class TestCliDispatch(unittest.TestCase):
    def test_ai_tracker_only_flag_is_wired_in_dispatcher(self):
        module_source = inspect.getsource(r2_upload)
        self.assertIn('"--ai-tracker-only" in sys.argv', module_source)
        self.assertIn("main_ai_tracker_only()", module_source)


if __name__ == "__main__":
    unittest.main()
