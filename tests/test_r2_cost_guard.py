#!/usr/bin/env python3
"""
tests/test_r2_cost_guard.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- P0 R2 Cost Incident: cost-guard regression tests.

Locks in scripts/r2_cost_guard.py's fail-closed budget contract so it cannot
silently regress into a warning-only or continue-on-error posture. See
docs/P0_R2_COST_CONTAINMENT.md for the incident this guards against.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import r2_cost_guard as guard  # noqa: E402


class TestBudgetEnforcement(unittest.TestCase):
    def test_plan_within_budget_does_not_raise(self):
        plan = guard.R2OperationPlan(label="t", bucket="b")
        plan.record_put(10)
        plan.record_delete(5)
        budgets = guard.R2Budgets(max_report_writes_per_run=500, max_report_deletes_per_run=500,
                                   max_list_calls_per_run=0, max_data_writes_per_run=200)
        guard.enforce_budget(plan, budgets, is_report_plan=True)  # must not raise

    def test_put_over_budget_raises_before_any_mutation_flag(self):
        """The whole point of this function: it is called to decide whether
        to mutate, so it must be a pure decision -- callers rely on the
        exception firing before they issue a single real R2 call."""
        plan = guard.R2OperationPlan(label="t", bucket="b")
        plan.record_put(501)
        budgets = guard.R2Budgets(max_report_writes_per_run=500, max_report_deletes_per_run=500,
                                   max_list_calls_per_run=0, max_data_writes_per_run=200)
        with self.assertRaises(guard.R2BudgetExceeded) as ctx:
            guard.enforce_budget(plan, budgets, is_report_plan=True)
        self.assertIn("MAX_REPORT_UPLOADS_PER_RUN", str(ctx.exception))

    def test_delete_over_budget_raises(self):
        plan = guard.R2OperationPlan(label="t", bucket="b")
        plan.record_delete(501)
        budgets = guard.R2Budgets()
        with self.assertRaises(guard.R2BudgetExceeded) as ctx:
            guard.enforce_budget(plan, budgets, is_report_plan=True)
        self.assertIn("MAX_REPORT_DELETIONS_PER_RUN", str(ctx.exception))

    def test_any_list_call_at_all_raises_by_default(self):
        """The recurring publish path is designed to need ZERO LIST calls --
        the default ceiling is 0, so even a single LIST is a budget breach,
        not a tolerated norm (see scripts/r2_report_publisher.py's module
        docstring)."""
        plan = guard.R2OperationPlan(label="t", bucket="b")
        plan.record_list(1, reason="accidental bucket enumeration")
        budgets = guard.R2Budgets()
        with self.assertRaises(guard.R2BudgetExceeded) as ctx:
            guard.enforce_budget(plan, budgets, is_report_plan=True)
        self.assertIn("MAX_R2_LIST_CALLS_PER_RUN", str(ctx.exception))

    def test_data_bucket_uses_separate_write_ceiling(self):
        plan = guard.R2OperationPlan(label="t", bucket="sentinel-apex-data")
        plan.record_put(150)  # over the data-bucket default (100 is not the default; use explicit)
        budgets = guard.R2Budgets(max_data_writes_per_run=100)
        with self.assertRaises(guard.R2BudgetExceeded) as ctx:
            guard.enforce_budget(plan, budgets, is_report_plan=False)
        self.assertIn("MAX_R2_DATA_WRITES_PER_RUN", str(ctx.exception))
        # Same plan against the (much larger) report-bucket ceiling passes --
        # proves the two ceilings are genuinely independent, not aliased.
        report_budgets = guard.R2Budgets(max_report_writes_per_run=500)
        guard.enforce_budget(plan, report_budgets, is_report_plan=True)

    def test_multiple_violations_all_reported_together(self):
        plan = guard.R2OperationPlan(label="t", bucket="b")
        plan.record_put(600)
        plan.record_delete(600)
        plan.record_list(1)
        budgets = guard.R2Budgets()
        with self.assertRaises(guard.R2BudgetExceeded) as ctx:
            guard.enforce_budget(plan, budgets, is_report_plan=True)
        msg = str(ctx.exception)
        self.assertIn("MAX_REPORT_UPLOADS_PER_RUN", msg)
        self.assertIn("MAX_REPORT_DELETIONS_PER_RUN", msg)
        self.assertIn("MAX_R2_LIST_CALLS_PER_RUN", msg)


class TestPreviouslyUnboundedMeteredOperations(unittest.TestCase):
    def test_copy_is_zero_budget_by_default(self):
        plan = guard.R2OperationPlan(label="test", bucket="data")
        plan.record_copy(1)
        with self.assertRaisesRegex(guard.R2BudgetExceeded, "MAX_R2_COPY_CALLS_PER_RUN"):
            guard.enforce_budget(plan, guard.R2Budgets(), is_report_plan=False)

    def test_multipart_is_zero_budget_by_default(self):
        plan = guard.R2OperationPlan(label="test", bucket="data")
        plan.record_multipart(1)
        with self.assertRaisesRegex(guard.R2BudgetExceeded, "MAX_R2_MULTIPART_CALLS_PER_RUN"):
            guard.enforce_budget(plan, guard.R2Budgets(), is_report_plan=False)

    def test_class_b_read_ceiling_is_enforced_across_head_and_get(self):
        plan = guard.R2OperationPlan(label="test", bucket="reports")
        plan.record_head(1200)
        plan.record_get(801)
        with self.assertRaisesRegex(guard.R2BudgetExceeded, "MAX_R2_CLASS_B_CALLS_PER_RUN"):
            guard.enforce_budget(plan, guard.R2Budgets(), is_report_plan=True)

    def test_bounded_read_only_verification_still_allowed(self):
        plan = guard.R2OperationPlan(label="test", bucket="reports")
        plan.record_head(200)
        plan.record_get(200)
        guard.enforce_budget(plan, guard.R2Budgets(), is_report_plan=True)

    def test_negative_or_noninteger_counts_cannot_satisfy_budgets(self):
        for count in (-1, 0.5, True):
            with self.subTest(count=count):
                plan = guard.R2OperationPlan(label="test", bucket="reports")
                plan.put = count
                with self.assertRaisesRegex(guard.R2BudgetExceeded, "INVALID_R2_OPERATION_COUNT"):
                    guard.enforce_budget(plan, guard.R2Budgets())

    def test_negative_ceiling_cannot_be_used_to_authorize_io(self):
        plan = guard.R2OperationPlan(label="test", bucket="reports")
        budget = guard.R2Budgets(max_class_b_calls_per_run=-1)
        with self.assertRaisesRegex(guard.R2BudgetExceeded, "INVALID_R2_BUDGET_CEILING"):
            guard.enforce_budget(plan, budget)


class TestEstimatedClassA(unittest.TestCase):
    def test_class_a_excludes_delete(self):
        """Billing-accuracy contract (module docstring): Cloudflare R2 does
        not bill DeleteObject as Class A -- estimated_class_a() must not
        double-count delete-heavy runs as expensive when they are not."""
        plan = guard.R2OperationPlan(label="t", bucket="b")
        plan.record_put(10)
        plan.record_delete(1000)
        plan.record_list(2)
        plan.record_copy(3)
        self.assertEqual(plan.estimated_class_a(), 10 + 2 + 3)

    def test_expired_is_item_level_delete_is_operation_level(self):
        """One expired item with both an html and a pdf object must count
        as 1 expired item but 2 delete operations."""
        plan = guard.R2OperationPlan(label="t", bucket="b")
        plan.record_expired()
        plan.record_delete(expired=False)
        plan.record_delete(expired=False)
        self.assertEqual(plan.expired, 1)
        self.assertEqual(plan.delete, 2)


class TestEnvDrivenConfig(unittest.TestCase):
    def test_pre_revenue_cost_mode_defaults_true(self):
        env_backup = os.environ.pop("PRE_REVENUE_COST_MODE", None)
        try:
            self.assertTrue(guard.is_pre_revenue_cost_mode())
        finally:
            if env_backup is not None:
                os.environ["PRE_REVENUE_COST_MODE"] = env_backup

    def test_pre_revenue_cost_mode_false_is_respected(self):
        env_backup = os.environ.get("PRE_REVENUE_COST_MODE")
        os.environ["PRE_REVENUE_COST_MODE"] = "false"
        try:
            self.assertFalse(guard.is_pre_revenue_cost_mode())
        finally:
            if env_backup is None:
                os.environ.pop("PRE_REVENUE_COST_MODE", None)
            else:
                os.environ["PRE_REVENUE_COST_MODE"] = env_backup

    def test_pre_revenue_cost_mode_case_mismatch_is_still_respected(self):
        """Phase 6 contract: PRE_REVENUE_COST_MODE must not silently fail
        open on a case mismatch (e.g. a workflow author writing "False" or
        "FALSE" instead of the exact lowercase "false")."""
        env_backup = os.environ.get("PRE_REVENUE_COST_MODE")
        for value in ("False", "FALSE", "  false  ", "FaLsE"):
            os.environ["PRE_REVENUE_COST_MODE"] = value
            try:
                self.assertFalse(
                    guard.is_pre_revenue_cost_mode(),
                    f"PRE_REVENUE_COST_MODE={value!r} must still be recognized as false",
                )
            finally:
                if env_backup is None:
                    os.environ.pop("PRE_REVENUE_COST_MODE", None)
                else:
                    os.environ["PRE_REVENUE_COST_MODE"] = env_backup

    def test_pre_revenue_cost_mode_empty_string_defaults_to_strict(self):
        """An empty env var (workflow sets `PRE_REVENUE_COST_MODE: ""`) must
        default to the SAFE (strict) posture, not silently disable it."""
        env_backup = os.environ.get("PRE_REVENUE_COST_MODE")
        os.environ["PRE_REVENUE_COST_MODE"] = ""
        try:
            self.assertTrue(guard.is_pre_revenue_cost_mode())
        finally:
            if env_backup is None:
                os.environ.pop("PRE_REVENUE_COST_MODE", None)
            else:
                os.environ["PRE_REVENUE_COST_MODE"] = env_backup

    def test_pre_revenue_cost_mode_malformed_value_defaults_to_strict(self):
        """Any value other than an exact (case/whitespace-insensitive) match
        for "false" must fail closed to the strict/safe posture -- a typo'd
        workflow env var must never silently restore unbounded behavior."""
        env_backup = os.environ.get("PRE_REVENUE_COST_MODE")
        for value in ("maybe", "0", "no", "disabled"):
            os.environ["PRE_REVENUE_COST_MODE"] = value
            try:
                self.assertTrue(
                    guard.is_pre_revenue_cost_mode(),
                    f"PRE_REVENUE_COST_MODE={value!r} (not exactly 'false') must "
                    "default to strict mode, not be treated as disabling it",
                )
            finally:
                if env_backup is None:
                    os.environ.pop("PRE_REVENUE_COST_MODE", None)
                else:
                    os.environ["PRE_REVENUE_COST_MODE"] = env_backup

    def test_budgets_from_env_uses_evidence_based_defaults_when_unset(self):
        for var in ("MAX_REPORT_UPLOADS_PER_RUN", "MAX_REPORT_DELETIONS_PER_RUN",
                     "MAX_R2_LIST_CALLS_PER_RUN", "MAX_R2_DATA_WRITES_PER_RUN"):
            os.environ.pop(var, None)
        budgets = guard.R2Budgets.from_env()
        self.assertEqual(budgets.max_report_writes_per_run, 500)
        self.assertEqual(budgets.max_report_deletes_per_run, 500)
        self.assertEqual(budgets.max_list_calls_per_run, 0)
        self.assertEqual(budgets.max_data_writes_per_run, 200)

    def test_budgets_from_env_malformed_value_falls_back_to_default(self):
        os.environ["MAX_REPORT_UPLOADS_PER_RUN"] = "not-a-number"
        try:
            budgets = guard.R2Budgets.from_env()
            self.assertEqual(budgets.max_report_writes_per_run, 500)
        finally:
            os.environ.pop("MAX_REPORT_UPLOADS_PER_RUN", None)


class TestEmitSummary(unittest.TestCase):
    def test_emit_summary_writes_valid_json_report(self):
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "r2_cost_guard_report.json"
            orig_path = guard.REPORT_PATH
            guard.REPORT_PATH = report_path
            try:
                plan = guard.R2OperationPlan(label="test_stage", bucket="sentinel-apex-reports")
                plan.record_put(5)
                plan.record_new(5)
                budgets = guard.R2Budgets()
                result = guard.emit_summary(plan, budgets, status="PASS", is_report_plan=True)
                self.assertTrue(report_path.exists())
                on_disk = json.loads(report_path.read_text())
                self.assertEqual(on_disk["overall_status"], "PASS")
                self.assertIn("test_stage", on_disk["plans"])
                self.assertEqual(on_disk["plans"]["test_stage"]["put"], 5)
                self.assertEqual(result, on_disk)
            finally:
                guard.REPORT_PATH = orig_path

    def test_emit_summary_merges_multiple_plans_without_clobbering(self):
        """r2_upload.py and r2_report_publisher.py both call emit_summary in
        the same pipeline run -- the second call must not erase the first's
        entry (Section 8's per-run accounting requires seeing the WHOLE
        run's R2 footprint, not just the last stage that reported)."""
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "r2_cost_guard_report.json"
            orig_path = guard.REPORT_PATH
            guard.REPORT_PATH = report_path
            try:
                budgets = guard.R2Budgets()
                plan_a = guard.R2OperationPlan(label="stage_a", bucket="sentinel-apex-data")
                plan_a.record_put(3)
                guard.emit_summary(plan_a, budgets, status="PASS", is_report_plan=False)

                plan_b = guard.R2OperationPlan(label="stage_b", bucket="sentinel-apex-reports")
                plan_b.record_put(7)
                result = guard.emit_summary(plan_b, budgets, status="PASS", is_report_plan=True)

                self.assertIn("stage_a", result["plans"])
                self.assertIn("stage_b", result["plans"])
                self.assertEqual(result["plans"]["stage_a"]["put"], 3)
                self.assertEqual(result["plans"]["stage_b"]["put"], 7)
            finally:
                guard.REPORT_PATH = orig_path

    def test_emit_summary_overall_status_blocked_if_any_plan_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "r2_cost_guard_report.json"
            orig_path = guard.REPORT_PATH
            guard.REPORT_PATH = report_path
            try:
                budgets = guard.R2Budgets()
                guard.emit_summary(guard.R2OperationPlan(label="ok_stage", bucket="b"), budgets, status="PASS")
                result = guard.emit_summary(guard.R2OperationPlan(label="bad_stage", bucket="b"), budgets, status="BLOCKED")
                self.assertEqual(result["overall_status"], "BLOCKED")
            finally:
                guard.REPORT_PATH = orig_path


if __name__ == "__main__":
    unittest.main()
