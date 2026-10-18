#!/usr/bin/env python3
"""P0: Bounded publisher subprocess/overall deadlines, no false publication PASS."""
import subprocess
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import r2_upload
import r2_report_publisher as pub


class TestAwsPerObjectDeadline(unittest.TestCase):
    def test_single_object_upload_timeout_is_bounded_and_reports_failure(self):
        with patch.object(r2_upload.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("aws", 30)) as run:
            ok = r2_upload.s3_cp("/tmp/report.html", "reports", "reports/a.html",
                                 "https://example.invalid", timeout_seconds=30)
        self.assertFalse(ok)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_single_object_delete_timeout_is_bounded_and_reports_failure(self):
        with patch.object(r2_upload.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("aws", 30)) as run:
            ok = r2_upload.s3_delete("reports", "reports/a.html",
                                     "https://example.invalid", timeout_seconds=30)
        self.assertFalse(ok)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_omitted_deadline_preserves_prior_generic_upload_behavior(self):
        fake = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(r2_upload.subprocess, "run", return_value=fake) as run:
            ok = r2_upload.s3_cp("/tmp/a.json", "data", "api/a.json", "https://example.invalid")
        self.assertTrue(ok)
        self.assertIsNone(run.call_args.kwargs["timeout"])


class TestPublicationBoundaries(unittest.TestCase):
    def test_expired_whole_stage_deadline_issues_no_extra_r2_ops(self):
        put = [{"id": "intel--fixture", "kind": "html",
                "key": "reports/x.html", "local_path": Path("/tmp/nonexistent"),
                "sha256": "a" * 64}]
        with patch.object(pub, "s3_cp") as copy, patch.object(pub, "s3_delete") as delete, \
             patch.object(pub, "clear_report_urls", return_value=[]):
            result = pub.execute_plan(put, [], {"items": {}},
                                      "https://example.invalid", deadline_monotonic=0.0)
        self.assertEqual(result, (0, 0))
        copy.assert_not_called()
        delete.assert_not_called()

    def test_put_propagates_explicit_maximum_30_second_timeout(self):
        put = [{"id": "intel--fixture", "kind": "html",
                "key": "reports/x.html", "local_path": Path("/tmp/nonexistent"),
                "sha256": "a" * 64}]
        with patch.object(pub, "s3_cp", return_value=True) as copy, \
             patch.object(pub, "clear_report_urls", return_value=[]):
            result = pub.execute_plan(put, [], {"items": {}},
                                      "https://example.invalid",
                                      deadline_monotonic=time.monotonic() + 120)
        self.assertEqual(result, (1, 0))
        timeout = copy.call_args.kwargs["timeout_seconds"]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 30)

    def test_partial_report_publish_saves_successes_but_reports_blocked(self):
        plan = pub.R2OperationPlan(label="fixture", bucket=pub.BUCKET_REPORTS)
        budget = SimpleNamespace(max_report_deletes_per_run=500)
        state = {"schema_version": "1.0", "items": {}}
        patches = [
            patch.object(pub, "report_publishing_enabled", return_value=True),
            patch.object(pub, "_load_json", return_value=[]),
            patch.object(pub, "_get_items", return_value=[]),
            patch.object(pub, "load_publish_state", return_value=state),
            patch.object(pub, "apply_tlp_gate", return_value=([], [])),
            patch.object(pub, "write_tlp_quarantine_report"),
            patch.object(pub, "build_publish_candidates", return_value=[]),
            patch.object(pub.R2Budgets, "from_env", return_value=budget),
            patch.object(pub, "build_plan", return_value=(plan, [{"id": "x"}], [])),
            patch.object(pub, "enforce_budget"),
            patch.object(pub, "get_credentials", return_value=("account", "", "")),
            patch.object(pub, "install_awscli"),
            patch.object(pub, "execute_plan", return_value=(0, 0)),
            patch.object(pub, "save_publish_state"),
            patch.object(pub, "emit_summary"),
            patch.object(sys, "argv", ["r2_report_publisher.py"]),
        ]
        for p in patches:
            p.start()
        try:
            result = pub.main()
            self.assertEqual(result, 1, "a customer report was not published")
            pub.save_publish_state.assert_called_once_with(state)
            self.assertEqual(pub.emit_summary.call_args.kwargs["status"], "BLOCKED")
        finally:
            for p in reversed(patches):
                p.stop()


if __name__ == "__main__":
    unittest.main()
