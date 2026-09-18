"""
tests/test_backup_workflow_timeout_isolation.py

P0 regression guard (2026-09-18, Telegram staleness-alert incident):
automated-backup.yml's cf-data-backup job ("Cloudflare KV + R2 Backup") has
continue-on-error: true since it was authored, specifically so this optional
mirror job never blocks the real encrypted backup (full-backup, a sibling
job in the same workflow). That protection turned out to have a gap: once
SECURITY_HUB_KV grew to ~92,400 keys (50x+ every other KV namespace here
combined), its "Backup KV namespaces to R2" step could no longer finish
inside the job's 30min timeout-minutes even with the 10-way parallel fetch
(tests/test_backup_kv_to_r2_parallel_fetch.py) -- confirmed live across
every run of this workflow from 2026-09-11 through 2026-09-18 (8/8 days).

A runner-enforced timeout-minutes kill produces job conclusion "cancelled",
and continue-on-error only absorbs "failure" -- it does not absorb
"cancelled". Confirmed live via the Actions API that a cancelled
cf-data-backup dragged automated-backup.yml's WHOLE workflow run conclusion
to "cancelled" on all 8 of those days, even though full-backup (the actual
encrypted backup) succeeded in under a minute every single time.
scripts/check_pipeline_staleness.py asks the Actions API for the most
recent run with status=success on this workflow file -- finding none since
2026-09-10, it correctly (on objectively wrong input) told Telegram this
platform's backup pipeline was down for over a week, 4x/day. The same
mechanism silenced "Notify on CF backup failure" (if: failure()) below,
which never fires for a cancelled conclusion either -- so nobody got a
specific, correct alert about the real, narrow issue.

Fix (automated-backup.yml): the risky step now self-bounds its own runtime
via a shell `timeout <seconds>` wrapper, safely under the job's own
timeout-minutes ceiling. That converts an uncontrolled runner cancellation
into an ordinary, continue-on-error-safe non-zero exit (124), which
if: failure() below correctly sees. This is the same class of bug already
found and fixed at STEP granularity in sentinel-blogger.yml (see its
"Upload Intel State to R2 (final, post-enrichment)" and "STAGE 5.4.0b" step
comments) -- reused here at JOB granularity, since GitHub Actions has no
"job timeout continue-on-error actually absorbs" primitive of its own.

This test locks the structural invariant in place (TestJobLevelTimeout...)
and separately proves the actual shell logic behaves as intended for all
three real outcomes -- success, a genuine script failure, and a self-timeout
-- by executing the real `run:` script text from the workflow file against a
stub backup_kv_to_r2.py (TestRunScriptBehavesAsIntended).
"""
import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "automated-backup.yml"

# Mirrors test_pipeline_staleness_thresholds.py's SAFETY_FACTOR philosophy:
# the internal soft-timeout must leave real headroom under the job's own
# hard timeout-minutes for job setup plus whatever steps run after it, not
# just be numerically smaller than it.
MIN_MARGIN_SECONDS = 300  # >= 5 minutes for setup + the 3 steps after this one
MAX_BUDGET_FRACTION = 0.8  # soft-timeout may use at most 80% of the job's ceiling


def _load_cf_data_backup_job():
    doc = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    return doc["jobs"]["cf-data-backup"]


def _step(job, name):
    return next(s for s in job["steps"] if s["name"] == name)


class TestJobLevelTimeoutCannotPoisonRunConclusion(unittest.TestCase):
    def setUp(self):
        self.job = _load_cf_data_backup_job()
        self.step = _step(self.job, "Backup KV namespaces to R2")

    def test_job_keeps_continue_on_error(self):
        self.assertTrue(
            self.job.get("continue-on-error"),
            "cf-data-backup must stay continue-on-error: true -- this job "
            "is an optional mirror and must never block the real backup.",
        )

    def test_step_self_bounds_below_the_job_timeout(self):
        job_timeout_s = self.job["timeout-minutes"] * 60
        run_script = self.step["run"]

        m = re.search(r"\btimeout\s+(\d+)\s+python3\s+scripts/backup_kv_to_r2\.py", run_script)
        self.assertIsNotNone(
            m,
            "'Backup KV namespaces to R2' must invoke backup_kv_to_r2.py through "
            "a shell `timeout <seconds>` wrapper -- without it, a slow export is "
            "at the mercy of the job's own timeout-minutes, which produces a "
            "'cancelled' conclusion that continue-on-error does not absorb.",
        )
        soft_timeout_s = int(m.group(1))

        self.assertLess(
            soft_timeout_s, job_timeout_s,
            "the internal soft-timeout must be strictly less than the job's own "
            "timeout-minutes, or the runner's hard kill (an unabsorbable "
            "'cancelled' conclusion) can still win the race.",
        )
        self.assertLessEqual(
            soft_timeout_s, job_timeout_s * MAX_BUDGET_FRACTION,
            f"soft-timeout uses more than {MAX_BUDGET_FRACTION:.0%} of the job's "
            f"own {job_timeout_s}s ceiling -- too little margin for job setup "
            f"plus the steps that run after this one.",
        )
        self.assertGreaterEqual(
            job_timeout_s - soft_timeout_s, MIN_MARGIN_SECONDS,
            f"less than {MIN_MARGIN_SECONDS}s of margin is left under the job's "
            f"timeout-minutes for setup and the remaining steps in this job.",
        )

    def test_timeout_exit_code_124_is_explicitly_surfaced(self):
        """A silent partial backup is its own (lesser) incident -- 124 (the
        documented `timeout(1)` exit code) must be recognized and annotated,
        not just swallowed into a generic non-zero exit."""
        run_script = self.step["run"]
        self.assertIn("124", run_script)
        self.assertIn("::warning::", run_script)

    def test_missing_cf_credentials_still_skips_cleanly(self):
        """Pre-existing behavior (unrelated to this fix) must survive:
        missing CF_API_TOKEN/CF_ACCOUNT_ID is an expected, non-error SKIP,
        which the new timeout wrapper must never be reached to override."""
        run_script = self.step["run"]
        self.assertIn("exit 0", run_script.split("timeout ")[0])

    def test_notify_on_cf_backup_failure_step_still_gated_on_failure(self):
        """The whole point of converting a runner cancellation into an
        ordinary non-zero exit is so this step's if: failure() can finally
        see it. If this step ever loses its if: failure() gate (or the gate
        is weakened), the fix above stops mattering."""
        notify_step = _step(self.job, "Notify on CF backup failure")
        self.assertEqual(notify_step.get("if"), "failure()")


class TestRunScriptBehavesAsIntended(unittest.TestCase):
    """End-to-end behavioral proof, not just a YAML-shape check: executes the
    ACTUAL `run:` shell text from the workflow file (so a future edit to its
    logic is verified, not just today's literal `timeout N` prefix) against
    a stub backup_kv_to_r2.py, for all three real outcomes."""

    def setUp(self):
        job = _load_cf_data_backup_job()
        self.run_script = _step(job, "Backup KV namespaces to R2")["run"]

    def _run(self, stub_body: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            scripts_dir = tmp_path / "scripts"
            scripts_dir.mkdir()
            (scripts_dir / "backup_kv_to_r2.py").write_text(textwrap.dedent(stub_body))
            # Exercise the real workflow shell text at a short, fast-test
            # budget instead of its real 1200s, by rewriting only the numeric
            # budget -- every other character (the SKIP guard, the STATUS
            # capture, the 124 handling, the final `exit`) is the unmodified
            # text this repo will actually run in CI.
            fast_script = re.sub(r"\btimeout\s+\d+\b", "timeout 1", self.run_script)
            script_path = tmp_path / "run.sh"
            script_path.write_text(fast_script)
            env = {**os.environ, "CF_API_TOKEN": "x", "CF_ACCOUNT_ID": "y"}
            return subprocess.run(
                ["bash", str(script_path)],
                cwd=tmp_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )

    def test_fast_success_exits_zero_with_no_warning(self):
        result = self._run("import sys; sys.exit(0)")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("::warning::", result.stdout + result.stderr)

    def test_real_script_failure_still_propagates_its_own_code(self):
        result = self._run("import sys; sys.exit(3)")
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(
            "::warning::", result.stdout + result.stderr,
            "a real script failure is not a timeout -- must not be mislabeled as one.",
        )

    def test_slow_script_self_terminates_as_124_with_warning_not_hung(self):
        result = self._run("import time; time.sleep(30)")
        self.assertEqual(result.returncode, 124)
        self.assertIn("::warning::", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
