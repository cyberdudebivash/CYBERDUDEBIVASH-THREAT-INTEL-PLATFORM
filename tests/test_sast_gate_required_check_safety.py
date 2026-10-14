#!/usr/bin/env python3
"""
tests/test_sast_gate_required_check_safety.py

P0 (2026-09-10): sast-security-scan.yml's `SAST Gate (required)` job is
intended to become a required branch status check on main. GitHub's
documented behavior for a required check whose workflow is path-filtered is
that a PR touching none of the listed paths never triggers the workflow at
all -- the check stays "Expected"/pending forever and permanently blocks
merging that PR. The workflow's `pull_request:` trigger carried exactly
such a path filter before this commit.

Fixed by removing that filter (the workflow now runs on every PR to
main/develop) and adding a `changes` job that classifies what actually
changed, driving each expensive scanner's own `if:` condition -- so an
unrelated PR still doesn't pay for a full Bandit/pip-audit/Semgrep run, it
just always produces a real, deterministic SAST Gate result instead of
never running at all.

This file proves that design mechanically, from the actual workflow file
and the actual bash classification logic inside it -- not a hand-written
reimplementation that could quietly drift out of sync with the real thing.
"""
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SAST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sast-security-scan.yml"

CONDITIONAL_JOBS = {
    "bandit": "python_relevant",
    "safety": "dependency_relevant",
    "semgrep": "semgrep_relevant",
    "scripts-sast": "scripts_relevant",
}
MANDATORY_JOBS = {"changes", "trufflehog", "workflow-hygiene"}
GATE_JOB_ID = "sast-gate"
GATE_JOB_NAME = "SAST Gate (required)"


def _load_workflow() -> dict:
    return yaml.safe_load(SAST_WORKFLOW.read_text(encoding="utf-8"))


def _jobs() -> dict:
    return _load_workflow()["jobs"]


class TestRequiredCheckCannotDeadlock(unittest.TestCase):
    def test_pull_request_trigger_has_no_paths_filter(self):
        doc = _load_workflow()
        on_block = doc.get(True, doc.get("on"))  # PyYAML parses bare `on:` as bool True
        pr_trigger = on_block.get("pull_request")
        self.assertIsNotNone(pr_trigger, "sast-security-scan.yml must still trigger on pull_request")
        self.assertNotIn(
            "paths", pr_trigger or {},
            "pull_request trigger has a 'paths:' filter again -- this is exactly the "
            "condition that deadlocks a required check: a PR touching none of the "
            "listed paths never triggers this workflow, so 'SAST Gate (required)' "
            "stays pending forever and permanently blocks that PR's merge.",
        )

    def test_push_trigger_keeps_its_own_unrelated_paths_filter(self):
        """The push: filter is a separate, pre-existing cost optimization, not
        part of the required-check deadlock (direct pushes to main aren't
        gated by a PR-required-check) -- confirms this fix didn't touch it."""
        doc = _load_workflow()
        on_block = doc.get(True, doc.get("on"))
        push_trigger = on_block.get("push")
        self.assertIn("paths", push_trigger or {}, "push: trigger's pre-existing path filter should be untouched")


class TestGateJobIdentityIsStable(unittest.TestCase):
    def test_sast_gate_job_id_and_name_unchanged(self):
        jobs = _jobs()
        self.assertIn(GATE_JOB_ID, jobs, f"job id '{GATE_JOB_ID}' must exist -- this is what a branch ruleset binds to")
        self.assertEqual(
            jobs[GATE_JOB_ID].get("name"), GATE_JOB_NAME,
            f"the gate job's display name must stay exactly {GATE_JOB_NAME!r} -- "
            f"that literal string is what gets bound as the required status check",
        )

    def test_sast_gate_runs_unconditionally_via_always(self):
        jobs = _jobs()
        self.assertEqual(
            jobs[GATE_JOB_ID].get("if"), "always()",
            "sast-gate must run even when an upstream job fails/is skipped, or it "
            "could itself disappear instead of reporting a deterministic pass/fail",
        )


class TestMandatoryJobsAlwaysRunAndAreRequired(unittest.TestCase):
    def test_mandatory_jobs_have_no_suppressing_if_condition(self):
        jobs = _jobs()
        for job_id in MANDATORY_JOBS:
            self.assertIn(job_id, jobs, f"mandatory job '{job_id}' is missing entirely")
            self.assertNotIn(
                "if", jobs[job_id],
                f"'{job_id}' is supposed to be mandatory (runs on every trigger) but "
                f"has an `if:` condition that could skip it",
            )

    def test_mandatory_jobs_are_all_in_sast_gate_needs(self):
        needs = set(_jobs()[GATE_JOB_ID]["needs"])
        missing = MANDATORY_JOBS - needs
        self.assertEqual(missing, set(), f"sast-gate's needs: list is missing mandatory job(s): {missing}")


class TestConditionalScannersAreGovernedByChangeClassification(unittest.TestCase):
    def test_every_conditional_scanner_needs_changes_job(self):
        jobs = _jobs()
        for job_id in CONDITIONAL_JOBS:
            needs = jobs[job_id].get("needs")
            needs_set = {needs} if isinstance(needs, str) else set(needs or [])
            self.assertIn("changes", needs_set, f"'{job_id}' must declare needs: changes to consume its classification output")

    def test_every_conditional_scanner_if_references_its_own_output(self):
        """Proves the `if:` actually reads the matching classification output --
        not hardcoded true/false, not reading a different job's output, and
        not silently unconditional (which would defeat the whole point of
        classifying changes at all)."""
        jobs = _jobs()
        for job_id, output_name in CONDITIONAL_JOBS.items():
            if_cond = jobs[job_id].get("if", "")
            expected = f"needs.changes.outputs.{output_name}"
            self.assertIn(
                expected, if_cond,
                f"'{job_id}' job's if: condition ({if_cond!r}) does not reference "
                f"{expected} -- its execution is no longer actually governed by "
                f"whether its own surface changed",
            )

    def test_sast_gate_needs_includes_every_conditional_scanner(self):
        needs = set(_jobs()[GATE_JOB_ID]["needs"])
        missing = set(CONDITIONAL_JOBS) - needs
        self.assertEqual(missing, set(), f"sast-gate's needs: list is missing conditional scanner(s): {missing}")

    def test_sast_gate_check_step_treats_skip_as_valid_only_when_output_says_so(self):
        """Static proof that the gate's own bash doesn't just check for
        'failure' (the pre-fix behavior) -- it must reference each
        classification output to decide whether 'skipped' is acceptable."""
        jobs = _jobs()
        script = jobs[GATE_JOB_ID]["steps"][0]["run"]
        for output_name in CONDITIONAL_JOBS.values():
            env_var = output_name.upper()
            self.assertIn(
                env_var, script,
                f"SAST Gate's check script never references {env_var} -- it can't "
                f"be validating that a skipped conditional job was actually "
                f"classified non-applicable",
            )
        self.assertIn("skipped", script, "gate script must explicitly reason about the 'skipped' result")


class TestChangeClassificationLogicIsCorrect(unittest.TestCase):
    """Executes the REAL bash from the `changes` job's classification step
    against synthetic git history -- not a Python reimplementation that
    could drift from what actually runs in CI. Covers both scenarios named
    in the P0 spec: a docs-only PR and a source/workflow-relevant PR."""

    @classmethod
    def setUpClass(cls):
        jobs = _jobs()
        classify_step = next(s for s in jobs["changes"]["steps"] if s.get("id") == "classify")
        cls.script = classify_step["run"]

    def _run_classification(self, changed_files, event_name="pull_request"):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@test"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)

            for rel in ["README.md"]:
                (repo / rel).write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=repo, check=True)
            base_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
            ).stdout.strip()

            if changed_files:
                for rel in changed_files:
                    path = repo / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("changed\n", encoding="utf-8")
                subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
                subprocess.run(["git", "commit", "-q", "-m", "head"], cwd=repo, check=True)
                head_sha = subprocess.run(
                    ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
                ).stdout.strip()
            else:
                # Non-PR events (schedule/dispatch/push) never reach the git
                # diff at all -- the real script returns "everything relevant"
                # before looking at PR_BASE_SHA/PR_HEAD_SHA, so reusing the
                # base commit for both is fine here; there is no "head" to diff.
                head_sha = base_sha

            output_file = repo / "github_output.txt"
            env = {
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "EVENT_NAME": event_name,
                "PR_BASE_SHA": base_sha,
                "PR_HEAD_SHA": head_sha,
                "GITHUB_OUTPUT": str(output_file),
            }
            result = subprocess.run(
                ["bash", "-c", self.script], cwd=repo, env=env,
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, f"classify script exited non-zero: {result.stderr}")

            outputs = {}
            for line in output_file.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    outputs[k] = v
            return outputs

    def test_scenario_a_docs_only_pr_marks_nothing_relevant(self):
        """A PR touching only docs/README must not trigger any expensive
        scanner -- proves the classification narrows scope correctly."""
        outputs = self._run_classification(["docs/CHANGELOG.md"])
        self.assertEqual(outputs.get("python_relevant"), "false")
        self.assertEqual(outputs.get("dependency_relevant"), "false")
        self.assertEqual(outputs.get("semgrep_relevant"), "false")
        self.assertEqual(outputs.get("scripts_relevant"), "false")

    def test_scenario_b_source_change_pr_marks_the_right_scanners_relevant(self):
        """A PR touching agent/ source, a requirements file, and api/ must
        mark exactly the scanners actually governing those paths relevant."""
        outputs = self._run_classification([
            "agent/some_module.py",
            "requirements.txt",
            "api/some_data.json",
        ])
        self.assertEqual(outputs.get("python_relevant"), "true")
        self.assertEqual(outputs.get("dependency_relevant"), "true")
        self.assertEqual(outputs.get("semgrep_relevant"), "true")

    def test_scripts_python_change_requires_bounded_production_scanner(self):
        outputs = self._run_classification(["scripts/p0_r44_publication_boundary.py"])
        self.assertEqual(outputs.get("scripts_relevant"), "true")
        self.assertEqual(outputs.get("python_relevant"), "false")
        self.assertEqual(outputs.get("semgrep_relevant"), "false")
        self.assertEqual(outputs.get("dependency_relevant"), "false")

    def test_scripts_json_alone_is_not_a_python_scan_target(self):
        outputs = self._run_classification(["scripts/generated.json"])
        self.assertEqual(outputs.get("scripts_relevant"), "false")

    def test_api_json_alone_is_not_python_relevant_but_is_semgrep_relevant(self):
        """Confirms the deliberate asymmetry: Bandit only scans api/**.py
        (matches the old path filter's own restriction), Semgrep scans all
        of api/ -- a non-.py api/ change should reflect that difference."""
        outputs = self._run_classification(["api/some_data.json"])
        self.assertEqual(outputs.get("python_relevant"), "false")
        self.assertEqual(outputs.get("semgrep_relevant"), "true")

    def test_workflow_file_itself_changing_is_relevant_to_every_scanner(self):
        outputs = self._run_classification([".github/workflows/sast-security-scan.yml"])
        self.assertEqual(outputs.get("python_relevant"), "true")
        self.assertEqual(outputs.get("dependency_relevant"), "true")
        self.assertEqual(outputs.get("semgrep_relevant"), "true")

    def test_non_pull_request_event_marks_everything_relevant(self):
        """schedule/workflow_dispatch/push must keep scanning everything --
        this fix only narrows the pull_request case."""
        outputs = self._run_classification([], event_name="schedule")
        self.assertEqual(outputs.get("python_relevant"), "true")
        self.assertEqual(outputs.get("dependency_relevant"), "true")
        self.assertEqual(outputs.get("semgrep_relevant"), "true")
        self.assertEqual(outputs.get("scripts_relevant"), "true")



# ---------------------------------------------------------------------------
# CI reliability (2026-10-02): the classifier no longer clones the repository
# history. Over 37 PR runs its full-history checkout took a median 207 s of a
# 211 s job, max 299 s, and the 5-minute job timeout cancelled it twice (runs
# 1125 and 1133 attempt 1), failing the required gate closed with no finding.
# The step now fetches only the PR's base and head commits and their trees.
# These tests run the REAL step from an empty directory against a local bare
# "origin", so the fetch path itself is exercised, not only the diff.
# ---------------------------------------------------------------------------
def _git(cwd, *args, check=True):
    return subprocess.run(["git", *args], cwd=cwd, check=check, capture_output=True, text=True)


def _commit_all(repo, message):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


class _OriginFixture:
    """A source repo (base commit, head commit) published as a bare remote
    that, like GitHub, serves partial and by-SHA fetches."""

    def __init__(self, tmp, base_files, head_changes):
        self.root = pathlib.Path(tmp)
        src = self.root / "src"
        src.mkdir()
        _git(src, "init", "-q")
        _git(src, "config", "user.email", "test@test")
        _git(src, "config", "user.name", "test")
        for rel, content in {"README.md": "base\n", **base_files}.items():
            path = src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.base_sha = _commit_all(src, "base")
        for rel, content in head_changes.items():
            path = src / rel
            if content is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
        self.head_sha = _commit_all(src, "head") if head_changes else self.base_sha
        self.bare = self.root / "origin.git"
        _git(self.root, "clone", "-q", "--bare", str(src), str(self.bare))
        _git(self.bare, "config", "uploadpack.allowFilter", "true")
        _git(self.bare, "config", "uploadpack.allowAnySHA1InWant", "true")
        self.url = self.bare.resolve().as_uri()


class TestClassifierFetchesOnlyTheTwoCommits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        jobs = _jobs()
        cls.changes_job = jobs["changes"]
        cls.script = next(s for s in jobs["changes"]["steps"] if s.get("id") == "classify")["run"]

    def _run(self, base_files, head_changes, *, repo_url=None, base_sha=None, head_sha=None):
        with tempfile.TemporaryDirectory() as tmp:
            origin = _OriginFixture(tmp, base_files, head_changes)
            work = pathlib.Path(tmp) / "work"
            work.mkdir()
            output_file = pathlib.Path(tmp) / "github_output.txt"
            output_file.write_text("", encoding="utf-8")
            env = {
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "EVENT_NAME": "pull_request",
                "PR_BASE_SHA": origin.base_sha if base_sha is None else base_sha,
                "PR_HEAD_SHA": origin.head_sha if head_sha is None else head_sha,
                "REPO_URL": origin.url if repo_url is None else repo_url,
                "GITHUB_OUTPUT": str(output_file),
                "CLASSIFY_RETRY_SLEEP_SECONDS": "0",
            }
            result = subprocess.run(["bash", "-e", "-c", self.script], cwd=work, env=env,
                                    capture_output=True, text=True)
            outputs = dict(line.split("=", 1) for line in output_file.read_text(encoding="utf-8").splitlines() if "=" in line)
            objects = ""
            shallow = (work / ".git" / "shallow").exists()
            if (work / ".git").exists():
                objects = _git(work, "cat-file", "--batch-all-objects", "--batch-check=%(objecttype)", check=False).stdout
            return result, outputs, objects, shallow

    def _assert_classified(self, result, outputs, python, dependency, semgrep, scripts="false"):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(outputs.get("python_relevant"), python)
        self.assertEqual(outputs.get("dependency_relevant"), dependency)
        self.assertEqual(outputs.get("semgrep_relevant"), semgrep)
        self.assertEqual(outputs.get("scripts_relevant"), scripts)

    def test_docs_only_change_legitimately_skips_every_code_scanner(self):
        result, outputs, _, _ = self._run({"docs/guide.md": "a\n"}, {"docs/guide.md": "b\n", "docs/new.md": "c\n"})
        self._assert_classified(result, outputs, "false", "false", "false")
        self.assertIn("Fetched 2 commit(s)", result.stdout)

    def test_python_change_requires_bandit_and_semgrep(self):
        result, outputs, _, _ = self._run({}, {"agent/core.py": "x = 1\n"})
        self._assert_classified(result, outputs, "true", "false", "true")

    def test_production_scripts_change_requires_dedicated_scanner(self):
        result, outputs, _, _ = self._run({}, {"scripts/r2_upload.py": "x = 1\n"})
        self._assert_classified(result, outputs, "false", "false", "false", "true")

    def test_scripts_rename_and_deletion_keep_coverage(self):
        result, outputs, _, _ = self._run(
            {"scripts/legacy.py": "old\n"}, {"scripts/legacy.py": None, "docs/legacy.py": "old\n"})
        self._assert_classified(result, outputs, "false", "false", "false", "true")

    def test_dependency_manifest_change_requires_the_dependency_scanner(self):
        for manifest in ("requirements.txt", "api/requirements.txt", "platform/services/feed/requirements.txt"):
            with self.subTest(manifest=manifest):
                result, outputs, _, _ = self._run({}, {manifest: "requests==2.32.3\n"})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(outputs.get("dependency_relevant"), "true")

    def test_mixed_docs_and_code_change_requires_the_code_scanners(self):
        result, outputs, _, _ = self._run({}, {"docs/a.md": "a\n", "README.md": "changed\n", "api/handler.py": "y = 2\n"})
        self._assert_classified(result, outputs, "true", "false", "true")

    def test_deleting_scanned_code_is_a_change(self):
        result, outputs, _, _ = self._run({"agent/legacy.py": "old\n"}, {"agent/legacy.py": None})
        self._assert_classified(result, outputs, "true", "false", "true")

    def test_moving_a_file_into_scanned_code_is_a_change(self):
        result, outputs, _, _ = self._run({"docs/tool.py": "z = 3\n"}, {"docs/tool.py": None, "agent/tool.py": "z = 3\n"})
        self._assert_classified(result, outputs, "true", "false", "true")

    def test_moving_a_file_out_of_scanned_code_is_a_change(self):
        """With rename detection git would list only docs/tool.py; --no-renames
        lists both sides, so the scanned tree's side is never dropped."""
        result, outputs, _, _ = self._run({"agent/tool.py": "z = 3\n"}, {"agent/tool.py": None, "docs/tool.py": "z = 3\n"})
        self._assert_classified(result, outputs, "true", "false", "true")

    def test_unusual_path_names_still_match(self):
        """git quotes non-ASCII and special paths by default ("agent/na\\303\\257ve.py"),
        which `^agent/` would not match; the step reads -z output instead."""
        result, outputs, _, _ = self._run({}, {"agent/naïve module.py": "q = 4\n"})
        self._assert_classified(result, outputs, "true", "false", "true")

    def test_fetch_is_shallow_and_carries_no_file_contents(self):
        result, outputs, objects, shallow = self._run({"docs/big.md": "x" * 4096 + "\n"}, {"agent/core.py": "x = 1\n"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(shallow, "the fetch must not bring history (expected a shallow repository)")
        kinds = set(objects.split())
        self.assertNotIn("blob", kinds, "the fetch must not bring file contents: only commits and trees are needed")
        self.assertEqual(kinds, {"commit", "tree"})

    def test_unreachable_remote_fails_closed(self):
        result, outputs, _, _ = self._run({}, {"agent/core.py": "x = 1\n"}, repo_url="file:///nonexistent/origin.git")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("::error::", result.stdout)
        self.assertEqual(outputs, {}, "no classification may be published when the commits could not be fetched")

    def test_commit_missing_from_the_remote_fails_closed(self):
        result, outputs, _, _ = self._run({}, {"agent/core.py": "x = 1\n"}, base_sha="0" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outputs, {})

    def test_malformed_or_missing_sha_fails_closed_before_any_fetch(self):
        for bad in ("", "main", "abc123", "G" * 40):
            with self.subTest(sha=bad):
                result, outputs, objects, _ = self._run({}, {"agent/core.py": "x = 1\n"}, head_sha=bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs, {})
                self.assertIn("not a full commit SHA", result.stdout)

    def test_the_job_no_longer_clones_history(self):
        steps = self.changes_job["steps"]
        self.assertFalse(any("actions/checkout" in str(s.get("uses", "")) for s in steps),
                         "the classifier must not check out the repository: two trees are all it reads")
        self.assertNotIn("fetch-depth", self.script)
        self.assertNotIn("--unshallow", self.script)
        self.assertIn("--depth=1", self.script)
        self.assertIn("--filter=blob:none", self.script)


class TestSastGateFailsClosed(unittest.TestCase):
    """Executes the REAL gate step with the needs results GitHub would pass."""

    @classmethod
    def setUpClass(cls):
        cls.script = _jobs()[GATE_JOB_ID]["steps"][0]["run"]

    def _gate(self, **overrides):
        env = {
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "CHANGES": "success", "TRUFFLE": "success", "HYGIENE": "success",
            "BANDIT": "skipped", "SAFETY": "skipped", "SEMGREP": "skipped", "SCRIPTS": "skipped",
            "PYTHON_RELEVANT": "false", "DEPENDENCY_RELEVANT": "false", "SEMGREP_RELEVANT": "false", "SCRIPTS_RELEVANT": "false",
            "EVENT_NAME": "pull_request", "FULL_SCAN": "",
        }
        env.update(overrides)
        return subprocess.run(["bash", "-e", "-c", self.script], env=env, capture_output=True, text=True)

    def test_docs_only_pr_with_scanners_skipped_passes(self):
        result = self._gate()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_classification_failure_fails_the_gate(self):
        for outcome in ("failure", "cancelled", "skipped", ""):
            with self.subTest(changes=outcome):
                # A failed classifier publishes no outputs, so GitHub passes empty strings.
                result = self._gate(CHANGES=outcome, PYTHON_RELEVANT="", DEPENDENCY_RELEVANT="", SEMGREP_RELEVANT="")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("Mandatory job 'Classify Changed Surfaces' did not succeed", result.stdout)

    def test_applicable_code_scanner_cannot_be_skipped(self):
        cases = [
            dict(PYTHON_RELEVANT="true", SEMGREP_RELEVANT="true", SEMGREP="success"),  # Bandit skipped
            dict(DEPENDENCY_RELEVANT="true"),                                          # Safety skipped
            dict(SEMGREP_RELEVANT="true"),                                              # Semgrep skipped
            dict(SCRIPTS_RELEVANT="true"),                                            # Scripts scan skipped
        ]
        for case in cases:
            with self.subTest(**case):
                self.assertEqual(self._gate(**case).returncode, 1)

    def test_applicable_scanners_that_succeeded_pass(self):
        result = self._gate(PYTHON_RELEVANT="true", SEMGREP_RELEVANT="true", DEPENDENCY_RELEVANT="true",
                            BANDIT="success", SEMGREP="success", SAFETY="success", SCRIPTS_RELEVANT="true", SCRIPTS="success")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_scripts_sast_cannot_mismatch_classification(self):
        self.assertEqual(self._gate(SCRIPTS_RELEVANT="true", SCRIPTS="failure").returncode, 1)
        self.assertEqual(self._gate(SCRIPTS_RELEVANT="false", SCRIPTS="success").returncode, 1)
        self.assertEqual(self._gate(SCRIPTS_RELEVANT="true", SCRIPTS="success").returncode, 0)

    def test_secret_scan_and_hygiene_stay_mandatory(self):
        for key in ("TRUFFLE", "HYGIENE"):
            with self.subTest(job=key):
                self.assertEqual(self._gate(**{key: "failure"}).returncode, 1)


if __name__ == "__main__":
    unittest.main()
