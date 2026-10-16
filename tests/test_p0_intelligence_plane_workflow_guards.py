#!/usr/bin/env python3
"""
tests/test_p0_intelligence_plane_workflow_guards.py

P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10) -- structural
regression guards for genesis-powerhouse.yml / sovereign-platform.yml,
mirroring tests/test_r2_state_migration_wiring.py's established pattern for
multi-source-intel.yml / sentinel-apex.yml. These assert the *wiring*
this mission fixed cannot silently regress: no direct git push for runtime
state, no swallowed engine failures, R2 persistence steps present and
fail-closed, and permissions genuinely reduced.
"""
import pathlib
import re
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GENESIS_YML = REPO_ROOT / ".github" / "workflows" / "genesis-powerhouse.yml"
SOVEREIGN_YML = REPO_ROOT / ".github" / "workflows" / "sovereign-platform.yml"


def _load(path):
    text = path.read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def _job_name(doc):
    return next(iter(doc["jobs"]))


def _all_run_bodies(doc):
    """Every step's `run:` value, concatenated -- explicitly excludes YAML
    comments (parsed away by yaml.safe_load), which the mission's own
    explanatory header comments deliberately quote the *old, removed*
    `git push`/`|| echo`/tenants.json patterns for context. A raw-text
    search over the file would false-positive on those comments; only the
    actual executable step bodies matter for these guards."""
    job = _job_name(doc)
    return "\n".join(s.get("run", "") for s in doc["jobs"][job]["steps"])


class TestWorkflowsAreValidYaml(unittest.TestCase):
    def test_genesis_is_valid_yaml(self):
        with open(GENESIS_YML, encoding="utf-8") as f:
            yaml.safe_load(f)

    def test_sovereign_is_valid_yaml(self):
        with open(SOVEREIGN_YML, encoding="utf-8") as f:
            yaml.safe_load(f)


class TestNoDirectGitPushForRuntimeState(unittest.TestCase):
    """Mutation-test scenario 1 (reintroduce git push): a future edit
    resurrecting `git push origin main` in either workflow must fail this
    test, not silently ship a regression to the exact defect class this
    mission exists to eliminate."""

    def test_genesis_has_no_git_push(self):
        _, doc = _load(GENESIS_YML)
        run_bodies = _all_run_bodies(doc)
        self.assertNotIn("git push", run_bodies)
        self.assertNotIn("git commit", run_bodies)
        self.assertNotIn("git config user.name", run_bodies)

    def test_sovereign_has_no_git_push(self):
        _, doc = _load(SOVEREIGN_YML)
        run_bodies = _all_run_bodies(doc)
        self.assertNotIn("git push", run_bodies)
        self.assertNotIn("git commit", run_bodies)
        self.assertNotIn("git config user.name", run_bodies)


class TestNoSwallowedEngineFailures(unittest.TestCase):
    """Mutation-test scenario 2 (reintroduce `|| echo` on CORTEX, or any
    sibling engine): the old `run: ... || echo "X cycle complete"` pattern
    had zero observability -- the step showed green even when the engine
    raised. continue-on-error: true is the only acceptable replacement
    (genuinely shows red in the Actions UI), and only in combination with
    the fail-closed output-validation step that catches what
    continue-on-error alone would let through."""

    def test_sovereign_has_no_shell_level_failure_suppression(self):
        _, doc = _load(SOVEREIGN_YML)
        run_bodies = _all_run_bodies(doc)
        self.assertNotIn("|| echo", run_bodies)
        self.assertNotIn('cycle complete"', run_bodies)

    def test_genesis_has_no_shell_level_failure_suppression(self):
        _, doc = _load(GENESIS_YML)
        run_bodies = _all_run_bodies(doc)
        self.assertNotIn("|| echo", run_bodies)

    def test_sovereign_four_engines_use_continue_on_error_not_shell_suppression(self):
        _, doc = _load(SOVEREIGN_YML)
        steps = doc["jobs"]["sovereign-cycle"]["steps"]
        engine_steps = [s for s in steps if s.get("name", "").startswith("Execute ")]
        self.assertEqual(len(engine_steps), 4, "expected exactly 4 engine steps (NEXUS/CORTEX/QUANTUM/SOVEREIGN)")
        for step in engine_steps:
            self.assertTrue(step.get("continue-on-error"), f"{step['name']} must use continue-on-error: true")
            self.assertNotIn("||", step["run"], f"{step['name']} must not shell-suppress failures")

    def test_sovereign_and_genesis_test_runner_steps_are_not_pipe_masked(self):
        """Residual gap this mission's own required live-production
        verification found (run 34515087369's job log, 2026-09-10): both
        workflows' pytest-invoking step piped `2>&1 | tail -N`. GitHub's
        default `bash -e` shell does not set `pipefail`, so the pipeline's
        exit code was `tail`'s (always 0), not pytest's -- meaning the step
        reported success even when pytest raised "No module named pytest"
        and never ran a single test. `|| echo`-style suppression was
        already guarded above; a masking pipe is a different mechanism
        producing the identical blind spot, so it needs its own guard."""
        cases = [
            (SOVEREIGN_YML, "sovereign-cycle", "Run validation tests"),
            (GENESIS_YML, "genesis-cycle", "Validate"),
        ]
        for yml, job, step_name in cases:
            _, doc = _load(yml)
            steps = {s.get("name"): s for s in doc["jobs"][job]["steps"] if "name" in s}
            self.assertIn(step_name, steps, f"{yml}: expected a '{step_name}' step")
            run_body = steps[step_name]["run"]
            self.assertNotIn("|", run_body, f"{yml}: '{step_name}' must not pipe its test runner's output through another command without `pipefail` -- doing so masks a real test/runner failure as success")

    def test_sovereign_and_genesis_install_pytest_before_running_it(self):
        """Companion to the guard above: removing the masking pipe is only
        a genuine fix if pytest is actually installed first -- otherwise
        the step still never runs a real test, it just fails on a missing
        interpreter instead of silently passing. Verified locally this
        mission that both suites genuinely pass once installed (sovereign:
        62/62 across test_v39_modules.py + test_v40_v41_v42_modules.py;
        genesis: 13/13 in test_v43_genesis.py) before this became a
        requirement."""
        cases = [
            (SOVEREIGN_YML, "sovereign-cycle", "Run validation tests"),
            (GENESIS_YML, "genesis-cycle", "Validate"),
        ]
        for yml, job, step_name in cases:
            _, doc = _load(yml)
            steps = doc["jobs"][job]["steps"]
            names = [s.get("name") for s in steps]
            self.assertIn(step_name, names, f"{yml}: expected a '{step_name}' step")
            preceding_run = "\n".join(s.get("run", "") for s in steps[:names.index(step_name)])
            self.assertIn("pip install pytest", preceding_run, f"{yml}: pytest must be installed by a step before '{step_name}' runs it")


class TestRequiredStepsPresentAndFailClosed(unittest.TestCase):
    """Mutation-test scenarios 3/6/7/8 (remove an R2 upload / missing
    output / malformed JSON / old timestamp all funnel through these two
    steps existing and NOT being continue-on-error)."""

    def _steps_by_name(self, doc, job):
        return {s.get("name"): s for s in doc["jobs"][job]["steps"] if "name" in s}

    def test_sovereign_has_validation_upload_and_verification_steps_all_fail_closed(self):
        _, doc = _load(SOVEREIGN_YML)
        steps = self._steps_by_name(doc, "sovereign-cycle")
        for name in (
            "Download STIX manifest from R2",
            "Validate engine outputs are non-degenerate",
            "Upload intelligence state to R2",
            "Verify R2 round trip",
        ):
            self.assertIn(name, steps, f"missing required step: {name}")
            self.assertFalse(steps[name].get("continue-on-error"), f"{name} must be fail-closed (not continue-on-error)")

    def test_genesis_has_validation_upload_and_verification_steps_all_fail_closed(self):
        _, doc = _load(GENESIS_YML)
        steps = self._steps_by_name(doc, "genesis-cycle")
        for name in (
            "Download STIX manifest from R2",
            "Validate GENESIS output is non-degenerate",
            "Upload GENESIS state to R2",
            "Verify R2 round trip",
        ):
            self.assertIn(name, steps, f"missing required step: {name}")
            self.assertFalse(steps[name].get("continue-on-error"), f"{name} must be fail-closed (not continue-on-error)")

    def test_upload_steps_reference_r2_state_sync(self):
        sov_text = SOVEREIGN_YML.read_text(encoding="utf-8")
        gen_text = GENESIS_YML.read_text(encoding="utf-8")
        self.assertIn("r2_state_sync.py --upload", sov_text)
        self.assertIn("r2_state_sync.py --upload", gen_text)

    def test_no_workflow_uploads_tenants_json(self):
        """Mutation-test scenario 9 (attempt to persist the sensitive tenant
        file): even if a future edit widened either --upload --only list,
        it must never include tenants.json."""
        for path in (SOVEREIGN_YML, GENESIS_YML):
            _, doc = _load(path)
            self.assertNotIn("tenants.json", _all_run_bodies(doc))


class TestPermissionsGenuinelyReduced(unittest.TestCase):
    def test_genesis_permissions_are_read_only(self):
        _, doc = _load(GENESIS_YML)
        self.assertEqual(doc["permissions"], {"contents": "read"})

    def test_sovereign_permissions_are_read_only(self):
        _, doc = _load(SOVEREIGN_YML)
        self.assertEqual(doc["permissions"], {"contents": "read"})


class TestNoDuplicateWriterAcrossTargetWorkflows(unittest.TestCase):
    """Mutation-test scenario 5 (reintroduce duplicate writer): every R2 key
    this mission's 2 workflows upload must be uploaded by exactly one of
    them -- never both, and never also by nexus-intelligence.yml (confirmed
    dormant: schedule trigger commented out since 2026-07-29 specifically
    because it duplicated sovereign-platform.yml's own NEXUS invocation)."""

    def _only_args(self, text):
        match = re.search(r"r2_state_sync\.py --upload --only\s*\n?\s*([^\n\"]+)", text)
        self.assertIsNotNone(match, "could not find --upload --only argument")
        return {p.strip() for p in match.group(1).split(",") if p.strip()}

    def test_upload_only_lists_are_disjoint(self):
        sov_only = self._only_args(SOVEREIGN_YML.read_text(encoding="utf-8"))
        gen_only = self._only_args(GENESIS_YML.read_text(encoding="utf-8"))
        overlap = sov_only & gen_only
        self.assertEqual(overlap, set(), f"sovereign-platform.yml and genesis-powerhouse.yml must never upload the same key(s): {overlap}")

    def test_nexus_intelligence_yml_schedule_remains_disabled(self):
        """nexus-intelligence.yml still independently invokes NEXUS and has
        its own (unmigrated, still git-push-based) persistence path. It is
        out of this mission's explicit scope (only sovereign-platform.yml's
        NEXUS invocation was migrated) specifically because its schedule
        trigger is disabled -- workflow_dispatch only. If that schedule were
        ever silently re-enabled, it would race sovereign-platform.yml for
        data/nexus/ with two independent, uncoordinated writers. This test
        fails loudly if that ever happens without a deliberate reconciliation."""
        path = REPO_ROOT / ".github" / "workflows" / "nexus-intelligence.yml"
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        triggers = doc.get(True, doc.get("on", {}))
        self.assertNotIn("schedule", triggers, (
            "nexus-intelligence.yml's schedule trigger must stay disabled -- "
            "re-enabling it without reconciling it against sovereign-platform.yml's "
            "own NEXUS invocation reintroduces a duplicate-writer race on data/nexus/."
        ))


if __name__ == "__main__":
    unittest.main()
