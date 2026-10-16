"""
tests/test_git_publish_no_silent_push_failure.py

Regression test for the P0 root cause of the 2026-08-26 core-feed staleness
incident: both of this platform's automated git-publish paths --
.github/workflows/multi-source-intel.yml's inline "Commit Intel State &
Manifest" step and scripts/safe_git_commit.py (used by sentinel-apex.yml's
STAGE 4 - Git Sync) -- retry `git push origin main` up to 4 times and then,
on total exhaustion, only logged a bare warning and continued with exit 0.

Confirmed live via GitHub Actions job logs: since main's branch ruleset
started requiring "Changes must be made through a pull request" (~2026-08-26),
every single scheduled run of both workflows has had all 4 push attempts
rejected with "remote: error: GH013: Repository rule violations ... - Changes
must be made through a pull request", yet both jobs kept reporting SUCCESS.
multi-source-intel.yml's true_intel_ingestor.py was genuinely fetching fresh
intelligence (e.g. one run logged "[RSS] Ingestion complete: 95 feeds, 227 new
items, 2234 skipped") but every byte of it was discarded on every run because
it never reached main -- this is why api/feed.json's generated_at stayed
frozen at 2026-08-26T09:55:27Z through Sep 2 despite dozens of "green" runs
of both workflows in between.

Fix:
  - multi-source-intel.yml: this workflow's "Commit Intel State & Manifest"
    step is its last substantive step (no downstream steps in this job
    depend on it), so a fully-exhausted push now hard-fails the job
    (`exit 1` + an `::error::` annotation) instead of silently continuing.
  - safe_git_commit.py: deliberately NOT hard-failed. STAGE 4 sits mid-way
    through sentinel-apex.yml's 162-stage pipeline, and many downstream
    steps (STAGE 5.6.1 Regression Immunity, STAGE 5.6.2 Stale-Feed
    Recurrence Guard, STAGE 5 Deploy to GitHub Pages, etc.) have no
    `if: always()` guard -- flipping STAGE 4 to "failure" would silently
    skip all of them via GitHub Actions' default `if: success()`, which is
    a worse outcome than today's silent-but-contained warning. Instead this
    now emits a loud `::error::` GitHub Actions annotation (still exits 0),
    matching the same pattern already used one stage later by STAGE 4.1's
    r2_resync_manifests.py failure handling.

Superseded update (see scripts/r2_state_sync.py / tests/test_r2_state_sync.py
/ tests/test_r2_state_migration_wiring.py): multi-source-intel.yml's
"Commit Intel State & Manifest" step no longer attempts a git push at all.
The hard-fail-on-exhaustion behavior above was a genuine improvement over
silent failure, but it was still failing on every single run: main's branch
ruleset rejects ANY direct push to main, not just pushes of specific files,
so once ALL of this step's files were migrated to R2 (feed_state.json /
processed_intel.json / feed_manifest.json / data/feed_manifest.json plus,
found by a later CodeRabbit review, the 5 data/intelligence_repository/*.json
registry files + advisories/), there was nothing left this step could ever
successfully commit -- a push attempt here was structurally guaranteed to
fail, forever, not just historically. TestMultiSourceIntelCommitStepFailsLoudly
below is updated to assert the step no longer attempts a push at all, rather
than asserting how it fails when it does.
"""
import pathlib
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MULTI_SOURCE_YML = REPO_ROOT / ".github" / "workflows" / "multi-source-intel.yml"
SAFE_GIT_COMMIT_PY = REPO_ROOT / "scripts" / "safe_git_commit.py"


class TestMultiSourceIntelCommitStepFailsLoudly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = MULTI_SOURCE_YML.read_text(encoding="utf-8")
        with open(MULTI_SOURCE_YML, encoding="utf-8") as f:
            cls.doc = yaml.safe_load(f)

    def test_workflow_is_valid_yaml(self):
        self.assertIn("multi-source-enrichment", self.doc["jobs"])

    def _commit_step_source(self) -> str:
        """Locate the step that persists this job's ingestion output.

        Renamed from "Commit Intel State & Manifest" to "Upload Intel State
        to R2" when persistence was migrated off git-push (see module
        docstring's "Superseded update"): this lookup was never updated to
        match, which is why the three tests below regressed to failing
        against current `main` even though the underlying architecture was
        already correct.
        """
        steps = self.doc["jobs"]["multi-source-enrichment"]["steps"]
        commit_steps = [s for s in steps if s.get("name") == "Upload Intel State to R2"]
        self.assertEqual(len(commit_steps), 1)
        return commit_steps[0]["run"]

    def test_commit_step_exists_exactly_once(self):
        self._commit_step_source()

    def test_step_no_longer_attempts_a_git_push(self):
        """Superseded by the R2 migration (see module docstring): every file
        this step used to commit is R2-authoritative now, and main's branch
        ruleset rejects ANY direct push to main -- not just pushes of
        specific files -- so a push here was structurally guaranteed to
        fail on every run, forever. The correct fix escalated from "hard-fail
        loudly when the push is rejected" to "don't attempt a push that
        cannot succeed"."""
        run_block = self._commit_step_source()
        self.assertNotIn("git push", run_block)
        self.assertNotIn("git add -f", run_block)
        self.assertNotIn("PUSHED=", run_block)

    def test_no_more_bare_warn_only_deferral(self):
        """The old behaviour -- print a [WARN] and just fall through -- must be gone."""
        run_block = self._commit_step_source()
        self.assertNotIn("[WARN] Push deferred after 4 attempts - will retry next run", run_block)


class TestSafeGitCommitPushExhaustionIsLoud(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SAFE_GIT_COMMIT_PY.read_text(encoding="utf-8")

    def test_file_is_valid_python(self):
        import ast
        ast.parse(self.text)

    def _push_retry_loop_block(self) -> str:
        start = self.text.index("# --- Push with 4-attempt retry ---")
        end = self.text.index('log.info("safe_git_commit.py complete.")', start)
        return self.text[start:end]

    def test_push_exhaustion_branch_emits_error_annotation(self):
        block = self._push_retry_loop_block()
        self.assertIn("::error::", block)

    def test_git_sync_still_never_kills_the_pipeline(self):
        """
        Deliberate design constraint (STAGE 4 sits mid-pipeline; many
        downstream steps default to if:success() with no if:always() guard)
        -- must NOT regress into a hard sys.exit(1) for push exhaustion.
        """
        self.assertIn('sys.exit(0)', self.text)
        # The push-retry loop itself must not introduce a sys.exit(1).
        self.assertNotIn("sys.exit(1)", self._push_retry_loop_block())


if __name__ == "__main__":
    unittest.main()
