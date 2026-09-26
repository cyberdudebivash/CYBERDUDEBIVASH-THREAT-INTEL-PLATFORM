"""
tests/test_safe_git_commit_frontend_integrity_sync.py

Regression test for the GATE E (post-deploy-validation.yml "Frontend
integrity") false "TAMPERED: index.html" failure reproduced live in
GitHub Actions run #165 (2026-08-13) and confirmed to reproduce locally
against origin/main at the time of investigation.

Root cause: scripts/safe_git_commit.py's automated pipeline commits always
carry "[skip ci]" in their message (to avoid re-triggering
sentinel-blogger.yml). GitHub's [skip ci] convention suppresses *every*
push-triggered workflow for that commit -- including
.github/workflows/frontend-integrity-sync.yml (PR #166), whose only job is
to regenerate config/frontend_checksums.json after a protected asset
(index.html, staged unconditionally by safe_git_commit.py) changes. Since
every automated index.html regeneration is committed with [skip ci], that
workflow never actually fires for the commits that most need it, and the
registry silently goes stale until the next *human* (non-skip-ci) commit
happens to touch a protected asset -- at which point GATE E hard-fails on
content that was never tampered with, just legitimately regenerated.

Fix: safe_git_commit.py now regenerates config/frontend_checksums.json
(via the existing scripts/frontend_integrity.py CLI, unchanged) and stages
it in the SAME commit as index.html, right after index.html is staged.
This makes the registry atomic with the asset it certifies regardless of
whether any later workflow run ever fires for that commit.

This test builds a real git repository (bare "origin" + a "runner" clone,
mirroring tests/test_safe_git_commit_artifact_recovery.py's established
pattern for exercising this script), copies the real safe_git_commit.py
and frontend_integrity.py into it, simulates the pipeline regenerating
index.html this run, and asserts that after the script runs:
  1. The registry it leaves behind matches the just-changed index.html.
  2. `frontend_integrity.py verify` passes against the final state.
  3. The corrected registry actually reaches origin/main (not just local
     disk) -- git push publishes commits, not working-tree state.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT_REAL = Path(__file__).resolve().parent.parent
REAL_SAFE_GIT_COMMIT = REPO_ROOT_REAL / "scripts" / "safe_git_commit.py"
REAL_FRONTEND_INTEGRITY = REPO_ROOT_REAL / "scripts" / "frontend_integrity.py"

# Mirrors frontend_integrity.py's own PROTECTED_ASSETS list -- kept as a
# literal here (not imported) so this test still catches a drift between
# the two if the real list ever changes without this test being updated.
PROTECTED_ASSETS = [
    "index.html",
    "js/api_adapter.js",
    "js/card_renderer.js",
    "js/card_renderer_integration.js",
    "js/sla-monitor.js",
    "css/card_renderer_styles.css",
    "css/homepage-design-system.css",
]


def _git(cwd, *args):
    result = subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed in {cwd}:\n{result.stdout}\n{result.stderr}")
    return result


def _init_repo_with_identity(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestFrontendChecksumRegistryStaysAtomicWithCommit(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sgc_fi_test_"))
        self.bare = self.tmp / "origin.git"
        self.runner = self.tmp / "runner"

        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.bare)], check=True)

        seed = self.tmp / "seed"
        _init_repo_with_identity(seed)
        for rel in PROTECTED_ASSETS:
            p = seed / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"/* original {rel} */" if not rel.endswith(".html") else "<html>original</html>",
                         encoding="utf-8")
        (seed / "scripts").mkdir(parents=True, exist_ok=True)
        shutil.copy(REAL_FRONTEND_INTEGRITY, seed / "scripts" / "frontend_integrity.py")
        (seed / "config").mkdir(parents=True, exist_ok=True)
        gen = subprocess.run(
            [sys.executable, "scripts/frontend_integrity.py", "generate"],
            cwd=seed, capture_output=True, text=True,
        )
        self.assertEqual(gen.returncode, 0, f"seed registry generation failed: {gen.stdout}{gen.stderr}")
        _git(seed, "add", "-A")
        _git(seed, "commit", "-q", "-m", "ancestor")
        _git(seed, "remote", "add", "origin", str(self.bare))
        _git(seed, "push", "-q", "origin", "main")

        _git(self.tmp, "clone", "-q", str(self.bare), str(self.runner))
        _git(self.runner, "config", "user.email", "sentinel@cyberdudebivash.com")
        _git(self.runner, "config", "user.name", "CDB-Sentinel-Bot")

        # Place the real scripts under test at <runner>/scripts/, so
        # safe_git_commit.py's own `Path(__file__).resolve().parent.parent`
        # resolves REPO_ROOT to this temp repo -- exactly like running
        # `python3 scripts/safe_git_commit.py` from within the real repo.
        shutil.copy(REAL_SAFE_GIT_COMMIT, self.runner / "scripts" / "safe_git_commit.py")

        # Simulate the automated pipeline regenerating index.html this run
        # (e.g. a fresh advisory count / timestamp banner) -- the exact
        # class of change scripts/safe_git_commit.py stages unconditionally
        # via files_to_stage, and the exact class of change that reproduced
        # GATE E run #165's false "TAMPERED: index.html" failure.
        (self.runner / "index.html").write_text(
            "<html>freshly regenerated by this pipeline run</html>", encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_script(self):
        env = dict(os.environ)
        env.pop("GH_TOKEN", None)
        env.pop("GITHUB_REPOSITORY", None)
        env["PIPELINE_VERSION"] = "test"
        proc = subprocess.run(
            [sys.executable, str(self.runner / "scripts" / "safe_git_commit.py")],
            cwd=self.runner, env=env, capture_output=True, text=True, timeout=60,
        )
        return proc

    def test_registry_is_regenerated_and_staged_in_the_same_run(self):
        proc = self._run_script()
        self.assertEqual(proc.returncode, 0, f"script must always exit 0\nstdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn(
            "[frontend-integrity] Registry resynced atomically with this commit", proc.stdout,
            "safe_git_commit.py must regenerate and stage config/frontend_checksums.json "
            "in the same run that stages index.html -- this is the fix for GATE E run #165's "
            "false TAMPERED failure, whose root cause is that a separate [skip ci]-triggered "
            "workflow can never see these commits at all.",
        )

    def test_registry_matches_the_freshly_regenerated_index_html(self):
        proc = self._run_script()
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")

        registry = json.loads((self.runner / "config" / "frontend_checksums.json").read_text())
        expected_sha = _sha256(self.runner / "index.html")
        actual_sha = registry["assets"]["index.html"]["sha256"]
        self.assertEqual(
            actual_sha, expected_sha,
            "config/frontend_checksums.json's index.html entry must match the index.html "
            "this same run just committed -- a mismatch here is exactly what GATE E's "
            "`verify` reports as TAMPERED against perfectly legitimate content.",
        )

    def test_frontend_integrity_verify_passes_against_the_final_state(self):
        """End-to-end: running the real GATE E command against the exact
        working tree safe_git_commit.py leaves behind must PASS, not
        reproduce the live TAMPERED failure."""
        proc = self._run_script()
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")

        verify = subprocess.run(
            [sys.executable, "scripts/frontend_integrity.py", "verify"],
            cwd=self.runner, capture_output=True, text=True,
        )
        self.assertEqual(
            verify.returncode, 0,
            f"GATE E's own command must pass against the state safe_git_commit.py "
            f"leaves behind:\n{verify.stdout}\n{verify.stderr}",
        )
        self.assertIn("RESULT: PASS", verify.stdout)

    def test_resynced_registry_actually_reaches_origin_main(self):
        """git push publishes commits, not working-tree state -- prove the
        corrected registry is on origin/main, not just the runner's local
        disk (GATE E runs in a fresh checkout of origin/main, not this
        runner's working tree)."""
        proc = self._run_script()
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")

        _git(self.runner, "fetch", "-q", "origin", "main")
        show = subprocess.run(
            ["git", "show", "origin/main:config/frontend_checksums.json"],
            cwd=self.runner, capture_output=True, text=True,
        )
        self.assertEqual(show.returncode, 0, f"could not read the registry back from pushed origin/main: {show.stderr}")
        published_registry = json.loads(show.stdout)
        expected_sha = _sha256(self.runner / "index.html")
        self.assertEqual(
            published_registry["assets"]["index.html"]["sha256"], expected_sha,
            "the resynced registry must be pushed to origin/main, not left uncommitted/unpushed "
            "on the runner's local disk.",
        )


if __name__ == "__main__":
    unittest.main()
