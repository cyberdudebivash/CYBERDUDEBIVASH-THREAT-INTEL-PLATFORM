"""
Regression tests for issue #274: api/ai/{tracker,health,executive-brief,
monetization}.json moved off git entirely, onto R2 (owner decision, via
AskUserQuestion).

Root cause (from #274's investigation): generate-and-sync.yml's
`git push origin main` for these files has been failing on every scheduled
run since main started requiring PRs, silently (continue-on-error), freezing
whatever copy was committed before that. Meanwhile the real serving path --
R2, uploaded independently by both sentinel-apex.yml's r2_upload.py and
generate-and-sync.yml's own STAGE 9.5 -- kept updating, but the Worker's
/api/ai/{filename} handler only ever checked a gh-pages raw-GitHub fallback,
never the R2 bucket both pipelines were already populating.

Fix: the Worker now checks R2 first (falls back to gh-pages only if the R2
object is missing); these 4 files are no longer git-tracked or staged for
commit; a dead KV-cache-bust call (busting cache keys that were never in the
endpoint's own allowlist, so always got HTTP 400) was removed alongside it.

Run with: pytest tests/test_ai_tracker_off_git.py -v
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKER_SRC = REPO_ROOT / "workers" / "intel-gateway" / "src" / "index.js"
GENERATE_AND_SYNC_YML = REPO_ROOT / ".github" / "workflows" / "generate-and-sync.yml"
GITIGNORE = REPO_ROOT / ".gitignore"

AI_TRACKER_FILES = [
    "api/ai/tracker.json",
    "api/ai/health.json",
    "api/ai/executive-brief.json",
    "api/ai/monetization.json",
]


@pytest.fixture(scope="module")
def worker_src_text() -> str:
    assert WORKER_SRC.exists()
    return WORKER_SRC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def generate_and_sync_text() -> str:
    assert GENERATE_AND_SYNC_YML.exists()
    return GENERATE_AND_SYNC_YML.read_text(encoding="utf-8")


def test_generate_and_sync_yml_is_valid_yaml(generate_and_sync_text: str):
    yaml.safe_load(generate_and_sync_text)


def test_ai_proxy_checks_r2_before_gh_pages_fallback(worker_src_text: str):
    match = re.search(
        r'const AI_STATIC_PROXY_FILES.*?\n(.*?)\n  \}\n\n  // --- 404',
        worker_src_text, re.DOTALL,
    )
    assert match, "could not locate the /api/ai/ static proxy handler in index.js"
    # Compare positions in code only: the handler's own comments mention
    # raw.githubusercontent.com (explaining the fallback) above the R2 read.
    handler_body = "\n".join(
        line for line in match.group(1).splitlines()
        if not line.strip().startswith("//")
    )

    r2_pos = handler_body.find("env.INTEL_R2.get(`ai/")
    ghpages_pos = handler_body.find("raw.githubusercontent.com")
    assert r2_pos != -1, "handler must read from INTEL_R2 (bucket sentinel-apex-data, key ai/{filename})"
    assert ghpages_pos != -1, "gh-pages fallback must still exist for when the R2 object is missing"
    assert r2_pos < ghpages_pos, "R2 must be checked BEFORE the gh-pages fallback, not after"


def test_ai_tracker_files_not_git_tracked():
    import subprocess
    result = subprocess.run(
        ["git", "ls-files"] + AI_TRACKER_FILES,
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    tracked = result.stdout.strip()
    assert tracked == "", f"these must not be git-tracked anymore (still are): {tracked}"


def test_ai_tracker_files_are_gitignored():
    gitignore_text = GITIGNORE.read_text(encoding="utf-8")
    for f in AI_TRACKER_FILES:
        assert f in gitignore_text, f"{f} must be listed in .gitignore"


def test_generate_and_sync_no_longer_stages_ai_tracker_files_for_commit(generate_and_sync_text: str):
    for f in AI_TRACKER_FILES:
        assert f"git add {f}" not in generate_and_sync_text, (
            f"STAGE 9 must not stage {f} for commit anymore -- R2 (STAGE 9.5) "
            "is the authoritative path now, and the git push for these files "
            "was failing on every run anyway"
        )


def test_generate_and_sync_still_uploads_ai_tracker_files_to_r2(generate_and_sync_text: str):
    """The R2 upload itself (STAGE 9.5) must be untouched -- only the dead
    KV-cache-bust calls after it were removed."""
    for f in AI_TRACKER_FILES:
        assert f in generate_and_sync_text, f"STAGE 9.5 must still upload {f} to R2"


def test_generate_and_sync_no_longer_has_dead_cache_bust_calls(generate_and_sync_text: str):
    """ai:tracker/ai:health/ai:exec-brief/ai:monetize were never in
    /api/admin/cache/bust's own ALLOWED_EXACT_KEYS allowlist -- every one of
    these calls always got HTTP 400. Confirmed by reading the Worker's own
    allowlist, not assumed. Checks the actual curl call pattern, not prose --
    this file's own comments legitimately mention these key names as
    documentation of what was removed."""
    assert "cache/bust?key=" not in generate_and_sync_text, (
        "the dead cache-bust curl call should be removed, not left calling a 400"
    )


def test_admin_cache_bust_allowlist_still_excludes_ai_tracker_keys(worker_src_text: str):
    """Regression guard confirming the premise above stays true: if someone
    ever adds these keys to the allowlist, that's a deliberate KV-caching
    reintroduction, not an accident -- this test should be revisited then,
    not silently broken."""
    match = re.search(r"ALLOWED_EXACT_KEYS = new Set\(\[(.*?)\]\)", worker_src_text, re.DOTALL)
    assert match, "could not locate ALLOWED_EXACT_KEYS in the cache/bust handler"
    allowlist_body = match.group(1)
    for dead_key in ("ai:tracker", "ai:health", "ai:exec-brief", "ai:monetize"):
        assert dead_key not in allowlist_body
