"""Offline regression contract for bounded deploy-drift watchdog checkout.

This checks the exact workflow source without invoking GitHub Actions, GitHub API,
Cloudflare, R2, or a production deployment. A passing test does not establish
runtime performance or deployment convergence.
"""
from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "deploy-drift-watchdog.yml"
)


def _source():
    return WORKFLOW.read_text(encoding="utf-8")


def _checkout():
    source = _source()
    marker = "      - name: Checkout repository\n"
    assert source.count(marker) == 1
    return source.split(marker, 1)[1].split("      - name:", 1)[0]


def test_blobless_checkout_does_not_download_all_historical_blobs():
    assert "filter: blob:none" in _checkout()


def test_complete_commit_history_is_preserved_for_path_search():
    assert "fetch-depth: 0" in _checkout()


def test_checkout_does_not_use_sparse_paths():
    assert "sparse-checkout:" not in _checkout()


def test_path_scoped_main_commit_lookup_remains_intact():
    assert (
        "git log -1 --format=%H -- index.html 'js/**' 'css/**' "
        "_headers service-worker.js"
    ) in _source()


def test_historical_deployment_commit_is_still_verified():
    assert 'git cat-file -e "${cited}^{commit}"' in _source()
    assert (
        'git diff --quiet "$cited" HEAD -- index.html js css '
        '_headers service-worker.js'
    ) in _source()


def test_fail_closed_and_single_recovery_dispatch_invariants_remain():
    source = _source()
    assert "timeout-minutes: 5" in source
    assert "if: github.ref == 'refs/heads/main'" in source
    assert "cancel-in-progress: true" in source
    assert 'gh workflow run pages-fast-publish.yml --repo "${{ github.repository }}" --ref main' in source
