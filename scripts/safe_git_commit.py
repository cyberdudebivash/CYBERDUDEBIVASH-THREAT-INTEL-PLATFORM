#!/usr/bin/env python3
"""
scripts/safe_git_commit.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0.0 -- Safe Git Commit & Push
====================================================================
P0 FIX: Replaces the inline Python + git bash block in sentinel-blogger.yml.
Zero inline Python in YAML.

Responsibilities:
  1.  Configure git identity.
  2.  Set remote URL with GH_TOKEN.
  3.  Clear any stale git locks.
  4.  Stage NON-SENSITIVE files (STIX bundles, metadata, HTML).
  5.  Build commit message (entry count from manifest).
  6.  Commit if there are staged changes.
  7.  Push with up to 4 retries, merge recovery on conflict.

Files staged (never feed_manifest.json data -- that goes to R2 only):
  - data/stix/CDB-APEX-*.json      (STIX bundles, capped at 500)
  - data/sync_marker.json
  - api/latest.json, api/status.json, api/engines.json, api/ai/
  - index.html, sitemap.xml
  - .gitignore
  - reports/                        (HTML Tactical Dossiers for gh-pages)
  - data/status/status.json
  - data/health/*.json
  - data/apex_v2_manifest.json etc.
  - data/publish_queue.json         (always cleared/empty)
  - data/feed_manifest.json         (with schema_version for v70)

Runs with if: always() -- persists state even when upstream steps fail.

Environment variables:
  GH_TOKEN            -- GitHub token for push auth
  GITHUB_REPOSITORY   -- owner/repo
  PIPELINE_VERSION    -- version string
  R2_UPLOAD_COUNT     -- set by r2_upload.py (advisory count)
  MANIFEST_FINAL_COUNT -- set by run_pipeline.py

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [safe_git_commit] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.safe_git_commit")

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "131.2.0")


def run_git(*args: str, check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a git command."""
    cmd = ["git"] + list(args)
    result = subprocess.run(cmd, capture_output=capture, text=True, check=False)
    return result


def git_add(path: str) -> None:
    run_git("add", "-f", path)


def count_manifest() -> str:
    """Return entry count string from manifest (for commit message)."""
    # Prefer R2_UPLOAD_COUNT set by r2_upload.py
    count_env = os.environ.get("R2_UPLOAD_COUNT", "").strip()
    if count_env and count_env.isdigit():
        return count_env

    manifest_count = os.environ.get("MANIFEST_FINAL_COUNT", "").strip()
    if manifest_count and manifest_count.isdigit():
        return manifest_count

    # Fall back: read from file
    for path in ("data/stix/feed_manifest.json", "data/feed_manifest.json"):
        full = REPO_ROOT / path
        if full.exists():
            try:
                d = json.loads(full.read_text(encoding="utf-8"))
                if isinstance(d, list):
                    return str(len(d))
                if isinstance(d, dict):
                    for key in ("advisories", "reports", "items"):
                        if key in d and isinstance(d[key], list):
                            return str(len(d[key]))
            except Exception:
                pass
    return "N/A"


def main() -> None:
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- Safe Git Commit & Push", PIPELINE_VERSION)
    log.info("=" * 60)

    os.chdir(REPO_ROOT)

    gh_token   = os.environ.get("GH_TOKEN", "").strip()
    gh_repo    = os.environ.get("GITHUB_REPOSITORY", "").strip()

    # --- Configure git identity ---
    run_git("config", "--local", "user.email", "sentinel@cyberdudebivash.com")
    run_git("config", "--local", "user.name",  "CDB-Sentinel-Bot")

    if gh_token and gh_repo:
        remote_url = f"https://x-access-token:{gh_token}@github.com/{gh_repo}"
        run_git("remote", "set-url", "origin", remote_url)
    else:
        log.warning("GH_TOKEN or GITHUB_REPOSITORY not set -- push may fail.")

    # --- Clear stale locks ---
    for lock in (".git/index.lock", ".git/config.lock", ".git/HEAD.lock"):
        lock_path = REPO_ROOT / lock
        if lock_path.exists():
            try:
                lock_path.unlink()
                log.info("Cleared stale lock: %s", lock)
            except Exception:
                pass
    run_git("rebase", "--abort")
    run_git("merge",  "--abort")
    for d in (".git/rebase-merge", ".git/rebase-apply"):
        p = REPO_ROOT / d
        if p.is_dir():
            import shutil
            try:
                shutil.rmtree(p)
            except Exception:
                pass

    # --- Stage NON-SENSITIVE files ---
    files_to_stage = [
        "data/stix/CDB-APEX-*.json",
        "data/sync_marker.json",
        "api/latest.json",
        "api/status.json",
        "api/engines.json",
        "api/ai/",
        "index.html",
        "sitemap.xml",
        ".gitignore",
        "reports/",
        "data/status/status.json",
        "data/health/guardian_report.json",
        "data/health/apex_engine_report.json",
        "data/health/apex_v2_audit.json",
        "data/apex_v2_manifest.json",
        "data/apex_v2_strategic_report.json",
        "data/apex_intelligence_report.json",
        "data/apex_enriched_manifest.json",
        "data/validated_manifest.json",
        "config/feature_flags.json",
        "data/publish_queue.json",
        "data/feed_manifest.json",
    ]
    for path in files_to_stage:
        run_git("add", "-f", path)

    # --- Check if there is anything to commit ---
    diff_result = run_git("diff", "--staged", "--quiet")
    if diff_result.returncode == 0:
        log.info("No metadata changes to commit.")
    else:
        entry_count = count_manifest()
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        commit_msg = (
            f"SENTINEL APEX v{PIPELINE_VERSION} -- "
            f"{entry_count} advisories @ {ts} [P0-FIXED] [skip ci]"
        )
        result = run_git("commit", "-m", commit_msg)
        if result.returncode == 0:
            log.info("Committed: %s", commit_msg[:80])
        else:
            log.warning("Commit failed: %s", result.stderr.strip()[:200])

    # --- Push with 4-attempt retry ---
    for attempt in range(1, 5):
        run_git("fetch", "origin", "main", "--quiet")

        # Clear lock again (may reappear after fetch)
        lock_path = REPO_ROOT / ".git" / "index.lock"
        if lock_path.exists():
            try:
                lock_path.unlink()
            except Exception:
                pass

        # Merge with ours strategy
        merge_result = run_git("merge", "origin/main", "-X", "ours", "--no-edit", "--quiet")
        if merge_result.returncode != 0:
            log.warning("Merge failed on attempt %d -- stash recovery.", attempt)
            run_git("merge", "--abort")
            run_git("stash", "push", "-m", f"sentinel-recovery-{attempt}")
            run_git("reset", "--hard", "origin/main")
            run_git("stash", "pop")

        push_result = run_git("push", "origin", "main")
        if push_result.returncode == 0:
            log.info("OK: Push succeeded (attempt %d)", attempt)
            break

        log.warning("Push attempt %d failed: %s", attempt, push_result.stderr.strip()[:100])
        if attempt < 4:
            sleep_secs = attempt * 15
            log.info("Retrying in %ds...", sleep_secs)
            time.sleep(sleep_secs)
        else:
            log.warning("All push attempts exhausted -- state will sync on next run.")

    log.info("safe_git_commit.py complete.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        log.warning("safe_git_commit.py error (non-fatal): %s\n%s", e, traceback.format_exc())
        sys.exit(0)  # Git sync must never kill pipeline
