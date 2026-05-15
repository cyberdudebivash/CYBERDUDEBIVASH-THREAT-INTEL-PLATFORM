#!/usr/bin/env python3
"""
scripts/safe_git_commit.py
CYBERDUDEBIVASH(R) SENTINEL APEX v150.0 -- Safe Git Commit & Push (Immutable API-First)
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
  - data/cache/intel_index.json     (P0-FIX: dedup index persists across runs)
  - data/cache/feed_state.json      (P0-FIX: per-feed anti-loop state persists)

Runs with if: always() -- persists state even when upstream steps fail.

Environment variables:
  GH_TOKEN            -- GitHub token for push auth
  GITHUB_REPOSITORY   -- owner/repo
  PIPELINE_VERSION    -- version string
  R2_UPLOAD_COUNT     -- set by r2_upload.py (advisory count)
  MANIFEST_FINAL_COUNT -- set by run_pipeline.py

v142.4.0 P0 FIX -- Manifest Corruption Guard:
  data/stix/feed_manifest.json is gitignored but was historically force-added
  to git. During merge recovery (stash push -> reset --hard -> stash pop),
  git can write conflict markers (<<<<<<< Updated upstream) into this large
  JSON file, producing invalid JSON that breaks CI validation (json_valid and
  intel_schema checks fail with "Expecting value: line 1 column 1 (char 0)").

  Two-layer fix:
  1. Permanently untrack the file from git (git rm --cached) so it is never
     included in stash operations again.
  2. Backup/restore guard: snapshot valid manifest bytes before stash ops and
     restore them if stash pop leaves the file corrupted or missing.

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
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "147.0.0")


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

    # --- P0-FIX v141.6.0: Validate JSON files BEFORE staging ---
    # feed.json and any other JSON files must be valid before git add.
    # If a file is invalid JSON, skip staging it so the previous committed
    # (valid) version stays in the tree and validate_repo.py won't fail.
    def _validate_json_file(rel_path: str) -> bool:
        """Return True if file exists and contains valid JSON; False otherwise."""
        full = REPO_ROOT / rel_path
        if not full.exists():
            return True  # missing file is fine — git add will just skip it
        try:
            data = json.loads(full.read_text(encoding="utf-8"))
            # Extra: no null bytes
            raw_bytes = full.read_bytes()
            if b"\x00" in raw_bytes:
                log.warning("[git-guard] %s contains null bytes — skipping stage", rel_path)
                return False
            log.info("[git-guard] %s: VALID JSON (%s entries)",
                     rel_path, len(data) if isinstance(data, list) else "dict")
            return True
        except Exception as e:
            log.warning("[git-guard] %s: INVALID JSON (%s) — skipping stage to protect CI",
                        rel_path, e)
            return False

    # ── PROTECTED_FILES: hand-crafted HTML/assets the pipeline must NEVER overwrite ──
    # These files contain manually-engineered JS, payment flows, and UI code.
    # If encoding_guard.py or any pipeline stage modifies them during a run,
    # Stage 4 (this script) will restore them from the last committed HEAD version
    # before staging, preventing accidental overwrites of human-authored code.
    PROTECTED_FILES = [
        "upgrade.html",       # payment checkout UI + JS payment engine (god-mode)
        "pricing.html",       # pricing page if it exists
        "store.html",         # store page if it exists
        "services.html",      # services page if it exists
        "_headers",           # Cloudflare Pages security headers
        # SENTINEL APEX card system -- v145 enterprise SOC card renderer
        # These files are hand-authored; pipeline must NEVER overwrite them.
        "js/api_adapter.js",               # API normalizer + fetchAndNormalize (v145)
        "js/card_renderer.js",             # 9-zone enterprise SOC card renderer (v145)
        "js/card_renderer_integration.js", # EMBEDDED_INTEL instant boot + live upgrade (v145)
        "css/card_renderer_styles.css",    # glassmorphism design system (v145)
    ]
    for pf in PROTECTED_FILES:
        pf_path = REPO_ROOT / pf
        if pf_path.exists():
            # Restore to the committed HEAD version — discards any pipeline-stage modifications
            restore_result = run_git("checkout", "HEAD", "--", pf)
            if restore_result.returncode == 0:
                log.info("[protected] Restored %s from HEAD (preventing pipeline overwrite)", pf)
            else:
                log.warning("[protected] Could not restore %s from HEAD: %s", pf, restore_result.stderr)

    # ── P0-FIX v142.4.0: Untrack gitignored runtime files from git index ──────────
    # data/stix/feed_manifest.json is in .gitignore but was historically force-added.
    # While tracked, it participates in git stash/reset operations and can receive
    # conflict markers during stash pop, producing invalid JSON that breaks CI.
    # Solution: permanently untrack it so git stash/reset never touch it again.
    _RUNTIME_UNTRACK = [
        "data/stix/feed_manifest.json",
    ]
    for _ut in _RUNTIME_UNTRACK:
        _ut_result = run_git("rm", "--cached", "--ignore-unmatch", "-f", _ut)
        if _ut_result.returncode == 0:
            if _ut_result.stdout.strip():
                log.info("[untrack] Removed '%s' from git index (gitignored runtime file -- "
                         "prevents stash-pop conflict corruption)", _ut)
            else:
                log.info("[untrack] '%s' already untracked from git index", _ut)
        else:
            log.warning("[untrack] Could not untrack '%s': %s", _ut, _ut_result.stderr.strip()[:80])

    JSON_GUARDED = {
        "feed.json",
        "api/feed.json",
        "data/feed_manifest.json",
        "data/cache/intel_index.json",
        "data/cache/feed_state.json",
        "api/latest.json",
        "api/status.json",
    }

    # Stage guarded JSON files individually with validation
    for jf in JSON_GUARDED:
        if _validate_json_file(jf):
            run_git("add", "-f", jf)

    # ── IMMUTABLE API-FIRST GUARD (v150.0) ────────────────────────────────────
    # REPLACES: old EMBEDDED_INTEL guard (deleted — root cause of P0 regressions)
    #
    # NEW ARCHITECTURE: index.html is NEVER modified by the pipeline.
    # Data is served from api/v1/intel/*.json immutable bundles generated by
    # generate_api_manifests.py at Stage 3.93.
    #
    # This guard verifies:
    #   1. api/v1/intel/latest.json exists and is populated (required for frontend)
    #   2. index.html EMBEDDED_INTEL is still [] (confirms no HTML mutation occurred)
    #   3. If api/v1/intel/ bundles are missing, log a warning but do NOT restore
    #      index.html from HEAD (the static stub is correct in all cases).
    # ──────────────────────────────────────────────────────────────────────────
    import re as _re_guard

    # Check 1: API manifest bundles exist and are populated
    _latest_path = REPO_ROOT / "api" / "v1" / "intel" / "latest.json"
    if _latest_path.exists():
        try:
            _latest_data = json.loads(_latest_path.read_text(encoding="utf-8"))
            _item_count  = _latest_data.get("count", 0) or len(_latest_data.get("items", []))
            if _item_count >= 1:
                log.info("[API-MANIFEST GUARD] PASS -- api/v1/intel/latest.json has %d items", _item_count)
            else:
                log.warning("[API-MANIFEST GUARD] WARN -- api/v1/intel/latest.json is empty (count=0) "
                            "-- generate_api_manifests.py may not have run this cycle")
        except Exception as _amg_err:
            log.warning("[API-MANIFEST GUARD] api/v1/intel/latest.json parse error: %s", _amg_err)
    else:
        log.warning("[API-MANIFEST GUARD] api/v1/intel/latest.json NOT FOUND -- "
                    "generate_api_manifests.py must run before Stage 4 on first deploy")

    # Check 2: index.html must NOT be mutated (EMBEDDED_INTEL must be static [])
    _index_path = REPO_ROOT / "index.html"
    if _index_path.exists():
        try:
            _html_text  = _index_path.read_text(encoding="utf-8", errors="replace")
            _ei_pattern = _re_guard.compile(
                r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', _re_guard.DOTALL
            )
            _ei_match = _ei_pattern.search(_html_text)
            if _ei_match:
                _ei_val     = _ei_match.group(1).strip()
                _ei_compact = _ei_val.replace(" ", "").replace("\n", "").replace("\r", "")
                _is_empty   = (_ei_compact == "[]" or len(_ei_compact) <= 4)
                if _is_empty:
                    log.info("[IMMUTABILITY GUARD] PASS -- index.html EMBEDDED_INTEL is static [] "
                             "(immutable architecture active, zero HTML mutation confirmed)")
                else:
                    log.error(
                        "[IMMUTABILITY GUARD] VIOLATION -- index.html EMBEDDED_INTEL was MUTATED "
                        "(%d chars) -- restoring from HEAD to enforce immutable architecture",
                        len(_ei_val)
                    )
                    _restore = run_git("checkout", "HEAD", "--", "index.html")
                    if _restore.returncode == 0:
                        log.info("[IMMUTABILITY GUARD] RESTORED index.html from HEAD "
                                 "(immutable state preserved)")
                    else:
                        log.error("[IMMUTABILITY GUARD] Could not restore index.html: %s",
                                  _restore.stderr)
            else:
                log.warning("[IMMUTABILITY GUARD] EMBEDDED_INTEL declaration not found in index.html "
                            "-- proceeding (may be pre-v150 build)")
        except Exception as _ig_err:
            log.warning("[IMMUTABILITY GUARD] Guard check failed: %s -- proceeding", _ig_err)
    # ── END IMMUTABLE API-FIRST GUARD ─────────────────────────────────────────

    # --- Stage NON-SENSITIVE files ---
    # NOTE: JSON files that need validation are handled ABOVE by JSON_GUARDED.
    # Do NOT list them here — the unguarded git-add would override the guard.
    files_to_stage = [
        "data/stix/CDB-APEX-*.json",
        "data/sync_marker.json",
        # api/latest.json        → JSON_GUARDED (validated above)
        # api/status.json        → JSON_GUARDED (validated above)
        "api/engines.json",
        "api/ai/",
        # v150.0 IMMUTABLE API-FIRST: stage immutable manifest bundles
        "api/v1/intel/latest.json",
        "api/v1/intel/top10.json",
        "api/v1/intel/apex.json",
        "api/v1/intel/manifest.json",
        "api/v1/intel/ai_summary.json",    # AI Cyber Brain endpoint (v147.0)
        "version.json",                    # Platform version manifest (v147.0 governance)
        "config/version.json",             # Deploy-worker SSOT (v147.0 governance)
        "VERSION",                         # Authoritative semver (v147.0 governance)
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
        # data/feed_manifest.json     → JSON_GUARDED (validated above)
        # data/cache/intel_index.json → JSON_GUARDED (validated above)
        # data/cache/feed_state.json  → JSON_GUARDED (validated above)
        # feed.json                   → JSON_GUARDED (validated above)
        # api/feed.json               → JSON_GUARDED (validated above)
    ]
    for path in files_to_stage:
        run_git("add", "-f", path)

    # --- v141.7.0 Phase 5: Pre-commit reports/ existence check ---
    reports_dir = REPO_ROOT / "reports"
    if reports_dir.is_dir():
        _html_count = sum(
            1 for f in reports_dir.rglob("*.html") if f.name != "index.html"
        )
        log.info("[pre-commit] reports/ has %d HTML report(s)", _html_count)
        if _html_count == 0:
            log.warning(
                "[pre-commit] WARNING: reports/ directory has ZERO HTML files. "
                "Either pipeline produced no reports (investigate) or "
                "reports were not generated yet. Continuing commit of other assets."
            )
    else:
        log.warning("[pre-commit] reports/ directory does not exist -- creating empty dir")
        reports_dir.mkdir(parents=True, exist_ok=True)

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

    # --- v141.7.0 Post-commit: verify key files are in git index ---
    _verify_files = ["index.html", "feed.json"]
    for _vf in _verify_files:
        _ls = run_git("ls-files", "--error-unmatch", _vf)
        if _ls.returncode == 0:
            log.info("[post-commit] git index verify: %s -- IN INDEX", _vf)
        else:
            log.warning("[post-commit] git index verify: %s -- NOT TRACKED (new file?)", _vf)

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

            # == P0-FIX v142.4.0: Manifest Corruption Guard ==
            # PROBLEM: git stash push -> reset --hard -> stash pop can write conflict
            # markers into large runtime JSON files still tracked in git, producing
            # invalid JSON: "Expecting value: line 1 column 1 (char 0)".
            # SOLUTION: snapshot valid manifest bytes BEFORE stash; restore AFTER pop.
            _MANIFEST_GUARD_PATHS = [
                REPO_ROOT / "data" / "stix" / "feed_manifest.json",
                REPO_ROOT / "data" / "feed_manifest.json",
            ]
            _manifest_backups: dict = {}
            for _mp in _MANIFEST_GUARD_PATHS:
                if _mp.exists():
                    try:
                        _raw = _mp.read_bytes()
                        json.loads(_raw.decode("utf-8"))  # validate before saving
                        _manifest_backups[str(_mp)] = (_mp, _raw)
                        log.info("[manifest-guard] Snapshot saved: %s (%d bytes)",
                                 _mp.name, len(_raw))
                    except Exception as _snap_err:
                        log.warning("[manifest-guard] Skipping snapshot of %s (already "
                                    "invalid -- %s)", _mp.name, _snap_err)

            # == P0-FIX v154.0.0: HTML Reports Recovery Guard ==
            # PROBLEM (P0 REGRESSION — confirmed 2026-05-15):
            #   git reset --hard origin/main wipes HTML report files that exist
            #   locally but are absent from the current origin/main HEAD
            #   (due to a concurrent pipeline run that also lost them via an
            #   earlier stash recovery cycle).  Reports that passed validate_reports.py
            #   (Stage 3.3) are silently deleted and never deployed to GitHub Pages,
            #   causing every manifest report_url to return HTTP 404.
            # ROOT CAUSE:
            #   git stash push does NOT stash unmodified tracked files.
            #   git reset --hard origin/main REMOVES any tracked file that is
            #   present in our local HEAD but absent from origin/main HEAD.
            #   git stash pop restores only what was stashed (data JSON).
            #   Reports are gone. Pipeline reports SUCCESS. Pages returns 404.
            # SOLUTION:
            #   1. Snapshot the count and path set of all HTML reports BEFORE reset.
            #   2. After stash pop, detect if any HTML reports are missing.
            #   3. Restore lost reports from ORIG_HEAD (set by git reset --hard)
            #      which points to our pre-reset local commit containing all reports.
            # ──────────────────────────────────────────────────────────────────
            _reports_dir = REPO_ROOT / "reports"
            _pre_reset_reports: set = set()
            if _reports_dir.is_dir():
                _pre_reset_reports = {
                    str(f.relative_to(REPO_ROOT))
                    for f in _reports_dir.rglob("*.html")
                }
                log.info("[reports-guard] Pre-reset snapshot: %d HTML report(s)",
                         len(_pre_reset_reports))

            run_git("stash", "push", "-m", "sentinel-recovery-{}".format(attempt))
            run_git("reset", "--hard", "origin/main")
            run_git("stash", "pop")

            # Restore any HTML reports wiped by reset --hard
            if _pre_reset_reports:
                _post_reset_reports: set = set()
                if _reports_dir.is_dir():
                    _post_reset_reports = {
                        str(f.relative_to(REPO_ROOT))
                        for f in _reports_dir.rglob("*.html")
                    }
                _lost_reports = _pre_reset_reports - _post_reset_reports
                if _lost_reports:
                    log.warning(
                        "[reports-guard] %d HTML report(s) LOST by reset --hard "
                        "(concurrent origin/main lacked them). Restoring from "
                        "ORIG_HEAD (pre-reset commit).", len(_lost_reports)
                    )
                    # ORIG_HEAD is set by git reset --hard to our pre-reset commit
                    _restore_result = run_git("checkout", "ORIG_HEAD", "--", "reports/")
                    if _restore_result.returncode == 0:
                        _restored_count = sum(1 for f in _reports_dir.rglob("*.html"))
                        log.info(
                            "[reports-guard] RESTORED reports/ from ORIG_HEAD: "
                            "%d total HTML reports (recovered %d lost files).",
                            _restored_count, len(_lost_reports)
                        )
                    else:
                        log.error(
                            "[reports-guard] CRITICAL: Could not restore reports/ "
                            "from ORIG_HEAD: %s -- deploying without %d reports!",
                            _restore_result.stderr.strip()[:200], len(_lost_reports)
                        )
                else:
                    log.info("[reports-guard] Report count intact after stash recovery: "
                             "%d HTML files (no reports lost).", len(_post_reset_reports))
            # == END P0-FIX v154.0.0 ==

            # == P0-FIX v145.1.0: Workflow YAML Conflict-Marker Guard ==
            # PROBLEM: git stash pop replays stashed changes on top of origin/main.
            # When .github/workflows/ files changed between the stash base and
            # origin/main (e.g. a fix merged mid-run), git writes conflict markers
            # "<<<<<<< Updated upstream" into YAML files. validate_repo.py's
            # yaml_parse check then fails, breaking the Final Validation Gate.
            # SOLUTION: restore the entire .github/ tree from origin/main after
            # every stash pop. safe_git_commit.py NEVER intentionally modifies
            # workflow files, so any stash-pop change there is always corruption.
            _wf_restore = run_git("checkout", "origin/main", "--", ".github/")
            if _wf_restore.returncode == 0:
                log.info("[workflow-guard] Restored .github/ from origin/main after "
                         "stash pop (prevents YAML conflict markers in validate_repo)")
            else:
                log.warning("[workflow-guard] Could not restore .github/ from "
                            "origin/main: %s", _wf_restore.stderr.strip()[:120])

            # Secondary: detect any remaining unresolved conflicts in tracked files
            _unmerged = run_git("diff", "--name-only", "--diff-filter=U")
            if _unmerged.returncode == 0 and _unmerged.stdout.strip():
                for _cf in _unmerged.stdout.strip().split("\n"):
                    _cf = _cf.strip()
                    if not _cf:
                        continue
                    log.warning("[conflict-cleanup] Conflict marker in '%s' after "
                                "stash pop -- restoring from origin/main", _cf)
                    run_git("checkout", "origin/main", "--", _cf)
            else:
                log.info("[conflict-cleanup] No unresolved conflicts after stash pop")

            # Restore manifests if stash pop corrupted them
            for _key, (_mp, _saved_bytes) in _manifest_backups.items():
                _needs_restore = False
                if not _mp.exists():
                    _needs_restore = True
                    log.warning("[manifest-guard] %s MISSING after stash pop -- restoring",
                                _mp.name)
                else:
                    try:
                        json.loads(_mp.read_bytes().decode("utf-8"))
                        log.info("[manifest-guard] %s intact after stash pop", _mp.name)
                    except Exception as _chk_err:
                        _needs_restore = True
                        log.warning("[manifest-guard] %s CORRUPTED after stash pop "
                                    "(%s) -- restoring snapshot", _mp.name, _chk_err)
                if _needs_restore:
                    try:
                        _mp.parent.mkdir(parents=True, exist_ok=True)
                        _mp.write_bytes(_saved_bytes)
                        log.info("[manifest-guard] RESTORED %s (%d bytes) -- "
                                 "pipeline data integrity preserved",
                                 _mp.name, len(_saved_bytes))
                    except Exception as _write_err:
                        log.error("[manifest-guard] Failed to restore %s: %s",
                                  _mp.name, _write_err)

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
