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


def _write_metadata_sync_state(state: dict) -> None:
    """Record recovery evidence without publishing it as production success."""
    health = REPO_ROOT / "data" / "health"
    health.mkdir(parents=True, exist_ok=True)
    target = health / "git_sync_state.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temporary.replace(target)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(
                f"\nGenerated metadata: **{state['state']}**; main not updated. "
                f"Commit `{state['commit_sha']}` on `{state['branch']}`. "
                f"[Review preserved diff]({state['compare_url']}).\n")
            if state.get("reason"):
                summary.write(f"PR blocker: `{state['reason']}`. {state['operator_action']}\n")
            if state.get("pr_number"):
                summary.write(f"Draft PR #{state['pr_number']}; review pending.\n")


def publish_metadata_pr(token: str, repository: str) -> dict:
    """Persist the exact generated commit on a unique branch; never push main.

    A reviewable PR is durable evidence, not proof that main was updated.
    GITHUB_RUN_ID/ATTEMPT make retries idempotent without force-pushing.
    """
    import re
    import urllib.request
    import urllib.error
    if not token or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise RuntimeError("Metadata PR requires GH_TOKEN and a valid GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if not run_id.isdigit() or not attempt.isdigit():
        raise RuntimeError("Metadata PR requires numeric run identity")
    branch = f"sentinel-generated/run-{run_id}-{attempt}"
    head = run_git("rev-parse", "HEAD")
    commit_sha = (head.stdout or "").strip()
    if head.returncode or not re.fullmatch(r"[a-f0-9]{40}", commit_sha):
        raise RuntimeError("Cannot establish generated commit identity; publication stopped")
    push = run_git("push", "origin", f"HEAD:refs/heads/{branch}")
    if push.returncode:
        raise RuntimeError("Generated metadata branch push rejected; no main write attempted")

    # A successful push process is not sufficient persistence evidence. Read
    # the remote ref back and require the exact generated commit. This closes
    # the gap where transport/proxy behavior could report a successful command
    # while the intended review branch was not durably updated.
    remote = run_git("ls-remote", "--exit-code", "origin", f"refs/heads/{branch}")
    remote_sha = ""
    if remote.returncode == 0:
        first = (remote.stdout or "").strip().splitlines()
        if first:
            remote_sha = first[0].split()[0].strip()
    if remote_sha != commit_sha:
        raise RuntimeError(
            "Generated metadata remote verification failed; review branch identity is unproven; "
            "main unchanged"
        )

    state = {"state": "PERSISTED_BRANCH_ONLY", "branch": branch, "commit_sha": commit_sha,
             "remote_verified": True, "review_required": True,
             "main_updated": False, "run_id": run_id, "run_attempt": attempt,
             "compare_url": f"https://github.com/{repository}/compare/main...{commit_sha}"}
    _write_metadata_sync_state(state)

    def blocked(reason, status=None):
        state.update(state="PERSISTED_PR_BLOCKED", reason=reason)
        if status is not None:
            state["http_status"] = status
        state["operator_action"] = (
            "Check repository/organization Actions PR-creation policy and the token's "
            "pull-request permission. Review the preserved commit; do not bypass main protection.")
        _write_metadata_sync_state(state)
        return RuntimeError(f"Metadata PR blocked: {reason}; generated commit {commit_sha} "
                            f"preserved on {branch}; main unchanged")

    def api(method, path, payload=None):
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/{path}",
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read(1024 * 1024))
        except urllib.error.HTTPError as exc:
            # Never echo GitHub's raw body, token, request headers or transport
            # diagnostics. Only allowlisted classifications enter logs/evidence.
            reason = "GITHUB_API_REJECTED"
            if exc.code == 403:
                reason = "TOKEN_OR_POLICY_FORBIDDEN"
                try:
                    message = json.loads(exc.read(8192)).get("message", "")
                    if message == "GitHub Actions is not permitted to create or approve pull requests.":
                        reason = "ACTIONS_PR_CREATION_DISABLED"
                except (ValueError, AttributeError, OSError):
                    pass
            elif exc.code == 401:
                reason = "TOKEN_AUTHENTICATION_REJECTED"
            raise blocked(reason, exc.code) from None
        except urllib.error.URLError:
            raise blocked("GITHUB_TRANSPORT_UNAVAILABLE") from None
        except (ValueError, UnicodeError):
            raise blocked("INVALID_GITHUB_RESPONSE") from None

    owner = repository.split('/')[0]
    from urllib.parse import urlencode
    try:
        prs = api("GET", "pulls?" + urlencode({"state": "open", "head": f"{owner}:{branch}", "base": "main"}))
        if not isinstance(prs, list):
            raise blocked("INVALID_PR_LOOKUP_RESPONSE")
        pr = prs[0] if prs else api("POST", "pulls", {
            "head": branch, "base": "main", "draft": True,
            "title": f"chore: generated intel metadata from run {run_id}",
            "body": f"Generated artifacts preserved from workflow run {run_id}, attempt {attempt}. "
                    "Requires review and merge under main protection. R2 remains the runtime state authority. "
                    "This PR does not certify production deployment or customer readiness."})
        if not isinstance(pr, dict) or not isinstance(pr.get("number"), int):
            raise blocked("MISSING_PR_IDENTITY")
    except RuntimeError:
        # Repository policy can intentionally disallow PR creation by
        # GITHUB_TOKEN. At this point the exact generated commit has already
        # been read back from the remote review branch, so persistence is
        # proven. Treat only this explicit owner-policy condition as
        # "persisted, manual review required"; every other API/auth/transport
        # failure remains blocking and is re-raised.
        if state.get("reason") == "ACTIONS_PR_CREATION_DISABLED" and state.get("remote_verified") is True:
            state.update(
                state="PERSISTED_REVIEW_BLOCKED",
                review_required=True,
                operator_action=(
                    "Generated commit is remotely verified on the preserved branch. "
                    "Open/review a PR manually or enable Actions PR creation; do not bypass main protection."
                ),
            )
            _write_metadata_sync_state(state)
            return state
        raise

    state.update(state="PERSISTED_REVIEW_PENDING", pr_number=pr["number"], review_required=True)
    _write_metadata_sync_state(state)
    return state


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

    # P0 production-architecture-transformation mission (2026-09-08):
    # data/feed_manifest.json, data/cache/intel_index.json, and
    # data/cache/feed_state.json removed from this set -- all three are now
    # exclusively owned by scripts/r2_state_sync.py (--download/--upload,
    # already wired into sentinel-blogger.yml's "Download/Upload Intel
    # State from/to R2" steps), which was staging the same three files
    # here too. Keeping both authorities would mean git and R2 could each
    # hold a different "correct" copy with no reconciliation -- exactly
    # the duplicate-state-authority risk this mission was scoped to
    # eliminate, not merely tolerate. R2 is the durable one (git pushes to
    # main have been rejected by the branch ruleset since 2026-08-26; see
    # r2_state_sync.py's own module docstring for the full incident this
    # traces back to).
    JSON_GUARDED = {
        "feed.json",
        "api/feed.json",
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
    # P0 production-architecture-transformation mission (2026-09-08):
    # data/sync_marker.json removed -- full trace found zero live producer
    # or consumer (its only other references are patch_sync_display.py,
    # patch_workflow_sync.py, self_improve_monitor.py, none invoked by any
    # workflow). Staging and committing it every run persisted a file
    # nothing reads, for no reason -- not a persistence-layer defect to fix,
    # just dead weight to remove.
    files_to_stage = [
        "data/stix/CDB-APEX-*.json",
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
        # P0 production-architecture-transformation mission (2026-09-08):
        # .gitignore removed -- traced every write pattern across scripts/;
        # nothing in the live pipeline ever opens .gitignore for writing
        # (the one grep hit that looked like a match, generate_detection_pack.py,
        # turned out to be a comment mentioning an unrelated gitignored path,
        # not a write to this file). Staging an unchanged Class-C file every
        # run has no effect beyond risk surface -- removed rather than kept
        # "just in case".
        "reports/",
        # P0-FIX v184.4: written by build_reports_index.py (Stage 3.3.7) but
        # never explicitly staged here -- meaning any fresh-generated value
        # sat as an uncommitted working-tree change. That is only safe if
        # the file is genuinely stash-protected end to end; live production
        # showed it reverting to a stale prior-origin/main snapshot instead
        # (see the matching entry in _GENERATED_ARTIFACT_PATHS below, which
        # depends on these three being staged+committed here first -- ORIG_HEAD
        # only contains this run's fresh content if it was staged before the
        # pre-reset commit).
        "api/reports/index.json",
        "api/reports/latest.json",
        "api/reports/stats.json",
        "data/status/status.json",
        "data/health/guardian_report.json",
        "data/health/apex_engine_report.json",
        "data/health/apex_v2_audit.json",
        # GAP-001 FIX: report_engine_consistency_gate.py (STAGE 3.6.5) writes this
        # ledger every run, but it was never in this list -- the gate has run in
        # production and succeeded, yet its output evaporated every single time
        # because nothing ever staged it. Same category as the other data/health
        # and data/status observability artifacts above; staged the same way.
        "data/quality/report_engine_ledger.json",
        # Phase 4: quality_drift_monitor.py (STAGE 4.05) writes this every
        # run. Same category and same risk as report_engine_ledger.json
        # immediately above -- staged explicitly from day one rather than
        # waiting to rediscover the GAP-001 pattern a second time.
        "data/quality/quality_drift_report.json",
        "data/apex_v2_manifest.json",
        "data/apex_v2_strategic_report.json",
        "data/apex_intelligence_report.json",
        "data/apex_enriched_manifest.json",
        "data/validated_manifest.json",
        # P0 production-architecture-transformation mission (2026-09-08):
        # config/feature_flags.json removed -- traced every write pattern
        # across scripts/; nothing in the live pipeline ever opens this
        # file for writing (a broad grep for "feature_flags.json" plus "any
        # write pattern in the same file" produced false positives from
        # unrelated writes elsewhere in those same files; a precise
        # write-to-this-path check found zero real hits). Class-C
        # configuration, correctly never runtime-mutated; staging it every
        # run was already a no-op, now made explicit by removing it.
        #
        # data/publish_queue.json removed -- run_pipeline.py's own
        # stage_purge_publish_queue() unconditionally empties this file near
        # the start of EVERY run, before anything downstream reads it. It is
        # not cross-run state by construction (nothing depends on its
        # content surviving to the next run), so it needed neither git nor
        # R2 persistence -- committing "0 entries" every run was staging a
        # file whose content is always about to be discarded.
        #
        # The 5 data/intelligence_repository/*.json registries + advisories/
        # directory removed -- all 6 are now exclusively owned by
        # scripts/r2_state_sync.py's STATE_FILES/STATE_DIRS (same
        # duplicate-authority reasoning as data/feed_manifest.json etc.
        # above; these were already being double-staged here AND synced to
        # R2 by r2_state_sync.py with no reconciliation between the two).
        "intelligence-archive.html",
        # data/feed_manifest.json, data/cache/intel_index.json,
        # data/cache/feed_state.json, data/intelligence_repository/* →
        # scripts/r2_state_sync.py (sole authority, see module docstring)
        # feed.json                   → JSON_GUARDED (validated above)
        # api/feed.json               → JSON_GUARDED (validated above)
    ]
    for path in files_to_stage:
        run_git("add", "-f", path)

    # --- P0 FIX (2026-08-13): keep config/frontend_checksums.json atomic
    # with every commit that touches index.html (staged unconditionally
    # above). frontend-integrity-sync.yml (PR #166) already regenerates the
    # registry on `push`, but every commit this script makes carries
    # "[skip ci]" in its message (see commit_msg below) to avoid
    # re-triggering sentinel-blogger.yml -- and GitHub's [skip ci]
    # convention suppresses *every* push-triggered workflow for that
    # commit, including frontend-integrity-sync.yml. That left the registry
    # silently stale after each automated index.html regeneration until the
    # next non-skip-ci push happened to touch a protected asset, producing
    # false "TAMPERED: index.html" failures on GATE E (Post-Deploy
    # Validation) in the interim. Regenerating the registry here -- via the
    # existing frontend_integrity.py CLI, unchanged -- and staging it in the
    # same commit as the asset it certifies closes the gap unconditionally;
    # it no longer depends on a second workflow run firing at all.
    _fi_result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "frontend_integrity.py"), "generate"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    if _fi_result.returncode == 0:
        run_git("add", "-f", "config/frontend_checksums.json")
        log.info("[frontend-integrity] Registry resynced atomically with this commit")
    else:
        log.warning("[frontend-integrity] Registry resync failed (exit %d): %s -- "
                    "GATE E may see a stale registry until the next resync",
                    _fi_result.returncode, _fi_result.stderr.strip()[:300])

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
            f"{entry_count} advisories @ {ts} [GENERATED METADATA]"
        )
        result = run_git("commit", "-m", commit_msg)
        if result.returncode == 0:
            log.info("Committed: %s", commit_msg[:80])
        else:
            raise RuntimeError("Generated metadata commit failed; publication stopped")

    # --- v141.7.0 Post-commit: verify key files are in git index ---
    _verify_files = ["index.html", "feed.json"]
    for _vf in _verify_files:
        _ls = run_git("ls-files", "--error-unmatch", _vf)
        if _ls.returncode == 0:
            log.info("[post-commit] git index verify: %s -- IN INDEX", _vf)
        else:
            log.warning("[post-commit] git index verify: %s -- NOT TRACKED (new file?)", _vf)

    # GitHub production main requires PRs (ruleset 21556637). Keep the
    # existing local recovery path for offline tooling, never use it in CI.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if diff_result.returncode == 0:
            log.info("No generated metadata changes; no persistence PR required.")
            return
        state = publish_metadata_pr(gh_token, gh_repo)
        if state.get("state") == "PERSISTED_REVIEW_PENDING":
            log.info("Generated metadata persisted for review: PR #%s; main unchanged", state["pr_number"])
        elif state.get("state") == "PERSISTED_REVIEW_BLOCKED":
            log.warning(
                "Generated metadata remotely persisted on %s at %s; repository policy blocks "
                "Actions PR creation, so manual review/PR creation is required; main unchanged",
                state["branch"], state["commit_sha"],
            )
        else:
            raise RuntimeError("Generated metadata persistence ended in an unrecognized state")
        return

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
                # v173.2 FIX: These runtime-written data files repeatedly get conflict
                # markers during stash pop because both pipeline and remote modified them.
                # Pre-snapshot and restore avoids the conflict entirely (no WARN needed).
                REPO_ROOT / "data" / "governance" / "evidence_score_enforcement.json",
                REPO_ROOT / "data" / "health"      / "sla_status.json",
                REPO_ROOT / "data" / "quality"     / "source_trust_scores.json",
                REPO_ROOT / "data" / "health"      / "kev_marker_report.json",
                REPO_ROOT / "data" / "health"      / "pipeline_status.json",
                REPO_ROOT / "data" / "telemetry"   / "pipeline_telemetry.json",
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
            #
            # RX-PUB-A0 FIX (content-reversion blind spot -- confirmed via forensic
            # investigation of a live stale customer-facing report):
            #   The existence-only check above catches reports that VANISH but is
            #   blind to reports that ALREADY EXIST on origin/main (any report from
            #   a prior run) whose CONTENT gets silently reverted by
            #   `git reset --hard origin/main` -- the file path survives (it's
            #   present in both pre- and post-reset scans) so `_lost_reports` is
            #   empty and this guard reports "intact", even though the bytes now
            #   match stale origin/main instead of this run's freshly regenerated
            #   content. This is the exact same failure class the [artifact-guard]
            #   block below already fixes for JSON artifacts (P0-FIX v184.2,
            #   before/after item-count comparison) -- that fix was never extended
            #   to reports/*.html. Fixed the same way: hash every report before
            #   reset, and after stash-pop, treat a same-path/different-hash file
            #   exactly like a lost one (single whole-tree restore already handles
            #   both cases).
            # ──────────────────────────────────────────────────────────────────
            import hashlib as _reports_guard_hashlib

            def _sha256_of(_p: Path) -> str:
                try:
                    return _reports_guard_hashlib.sha256(_p.read_bytes()).hexdigest()
                except Exception:
                    return ""

            _reports_dir = REPO_ROOT / "reports"
            _pre_reset_reports: set = set()
            _pre_reset_hashes: dict = {}
            if _reports_dir.is_dir():
                for _f in _reports_dir.rglob("*.html"):
                    _rel = str(_f.relative_to(REPO_ROOT))
                    _pre_reset_reports.add(_rel)
                    _pre_reset_hashes[_rel] = _sha256_of(_f)
                log.info("[reports-guard] Pre-reset snapshot: %d HTML report(s)",
                         len(_pre_reset_reports))

            run_git("stash", "push", "-m", "sentinel-recovery-{}".format(attempt))
            run_git("reset", "--hard", "origin/main")
            run_git("stash", "pop")

            # Restore any HTML reports wiped OR content-reverted by reset --hard
            if _pre_reset_reports:
                _post_reset_reports: set = set()
                if _reports_dir.is_dir():
                    _post_reset_reports = {
                        str(f.relative_to(REPO_ROOT))
                        for f in _reports_dir.rglob("*.html")
                    }
                _lost_reports = _pre_reset_reports - _post_reset_reports
                _reverted_reports = {
                    _rel for _rel in (_pre_reset_reports & _post_reset_reports)
                    if _sha256_of(REPO_ROOT / _rel) != _pre_reset_hashes.get(_rel)
                }
                if _reverted_reports:
                    log.warning(
                        "[reports-guard] %d HTML report(s) CONTENT-REVERTED by "
                        "reset --hard (path survived, bytes reverted to stale "
                        "origin/main) -- e.g. %s",
                        len(_reverted_reports),
                        sorted(_reverted_reports)[:5],
                    )
                if _lost_reports or _reverted_reports:
                    log.warning(
                        "[reports-guard] %d lost + %d content-reverted HTML "
                        "report(s). Restoring from ORIG_HEAD (pre-reset commit).",
                        len(_lost_reports), len(_reverted_reports),
                    )
                    # ORIG_HEAD is set by git reset --hard to our pre-reset commit
                    _restore_result = run_git("checkout", "ORIG_HEAD", "--", "reports/")
                    if _restore_result.returncode == 0:
                        _restored_count = sum(1 for f in _reports_dir.rglob("*.html"))
                        log.info(
                            "[reports-guard] RESTORED reports/ from ORIG_HEAD: "
                            "%d total HTML reports (recovered %d lost + %d "
                            "content-reverted files).",
                            _restored_count, len(_lost_reports), len(_reverted_reports),
                        )
                    else:
                        log.error(
                            "[reports-guard] CRITICAL: Could not restore reports/ "
                            "from ORIG_HEAD: %s -- deploying with %d lost/reverted "
                            "reports!",
                            _restore_result.stderr.strip()[:200],
                            len(_lost_reports) + len(_reverted_reports),
                        )
                else:
                    log.info("[reports-guard] Report count and content intact after "
                             "stash recovery: %d HTML files (no reports lost or "
                             "reverted).", len(_post_reset_reports))
            # == END P0-FIX v154.0.0 (+ RX-PUB-A0 content-reversion extension) ==

            # == P0-FIX v184.2: Generated Customer-Artifact Recovery Guard ==
            # PROBLEM (confirmed via a live production pipeline run during
            # post-deploy verification): these files ARE staged and
            # committed above (JSON_GUARDED / files_to_stage) before this push
            # loop runs, so `git stash push` never protects them -- unlike an
            # uncommitted working-tree change, a committed file has nothing to
            # stash. `git reset --hard origin/main` above discards that local
            # commit wholesale (ORIG_HEAD now points at it, exactly like the
            # reports/ case above) -- but nothing restored these specific
            # paths afterward, so on every concurrent-push conflict this run's
            # freshly generated customer-facing intelligence silently reverted
            # to whatever origin/main had. Stage 4.1 then re-uploads whatever
            # is on disk to R2, so the reverted (stale) content overwrote the
            # correct version Stage 3.93.6 had just published moments earlier.
            # SOLUTION: same mechanism as the reports-guard above -- these
            # files are guaranteed correct in ORIG_HEAD (this run's own
            # pre-reset commit), so restore them the same way.
            #
            # P0-FIX v184.4: api/reports/index.json, api/reports/latest.json,
            # and api/reports/stats.json (written by build_reports_index.py,
            # Stage 3.3.7) were missing from this list. Confirmed via a live
            # production pipeline run (2026-08-11, run 31458784542) that hit
            # this exact concurrent-push conflict: the run's own log showed
            # build_reports_index.py wrote total_reports=11805 correctly, but
            # none of the three files were in the artifact-guard restore list
            # above, so they silently reverted to a stale prior-origin/main
            # snapshot (production served total_reports=356/21/81 across the
            # three files -- mutually inconsistent and none matching this
            # run's actual 11805-file disk scan) while every other generated
            # artifact was correctly restored and logged.
            #
            # P0-FIX v184.5: data/stix/feed_manifest.json (written by
            # multi_source_collector.py + reconciled by manifest_reconciler.py,
            # Stage 3.1.13/3.90) was missing from this list -- same class of
            # bug as v184.4, just on a different path. Confirmed via a live
            # production deploy-worker failure (2026-08-21): a run's own log
            # showed manifest_reconciler.py had correctly reconciled the
            # manifest in-memory/on-disk, but a concurrent-push conflict on
            # this same run triggered `git reset --hard origin/main`, and
            # because feed_manifest.json wasn't in the restore list, it
            # silently reverted to the stale pre-reset origin/main version
            # while api/feed.json (which IS on this list) correctly survived
            # -- producing a manifest 4 items behind the newly-published feed
            # and hard-failing scripts/api_dashboard_contract_validator.py's
            # CHECK 2 (genuine_regression) on the very next deploy-worker run.
            # P0-FIX v161.3 (Phase 2): api/detection_quality.json (written by
            # detection_quality_engine.py --apply, generate-and-sync.yml
            # STAGE 6.99) was missing from this list -- same class of bug as
            # v184.4/v184.5, on a different path, but with a worse blast
            # radius: this list already contains api/feed.json, so the
            # RESTORE step below unconditionally overwrites this run's
            # api/feed.json with ORIG_HEAD's version -- but ORIG_HEAD's
            # api/feed.json (written by THIS workflow, sentinel-blogger.yml,
            # which never calls detection_quality_engine.py) never had
            # detection_rules_total populated in the first place. So even
            # when this restore step "succeeds," it silently discards
            # detection_rules_total on every item, independent of whatever
            # generate-and-sync.yml's STAGE 6.99 had just computed and
            # committed. Confirmed via git history: two conflict-recovery
            # commits (609928b92, 239512ecd) touch api/feed.json but neither
            # touches api/detection_quality.json, and that file's last real
            # computation predates both. Root-caused during the Phase 2
            # detection-coverage-collapse investigation (0.0% on every item
            # in the live feed, despite a working, verified-correct
            # generator). Restoring it here alongside api/feed.json is not
            # sufficient by itself to fully fix the race (the two workflows'
            # commit strategies still differ), but it closes this specific,
            # confirmed silent-overwrite path.
            _GENERATED_ARTIFACT_PATHS = [
                "api/v1/intel/latest.json",
                "api/v1/intel/top10.json",
                "api/v1/intel/apex.json",
                "api/v1/intel/manifest.json",
                "api/v1/intel/ai_summary.json",
                "api/feed.json",
                "feed.json",
                "api/reports/index.json",
                "api/reports/latest.json",
                "api/reports/stats.json",
                "data/stix/feed_manifest.json",
                "api/detection_quality.json",
                # Phase 4: quality_drift_monitor.py accumulates a 30-run
                # rolling history in this file every run. It was staged
                # (files_to_stage, above) but not listed here -- meaning a
                # concurrent-push conflict's `reset --hard origin/main`
                # would discard this run's committed copy (in ORIG_HEAD)
                # without restoring it, silently losing that run's
                # history entry (the next run's history array would not
                # contain it either, since it can only append to whatever
                # it reads back). Same class of gap as the other entries
                # in this list, just not yet exercised by a live conflict.
                "data/quality/quality_drift_report.json",
            ]

            def _artifact_item_count(p: Path):
                try:
                    d = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(d, list):
                        return len(d)
                    if isinstance(d, dict):
                        if "items" in d:
                            return len(d["items"])
                        if "count" in d:
                            return d["count"]
                        if "total_reports" in d:
                            return d["total_reports"]
                    return "n/a"
                except Exception:
                    return "unreadable"

            for _ga in _GENERATED_ARTIFACT_PATHS:
                _ga_path = REPO_ROOT / _ga
                _before = _artifact_item_count(_ga_path) if _ga_path.exists() else "missing"
                _ga_restore = run_git("checkout", "ORIG_HEAD", "--", _ga)
                if _ga_restore.returncode == 0:
                    _after = _artifact_item_count(_ga_path) if _ga_path.exists() else "missing"
                    if _before != _after:
                        log.warning(
                            "[artifact-guard] %s was REVERTED by reset --hard "
                            "(%s items pre-restore) -- RESTORED from ORIG_HEAD "
                            "(%s items, this run's generation)",
                            _ga, _before, _after
                        )
                    else:
                        log.info("[artifact-guard] %s intact after restore (%s items)", _ga, _after)
                else:
                    log.warning(
                        "[artifact-guard] Could not restore %s from ORIG_HEAD: %s "
                        "(missing from pre-reset commit -- first run for this file?)",
                        _ga, _ga_restore.stderr.strip()[:120]
                    )
            # == END P0-FIX v184.2 ==

            # == P0-FIX v185.2: Post-Restore Dedup Safety Net ==
            # PROBLEM (Fortune-500 audit, Phase 1-2): the artifact-guard restore
            # loop above assumes ORIG_HEAD's copy of api/feed.json/feed.json is
            # always this run's own freshest generation and should always win --
            # but ORIG_HEAD is this run's pre-reset commit, produced by whatever
            # version of run_pipeline.py this run checked out at start. If a
            # concurrent push that lost the race to this run's reset carried a
            # newer run_pipeline.py fix (e.g. the source_url final-dedup gate
            # added in PR #249), this restore step silently overwrites that
            # newer, correct data with this run's own staler-code output --
            # confirmed live: governance run #1114 (commit cad092ab4) showed
            # grade=D with 2 source_url duplicates immediately after a
            # conflict-recovery commit (8dff1c7d6) restored api/feed.json from
            # ORIG_HEAD, reintroducing the exact duplicate PR #249 had just
            # removed. Since enforce_manifest_uniqueness() is idempotent and
            # cheap, re-run it here -- the last point before these files are
            # committed -- regardless of which code path produced the content
            # being restored.
            try:
                _scripts_dir_dedup = str(REPO_ROOT / "scripts")
                if _scripts_dir_dedup not in sys.path:
                    sys.path.insert(0, _scripts_dir_dedup)
                from intel_dedup_engine import enforce_manifest_uniqueness as _post_restore_dedup
                for _dg_rel in ("api/feed.json", "feed.json"):
                    _dg_path = REPO_ROOT / _dg_rel
                    if not _dg_path.exists():
                        continue
                    try:
                        _dg_raw = json.loads(_dg_path.read_text(encoding="utf-8").rstrip("\x00"))
                    except Exception as _dg_parse_e:
                        log.warning("[post-restore-dedup] Could not parse %s (%s) -- skipping", _dg_rel, _dg_parse_e)
                        continue
                    _dg_items = _dg_raw if isinstance(_dg_raw, list) else _dg_raw.get("items", _dg_raw.get("advisories", []))
                    _dg_unique, _dg_removed = _post_restore_dedup(_dg_items)
                    if _dg_removed:
                        if isinstance(_dg_raw, list):
                            _dg_out = _dg_unique
                        else:
                            if "advisories" in _dg_raw:
                                _dg_raw["advisories"] = _dg_unique
                            elif "items" in _dg_raw:
                                _dg_raw["items"] = _dg_unique
                            _dg_out = _dg_raw
                        _dg_tmp = Path(str(_dg_path) + ".tmp")
                        _dg_tmp.write_text(json.dumps(_dg_out, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
                        os.replace(str(_dg_tmp), str(_dg_path))
                        run_git("add", "-f", _dg_rel)
                        log.warning(
                            "[post-restore-dedup] %s: %d duplicate(s) reintroduced by ORIG_HEAD "
                            "restore, removed and re-staged", _dg_rel, _dg_removed
                        )
                    else:
                        log.info("[post-restore-dedup] %s: no duplicates after restore", _dg_rel)
            except ImportError as _dg_imp_e:
                log.warning("[post-restore-dedup] intel_dedup_engine unavailable (%s) -- skipped", _dg_imp_e)
            except Exception as _dg_e:
                log.warning("[post-restore-dedup] Failed (non-fatal): %s", _dg_e)
            # == END P0-FIX v185.2 ==

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

            # == P0-FIX v184.3: Recovery Commit Guard ==
            # PROBLEM: every guard above (reports-guard, artifact-guard,
            # workflow-guard, conflict-cleanup, manifest-guard) restores
            # content via `git checkout <ref> -- <path>` or a direct file
            # write -- both update the index/working tree but create no
            # commit. `git push` publishes commits, not working-tree or
            # staged state: after `git reset --hard origin/main` above, HEAD
            # already equals origin/main, so without a commit here the push
            # below has nothing new to send -- it exits 0 trivially
            # ("Everything up-to-date") while every restore above only ever
            # reaches the local runner disk, never origin/main's history.
            # Harmless for consumers that read local disk directly after
            # this script runs (e.g. an R2 sync step later in the same
            # job), but origin/main's tracked history would otherwise never
            # receive the correction. Commit whatever the guards actually
            # changed so it reaches the remote too.
            _recovery_diff = run_git("diff", "--cached", "--quiet")
            if _recovery_diff.returncode != 0:
                _recovery_commit = run_git(
                    "commit", "-m",
                    "SENTINEL APEX v{} -- conflict-recovery (attempt {}): "
                    "restore generated artifacts from ORIG_HEAD [skip ci]".format(
                        PIPELINE_VERSION, attempt
                    ),
                )
                if _recovery_commit.returncode == 0:
                    log.info("[recovery-commit] Committed restored artifacts "
                             "so they reach origin/main, not just local disk.")
                else:
                    log.warning("[recovery-commit] Commit failed: %s",
                                _recovery_commit.stderr.strip()[:200])
            else:
                log.info("[recovery-commit] Nothing to commit after recovery "
                         "(restored content already matches origin/main).")
            # == END P0-FIX v184.3 ==

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
            # P0 FIX: this used to be a bare log.warning() with no GitHub
            # Actions annotation, so a fully-exhausted push (all 4 attempts
            # rejected) was indistinguishable in the Actions UI from a normal
            # successful run -- confirmed live: every run for ~7 days had all
            # 4 attempts rejected with GH013 "Changes must be made through a
            # pull request" (main's branch ruleset), yet STAGE 4 showed green
            # throughout, silently discarding every run's committed STIX
            # bundles, reports, index.html and feed_state.json. Deliberately
            # still exit 0 below (see __main__ docstring: "Git sync must
            # never kill pipeline") -- STAGE 4 sits mid-pipeline and many
            # downstream steps (STAGE 5.6.1 Regression Immunity, STAGE 5.6.2
            # Stale-Feed Recurrence Guard, STAGE 5 Deploy to GitHub Pages,
            # etc.) have no `if: always()` guard and would be silently
            # skipped by GitHub Actions' default if:success() if this step
            # flipped to "failure" -- that blast radius is worse than the
            # bug this fixes. Loud annotation instead, matching the same
            # ::warning:: pattern STAGE 4.1's r2_resync_manifests.py failure
            # handling already uses one stage later in this same pipeline.
            _msg = (
                "safe_git_commit.py: push to main was rejected on all 4 attempts "
                f"(last error: {push_result.stderr.strip()[:200]!r}). This run's "
                "git-committed state (STIX bundles, reports, index.html, "
                "data/cache/feed_state.json, etc.) was NOT persisted to main -- "
                "the next run starts from stale state again. Check "
                f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', '')}"
                "/rules?ref=refs%2Fheads%2Fmain for the branch rule rejecting this push."
            )
            log.error(_msg)
            print(f"::error::{_msg}")

    log.info("safe_git_commit.py complete.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        log.error("safe_git_commit.py failed: %s\n%s", e, traceback.format_exc())
        sys.exit(1)
