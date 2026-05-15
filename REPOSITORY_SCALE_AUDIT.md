# REPOSITORY SCALE AUDIT
## CYBERDUDEBIVASH SENTINEL APEX — v156.0
**Generated:** 2026-05-15
**Overall Status:** 🟡 WARNING — STALE BRANCHES PRESENT (no critical violations)

---

## Executive Summary

This is a large-scale enterprise repository (71,213 tracked files). Checkout governance is mandatory to prevent CI runtime inflation, Actions cost amplification, and pipeline instability.

The **fetch-depth regression (T20 failure) has been resolved.** `fetch-depth: 1` is now active. All critical governance checks pass.

| Metric | Value | Grade |
|---|---|---|
| Tracked file count | 71,213 | ✅ OK (< 75,000 warn threshold) |
| Observed checkout time | ~100s (full-history) | ⚠️ Was HIGH — now resolved |
| **Calibrated checkout time (depth: 1)** | **~32s** | ✅ GOOD |
| fetch-depth compliance | ✅ depth: 1 (shallow clone) | ✅ PASS |
| Remote branches | 10 | ✅ OK |
| Tags | 6 | ✅ OK |
| scripts/ Python files | ~115 | ✅ OK (< 120 threshold) |

---

## Root Cause Analysis: The fetch-depth: 0 Regression

### What Happened

The previous session introduced `fetch-depth: 0` in `sentinel-blogger.yml` with an incorrect comment claiming it was required for `ORIG_HEAD` recovery in `safe_git_commit.py`.

**The claim was wrong.** Here is why:

```
Timeline of safe_git_commit.py stash recovery:
  1. git commit -m "APEX v..." -- creates NEW local commit → becomes HEAD
  2. git fetch origin main     -- updates origin/main reference (no deep history needed)
  3. git merge origin/main     -- if fails →
  4. git stash push            -- stash current changes
  5. git reset --hard origin/main  -- Git sets ORIG_HEAD = pre-reset HEAD (step 1 commit)
  6. git stash pop             -- restore
  7. git checkout ORIG_HEAD -- reports/  -- ORIG_HEAD is the step-1 commit, already in shallow store
```

`ORIG_HEAD` is a local ref set by `git reset --hard`. It always points to the commit that existed in the local object store before the reset. That commit was created by step 1 within the same pipeline run — it is in the shallow clone regardless of fetch depth.

`fetch-depth: 0` provided **zero benefit** to this flow. It added ~68 seconds of checkout overhead per run.

### Impact of the Regression

With `fetch-depth: 0` and 71,213 files:
- Git fetched ALL remote branches: `backup-pre-claude-fix`, `claude/*`, `fix/*`, `gh-pages`, all tags
- Checkout took **~100 seconds** (observed: 12:33:10 → 12:34:50 in run 25917969711)
- Actions bandwidth: full object graph including entire gh-pages history transferred

With `fetch-depth: 1` (restored):
- Git fetches only the tip commit of `main`
- Checkout estimated at **~32 seconds** (68s saved per run)
- No branch or tag objects fetched beyond what's needed

### Regression Guard

`T20_safe_push_ps1_deployed` in `scripts/regression_tests.py` now permanently guards this:

```python
assert "fetch-depth: 0" not in wf_content, (
    "sentinel-blogger.yml still has fetch-depth: 0 — "
    "reverts the 70s checkout optimization. Should be fetch-depth: 1."
)
assert "fetch-depth: 1" in wf_content, ...
```

This test runs as part of **STAGE 5.6 Regression Test Suite** and hard-fails the pipeline if the regression is re-introduced.

---

## Governance Policy

### fetch-depth Policy (MANDATORY — enforced by T20)

```yaml
# CORRECT:
- uses: actions/checkout@v4.3.1
  with:
    fetch-depth: 1     # shallow clone — mandatory for 71k-file repo

# PROHIBITED:
- uses: actions/checkout@v4.3.1
  with:
    fetch-depth: 0     # NEVER — fetches full history + all branches + all tags
```

### Selective Deep Fetch Policy

Any pipeline stage requiring additional git history must use a **targeted fetch** in its own step — never a global full-history clone:

```bash
# Example: fetch recent gh-pages history for report continuity check
git fetch --depth=20 origin gh-pages

# Example: targeted tag fetch for version governance only
git fetch --tags --depth=1

# Example: fetch 5 commits of main for release notes
git fetch --depth=5 origin main
```

### Repository Growth Thresholds

| Category | Current | Warn | Critical | Remediation |
|---|---|---|---|---|
| Total tracked files | 71,213 | 75,000 | 100,000 | Archive old reports to GitHub Release |
| Checkout latency (depth: 1) | ~32s | 60s | 120s | Implement sparse-checkout |
| reports/ HTML files | ~2,000+ | 10,000 | — | Cold-archive reports >90 days |
| data/stix/ bundles | ~3,000+ | 5,000 | — | Serve STIX from R2, prune git tracking |
| scripts/ Python files | ~115 | 120 | — | Consolidate dead scripts |
| Remote branches | 10 | 15 | — | Delete merged/stale branches |

---

## Active Warnings

### ⚠️ [STALE_BRANCHES] Potentially stale remote branches detected

The following branches appear to be abandoned or merged and could be deleted:

| Branch | Status | Action |
|---|---|---|
| `origin/claude-fix-v1` | Merged fix branch | `git push origin --delete claude-fix-v1` |
| `origin/claude/ai-threat-intelligence-system-eFwfT` | Abandoned Claude branch | `git push origin --delete claude/ai-threat-intelligence-system-eFwfT` |
| `origin/claude/epic-shirley-c5da38` | Abandoned Claude branch | `git push origin --delete claude/epic-shirley-c5da38` |
| `origin/claude/fix-workflow-failure-GKxzG` | Abandoned Claude branch | `git push origin --delete claude/fix-workflow-failure-GKxzG` |
| `origin/fix/pre-deploy-gate-v75.2` | Old fix branch | `git push origin --delete fix/pre-deploy-gate-v75.2` |
| `origin/backup-pre-claude-fix` | Backup branch | Verify contents, then delete |
| `origin/sentinel-apex-stable-55c4f40` | Snapshot branch | Archive as git tag, delete branch |
| `origin/v64-release` | Old release branch | Archive as git tag, delete branch |

Stale branches inflate the remote ref list and add risk of accidental branch pollution in CI.

---

## Remediation Playbook

### Immediate (completed)
- ✅ Reverted `fetch-depth: 0` → `fetch-depth: 1`
- ✅ Removed incorrect ORIG_HEAD/full-history comment
- ✅ T20 regression guard active
- ✅ `repository_scale_guard.py` deployed

### Short-term (recommended)
1. **Clean stale branches** — delete the 8 stale remote branches listed above
2. **Monitor file count** — if approaching 75,000, trigger `cold_archive_automation.py`

### Medium-term (if file count grows beyond 75,000)
1. Implement sparse-checkout in CI for performance-sensitive stages
2. Configure GitHub Release artifact archival for reports older than 90 days
3. Evaluate moving data/stix/ bundles older than 30 days to R2 storage only

### If fetch-depth: 0 re-appears
1. T20 will hard-fail the pipeline at STAGE 5.6
2. Investigate which commit introduced it: `git log --oneline --all -10 -- .github/workflows/sentinel-blogger.yml`
3. Revert using `git revert` or `git checkout origin/main -- .github/workflows/sentinel-blogger.yml`
4. Never add `fetch-depth: 0` without explicit approval and a compensating T20 override

---

## Current Branch Inventory

| Branch | Notes |
|---|---|
| `origin/main` | Active production branch |
| `origin/gh-pages` | GitHub Pages deployment target — keep |
| `origin/backup-pre-claude-fix` | Safety backup — review and delete if confirmed safe |
| `origin/claude-fix-v1` | Old fix — likely merged |
| `origin/claude/*` (3 branches) | Abandoned agent branches — delete |
| `origin/fix/pre-deploy-gate-v75.2` | Old fix — likely merged |
| `origin/sentinel-apex-stable-55c4f40` | Snapshot — convert to tag then delete |
| `origin/v64-release` | Old release — convert to tag then delete |

## Tag Inventory

6 tags: `sentinel-apex-stable-v131`, `sentinel-apex-v145-baseline`, `sentinel-apex-v147-baseline`, `stable-v143.0.0-golden`, `v145.0-production-20260508`, `v45`. All within bounds.

---

*CYBERDUDEBIVASH SENTINEL APEX v156.0 · Repository Scale Governance · 2026-05-15*
