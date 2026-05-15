# DEPLOYMENT CONSISTENCY REPORT
## CYBERDUDEBIVASH® SENTINEL APEX v154.0.0
**Date:** 2026-05-15  
**Pipeline Run:** 25907201821  
**Classification:** P0 POST-INCIDENT DEPLOYMENT AUDIT

---

## DEPLOYMENT STATE ANALYSIS

### Pre-Fix Deployment State (v152.0.0 — BROKEN)

| Metric | Expected | Actual | Status |
|--------|----------|--------|--------|
| Reports on runner disk (pre-git-sync) | 36,104 | 36,104 | PASS |
| Reports on runner disk (post-git-sync) | 36,104 | ~35,942 | **FAIL** |
| Reports missing from disk after stash recovery | 0 | 162 | **FAIL** |
| Manifest items with valid report_url on disk | 159 | 0 | **FAIL** |
| api/feed.json items with valid report_url on disk | 92 | 92 | PASS |
| Pages deployment artifact contains all reports | YES | NO | **FAIL** |
| Customer-facing report URLs returning HTTP 200 | 159 | 0 | **FAIL** |

### Root Cause of Deployment Inconsistency

The inconsistency originates in `safe_git_commit.py`'s stash recovery path. When a concurrent push causes `git push` to fail, the recovery sequence:

```
git stash push           # does NOT stash unmodified tracked files (reports/)
git reset --hard origin/main  # WIPES tracked files absent from origin/main
git stash pop            # restores only stashed JSON data, NOT reports/
```

This creates a race condition where two concurrent pipeline runs can "race to the bottom" — each run's stash recovery removes the other's reports from origin/main, establishing a permanent state where reports are absent.

### Deployment Pipeline Integrity Gates — Current State

| Gate | Stage | Pre-Fix Behavior | Post-Fix Behavior |
|------|-------|-----------------|-------------------|
| Report Generation | 3.2 | God Mode skips all 159 (files exist) | God Mode respects public `report_url`; regenerates if public path missing |
| Report Validation Gate | 3.3 | 159/159 PASS (uses internal_report_url, masks drift) | PASS + Rule 3b checks public `report_url` path independently |
| Report Count Gate | 5.4 | 35,945 reports counted — PASS | Same; not a regression |
| Report Existence Gate | 5.4.1 | **WARN-ONLY** — 159 missing, exits 0 | **HARD FAIL** — exits 1, blocks deployment |
| Git Sync (Reports Recovery) | 4 | Reports wiped by reset --hard, no recovery | **Reports Recovery Guard** restores from ORIG_HEAD |
| Deployment Canary | 5.8.1 | 5/5 API health — PASS (blind to report 404s) | Same (API health) |
| Report URL Canary | 5.8.1b | NOT PRESENT | **NEW** — probes live report URLs, hard fails on 404 |

---

## PAGES DEPLOYMENT ARTIFACT AUDIT

### Deployment Action Configuration

```yaml
uses: JamesIves/github-pages-deploy-action@v4.7.4
with:
  branch: gh-pages
  folder: .
  clean: false
  force: true
```

**`folder: .`** — deploys entire working tree (correct; includes reports/)  
**`clean: false`** — does not delete old files from gh-pages (correct; preserves historical reports)  
**`force: true`** — force-pushes to gh-pages (can overwrite; acceptable for this use case)  

The Pages action itself is correctly configured. The issue was in the working tree CONTENT at deploy time — reports were missing from the working tree before rsync ran.

### rsync Command (from Stage 54 logs)

```
rsync -q -av --checksum --progress /home/runner/work/.../ 
      github-pages-deploy-action-temp-deployment-folder
      --exclude .ssh --exclude .git --exclude .github 
      --exclude github-pages-deploy-action-temp-deployment-folder
```

rsync copies all files in the working tree including gitignored ones (feed_manifest.json, api/feed.json). No `--exclude reports/` present. When reports/ was truncated by stash recovery, rsync faithfully deployed the truncated tree.

---

## DETERMINISM GUARANTEE — POST-FIX

With v154.0.0 fixes applied, the deployment pipeline achieves:

**Condition A:** No push conflict → reports committed and deployed normally ✓  
**Condition B:** Push conflict → stash recovery fires → ORIG_HEAD restore recovers all lost reports → reports re-added to working tree → recommit includes reports → deploy succeeds ✓  
**Condition C:** Reports somehow still missing after recovery → Stage 5.4.1 (HARD FAIL) blocks deployment ✓  
**Condition D:** Pages deployed but CDN has issue → Stage 5.8.1b (Report URL Canary) fires ✓  

The deployment is now **deterministic under concurrent execution**.
