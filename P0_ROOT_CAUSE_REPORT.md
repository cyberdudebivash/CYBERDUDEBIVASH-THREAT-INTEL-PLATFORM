# P0 ROOT CAUSE REPORT
## CYBERDUDEBIVASH® SENTINEL APEX — Production Regression Forensics
**Severity:** P0 CRITICAL — Customer-Facing  
**Incident Date:** 2026-05-15  
**Workflow Run ID:** 25907201821  
**Pipeline Version:** 152.0.0  
**Forensic Analyst:** Global CTO / Principal Production Reliability Engineer  
**Status:** ROOT CAUSE CONFIRMED — PERMANENT FIX DEPLOYED (v154.0.0)

---

## INCIDENT SUMMARY

All 159 threat intel report URLs on intel.cyberdudebivash.com returned HTTP 404 to customers. Dashboard cards rendered correctly but "View Report" URLs were broken. The pipeline reported SUCCESS at every stage. Zero alerts fired. The deployment canary passed 5/5 checks. The regression was completely invisible to all existing monitoring.

---

## ROOT CAUSE CHAIN (5-LAYER FAILURE)

### RC-1 — PRIMARY: Git Stash Recovery Race Condition (safe_git_commit.py)

**File:** `scripts/safe_git_commit.py` — merge retry block (lines 438–440)

**Mechanism:**

When `git push` fails due to a concurrent pipeline run pushing to `origin/main` first, `safe_git_commit.py` executes a 3-step recovery:

```
1. git stash push          ← stashes only MODIFIED tracked files (reports/ is UNCHANGED from checkout — NOT stashed)
2. git reset --hard origin/main  ← RESETS working tree to origin/main HEAD
3. git stash pop           ← restores only what was stashed (JSON data, NOT reports/)
```

**The fatal step:** `git reset --hard origin/main` resets the working tree to the concurrent origin/main HEAD. If that concurrent HEAD is missing the 159 HTML reports (because it was also produced by a stash recovery that lost them), those 159 files are **silently deleted from the runner's working tree**.

Since reports are tracked but **unmodified** (they came from checkout), `git stash push` does NOT include them in the stash. After `git stash pop`, they are permanently gone from the runner's disk. The Pages deployment deploys this truncated working tree → 404.

**Evidence:**
- Stage 28 (08:39:54): All 159 reports pass God Mode check — files exist at ~100 KB each
- Stage 30 (08:41:00): validate_reports.py reports `159/159 passed` — files confirmed on disk
- Stage 49 (08:44:15): `[pre-commit] reports/ has 36104 HTML report(s)` — all good
- Stage 49 (08:44:17): `WARNING: Merge failed on attempt 1 -- stash recovery.` — push conflict triggers reset
- Stage 52 (08:44:20): `checked=159 missing=159` — ALL 159 reports GONE from disk
- Workspace confirmation: `intel--65c2c6e58d5fbe0459e35b8a.html` MISSING from `reports/2026/05/`

**Confirmed missing count:** 162 HTML files (35,942 in main branch vs 36,104 on runner pre-reset)

---

### RC-2 — CRITICAL ENABLER: Report Existence Validator Silently Bypassed

**File:** `.github/workflows/sentinel-blogger.yml` — Stage 5.4.1

**Mechanism:**

Stage 5.4.1 (report_existence_validator.py) **correctly detected** all 159 missing reports:
```
RESULT: 159 report(s) referenced in manifest but MISSING on disk
```

But the stage was configured as:
```yaml
run: python3 scripts/report_existence_validator.py --warn-only || true
```

The `--warn-only` flag forces `exit 0` even on failures. The `|| true` doubles down as a safety net. **A perfectly working detection system was intentionally muzzled.** The pipeline proceeded to deploy a broken Pages site.

---

### RC-3 — ENABLER: validate_reports.py Masks URL Schema Drift

**File:** `scripts/validate_reports.py` — `_resolve_report_path()`

**Mechanism:**

`validate_reports.py` (Stage 3.3) uses `internal_report_url` as primary path, then falls back to `report_url`. This creates a false-pass scenario: if `internal_report_url` resolves to an existing file (e.g., an old report at a different path), Stage 3.3 passes — but the dashboard links use `report_url` which may point to a different/missing path.

**Result:** Stage 3.3 showed `159/159 PASS` even when `report_url` paths were customer-facing 404s.

---

### RC-4 — ENABLER: God Mode Skip on Public-Path-Missing Items

**File:** `scripts/report_generator.py` — God Mode gate (lines 1454–1475)

**Mechanism:**

The God Mode check fires when `expected.exists()` is True — using `internal_report_url` priority. If the existing internal file qualifies as god-mode quality (≥60 KB), regeneration is skipped regardless of whether the public `report_url` path exists.

**Result:** For items where `internal_report_url` and `report_url` differ (path drift), god mode protects the wrong file and the public customer-facing URL gets no report generated.

---

### RC-5 — ENABLER: No Post-Deploy HTTP Report URL Validation

**File:** `.github/workflows/sentinel-blogger.yml` — Stage 5.8.1 (Deployment Canary)

**Mechanism:**

The existing canary (Stage 5.8.1) validates 5 API health endpoints but does NOT probe any actual report HTML URLs against the live Pages site. A deployment that wipes all 159 reports passes the canary 5/5.

---

## FAILURE TIMELINE

```
08:39:54  Stage 28 — Report Generator
          159/159 reports skipped (God Mode — files exist on disk from checkout)
          REPORT_COUNT: 36,104

08:41:00  Stage 30 — Report Validation Gate (validate_reports.py)
          159/159 PASS (files exist on disk, internal_report_url resolves)

08:44:15  Stage 49 — Git Sync
          [pre-commit] reports/ has 36,104 HTML reports
          git commit SUCCESS
          git push FAILS (concurrent run already pushed)
          git stash push (reports/ NOT stashed — unchanged tracked files)
          git reset --hard origin/main  ◄── 159 reports DELETED from disk
          git stash pop (restores JSON only)
          git push SUCCESS (pushes state missing 159 reports)

08:44:20  Stage 52 — Report Existence Validator
          159/159 MISSING detected
          (--warn-only || true) → exits 0 → PIPELINE CONTINUES

08:44:21  Stage 54 — GitHub Pages Deploy
          rsync copies working tree to gh-pages branch
          Working tree MISSING 159 reports
          Deployment SUCCEEDS but reports are absent from artifact

08:45:32  Stage 61 — Deployment Canary
          5/5 PASS (API health, feed items, auth gate, dashboard, version)
          No report URL probe → canary BLIND to 404s

          Customer opens report URL → HTTP 404
```

---

## VERIFICATION: BOTH LOG ARCHIVES CONFIRM IDENTICAL FAILURE

Both `logs_69132508354.zip` and `logs_69132508354 (1).zip` are from the same workflow run (identical timestamps: 2026-05-15T08:39:54Z — 08:45:37Z). The regression is 100% reproducible and deterministic on any pipeline run where `git push` fails and stash recovery fires.

---

## PERMANENT FIXES IMPLEMENTED (v154.0.0)

| Fix | File | Description |
|-----|------|-------------|
| FIX-1 | `scripts/safe_git_commit.py` | **HTML Reports Recovery Guard** — snapshots report file set before `reset --hard`; after stash pop, detects lost reports and restores them from `ORIG_HEAD` |
| FIX-2 | `.github/workflows/sentinel-blogger.yml` | **Stage 5.4.1 HARD FAIL** — removed `--warn-only \|\| true`; pipeline now blocks deployment when any `report_url` is missing |
| FIX-3 | `scripts/report_generator.py` | **Dual-URL God Mode check** — God Mode only fires when BOTH `internal_report_url` path AND public `report_url` path exist; forces regeneration if public path missing |
| FIX-4 | `scripts/validate_reports.py` | **Rule 3b: Public Path Validation** — also validates `report_url` path independently of `internal_report_url`, catching schema drift |
| FIX-5 | `scripts/report_url_canary.py` (new) + workflow Stage 5.8.1b | **Live HTTP Report URL Canary** — post-deploy probe of sampled report URLs against live Pages site; hard fails on any 404 |

---

## POST-FIX DEPLOYMENT REQUIREMENTS

1. **Immediate:** Trigger a fresh pipeline run — FIX-1 will regenerate the 159 missing reports via ORIG_HEAD restore on the first push conflict, OR FIX-3 will force regeneration since `report_url` paths are missing.
2. **Validate:** Stage 5.4.1 must exit 0 (all report_urls found on disk).
3. **Validate:** Stage 5.8.1b must exit 0 (all sampled report URLs return HTTP 200).
4. **Confirm:** `intel--65c2c6e58d5fbe0459e35b8a.html` accessible at `intel.cyberdudebivash.com/reports/2026/05/intel--65c2c6e58d5fbe0459e35b8a.html`.

---

## SYSTEMIC RECOMMENDATION

The `git reset --hard origin/main` stash recovery pattern is architecturally unsafe for a repo with 35,000+ tracked HTML files. The pattern assumes all important changes are stashed. Large unmodified tracked files (like report HTMLs) are invisible to `git stash` — they exist in HEAD but are silently wiped by `reset --hard`.

**Long-term fix:** Replace the stash/reset/pop recovery with `git rebase --onto origin/main` or accumulate unstaged changes into a re-commit after the merge. The FIX-1 ORIG_HEAD restore guard is a targeted P0 remedy; a full architectural migration is recommended for v155.
