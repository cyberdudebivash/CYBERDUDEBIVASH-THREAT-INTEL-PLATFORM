# CYBERDUDEBIVASH® SENTINEL APEX v101.0.0
# SAFE DEPLOYMENT INSTRUCTIONS
# Classification: PRODUCTION ENFORCEMENT — PERMANENT STABILITY CONTRACT
# Prepared: 2026-04-04

---

## PRE-DEPLOYMENT CHECKLIST

Before running ANY git command, verify these locally:

```bash
# 1. Confirm you are on the correct branch
git branch --show-current
# Expected output: main

# 2. Confirm VERSION is correct
cat VERSION
# Expected output: 101.0.0

# 3. Confirm critical data files exist
ls -lh data/stix/feed_manifest.json api/feed.json api/latest.json api/status.json
# All four must be present and non-zero

# 4. Confirm all 24 workflow files are YAML-valid
python3 -c "
import yaml, pathlib, sys
errors = []
for wf in sorted(pathlib.Path('.github/workflows').glob('*.yml')):
    try: yaml.safe_load(wf.read_text())
    except Exception as e: errors.append(f'{wf.name}: {e}')
if errors:
    print('YAML ERRORS:')
    for e in errors: print(' ', e)
    sys.exit(1)
else:
    print(f'ALL {sum(1 for _ in pathlib.Path(\".github/workflows\").glob(\"*.yml\"))} WORKFLOW FILES: YAML VALID')
"

# 5. Run bootstrap to ensure all files are healthy
python3 scripts/bootstrap_critical_files.py
```

**All checks must pass before proceeding to Step 1.**

---

## STEP 1 — STAGE ALL v101 FIX FILES

Stage ONLY the files changed by the v101 fix. Do NOT stage unrelated dirty files.

```bash
# ── Workflow files (14 modified) ──────────────────────────────────────────
git add .github/workflows/sentinel-blogger.yml
git add .github/workflows/sync-dashboard.yml
git add .github/workflows/autonomous-guardian.yml
git add .github/workflows/multi-source-intel.yml
git add .github/workflows/status-monitor.yml
git add .github/workflows/ai-predictions.yml
git add .github/workflows/ai-threat-analyst.yml
git add .github/workflows/arsenal.yml
git add .github/workflows/bughunter-recon.yml
git add .github/workflows/bughunter-resilient.yml
git add .github/workflows/convergence.yml
git add .github/workflows/detection-engine.yml
git add .github/workflows/genesis-powerhouse.yml

# ── Root config files ─────────────────────────────────────────────────────
git add .gitignore
git add VERSION
git add CHANGELOG_v101.md

# ── New scripts (force-add — path may trigger gitignore) ─────────────────
git add -f scripts/git_safe_push.sh
git add -f scripts/bootstrap_critical_files.py

# ── Critical data files (force-add — previously gitignored) ──────────────
git add -f data/stix/feed_manifest.json
git add -f api/feed.json
git add -f api/latest.json
git add -f api/status.json

# ── Verify staged files (should show exactly the files above) ────────────
git diff --staged --name-only
```

**Expected staged file count: ~22 files. If you see hundreds of unrelated files, run `git restore --staged .` and repeat the selective `git add` commands above.**

---

## STEP 2 — COMMIT

```bash
git commit -m "fix: SENTINEL APEX v101.0.0 — PERMANENT STABILITY ENFORCEMENT

- .gitignore: restructured; blanket 'data/' removed; 12 critical state
  files explicitly un-ignored (feed_manifest.json, api/*.json, etc.)
- feed_manifest.json: rebuilt from 2,642 STIX bundles → 1,940 advisories
- api/feed.json + api/latest.json + api/status.json: restored
- sentinel-blogger.yml: complete v101 rewrite — bootstrap-first,
  4-attempt fetch+rebase push loop, unified sentinel-data-writer group
- sync-dashboard.yml: complete v101 rewrite — REMOVED fatal exit on
  missing manifest; bootstrap-first self-healing strategy
- autonomous-guardian.yml: rebuilt — safe push, no manifest ownership
- multi-source-intel.yml: race condition FIXED — cron shifted to
  '45 1,5,9,13,17,21 * * *' (no overlap with sentinel-blogger at :00)
- status-monitor.yml: concurrency group fixed (autonomous-guardian)
- 8x remaining workflows: push strategy patched with 4-attempt backoff
- scripts/git_safe_push.sh: new shared safe push helper
- scripts/bootstrap_critical_files.py: new self-healing bootstrap
- VERSION: 100.0.0 → 101.0.0

Fixes: non-fast-forward push failures, race conditions, missing manifest
fatal exit, gitignore data architecture, interrupted rebase state,
deleted api endpoint files.

[skip ci]"
```

---

## STEP 3 — SAFE PUSH TO REMOTE

Use the new safe push strategy. **Do NOT use `git push --force`.**

```bash
# Attempt 1
git fetch origin main
git rebase origin/main
git push origin main
```

If push is rejected (non-fast-forward):

```bash
# Attempt 2 — fetch + rebase + push
git fetch origin main
git rebase origin/main
git push origin main
```

If rebase has conflicts:

```bash
# Merge fallback
git rebase --abort
git merge origin/main -X ours --no-edit
git push origin main
```

If ALL else fails — last resort:

```bash
# ONLY if the above 3 attempts all failed
# This creates a merge commit — safe, no force-push
git pull origin main --no-rebase -X ours
git push origin main
```

**NEVER run `git push --force` on `main`. It will overwrite remote state and corrupt all workflows.**

---

## STEP 4 — VERIFY PUSH SUCCEEDED

```bash
# Confirm HEAD matches remote
git fetch origin main
git log --oneline -3
git log --oneline origin/main -3
# Both should show the same top commit
```

---

## STEP 5 — TRIGGER WORKFLOW VALIDATION

After the push lands on `main`, validate all GitHub Actions workflows:

### 5A — Manual Trigger (GitHub UI or CLI)

Trigger sentinel-blogger manually to confirm the full pipeline runs end-to-end:

```bash
# Via GitHub CLI (gh)
gh workflow run sentinel-blogger --repo cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM

# Then watch it
gh run watch --repo cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
```

Or via GitHub UI:
1. Go to **Actions** tab → **sentinel-blogger**
2. Click **Run workflow** → **Run workflow**
3. Watch for green checkmark

### 5B — Validate Key Workflows Passed

```bash
# Check last 5 workflow runs
gh run list --repo cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM \
  --workflow sentinel-blogger --limit 5

gh run list --repo cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM \
  --workflow sync-dashboard.yml --limit 5
```

Expected: All runs show `✓ completed` / `success` status.

---

## STEP 6 — POST-DEPLOYMENT VALIDATION

After sentinel-blogger runs successfully:

```bash
# 1. Pull the latest state
git pull origin main

# 2. Run local validation suite
python3 scripts/bootstrap_critical_files.py

# 3. Confirm manifest is live and populated
python3 -c "
import json
d = json.load(open('data/stix/feed_manifest.json'))
items = d.get('advisories', d if isinstance(d,list) else [])
s = d.get('summary', {})
print(f'Advisories  : {len(items)}')
print(f'Version     : {d.get(\"version\")}')
print(f'Critical    : {s.get(\"critical\")}')
print(f'Generated   : {d.get(\"generated_at\",\"\")[:19]}')
"

# 4. Confirm API files are populated
python3 -c "
import json
for f in ['api/feed.json', 'api/latest.json', 'api/status.json']:
    d = json.load(open(f))
    print(f'{f}: version={d.get(\"version\")} | status=OK')
"
```

---

## STEP 7 — MONITOR FIRST AUTOMATED CYCLES

The workflows run on these schedules post-deployment:

| Workflow | Cron | Next run | Group |
|----------|------|----------|-------|
| sentinel-blogger | `0 */4 * * *` | Next :00 mark | sentinel-data-writer |
| sync-dashboard | `20 */4 * * *` | :20 after blogger | sentinel-data-writer |
| multi-source-intel | `45 1,5,9,13,17,21 * * *` | Next odd-hour :45 | sentinel-data-writer |
| autonomous-guardian | `30 * * * *` | Next :30 mark | autonomous-guardian |
| status-monitor | `0 */1 * * *` | Next :00 mark | autonomous-guardian |

**Watch the first 2 automated sentinel-blogger runs.** Both must complete with ✅ green status. After that the platform is self-sustaining.

---

## ROLLBACK PROCEDURE

If something goes wrong after push:

```bash
# Option A: Soft rollback (reset to previous commit, keep files)
git log --oneline -5           # identify the commit before v101
git reset --soft <PREV_SHA>    # undo commit, keep staged changes
git push origin main --force-with-lease   # safe force (uses lease)

# Option B: Hard rollback to backup branch (if it exists)
git checkout backup-pre-claude-fix
git push origin backup-pre-claude-fix:main --force-with-lease
```

**The `backup-pre-claude-fix` branch exists in the remote as a safety net.**

---

## WHAT WILL NOT CHANGE AFTER DEPLOYMENT

- `gh-pages` branch deployment is handled exclusively by sentinel-blogger (unchanged)
- Secrets (`BLOG_ID`, `REFRESH_TOKEN`, `NVD_API_KEY`, etc.) remain unchanged
- All agent Python modules (`agent/`) are untouched
- `index.html` is not modified by this fix (only patched by existing scripts)
- All API endpoints in `api/main.py`, `api/billing.py` etc. unchanged

---

## SUMMARY OF v101 CHANGES (PERMANENT CONTRACT)

```
FIXED  : feed_manifest.json missing → dashboard fatal exit     ✅
FIXED  : Non-fast-forward push failures (all 14 workflows)     ✅
FIXED  : Race condition sentinel-blogger + multi-source-intel  ✅
FIXED  : Dirty working tree blocking git pull                  ✅
FIXED  : Interrupted rebase state (.git/REBASE_HEAD)           ✅
FIXED  : api/feed.json + api/latest.json deleted               ✅
FIXED  : .gitignore blanket data/ exclusion                    ✅
NEW    : scripts/bootstrap_critical_files.py (self-healing)    ✅
NEW    : scripts/git_safe_push.sh (4-attempt push helper)      ✅
NEW    : CHANGELOG_v101.md (audit trail)                       ✅
VERSION: 100.0.0 → 101.0.0                                     ✅
```

*CYBERDUDEBIVASH Pvt. Ltd. — CyberGod Engineering Standard v101*
