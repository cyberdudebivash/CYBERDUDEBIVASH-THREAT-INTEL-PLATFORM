# CYBERDUDEBIVASH® SENTINEL APEX — OPERATIONS RUNBOOK
## Version: v145.0 | Classification: INTERNAL | Last Updated: 2026-05-08

---

## 1. DAILY OPERATIONS CHECKLIST

Run every morning before starting threat intel work:

**Step 1 — Pipeline Health**
```
- Check GitHub Actions: https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions
- All workflows should show green checkmarks within last 24h
- If genesis-powerhouse is red: run ops/UNLOCK-PIPELINE.ps1 and re-trigger manually
```

**Step 2 — Platform Uptime**
```
- Verify intel.cyberdudebivash.com loads within 3 seconds
- Check feed.json is fresh: https://intel.cyberdudebivash.com/api/feed.json
- Verify data.updated_at timestamp is within 6 hours
```

**Step 3 — God Mode Reports Integrity**
```
- Verify both flagship reports load and display correctly:
  https://intel.cyberdudebivash.com/reports/2026/05/intel--c687f56fd93c6ea6d1e3dd6a.html
  https://intel.cyberdudebivash.com/reports/2026/05/intel--1e41dd3a24f78d6ae239f84a.html
- Both should be 70KB+ in file size
- Check that CTAs and monetization sections are visible
```

**Step 4 — Revenue Snapshot**
```
- Check Gumroad dashboard for new sales
- Review ConvertKit subscriber count delta
- Log to ops/revenue-log/ if tracking manually
```

---

## 2. INCIDENT SEVERITY CLASSIFICATION

| Severity | Code | Description | Response Time |
|----------|------|-------------|---------------|
| P0 | CRITICAL | Total platform outage — intel.cyberdudebivash.com unreachable | Immediate (< 15 min) |
| P1 | HIGH | Pipeline failure > 30 min, reports not updating | < 1 hour |
| P2 | MEDIUM | Report quality regression published live | < 4 hours |
| P3 | LOW | Monitoring alert, no customer-facing impact | < 24 hours |

---

## 3. INCIDENT RESPONSE PROCEDURES

### P0 — Total Platform Outage

```powershell
# Step 1: Verify the outage
curl -I https://intel.cyberdudebivash.com

# Step 2: Check GitHub Pages status
# Visit: https://www.githubstatus.com/

# Step 3: Check Cloudflare status
# Visit: https://www.cloudflarestatus.com/

# Step 4: If GitHub Pages is down — Cloudflare cache serves stale (max 3600s)
# If Cloudflare is down — brief outage, no action needed beyond monitoring

# Step 5: If persistent (> 15 min), check for broken push
cd C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
git log --oneline -5
git status

# Step 6: If repo has bad commit, rollback
.\ops\ROLLBACK.ps1 -Tag "v145.0-production-20260508"
```

### P1 — Pipeline Failure

```powershell
# Step 1: Check GitHub Actions logs for the failed workflow
# Step 2: If it's a Python error in report_generator.py
python -c "import ast; ast.parse(open('scripts/report_generator.py').read()); print('Syntax OK')"

# Step 3: If pipeline is locked
.\ops\UNLOCK-PIPELINE.ps1

# Step 4: Re-trigger genesis-powerhouse manually via GitHub Actions UI
# OR: push a minor commit to trigger workflows
git commit --allow-empty -m "chore: trigger pipeline recovery [skip ci]"
.\ops\PUSH-GODMODE.ps1
```

### P2 — Quality Regression (Bad Report Published)

```powershell
# Step 1: Identify the bad report hash from git log
git log --oneline reports/2026/05/ | head -10

# Step 2: Check report size — god mode reports must be > 60KB
$file = "reports/2026/05/intel--HASH.html"
(Get-Item $file).Length / 1KB

# Step 3: If pipeline-generated placeholder has overwritten god mode
# Restore from backup
Copy-Item "ops/backups/intel--c687f56fd93c6ea6d1e3dd6a.html" "reports/2026/05/"
Copy-Item "ops/backups/intel--1e41dd3a24f78d6ae239f84a.html" "reports/2026/05/"

# Step 4: Push fix
.\ops\PUSH-GODMODE.ps1
```

### P3 — Monitoring Alert

```
- Review alert details
- If false positive: document in ops/post-mortems/YYYY-MM-DD-alert.md
- If real issue: escalate to P2 or P1 as appropriate
```

---

## 4. ROLLBACK PROCEDURE

### Quick Rollback (< 5 minutes)

```powershell
# List available rollback tags
git tag -l "v*-production-*" | Sort-Object

# Rollback to specific version
.\ops\ROLLBACK.ps1 -Tag "v145.0-production-20260508"

# Force rollback (skips confirmation)
.\ops\ROLLBACK.ps1 -Tag "v145.0-production-20260508" -Force
```

### Manual Rollback

```powershell
cd C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM

# Find the good commit
git log --oneline -20

# Restore specific files from a commit
git checkout COMMIT_HASH -- reports/2026/05/intel--c687f56fd93c6ea6d1e3dd6a.html
git checkout COMMIT_HASH -- reports/2026/05/intel--1e41dd3a24f78d6ae239f84a.html

# Commit the restore
git add reports/
git commit -m "fix: rollback god mode reports to last known good [skip ci]"
.\ops\PUSH-GODMODE.ps1
```

---

## 5. PIPELINE LOCK PROCEDURE

### Lock Pipeline (before manual god mode work)

```powershell
# Lock — prevents automated pipeline from overwriting your work
.\ops\LOCK-PIPELINE.ps1

# Verify lock is active
Get-Content .git\PIPELINE_LOCK.txt
```

### Unlock Pipeline (after god mode work is pushed)

```powershell
# Unlock — resumes automated pipeline
.\ops\UNLOCK-PIPELINE.ps1
```

---

## 6. GOD MODE REPORT DEPLOYMENT

```powershell
# Standard god mode push (after manual report upgrades)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\ops\PUSH-GODMODE.ps1

# If there's a rebase conflict with the automated pipeline
.\ops\RESOLVE-AND-PUSH.ps1

# Full rollback + redeploy
.\ops\ROLLBACK.ps1 -Tag "v145.0-production-20260508"
.\ops\PUSH-GODMODE.ps1
```

---

## 7. SECRETS ROTATION SCHEDULE

See: `ops/SECRETS-ROTATION.md`

| Secret | Location | Rotation Frequency | Next Rotation |
|--------|----------|-------------------|---------------|
| GitHub PAT | Windows Credential Manager | 90 days | 2026-08-06 |
| CDB_JWT_SECRET | GitHub Actions Secrets | 90 days | 2026-08-06 |
| Cloudflare API Token | Cloudflare Dashboard | 180 days | 2026-11-04 |
| ADMIN_SECRET (Worker) | wrangler secret | 90 days | 2026-08-06 |

---

## 8. WEEKLY OPERATIONAL CALENDAR

| Day | Task |
|-----|------|
| Monday | Review pipeline health, check all GitHub Actions green |
| Wednesday | Publish 2 new god mode reports (manual or pipeline-generated) |
| Friday | Review revenue metrics, subscriber growth, conversion rates |
| Monthly | Rotate secrets per schedule, review .gitignore, audit logs |
| Quarterly | Pricing review, enterprise collateral update, SLA review |

---

## 9. EMERGENCY CONTACTS

- Platform Operator: CYBERDUDEBIVASH (bivash@cyberdudebivash.com)
- Intelligence Contact: intelligence@cyberdudebivash.com
- GitHub Repository: https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
- Live Platform: https://intel.cyberdudebivash.com
- Status Page: https://intel.cyberdudebivash.com/status.html

---

## 10. POST-INCIDENT REVIEW TEMPLATE

After every P0/P1 incident, create `ops/post-mortems/YYYY-MM-DD-[title].md` with:

```markdown
# Post-Mortem: [Incident Title]
**Date:** YYYY-MM-DD
**Severity:** P0/P1/P2
**Duration:** X hours Y minutes

## Timeline
- HH:MM UTC — [Event]
- HH:MM UTC — [Detection]
- HH:MM UTC — [Resolution]

## Root Cause
[What caused the incident]

## Impact
[Customer impact, data at risk, revenue impact]

## Resolution
[What was done to fix it]

## Prevention
[What changes were made to prevent recurrence]
```

---

*SENTINEL APEX Operations Runbook v145.0 | © 2026 CyberDudeBivash Pvt. Ltd.*
