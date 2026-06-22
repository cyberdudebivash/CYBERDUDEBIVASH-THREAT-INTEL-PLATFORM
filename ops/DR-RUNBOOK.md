# CYBERDUDEBIVASH® SENTINEL APEX — DISASTER RECOVERY RUNBOOK
## Version: v145.0 | RTO: 4 hours | RPO: 24 hours | Last Updated: 2026-05-08

---

## 1. DISASTER SCENARIOS AND RECOVERY PATHS

### Scenario A: GitHub Repository Deleted/Corrupted

**Detection:** git push fails with "repository not found" or all history lost.

**Recovery Steps:**
1. Check GitHub status: https://www.githubstatus.com/
2. If repository was accidentally deleted by admin action:
   - Contact GitHub Support immediately: https://support.github.com/
   - GitHub retains deleted repo data for 90 days — request restore
3. If local machine still has full git history:
   ```powershell
   cd C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
   git remote set-url origin https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM.git
   git push --mirror origin
   ```
4. Re-enable GitHub Pages in repo Settings → Pages

**RTO: 2 hours | RPO: Last push to origin**

---

### Scenario B: Windows Machine Failure (Total Loss)

**Detection:** Machine fails to boot or is stolen.

**Recovery Steps:**
1. All git history is on GitHub — this is the primary backup
2. Clone the repository on a new machine:
   ```bash
   git clone https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM.git
   ```
3. Re-create GitHub PAT (fine-grained, Contents:Write scope only)
4. Re-configure git credentials:
   ```bash
   git config user.email "enterprise@cyberdudebivash.com"
   git config user.name "CyberDudeBivash SENTINEL APEX"
   ```
5. Install Python, PowerShell, git on new machine
6. Verify push capability: run ops/PUSH-GODMODE.ps1

**RTO: 4 hours | RPO: Last push to origin**

---

### Scenario C: God Mode Reports Overwritten by Pipeline

**Detection:** Report file sizes drop below 60KB; sections are missing.

**Recovery Steps:**
1. Check ops/backups/ for pre-deployment backups
   ```powershell
   ls ops/backups/*.html
   ```
2. Restore from backup:
   ```powershell
   Copy-Item ops/backups/intel--c687f56fd93c6ea6d1e3dd6a.html reports/2026/05/
   Copy-Item ops/backups/intel--1e41dd3a24f78d6ae239f84a.html reports/2026/05/
   ```
3. If backup is missing, restore from git history:
   ```bash
   git log --oneline reports/2026/05/intel--c687f56fd93c6ea6d1e3dd6a.html
   git checkout GOOD_COMMIT_HASH -- reports/2026/05/intel--c687f56fd93c6ea6d1e3dd6a.html
   git checkout GOOD_COMMIT_HASH -- reports/2026/05/intel--1e41dd3a24f78d6ae239f84a.html
   ```
4. Push the restored versions:
   ```powershell
   .\ops\PUSH-GODMODE.ps1
   ```

**RTO: 30 minutes | RPO: Last known-good git commit**

---

### Scenario D: Cloudflare CDN Misconfiguration

**Detection:** Reports return 404/403 or missing security headers.

**Recovery Steps:**
1. Verify GitHub Pages is serving correctly:
   - Check: https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/reports/2026/05/intel--c687f56fd93c6ea6d1e3dd6a.html
2. If GitHub Pages works but CDN fails:
   - Log into Cloudflare Dashboard
   - Go to intel.cyberdudebivash.com → DNS → verify CNAME points to cyberdudebivash.github.io
   - Check Page Rules are not blocking /*.html
   - Purge cache: Caching → Configuration → Purge Everything
3. If _headers file was modified (security headers lost):
   - Restore from git: `git checkout HEAD -- _headers`
   - Push: `git add _headers && git commit -m "fix: restore security headers [skip ci]" && git push`

**RTO: 30 minutes | RPO: Last _headers commit**

---

### Scenario E: GitHub Actions Pipeline Infinite Loop

**Detection:** GitHub Actions shows hundreds of failed/running jobs; pipeline commits every few seconds.

**Recovery Steps:**
1. Immediately disable all workflows via GitHub Actions UI:
   - Settings → Actions → General → Disable Actions
2. Or, use PIPELINE_LOCK:
   ```powershell
   .\ops\LOCK-PIPELINE.ps1
   git add .PIPELINE_LOCK
   .\ops\PUSH-GODMODE.ps1
   ```
3. Review all workflow files for infinite triggers
4. Re-enable workflows once root cause is fixed

**RTO: 15 minutes | RPO: N/A (no data loss)**

---

## 2. BACKUP VERIFICATION PROCEDURE

Run monthly to verify backup integrity:

```powershell
# BACKUP-VERIFY.ps1
cd C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM

# Verify god mode report backups exist and are fresh
$r1 = "ops/backups/intel--c687f56fd93c6ea6d1e3dd6a.html"
$r2 = "ops/backups/intel--1e41dd3a24f78d6ae239f84a.html"

foreach ($f in @($r1, $r2)) {
    if (Test-Path $f) {
        $size = (Get-Item $f).Length / 1KB
        Write-Host "OK: $f ($([math]::Round($size,1)) KB)" -ForegroundColor Green
        if ($size -lt 60) {
            Write-Host "WARN: Backup is too small — may be placeholder version" -ForegroundColor Yellow
        }
    } else {
        Write-Host "MISSING: $f — backup needed" -ForegroundColor Red
    }
}

# Verify git history is accessible
$commitCount = (git log --oneline | Measure-Object -Line).Lines
Write-Host "Git history: $commitCount commits" -ForegroundColor Cyan
```

---

## 3. RTO/RPO SUMMARY

| Component | RTO | RPO | Backup Location |
|-----------|-----|-----|-----------------|
| God Mode Reports | 30 min | Last push | ops/backups/ + git history |
| Report Generator (report_generator.py) | 15 min | Last push | git history |
| Full Platform | 4 hours | 24 hours | GitHub repo |
| Cloudflare Config | 30 min | Last push | _headers + wrangler.toml in git |
| Pipeline Workflows | 15 min | Last push | .github/workflows/ in git |
| Customer Data (email list) | 4 hours | 24 hours | ConvertKit cloud (not local) |

---

## 4. RECOVERY CONTACT ESCALATION

1. **CYBERDUDEBIVASH** (enterprise@cyberdudebivash.com) — Primary responder
2. **GitHub Support** (https://support.github.com/) — Repository recovery
3. **Cloudflare Support** (https://support.cloudflare.com/) — CDN issues
4. **Railway/Render Support** — Backend API issues (Phase 3)

---

*SENTINEL APEX Disaster Recovery Runbook v145.0 | © 2026 CyberDudeBivash Pvt. Ltd.*
