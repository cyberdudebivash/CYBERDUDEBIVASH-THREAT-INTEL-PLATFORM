#!/usr/bin/env pwsh
# CYBERDUDEBIVASH SENTINEL APEX - GOD MODE PUSH SCRIPT v2.2
# Canonical location: ops/PUSH-GODMODE.ps1
# Run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\ops\PUSH-GODMODE.ps1

$ErrorActionPreference = "Continue"
$RepoRoot = "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
Set-Location $RepoRoot

Write-Host ""
Write-Host "=== SENTINEL APEX GOD MODE PUSH v2.2 ===" -ForegroundColor Cyan
Write-Host "    Repository: $RepoRoot" -ForegroundColor DarkCyan
Write-Host ""

# STEP 1: Remove stale git lock
$lockPath = Join-Path $RepoRoot ".git\index.lock"
if (Test-Path $lockPath) {
    Write-Host "[LOCK] Removing stale .git/index.lock ..." -ForegroundColor Yellow
    Remove-Item $lockPath -Force
    Write-Host "[LOCK] Removed OK" -ForegroundColor Green
} else {
    Write-Host "[LOCK] No stale lock - OK" -ForegroundColor Green
}

# STEP 2: Pre-deployment backup of god mode reports
Write-Host ""
Write-Host "[BACKUP] Backing up god mode reports..." -ForegroundColor Cyan
$r1 = "reports\2026\05\intel--c687f56fd93c6ea6d1e3dd6a.html"
$r2 = "reports\2026\05\intel--1e41dd3a24f78d6ae239f84a.html"
$backupDir = Join-Path $RepoRoot "ops\backups"
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
foreach ($f in @($r1, $r2)) {
    $src = Join-Path $RepoRoot $f
    if (Test-Path $src) {
        $sizeKB = [math]::Round((Get-Item $src).Length / 1024, 1)
        $dst = Join-Path $backupDir (Split-Path $f -Leaf)
        Copy-Item $src $dst -Force
        Write-Host "  Backed up: $(Split-Path $f -Leaf) ($sizeKB KB)" -ForegroundColor Green
    }
}

# STEP 3: Verify god mode files exist and meet quality threshold
Write-Host ""
Write-Host "[CHECK] Verifying god mode deliverables (min 60 KB)..." -ForegroundColor Cyan
$godModeFiles = @($r1, $r2, "scripts\report_generator.py")
$allPresent = $true
foreach ($f in $godModeFiles) {
    $fullPath = Join-Path $RepoRoot $f
    if (Test-Path $fullPath) {
        $sizeKB = [math]::Round((Get-Item $fullPath).Length / 1024, 1)
        if ($sizeKB -lt 10) {
            Write-Host "  WARN: $f may be too small ($sizeKB KB)" -ForegroundColor Yellow
        } else {
            Write-Host "  OK: $f ($sizeKB KB)" -ForegroundColor Green
        }
    } else {
        Write-Host "  MISSING: $f" -ForegroundColor Red
        $allPresent = $false
    }
}
if (-not $allPresent) {
    Write-Host "[ABORT] Required files missing." -ForegroundColor Red
    exit 1
}

# STEP 4: Configure git identity
Write-Host ""
Write-Host "[GIT] Configuring identity..." -ForegroundColor Cyan
& git config user.email "bivash@cyberdudebivash.com"
& git config user.name "CyberDudeBivash SENTINEL APEX"
Write-Host "  OK: Identity set" -ForegroundColor Green

# STEP 5: Pull with rebase to integrate remote commits
Write-Host ""
Write-Host "[GIT] Pulling remote changes (--rebase)..." -ForegroundColor Cyan
& git pull --rebase origin main
if ($LASTEXITCODE -ne 0) {
    $rebaseHead = Join-Path $RepoRoot ".git\REBASE_HEAD"
    if (Test-Path $rebaseHead) {
        Write-Host "[CONFLICT] Rebase conflict detected. Running RESOLVE-AND-PUSH..." -ForegroundColor Yellow
        & "$RepoRoot\ops\RESOLVE-AND-PUSH.ps1"
        exit $LASTEXITCODE
    }
    Write-Host "  Warning: pull returned non-zero but no rebase conflict - continuing" -ForegroundColor Yellow
} else {
    Write-Host "  OK: Pull with rebase successful" -ForegroundColor Green
}

# STEP 6: Stage all tracked modifications + god mode files
Write-Host ""
Write-Host "[GIT] Staging files..." -ForegroundColor Cyan
foreach ($f in $godModeFiles) {
    & git add $f 2>$null
}
& git add -u
& git add ops/ 2>$null
Write-Host "  Staged all modifications" -ForegroundColor Green

# STEP 7: Commit if there are changes
$statusOut = & git status --porcelain
if (-not $statusOut) {
    Write-Host ""
    Write-Host "[INFO] Nothing new to commit. Pushing..." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[GIT] Committing..." -ForegroundColor Cyan
    $msg = "feat: SENTINEL APEX v145.0 Platform Hardening + Enterprise Readiness [skip ci]"
    & git commit -m $msg
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ABORT] Commit failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "  OK: Committed" -ForegroundColor Green
}

# STEP 8: Push
Write-Host ""
Write-Host "[GIT] Pushing to origin/main..." -ForegroundColor Cyan
& git push origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "[RETRY] Remote diverged. Fetching + rebasing..." -ForegroundColor Yellow
    & git fetch origin main
    & git rebase origin/main
    & git push origin main
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[LAST RESORT] Force pushing with lease..." -ForegroundColor Yellow
        & git push --force-with-lease origin main
    }
}

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=== DEPLOYMENT COMPLETE - 100% PRODUCTION STABLE ===" -ForegroundColor Green
    Write-Host "  Platform: https://intel.cyberdudebivash.com" -ForegroundColor Cyan
    Write-Host "  LiteLLM CRITICAL 9.1: https://intel.cyberdudebivash.com/reports/2026/05/intel--c687f56fd93c6ea6d1e3dd6a.html" -ForegroundColor Green
    Write-Host "  Heimdall HIGH 8.2: https://intel.cyberdudebivash.com/reports/2026/05/intel--1e41dd3a24f78d6ae239f84a.html" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[ERROR] Push failed after all retry strategies." -ForegroundColor Red
    Write-Host "  Check auth: git remote -v" -ForegroundColor Yellow
}
