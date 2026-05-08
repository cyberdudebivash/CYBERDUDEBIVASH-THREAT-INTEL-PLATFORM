#!/usr/bin/env pwsh
# SENTINEL APEX - ROLLBACK SCRIPT v1.0
# Canonical location: ops/ROLLBACK.ps1
# Rolls back to a tagged production baseline
# Run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#      .\ops\ROLLBACK.ps1 -Tag "v145.0-production-20260508"
#      .\ops\ROLLBACK.ps1 -Tag "v145.0-production-20260508" -Force

param(
    [Parameter(Mandatory=$false)]
    [string]$Tag = "",
    [switch]$Force,
    [switch]$ListTags
)

$ErrorActionPreference = "Continue"
$RepoRoot = "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
Set-Location $RepoRoot

Write-Host ""
Write-Host "=== SENTINEL APEX ROLLBACK SYSTEM v1.0 ===" -ForegroundColor Cyan
Write-Host ""

# List available tags
if ($ListTags -or $Tag -eq "") {
    Write-Host "[TAGS] Available production rollback tags:" -ForegroundColor Cyan
    & git tag -l "v*-production-*" | Sort-Object
    Write-Host ""
    if ($Tag -eq "") {
        Write-Host "Usage: .\ops\ROLLBACK.ps1 -Tag <tagname>" -ForegroundColor Yellow
        exit 0
    }
}

# Verify tag exists
$tagExists = & git tag -l $Tag
if (-not $tagExists) {
    Write-Host "[ERROR] Tag '$Tag' not found." -ForegroundColor Red
    Write-Host "Available tags:" -ForegroundColor Yellow
    & git tag -l "v*-production-*"
    exit 1
}

Write-Host "[ROLLBACK] Target tag: $Tag" -ForegroundColor Yellow

# Confirm unless -Force
if (-not $Force) {
    Write-Host ""
    Write-Host "  This will restore god mode reports from tag '$Tag'" -ForegroundColor White
    Write-Host "  Current live reports will be replaced." -ForegroundColor White
    Write-Host ""
    $confirm = Read-Host "  Type 'ROLLBACK' to confirm"
    if ($confirm -ne "ROLLBACK") {
        Write-Host "[CANCELLED] Rollback aborted." -ForegroundColor Yellow
        exit 0
    }
}

# Backup current versions before rolling back
Write-Host ""
Write-Host "[BACKUP] Saving current versions before rollback..." -ForegroundColor Cyan
$backupDir = "ops\backups\pre-rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$r1 = "reports\2026\05\intel--c687f56fd93c6ea6d1e3dd6a.html"
$r2 = "reports\2026\05\intel--1e41dd3a24f78d6ae239f84a.html"
foreach ($f in @($r1, $r2)) {
    if (Test-Path $f) {
        Copy-Item $f $backupDir
        Write-Host "  Saved: $(Split-Path $f -Leaf) to $backupDir" -ForegroundColor Green
    }
}

# Restore reports from tag
Write-Host ""
Write-Host "[RESTORE] Restoring reports from tag '$Tag'..." -ForegroundColor Cyan
& git checkout $Tag -- $r1.Replace("\","/")
& git checkout $Tag -- $r2.Replace("\","/")
& git checkout $Tag -- "scripts/report_generator.py"

$restored = @()
foreach ($f in @($r1, $r2)) {
    if (Test-Path $f) {
        $sizeKB = [math]::Round((Get-Item $f).Length / 1024, 1)
        Write-Host "  Restored: $(Split-Path $f -Leaf) ($sizeKB KB)" -ForegroundColor Green
        $restored += $f
    }
}

# Stage and commit
Write-Host ""
Write-Host "[GIT] Committing rollback..." -ForegroundColor Cyan
& git add $r1.Replace("\","/") $r2.Replace("\","/") "scripts/report_generator.py"
$rollbackMsg = "fix: rollback to $Tag - god mode production baseline [skip ci]"
& git commit -m $rollbackMsg
if ($LASTEXITCODE -ne 0) {
    Write-Host "[INFO] Nothing to commit (already at rollback target)" -ForegroundColor Yellow
}

# Push
Write-Host ""
Write-Host "[PUSH] Pushing rollback to origin/main..." -ForegroundColor Cyan
& git pull --rebase origin main 2>&1 | Out-Null
& git push origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "[RETRY] Force pushing with lease..." -ForegroundColor Yellow
    & git push --force-with-lease origin main
}

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=== ROLLBACK COMPLETE ===" -ForegroundColor Green
    Write-Host "  Restored from: $Tag" -ForegroundColor Green
    Write-Host "  Platform: https://intel.cyberdudebivash.com" -ForegroundColor Cyan
    Write-Host "  CDN propagation: ~30 seconds" -ForegroundColor DarkCyan
    Write-Host "  Pre-rollback backup saved to: $backupDir" -ForegroundColor DarkCyan
} else {
    Write-Host "[ERROR] Rollback push failed." -ForegroundColor Red
    Write-Host "  Restore files are staged locally — re-run push manually" -ForegroundColor Yellow
}
