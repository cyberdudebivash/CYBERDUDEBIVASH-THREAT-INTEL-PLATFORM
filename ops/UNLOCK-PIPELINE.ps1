#!/usr/bin/env pwsh
# SENTINEL APEX - PIPELINE UNLOCK v1.0
# Removes .PIPELINE_LOCK file to resume automated pipeline
# Run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\ops\UNLOCK-PIPELINE.ps1

$ErrorActionPreference = "Continue"
$RepoRoot = "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
Set-Location $RepoRoot

Write-Host ""
Write-Host "=== SENTINEL APEX PIPELINE UNLOCK ===" -ForegroundColor Cyan
Write-Host ""

$lockFile = ".PIPELINE_LOCK"
if (-not (Test-Path $lockFile)) {
    Write-Host "[NOT LOCKED] No active pipeline lock found." -ForegroundColor Green
    Write-Host "  Automated pipeline is already running normally." -ForegroundColor DarkCyan
    exit 0
}

Write-Host "[CURRENT LOCK]" -ForegroundColor Yellow
Get-Content $lockFile
Write-Host ""

# Remove lock file
Remove-Item $lockFile -Force
Write-Host "[UNLOCKED] Pipeline lock removed." -ForegroundColor Green

# Stage removal and push
& git config user.email "bivash@cyberdudebivash.com"
& git config user.name "CyberDudeBivash SENTINEL APEX"
& git rm -f $lockFile 2>&1 | Out-Null
& git add -A
& git commit -m "ops: release pipeline lock - resuming automated workflows [skip ci]"
& git pull --rebase origin main 2>&1 | Out-Null
& git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "[PUSHED] Pipeline lock released on remote. Automated workflows will resume." -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not push unlock to remote." -ForegroundColor Yellow
    Write-Host "  Push manually: git push origin main" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Automated pipeline is now active." -ForegroundColor Cyan
