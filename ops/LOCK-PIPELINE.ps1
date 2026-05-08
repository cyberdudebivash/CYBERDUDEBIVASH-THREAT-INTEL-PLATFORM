#!/usr/bin/env pwsh
# SENTINEL APEX - PIPELINE LOCK v1.0
# Creates .PIPELINE_LOCK file to pause automated pipeline during manual god mode work
# Run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\ops\LOCK-PIPELINE.ps1

$ErrorActionPreference = "Continue"
$RepoRoot = "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
Set-Location $RepoRoot

Write-Host ""
Write-Host "=== SENTINEL APEX PIPELINE LOCK ===" -ForegroundColor Cyan
Write-Host ""

$lockFile = ".PIPELINE_LOCK"
if (Test-Path $lockFile) {
    Write-Host "[ALREADY LOCKED] Pipeline lock is already active:" -ForegroundColor Yellow
    Get-Content $lockFile
    Write-Host ""
    Write-Host "  Run .\ops\UNLOCK-PIPELINE.ps1 to release" -ForegroundColor DarkCyan
    exit 0
}

# Create lock file
$lockContent = @{
    locked_by = "CyberDudeBivash SENTINEL APEX Operator"
    locked_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    reason    = "Manual god mode report work in progress"
    machine   = $env:COMPUTERNAME
    note      = "Run ops/UNLOCK-PIPELINE.ps1 to release. All automated workflows will skip while this file exists."
} | ConvertTo-Json -Depth 2

$lockContent | Set-Content $lockFile -Encoding utf8

Write-Host "[LOCKED] Pipeline lock created." -ForegroundColor Green
Write-Host ""
Get-Content $lockFile
Write-Host ""

# Stage and push the lock file
& git config user.email "bivash@cyberdudebivash.com"
& git config user.name "CyberDudeBivash SENTINEL APEX"
& git add $lockFile
& git commit -m "ops: activate pipeline lock for manual god mode work [skip ci]"
& git pull --rebase origin main 2>&1 | Out-Null
& git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "[PUSHED] Lock is now active on remote. Automated pipeline will pause." -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not push lock to remote. Lock is local only." -ForegroundColor Yellow
    Write-Host "  Push manually: git push origin main" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  When done with god mode work, run: .\ops\UNLOCK-PIPELINE.ps1" -ForegroundColor Cyan
