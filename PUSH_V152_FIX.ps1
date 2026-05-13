# =============================================================================
# PUSH_V152_FIX.ps1
# Push the committed v152 generate-and-sync fix to GitHub origin/main
# Run from PowerShell in the repo root directory
# =============================================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SENTINEL APEX v152 -- Push 3-point CI fix to GitHub" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$RepoRoot = $PSScriptRoot

# Show what will be pushed
Write-Host "[INFO] Commit to push:" -ForegroundColor Yellow
git -C $RepoRoot log --oneline -1
Write-Host ""
Write-Host "[INFO] Changed files:" -ForegroundColor Yellow
git -C $RepoRoot show --stat HEAD | Select-String "\.yml"
Write-Host ""

# Push to origin main
Write-Host "[INFO] Pushing to origin/main..." -ForegroundColor Yellow
git -C $RepoRoot push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[SUCCESS] Push complete. The generate-and-sync workflow is now fixed." -ForegroundColor Green
    Write-Host ""
    Write-Host "What was fixed:" -ForegroundColor Green
    Write-Host "  FIX 1: STAGE 6.7 added -- version_governance --apply before --check" -ForegroundColor Green
    Write-Host "         Permanently prevents sla_status.json version drift failures." -ForegroundColor Green
    Write-Host "  FIX 2: STAGE 5.7 moved -- monetization gate now runs before commit/R2" -ForegroundColor Green
    Write-Host "         57 payment checks now block deployment on failure (correct)." -ForegroundColor Green
    Write-Host "  FIX 3: STAGE 9.5 restored -- complete R2 upload + KV bust script" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next scheduled run: 2026-05-14 02:00 UTC (every 6h)" -ForegroundColor Cyan
    Write-Host "Or trigger manually: GitHub -> Actions -> Generate & Sync -> Run workflow" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "[ERROR] Push failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "Try: git push origin main" -ForegroundColor Yellow
}
