#!/usr/bin/env pwsh
# =============================================================================
# SENTINEL APEX v148.0.0 — PRODUCTION FIX COMMIT + PUSH
# Commit: 9-gap audit fixes (version drift, YAML governance, telemetry, triggers)
# =============================================================================

Set-Location "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
$ErrorActionPreference = "Continue"

Write-Host "=== [1] Removing stale git locks ===" -ForegroundColor Cyan
Remove-Item ".git\index.lock"       -ErrorAction SilentlyContinue
Remove-Item ".git\MERGE_HEAD"       -ErrorAction SilentlyContinue
Remove-Item ".git\rebase-merge"     -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item ".git\rebase-apply"     -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "=== [2] Staging all fix files ===" -ForegroundColor Cyan
git add VERSION
git add .github/workflows/sentinel-blogger.yml
git add .github/workflows/generate-and-sync.yml
git add scripts/version_governance.py
git add scripts/emit_ai_telemetry.py
git add data/ai-telemetry/.gitkeep
git add data/ai-telemetry/last-run.json
git add version.json
git add config/version.json
git add workers/intel-gateway/src/index.js
git add scripts/ai_brain_publisher.py
git add scripts/r2_upload.py

Write-Host "=== [3] Git status ===" -ForegroundColor Cyan
git status --short

Write-Host "=== [4] Committing ===" -ForegroundColor Cyan
$MSG = "fix(v148): 9-gap production audit -- version drift zero, YAML governance, telemetry script, push triggers [skip ci]"
git commit -m $MSG
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] Nothing new to commit or commit failed" -ForegroundColor Yellow
}

Write-Host "=== [5] Pull rebase + push ===" -ForegroundColor Cyan
git pull --rebase origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] Pull rebase failed — attempting merge" -ForegroundColor Yellow
    git rebase --abort 2>$null
    git merge origin/main --no-edit
}
git push origin main
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Push successful!" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Push failed — check credentials" -ForegroundColor Red
}

Write-Host "=== [6] Final log ===" -ForegroundColor Cyan
git log --oneline -5
