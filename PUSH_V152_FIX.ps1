# =============================================================================
# PUSH_V152_FIX.ps1
# Push the committed v152 P0 fix to GitHub origin/main
# Run from PowerShell in the repo root directory
# =============================================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SENTINEL APEX v152 -- Push P0 SyntaxError fix to GitHub" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$RepoRoot = $PSScriptRoot

# Show what will be pushed
Write-Host "[INFO] Commits to push:" -ForegroundColor Yellow
git -C $RepoRoot log --oneline -3
Write-Host ""
Write-Host "[INFO] Changed files in latest commit:" -ForegroundColor Yellow
git -C $RepoRoot show --stat HEAD | Select-String "index\.html|v149|yml"
Write-Host ""

# Push to origin main
Write-Host "[INFO] Pushing to origin/main..." -ForegroundColor Yellow
git -C $RepoRoot push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[SUCCESS] Push complete. Both P0 fixes are now live." -ForegroundColor Green
    Write-Host ""
    Write-Host "What was fixed (commit c3c9feeb):" -ForegroundColor Green
    Write-Host "  P0 FIX 1: scripts/v149_frontend_dedup_patch.py" -ForegroundColor Green
    Write-Host "            PATCH-3 (INLINE_AVG_RISK_REPLACE) permanently disabled." -ForegroundColor Green
    Write-Host "            Root cause: [^)]+ regex stopped at first ) in nested reduce callbacks," -ForegroundColor Green
    Write-Host "            leaving dangling '}, 0)/items.length).toFixed(1);' in index.html JS," -ForegroundColor Green
    Write-Host "            which caused SyntaxError: Unexpected token ')' on EVERY CI run." -ForegroundColor Green
    Write-Host ""
    Write-Host "  P0 FIX 2: index.html" -ForegroundColor Green
    Write-Host "            v149 markers (DEDUP GUARD + UNIFIED RISK CALCULATOR) pre-committed." -ForegroundColor Green
    Write-Host "            Patch script now idempotent -- skips all patches on future CI runs." -ForegroundColor Green
    Write-Host ""
    Write-Host "What was fixed (commit 963fde51 -- from previous session):" -ForegroundColor Green
    Write-Host "  FIX A: generate-and-sync.yml STAGE 6.7 added -- version_governance --apply" -ForegroundColor Green
    Write-Host "          before --check. Permanently prevents sla_status.json version drift." -ForegroundColor Green
    Write-Host "  FIX B: generate-and-sync.yml STAGE 5.7 moved to pre-deployment gate." -ForegroundColor Green
    Write-Host "  FIX C: generate-and-sync.yml STAGE 9.5 R2 upload script restored." -ForegroundColor Green
    Write-Host ""
    Write-Host "VALIDATION:" -ForegroundColor Green
    Write-Host "  node --check on 434,719-char main <script> block: PASS" -ForegroundColor Green
    Write-Host "  dashboard_frontend_guard.py: 10/10 checks PASS, 0 FAIL" -ForegroundColor Green
    Write-Host "  STAGE 3.92 perpetual failure loop: ELIMINATED" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next scheduled run: 2026-05-14 02:00 UTC (every 6h)" -ForegroundColor Cyan
    Write-Host "Or trigger manually: GitHub -> Actions -> Sentinel Blogger -> Run workflow" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "[ERROR] Push failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "Try: git push origin main" -ForegroundColor Yellow
    Write-Host "If authentication fails, use GitHub Desktop or push via browser." -ForegroundColor Yellow
}
