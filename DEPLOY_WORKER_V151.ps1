# =============================================================================
# SENTINEL APEX v151.0 — Cloudflare Worker Deploy
# Deploys the hardened intel-gateway worker to Cloudflare edge
# Run AFTER COMMIT_V151_FIXES.ps1 completes
# =============================================================================

$ErrorActionPreference = "Stop"
$REPO   = "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
$WORKER = Join-Path $REPO "workers\intel-gateway"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " SENTINEL APEX — Cloudflare Worker Deploy" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Check wrangler is available
$wrangler = $null
try { $wrangler = (Get-Command wrangler -ErrorAction Stop).Source }
catch {
    try { $wrangler = (Get-Command npx -ErrorAction Stop).Source }
    catch {
        Write-Host "ERROR: wrangler / npx not found. Install with: npm install -g wrangler" -ForegroundColor Red
        exit 1
    }
}

Set-Location $WORKER

# Verify the key fix is in the worker
$indexJs = Join-Path $WORKER "src\index.js"
$content  = Get-Content $indexJs -Raw
if ($content -notmatch "ai:tracker") {
    Write-Host "ERROR: index.js does not contain the pathMap fix. Ensure COMMIT_V151_FIXES.ps1 ran first." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] index.js pathMap fix confirmed present" -ForegroundColor Green

if ($content -notmatch "engine_alpha") {
    Write-Host "ERROR: index.js fetchAIData broadening not found." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] index.js fetchAIData validation fix confirmed present`n" -ForegroundColor Green

Write-Host "Deploying worker to Cloudflare edge..." -ForegroundColor Cyan
Write-Host "(This will use your CLOUDFLARE_API_TOKEN from environment or wrangler login)`n" -ForegroundColor Gray

if ($wrangler -like "*npx*") {
    npx wrangler deploy
} else {
    wrangler deploy
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "`nDeploy FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "Ensure you are logged in: npx wrangler login" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n============================================" -ForegroundColor Green
Write-Host " Worker deployed to Cloudflare edge!" -ForegroundColor Green
Write-Host "============================================`n" -ForegroundColor Green
Write-Host "The AI Tracker endpoint fixes are now LIVE:" -ForegroundColor White
Write-Host "  /api/ai/tracker          -> R2: ai/tracker.json" -ForegroundColor Gray
Write-Host "  /api/ai/health           -> R2: ai/health.json" -ForegroundColor Gray
Write-Host "  /api/ai/executive-brief  -> R2: ai/executive-brief.json" -ForegroundColor Gray
Write-Host ""
Write-Host "Verify: https://intel.cyberdudebivash.com/ai-threat-tracker.html" -ForegroundColor Yellow
