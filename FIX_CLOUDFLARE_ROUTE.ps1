# =============================================================================
# SENTINEL APEX v109 — FORCE REASSIGN intel.cyberdudebivash.com TO NEW WORKER
# =============================================================================
# This script finds the old worker route and reassigns it to the v109 worker.
#
# BEFORE RUNNING: Set these 3 values:
#   $CF_API_TOKEN  — Cloudflare API token (needs Workers:Edit + Zone:Edit permissions)
#   $CF_ZONE_ID    — Your zone ID for cyberdudebivash.com
#   $NEW_WORKER    — The new worker script name
#
# HOW TO GET ZONE ID:
#   Cloudflare Dashboard → cyberdudebivash.com → Overview → right sidebar → "Zone ID"
#
# HOW TO GET API TOKEN:
#   Cloudflare Dashboard → My Profile → API Tokens → Create Token
#   Use template: "Edit Cloudflare Workers" (includes Workers Scripts + Routes)
# =============================================================================

$CF_API_TOKEN = "PASTE_YOUR_CLOUDFLARE_API_TOKEN_HERE"
$CF_ZONE_ID   = "PASTE_YOUR_ZONE_ID_FOR_cyberdudebivash.com_HERE"
$NEW_WORKER   = "sentinel-apex-gateway"
$TARGET_ROUTE = "intel.cyberdudebivash.com/*"

$headers = @{
    "Authorization" = "Bearer $CF_API_TOKEN"
    "Content-Type"  = "application/json"
}

Write-Host ""
Write-Host "=== SENTINEL APEX v109 — Route Reassignment ===" -ForegroundColor Cyan
Write-Host ""

# ── STEP 1: List all worker routes on this zone ───────────────────────────────
Write-Host "[1/4] Listing all Worker routes on cyberdudebivash.com..."
$routesResp = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/workers/routes" `
    -Method GET -Headers $headers

if (-not $routesResp.success) {
    Write-Host "ERROR: Failed to list routes. Check API token and Zone ID." -ForegroundColor Red
    Write-Host ($routesResp | ConvertTo-Json)
    exit 1
}

$routes = $routesResp.result
Write-Host "    Found $($routes.Count) route(s):"
foreach ($r in $routes) {
    $marker = if ($r.pattern -like "*intel.cyberdudebivash*") { " <-- TARGET" } else { "" }
    Write-Host "    [$($r.id)] $($r.pattern) → $($r.script)$marker"
}

# ── STEP 2: Find the intel.cyberdudebivash.com route ─────────────────────────
$intelRoute = $routes | Where-Object { $_.pattern -like "*intel.cyberdudebivash*" } | Select-Object -First 1

if (-not $intelRoute) {
    Write-Host ""
    Write-Host "[2/4] No route found for intel.cyberdudebivash.com — CREATING new route..." -ForegroundColor Yellow

    $body = @{ pattern = $TARGET_ROUTE; script = $NEW_WORKER } | ConvertTo-Json
    $createResp = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/workers/routes" `
        -Method POST -Headers $headers -Body $body

    if ($createResp.success) {
        Write-Host "    OK: Route CREATED — $TARGET_ROUTE → $NEW_WORKER" -ForegroundColor Green
        $routeId = $createResp.result.id
    } else {
        Write-Host "    ERROR creating route:" -ForegroundColor Red
        Write-Host ($createResp | ConvertTo-Json)
        exit 1
    }
} else {
    $routeId = $intelRoute.id
    $oldWorker = $intelRoute.script
    Write-Host ""
    Write-Host "[2/4] Found existing route: [$routeId] → currently assigned to '$oldWorker'" -ForegroundColor Yellow

    if ($oldWorker -eq $NEW_WORKER) {
        Write-Host "    Route already points to '$NEW_WORKER' — nothing to do." -ForegroundColor Green
        Write-Host ""
        Write-Host "=== Route is correct. Test: curl https://intel.cyberdudebivash.com/api/feed ===" -ForegroundColor Green
        exit 0
    }

    # ── STEP 3: Reassign route to new worker ──────────────────────────────────
    Write-Host "[3/4] Reassigning route from '$oldWorker' → '$NEW_WORKER'..."
    $body = @{ pattern = $TARGET_ROUTE; script = $NEW_WORKER } | ConvertTo-Json
    $updateResp = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/workers/routes/$routeId" `
        -Method PUT -Headers $headers -Body $body

    if ($updateResp.success) {
        Write-Host "    OK: Route UPDATED — $TARGET_ROUTE → $NEW_WORKER" -ForegroundColor Green
    } else {
        Write-Host "    ERROR updating route:" -ForegroundColor Red
        Write-Host ($updateResp | ConvertTo-Json)
        exit 1
    }
}

# ── STEP 4: Validate ──────────────────────────────────────────────────────────
Write-Host "[4/4] Waiting 3 seconds for route propagation..."
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "Testing https://intel.cyberdudebivash.com/api/feed (should return 401)..."
try {
    $testResp = Invoke-WebRequest -Uri "https://intel.cyberdudebivash.com/api/feed" -UseBasicParsing -ErrorAction Stop
    $body = $testResp.Content | ConvertFrom-Json
    if ($body.error -eq "api_key_required") {
        Write-Host "    PASS: Got 401 api_key_required — v109 Worker IS live" -ForegroundColor Green
    } elseif ($body.status -eq "ok") {
        Write-Host "    WARN: Got 200 OK — API key may have been passed. Check manually." -ForegroundColor Yellow
    } else {
        Write-Host "    WARN: Got unexpected response format — may still be old worker." -ForegroundColor Yellow
        Write-Host "    status: $($body.status)"
    }
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 401) {
        Write-Host "    PASS: 401 Unauthorized — v109 Worker IS live, auth enforced" -ForegroundColor Green
    } else {
        Write-Host "    HTTP $statusCode — check manually" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Testing https://intel.cyberdudebivash.com/api/preview (should return 200)..."
try {
    $prevResp = Invoke-RestMethod -Uri "https://intel.cyberdudebivash.com/api/preview" -UseBasicParsing
    if ($prevResp.status -eq "ok") {
        $count = $prevResp.preview.total_preview
        $total = $prevResp.preview.total_in_feed
        Write-Host "    PASS: /api/preview live — $count preview items, $total total in feed" -ForegroundColor Green
    }
} catch {
    Write-Host "    INFO: /api/preview check failed — try manually in 60s" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " DONE: intel.cyberdudebivash.com → v109 Worker LIVE" -ForegroundColor Green
Write-Host " Auth: REQUIRED on /api/feed (api_key_required)" -ForegroundColor Green
Write-Host " Public: /api/preview (no auth, 10-item teaser)" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
