param(
    [ValidateRange(1, 365)]
    [int]$ReportRetentionDays = 7,

    [ValidateRange(10, 300)]
    [int]$WranglerTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path $PSScriptRoot -Parent
$Gateway = Join-Path $RepoRoot "workers\intel-gateway"

$WranglerJs = Join-Path `
    $Gateway `
    "node_modules\wrangler\bin\wrangler.js"

$NodeExe = (
    Get-Command node -ErrorAction Stop
).Source

if (-not (Test-Path -LiteralPath $WranglerJs -PathType Leaf)) {
    throw "Repository-local Wrangler is unavailable. Run npm ci in workers/intel-gateway."
}


# =====================================================================
# ACCOUNT CONTRACT
# =====================================================================

$AccountId = $env:CLOUDFLARE_ACCOUNT_ID

if ([string]::IsNullOrWhiteSpace($AccountId)) {
    $AccountId = $env:CF_ACCOUNT_ID
}

if ([string]::IsNullOrWhiteSpace($AccountId)) {
    throw "Cloudflare account ID is required."
}

if ($AccountId -notmatch "^[a-fA-F0-9]{32}$") {
    throw "Cloudflare account ID format is invalid."
}

$env:CLOUDFLARE_ACCOUNT_ID = $AccountId

# Do not expose deprecated account variable to Wrangler.
Remove-Item Env:CF_ACCOUNT_ID -ErrorAction SilentlyContinue


# =====================================================================
# FAIL-BOUNDED WRANGLER OPERATOR
# =====================================================================

function Invoke-CdbWrangler {

    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $StdOut = Join-Path `
        $env:TEMP `
        ("cdb-wrangler-out-" + [Guid]::NewGuid().ToString("N") + ".log")

    $StdErr = Join-Path `
        $env:TEMP `
        ("cdb-wrangler-err-" + [Guid]::NewGuid().ToString("N") + ".log")

    $Process = $null

    try {

        $ArgumentList = @(
            "`"$WranglerJs`""
        ) + $Arguments

        Write-Host ""
        Write-Host "WRANGLER:" ($Arguments -join " ") -ForegroundColor Cyan

        $Process = Start-Process `
            -FilePath $NodeExe `
            -ArgumentList $ArgumentList `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $StdOut `
            -RedirectStandardError $StdErr

        if ($null -eq $Process) {
            throw "Unable to create Wrangler child process."
        }

        $Completed = $Process.WaitForExit(
            $WranglerTimeoutSeconds * 1000
        )

        if (-not $Completed) {

            try {
                Stop-Process `
                    -Id $Process.Id `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
            catch {
            }

            throw (
                "Wrangler timed out after " +
                $WranglerTimeoutSeconds +
                " seconds."
            )
        }

        # Critical Windows/.NET fix:
        # complete asynchronous redirection processing and refresh
        # the native process object's exit status.
        $Process.WaitForExit()
        $Process.Refresh()

        $ExitCode = [int]$Process.ExitCode

        $Utf8 = New-Object System.Text.UTF8Encoding($false)

        $Out = ""

        if (Test-Path -LiteralPath $StdOut) {
            $Out = [System.IO.File]::ReadAllText(
                $StdOut,
                $Utf8
            )
        }

        $Err = ""

        if (Test-Path -LiteralPath $StdErr) {
            $Err = [System.IO.File]::ReadAllText(
                $StdErr,
                $Utf8
            )
        }

        if (-not [string]::IsNullOrWhiteSpace($Out)) {
            Write-Host $Out
        }

        if (-not [string]::IsNullOrWhiteSpace($Err)) {
            Write-Host $Err -ForegroundColor Yellow
        }

        Write-Host "Wrangler exit code:" $ExitCode

        if ($ExitCode -ne 0) {
            throw "Wrangler failed with exit code $ExitCode."
        }

        return ($Out + "`n" + $Err)
    }
    finally {

        if ($null -ne $Process) {
            $Process.Dispose()
        }

        Remove-Item `
            -LiteralPath $StdOut `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            -LiteralPath $StdErr `
            -Force `
            -ErrorAction SilentlyContinue
    }
}


# =====================================================================
# BEGIN
# =====================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "P0 R2 NATIVE RETENTION ENFORCEMENT" -ForegroundColor Cyan
Write-Host "============================================================"


# =====================================================================
# AUTH PROBE
# =====================================================================

$WhoAmI = Invoke-CdbWrangler @(
    "whoami"
)

if ($WhoAmI -notmatch [regex]::Escape($AccountId)) {
    throw "Wrangler authentication does not expose the expected Cloudflare account."
}

Write-Host "Wrangler authentication: PASS" -ForegroundColor Green


# =====================================================================
# READ CURRENT STATE
# =====================================================================

$ReportsBefore = Invoke-CdbWrangler @(
    "r2",
    "bucket",
    "lifecycle",
    "list",
    "sentinel-apex-reports"
)

$DataBefore = Invoke-CdbWrangler @(
    "r2",
    "bucket",
    "lifecycle",
    "list",
    "sentinel-apex-data"
)


# =====================================================================
# MUTATE ONLY WHEN MISSING
# =====================================================================

if ($ReportsBefore -notmatch "reports-html-7d-backstop") {

    Write-Host ""
    Write-Host "Installing missing reports expiration rule..." -ForegroundColor Yellow

    Invoke-CdbWrangler @(
        "r2",
        "bucket",
        "lifecycle",
        "add",
        "sentinel-apex-reports",
        "reports-html-7d-backstop",
        "reports/",
        "--expire-days",
        [string]$ReportRetentionDays
    ) | Out-Null
}
else {

    Write-Host ""
    Write-Host "reports-html-7d-backstop already exists; no mutation required." -ForegroundColor Green
}


# =====================================================================
# AUTHORITATIVE POST-CONDITION
# =====================================================================

$ReportsAfter = Invoke-CdbWrangler @(
    "r2",
    "bucket",
    "lifecycle",
    "list",
    "sentinel-apex-reports"
)

$DataAfter = Invoke-CdbWrangler @(
    "r2",
    "bucket",
    "lifecycle",
    "list",
    "sentinel-apex-data"
)


$ReportsExpirationOk = (
    ($ReportsAfter -match "reports-html-7d-backstop") -and
    ($ReportsAfter -match "prefix:\s+reports/") -and
    ($ReportsAfter -match "Expire objects after 7 days")
)

$ReportsMultipartOk = (
    $ReportsAfter -match
    "Abort incomplete multipart uploads after 7 days"
)

$DataMultipartOk = (
    $DataAfter -match
    "Abort incomplete multipart uploads after 7 days"
)

$UnsafeDataExpiration = (
    ($DataAfter -match "reports-html-7d-backstop") -or
    ($DataAfter -match "Expire objects after 7 days")
)


if (-not $ReportsExpirationOk) {
    throw "Reports 7-day lifecycle post-condition failed."
}

if (-not $ReportsMultipartOk) {
    throw "Reports multipart-abort post-condition failed."
}

if (-not $DataMultipartOk) {
    throw "Data multipart-abort post-condition failed."
}

if ($UnsafeDataExpiration) {
    throw "CRITICAL: unsafe age-based expiration detected on sentinel-apex-data."
}


# =====================================================================
# RESULT
# =====================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "P0 R2 NATIVE RETENTION: PASS" -ForegroundColor Green
Write-Host "============================================================"
Write-Host "sentinel-apex-reports"
Write-Host "  reports/ expiration : 7 DAYS"
Write-Host "  multipart cleanup   : 7 DAYS"
Write-Host ""
Write-Host "sentinel-apex-data"
Write-Host "  age expiration      : NONE"
Write-Host "  multipart cleanup   : 7 DAYS"
Write-Host ""
Write-Host "Wrangler timeout      :" $WranglerTimeoutSeconds "SECONDS"
Write-Host "============================================================"