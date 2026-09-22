param(
    [ValidateRange(0, 1000000)]
    [decimal]$MaxUsageCostUsd = 0.00,

    [string]$UsageSnapshotPath = "",

    [string]$EvidencePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


function Get-CdbProperty {

    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string] $Name
    )

    $Property = $Object.PSObject.Properties[$Name]

    if ($null -eq $Property) {
        return $null
    }

    return $Property.Value
}


function Convert-CdbDecimal {

    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [string] $FieldName
    )

    try {

        return [Convert]::ToDecimal(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    catch {

        throw "Unable to parse $FieldName as decimal."
    }
}


function Convert-CdbUtcTimestamp {

    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$FieldName is missing; fail closed."
    }

    try {

        return [DateTimeOffset]::Parse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture
        ).ToUniversalTime()
    }
    catch {

        throw "Unable to parse $FieldName as timestamp: $Value"
    }
}


# =====================================================================
# INPUT SOURCE
# =====================================================================

$SourceMode = "LIVE_API"
$Rows = @()

if (-not [string]::IsNullOrWhiteSpace($UsageSnapshotPath)) {

    if (-not (
        Test-Path `
            -LiteralPath $UsageSnapshotPath `
            -PathType Leaf
    )) {
        throw "Usage snapshot does not exist: $UsageSnapshotPath"
    }

    $Snapshot = Get-Content `
        -LiteralPath $UsageSnapshotPath `
        -Raw |
        ConvertFrom-Json

    if ($Snapshot -is [System.Array]) {

        $Rows = @($Snapshot)
    }
    elseif (
        $Snapshot.PSObject.Properties.Name -contains "result"
    ) {

        $Rows = @($Snapshot.result)
    }
    else {

        throw "Snapshot must be an array or contain a result property."
    }

    $SourceMode = "OFFLINE_SNAPSHOT"
}
else {

    $AccountId = [Environment]::GetEnvironmentVariable(
        "CF_ACCOUNT_ID",
        "Process"
    )

    if ([string]::IsNullOrWhiteSpace($AccountId)) {

        $AccountId = [Environment]::GetEnvironmentVariable(
            "CLOUDFLARE_ACCOUNT_ID",
            "Process"
        )
    }

    $Token = [Environment]::GetEnvironmentVariable(
        "CF_BILLING_READ_TOKEN",
        "Process"
    )

    if ([string]::IsNullOrWhiteSpace($AccountId)) {
        throw "CF_ACCOUNT_ID or CLOUDFLARE_ACCOUNT_ID is required."
    }

    if ($AccountId -notmatch "^[a-fA-F0-9]{32}$") {
        throw "Cloudflare Account ID format is invalid."
    }

    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw "CF_BILLING_READ_TOKEN is required."
    }

    $Headers = @{
        Authorization = "Bearer $Token"
        Accept        = "application/json"
    }

    $Uri = (
        "https://api.cloudflare.com/client/v4/accounts/" +
        $AccountId +
        "/billable-usage"
    )

    try {

        $Response = Invoke-RestMethod `
            -Method Get `
            -Uri $Uri `
            -Headers $Headers `
            -TimeoutSec 60
    }
    catch {

        throw (
            "Cloudflare Billable Usage request failed: " +
            $_.Exception.Message
        )
    }

    if ($null -eq $Response) {
        throw "Cloudflare returned an empty response."
    }

    if ($Response.success -ne $true) {
        throw "Cloudflare Billable Usage API returned success=false."
    }

    $Rows = @($Response.result)
}


if ($Rows.Count -eq 0) {
    throw "No billable usage records returned; fail closed."
}


# =====================================================================
# NORMALIZATION
# =====================================================================

$Normalized = @()

foreach ($Row in $Rows) {

    $RawPeriod = [string](
        Get-CdbProperty `
            $Row `
            "BillingPeriodStart"
    )

    $BillingPeriodStart = Convert-CdbUtcTimestamp `
        $RawPeriod `
        "BillingPeriodStart"

    $RawContracted = Get-CdbProperty `
        $Row `
        "ContractedCost"

    if ($null -eq $RawContracted) {
        throw "ContractedCost is missing; fail closed."
    }

    $ContractedCost = Convert-CdbDecimal `
        $RawContracted `
        "ContractedCost"

    if ($ContractedCost -lt 0) {
        throw "Negative ContractedCost returned; fail closed."
    }

    $RawBilled = Get-CdbProperty `
        $Row `
        "BilledCost"

    $BilledCost = $null

    if ($null -ne $RawBilled) {

        $BilledCost = Convert-CdbDecimal `
            $RawBilled `
            "BilledCost"

        if (
            [math]::Abs(
                [double](
                    $BilledCost -
                    $ContractedCost
                )
            ) -gt 0.000001
        ) {
            throw (
                "BilledCost and ContractedCost disagree; " +
                "fail closed for accounting review."
            )
        }
    }

    $SubscriptionId = [string](
        Get-CdbProperty `
            $Row `
            "SubscriptionId"
    )

    $ServiceFamily = [string](
        Get-CdbProperty `
            $Row `
            "ServiceFamilyName"
    )

    $ServiceName = [string](
        Get-CdbProperty `
            $Row `
            "ServiceName"
    )

    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {

        $GroupKey = "subscription:" + $SubscriptionId
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ServiceFamily)) {

        $GroupKey = "family:" + $ServiceFamily
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ServiceName)) {

        $GroupKey = "service:" + $ServiceName
    }
    else {

        throw (
            "Unable to establish subscription/service billing group; " +
            "fail closed."
        )
    }

    $Metric = [string](
        Get-CdbProperty `
            $Row `
            "x_BillableMetricName"
    )

    if ([string]::IsNullOrWhiteSpace($Metric)) {
        $Metric = $ServiceName
    }

    if ([string]::IsNullOrWhiteSpace($Metric)) {
        $Metric = "UNKNOWN"
    }

    $Normalized += [PSCustomObject]@{
        GroupKey                  = $GroupKey
        SubscriptionId            = $SubscriptionId
        ServiceFamily             = $ServiceFamily
        ServiceName               = $ServiceName
        Metric                    = $Metric
        ZoneId                    = Get-CdbProperty $Row "ZoneId"
        ConsumedQuantity          = Get-CdbProperty $Row "ConsumedQuantity"
        ConsumedUnit              = Get-CdbProperty $Row "ConsumedUnit"
        PricingQuantity           = Get-CdbProperty $Row "PricingQuantity"
        PricingUnit               = Get-CdbProperty $Row "PricingUnit"
        ContractedCost            = $ContractedCost
        BilledCost                = $BilledCost
        CumulatedContractedCost   = Get-CdbProperty $Row "CumulatedContractedCost"
        BillingCurrency           = Get-CdbProperty $Row "BillingCurrency"
        BillingPeriodStart        = $BillingPeriodStart
        ChargePeriodStart         = Get-CdbProperty $Row "ChargePeriodStart"
        ChargePeriodEnd           = Get-CdbProperty $Row "ChargePeriodEnd"
    }
}


# =====================================================================
# DEDUPLICATION
# =====================================================================

$Unique = @{}
$DuplicateCount = 0

foreach ($Row in $Normalized) {

    $Signature = @(
        $Row.GroupKey,
        $Row.BillingPeriodStart.ToString("o"),
        [string]$Row.ZoneId,
        $Row.Metric,
        [string]$Row.ChargePeriodStart,
        [string]$Row.ChargePeriodEnd,
        [string]$Row.PricingQuantity,
        [string]$Row.ContractedCost
    ) -join "|"

    if ($Unique.ContainsKey($Signature)) {

        $DuplicateCount++
        continue
    }

    $Unique[$Signature] = $Row
}

$UniqueRows = @(
    $Unique.Values
)


# =====================================================================
# DETERMINE CURRENT BILLING PERIOD FOR EACH SUBSCRIPTION/SERVICE GROUP
# =====================================================================

$LatestPeriodByGroup = @{}

foreach ($Row in $UniqueRows) {

    $Key = $Row.GroupKey

    if (-not $LatestPeriodByGroup.ContainsKey($Key)) {

        $LatestPeriodByGroup[$Key] =
            [DateTimeOffset]$Row.BillingPeriodStart

        continue
    }

    $Existing =
        [DateTimeOffset]$LatestPeriodByGroup[$Key]

    $Candidate =
        [DateTimeOffset]$Row.BillingPeriodStart

    if (
        $Candidate.UtcDateTime.Ticks -gt
        $Existing.UtcDateTime.Ticks
    ) {

        $LatestPeriodByGroup[$Key] = $Candidate
    }
}


# =====================================================================
# SELECT ONLY CURRENT BILLING PERIOD ROWS
# =====================================================================

$CurrentRows = @(
    $UniqueRows |
    Where-Object {

        $Expected =
            [DateTimeOffset]$LatestPeriodByGroup[$_.GroupKey]

        $_.BillingPeriodStart.UtcDateTime.Ticks -eq
        $Expected.UtcDateTime.Ticks
    }
)

if ($CurrentRows.Count -eq 0) {
    throw "No current billing-period rows remain after filtering."
}


$HistoricalRows = @(
    $UniqueRows |
    Where-Object {

        $Expected =
            [DateTimeOffset]$LatestPeriodByGroup[$_.GroupKey]

        $_.BillingPeriodStart.UtcDateTime.Ticks -ne
        $Expected.UtcDateTime.Ticks
    }
)


# =====================================================================
# ACCOUNTING
# =====================================================================

$CurrentTotal = [decimal]0

foreach ($Row in $CurrentRows) {
    $CurrentTotal += [decimal]$Row.ContractedCost
}

$AllReturnedTotal = [decimal]0

foreach ($Row in $UniqueRows) {
    $AllReturnedTotal += [decimal]$Row.ContractedCost
}

$CurrentTotal = [decimal]::Round(
    $CurrentTotal,
    6
)

$AllReturnedTotal = [decimal]::Round(
    $AllReturnedTotal,
    6
)

$HistoricalReturnedTotal = [decimal]::Round(
    $AllReturnedTotal - $CurrentTotal,
    6
)

$PositiveCurrentRows = @(
    $CurrentRows |
    Where-Object {
        [decimal]$_.ContractedCost -gt 0
    }
)


# =====================================================================
# CURRENCY CONSISTENCY
# =====================================================================

$CurrentCurrencies = @(
    $CurrentRows |
    ForEach-Object {
        [string]$_.BillingCurrency
    } |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } |
    Sort-Object -Unique
)

if ($CurrentCurrencies.Count -gt 1) {
    throw "Multiple billing currencies detected in current period."
}


# =====================================================================
# CURRENT PERIOD SUMMARY
# =====================================================================

$CurrentPeriodSummary = @(
    $LatestPeriodByGroup.GetEnumerator() |
    Sort-Object Key |
    ForEach-Object {

        [PSCustomObject]@{
            GroupKey           = $_.Key
            BillingPeriodStart = (
                [DateTimeOffset]$_.Value
            ).ToString("o")
        }
    }
)


# =====================================================================
# EVIDENCE
# =====================================================================

if ([string]::IsNullOrWhiteSpace($EvidencePath)) {

    $EvidenceDir = Join-Path `
        $env:LOCALAPPDATA `
        "CYBERDUDEBIVASH\FinOps"

    New-Item `
        -ItemType Directory `
        -Path $EvidenceDir `
        -Force |
        Out-Null

    $EvidencePath = Join-Path `
        $EvidenceDir `
        "cloudflare-billable-usage-latest.json"
}
else {

    $EvidenceDir = Split-Path `
        -Parent `
        $EvidencePath

    if (
        -not [string]::IsNullOrWhiteSpace($EvidenceDir)
    ) {

        New-Item `
            -ItemType Directory `
            -Path $EvidenceDir `
            -Force |
            Out-Null
    }
}


$Status = "PASS"

if ($CurrentTotal -gt $MaxUsageCostUsd) {
    $Status = "BLOCKED"
}


$Evidence = [ordered]@{
    schema_version                 = "5.0"
    generated_at_utc               = [DateTime]::UtcNow.ToString("o")
    control                        = "CLOUDFLARE_PRE_REVENUE_ZERO_OVERAGE"
    source_mode                    = $SourceMode
    source                         = "Cloudflare Billable Usage API"
    api_rows                       = $Rows.Count
    unique_charge_rows             = $UniqueRows.Count
    duplicate_rows_removed         = $DuplicateCount
    current_period_rows            = $CurrentRows.Count
    historical_rows                = $HistoricalRows.Count
    current_periods                = $CurrentPeriodSummary
    current_usage_cost_usd         = $CurrentTotal
    historical_returned_cost_usd   = $HistoricalReturnedTotal
    all_returned_cost_usd          = $AllReturnedTotal
    allowed_overage_usd            = $MaxUsageCostUsd
    status                         = $Status
    positive_current_cost_rows     = $PositiveCurrentRows
    current_diagnostics            = $CurrentRows
    all_diagnostics                = $UniqueRows
}


$Json = $Evidence |
    ConvertTo-Json -Depth 12

$Utf8Bom = New-Object System.Text.UTF8Encoding($true)

[System.IO.File]::WriteAllText(
    $EvidencePath,
    $Json,
    $Utf8Bom
)


# =====================================================================
# OPERATOR OUTPUT
# =====================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "CYBERDUDEBIVASH P0 CURRENT-BILLING-PERIOD COST GUARD" -ForegroundColor Cyan
Write-Host "============================================================"
Write-Host "Source mode                  :" $SourceMode
Write-Host "API rows                     :" $Rows.Count
Write-Host "Unique rows                  :" $UniqueRows.Count
Write-Host "Current-period rows          :" $CurrentRows.Count
Write-Host "Historical rows              :" $HistoricalRows.Count
Write-Host "Duplicates removed           :" $DuplicateCount
Write-Host "Current-period cost USD      :" $CurrentTotal
Write-Host "Historical returned cost USD :" $HistoricalReturnedTotal
Write-Host "All returned cost USD        :" $AllReturnedTotal
Write-Host "Allowed overage USD          :" $MaxUsageCostUsd
Write-Host "Evidence                     :" $EvidencePath

Write-Host ""
Write-Host "CURRENT BILLING PERIODS" -ForegroundColor Cyan

$CurrentPeriodSummary |
    Format-Table -AutoSize


if ($PositiveCurrentRows.Count -gt 0) {

    Write-Host ""
    Write-Host "CURRENT-PERIOD POSITIVE USAGE CHARGES" -ForegroundColor Yellow

    $PositiveCurrentRows |
        Sort-Object ContractedCost -Descending |
        Select-Object `
            Metric,
            BillingPeriodStart,
            ChargePeriodStart,
            ChargePeriodEnd,
            ConsumedQuantity,
            ConsumedUnit,
            PricingQuantity,
            ContractedCost,
            CumulatedContractedCost,
            BillingCurrency |
        Format-Table -AutoSize
}


Write-Host ""

if ($CurrentTotal -gt $MaxUsageCostUsd) {

    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "P0 CURRENT-PERIOD COST GUARD: BLOCKED" -ForegroundColor Red
    Write-Host "============================================================"
    Write-Host "Current-period usage cost USD :" $CurrentTotal
    Write-Host "Allowed overage USD           :" $MaxUsageCostUsd
    Write-Host "Historical returned charges   :" $HistoricalReturnedTotal
    Write-Host "Customer production           : KEEP ONLINE"
    Write-Host "Nonessential expansion        : HOLD"
    Write-Host "============================================================"

    throw "P0 current billing-period usage-cost ceiling exceeded."
}


Write-Host "============================================================" -ForegroundColor Green
Write-Host "P0 CURRENT-PERIOD COST GUARD: PASS" -ForegroundColor Green
Write-Host "============================================================"
Write-Host "Current-period usage cost USD :" $CurrentTotal
Write-Host "Allowed overage USD           :" $MaxUsageCostUsd
Write-Host "Historical returned charges   :" $HistoricalReturnedTotal
Write-Host "Customer production           : KEEP ONLINE"
Write-Host "Pre-revenue mandate           : SATISFIED"
Write-Host "============================================================"