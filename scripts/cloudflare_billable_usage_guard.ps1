param(
    [ValidateRange(0, 1000000)]
    [decimal]$MaxUsageCostUsd = 0.00
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-PropertyValue {
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

function Convert-ToDecimal {
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


# =====================================================================
# INPUT CONTRACT
# =====================================================================

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


# =====================================================================
# CLOUDFLARE BILLABLE USAGE API
# =====================================================================

$Headers = @{
    Authorization = "Bearer $Token"
    Accept        = "application/json"
}

$Uri = (
    "https://api.cloudflare.com/client/v4/accounts/" +
    $AccountId +
    "/billable-usage"
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "CYBERDUDEBIVASH P0 CLOUDFLARE COST GUARD" -ForegroundColor Cyan
Write-Host "============================================================"
Write-Host "Mode             : PRE_REVENUE_ZERO_OVERAGE"
Write-Host "Allowed overage  : USD $MaxUsageCostUsd"
Write-Host "Accounting field : ContractedCost"
Write-Host "Credential       : BILLING READ ONLY / NOT PRINTED"

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
    throw "Cloudflare returned an empty API response."
}

if ($Response.success -ne $true) {
    throw "Cloudflare Billable Usage API returned success=false."
}

$Rows = @($Response.result)

if ($Rows.Count -eq 0) {
    throw "No billable usage records returned; fail closed."
}


# =====================================================================
# NORMALIZE + DEDUPLICATE CHARGE PERIODS
# =====================================================================

$UniqueRows = @{}
$DuplicateCount = 0

foreach ($Row in $Rows) {

    $Signature = @(
        [string](Get-PropertyValue $Row "SubscriptionId"),
        [string](Get-PropertyValue $Row "ZoneId"),
        [string](Get-PropertyValue $Row "ServiceName"),
        [string](Get-PropertyValue $Row "x_BillableMetricName"),
        [string](Get-PropertyValue $Row "ChargePeriodStart"),
        [string](Get-PropertyValue $Row "ChargePeriodEnd"),
        [string](Get-PropertyValue $Row "PricingQuantity"),
        [string](Get-PropertyValue $Row "ContractedCost")
    ) -join "|"

    if ($UniqueRows.ContainsKey($Signature)) {
        $DuplicateCount++
        continue
    }

    $UniqueRows[$Signature] = $Row
}


# =====================================================================
# ACCOUNTING
# =====================================================================

$TotalCost = [decimal]0
$Diagnostics = @()
$PositiveRows = @()

foreach ($Entry in $UniqueRows.GetEnumerator()) {

    $Row = $Entry.Value

    $RawContracted = Get-PropertyValue `
        $Row `
        "ContractedCost"

    if ($null -eq $RawContracted) {
        throw "ContractedCost missing from a billable usage record."
    }

    $ContractedCost = Convert-ToDecimal `
        $RawContracted `
        "ContractedCost"

    if ($ContractedCost -lt 0) {
        throw "Negative ContractedCost returned; fail closed."
    }

    $RawBilled = Get-PropertyValue `
        $Row `
        "BilledCost"

    $BilledCost = $null

    if ($null -ne $RawBilled) {

        $BilledCost = Convert-ToDecimal `
            $RawBilled `
            "BilledCost"

        if (
            [math]::Abs(
                [double]($BilledCost - $ContractedCost)
            ) -gt 0.000001
        ) {
            throw "BilledCost and ContractedCost disagree; fail closed for accounting review."
        }
    }

    $TotalCost += $ContractedCost

    $Metric = [string](
        Get-PropertyValue `
            $Row `
            "x_BillableMetricName"
    )

    if ([string]::IsNullOrWhiteSpace($Metric)) {
        $Metric = [string](
            Get-PropertyValue `
                $Row `
                "ServiceName"
        )
    }

    if ([string]::IsNullOrWhiteSpace($Metric)) {
        $Metric = "UNKNOWN"
    }

    $Record = [PSCustomObject]@{
        Metric                   = $Metric
        ServiceFamily            = Get-PropertyValue $Row "ServiceFamilyName"
        ServiceName              = Get-PropertyValue $Row "ServiceName"
        ConsumedQuantity         = Get-PropertyValue $Row "ConsumedQuantity"
        ConsumedUnit             = Get-PropertyValue $Row "ConsumedUnit"
        PricingQuantity          = Get-PropertyValue $Row "PricingQuantity"
        PricingUnit              = Get-PropertyValue $Row "PricingUnit"
        ContractedCost           = $ContractedCost
        BilledCost               = $BilledCost
        CumulatedContractedCost  = Get-PropertyValue $Row "CumulatedContractedCost"
        BillingCurrency          = Get-PropertyValue $Row "BillingCurrency"
        BillingPeriodStart       = Get-PropertyValue $Row "BillingPeriodStart"
        ChargePeriodStart        = Get-PropertyValue $Row "ChargePeriodStart"
        ChargePeriodEnd          = Get-PropertyValue $Row "ChargePeriodEnd"
    }

    $Diagnostics += $Record

    if ($ContractedCost -gt 0) {
        $PositiveRows += $Record
    }
}

$TotalCost = [decimal]::Round(
    $TotalCost,
    6
)


# =====================================================================
# LOCAL EVIDENCE - OUTSIDE GIT WORKTREE
# =====================================================================

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

$Status = "PASS"

if ($TotalCost -gt $MaxUsageCostUsd) {
    $Status = "BLOCKED"
}

$Evidence = [ordered]@{
    schema_version         = "4.0"
    generated_at_utc       = [DateTime]::UtcNow.ToString("o")
    control                = "CLOUDFLARE_PRE_REVENUE_ZERO_OVERAGE"
    source                 = "Cloudflare Billable Usage API"
    api_rows               = $Rows.Count
    unique_charge_rows     = $UniqueRows.Count
    duplicates_removed     = $DuplicateCount
    usage_cost_usd         = $TotalCost
    allowed_overage_usd    = $MaxUsageCostUsd
    status                 = $Status
    positive_cost_rows     = $PositiveRows
    diagnostics            = $Diagnostics
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
# OPERATOR RESULT
# =====================================================================

Write-Host ""
Write-Host "API rows           :" $Rows.Count
Write-Host "Unique charge rows :" $UniqueRows.Count
Write-Host "Duplicates removed :" $DuplicateCount
Write-Host "Usage cost USD     :" $TotalCost
Write-Host "Evidence           :" $EvidencePath

if ($PositiveRows.Count -gt 0) {

    Write-Host ""
    Write-Host "POSITIVE USAGE CHARGES" -ForegroundColor Yellow

    $PositiveRows |
        Sort-Object ContractedCost -Descending |
        Select-Object `
            Metric,
            ConsumedQuantity,
            ConsumedUnit,
            PricingQuantity,
            PricingUnit,
            ContractedCost,
            CumulatedContractedCost,
            BillingCurrency |
        Format-Table -AutoSize
}

Write-Host ""

if ($TotalCost -gt $MaxUsageCostUsd) {

    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "P0 CLOUDFLARE COST GUARD: BLOCKED" -ForegroundColor Red
    Write-Host "============================================================"
    Write-Host "Current usage cost USD :" $TotalCost
    Write-Host "Allowed overage USD    :" $MaxUsageCostUsd
    Write-Host "Customer production    : KEEP ONLINE"
    Write-Host "Background expansion   : HOLD"
    Write-Host "============================================================"

    throw "P0 Cloudflare usage-based cost ceiling exceeded."
}

Write-Host "============================================================" -ForegroundColor Green
Write-Host "P0 CLOUDFLARE COST GUARD: PASS" -ForegroundColor Green
Write-Host "============================================================"
Write-Host "Current usage cost USD :" $TotalCost
Write-Host "Allowed overage USD    :" $MaxUsageCostUsd
Write-Host "Customer production    : KEEP ONLINE"
Write-Host "Pre-revenue mandate    : SATISFIED"
Write-Host "============================================================"