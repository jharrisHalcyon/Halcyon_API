##############################################################################
# Get-HalcyonAuditLog.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-02-25
# Version : v1.1
#
# Exports the audit log for a tenant, polls until the report is ready,
# downloads the CSV, and optionally filters the output by keyword so you
# can confirm specific actions (e.g. policy changes by a specific user).
#
# Workflow:
#   1. POST /v2/audit-logs/export with optional timestamp window
#      Returns a reportId (UUID)
#   2. Poll GET /v2/jobs/{reportId} until status is Completed or Failed
#   3. Attempt to download the completed report
#   4. Parse CSV and filter rows by -Filter keyword if supplied
#
# Note: The API spec does not document a download URL on the job response.
#       This script captures and displays the full job response so you can
#       see what fields come back -- we may need to discover the download
#       path from the live response.
#
# Usage:
#   # Last 24 hours, all entries
#   .\Get-HalcyonAuditLog.ps1 -AuthObject $auth
#
#   # Last 24 hours, filter output for policy-related changes
#   .\Get-HalcyonAuditLog.ps1 -AuthObject $auth -Filter "policy"
#
#   # Last 24 hours, filter for a specific user
#   .\Get-HalcyonAuditLog.ps1 -AuthObject $auth -Filter "vancouverclinic"
#
#   # Combined -- policy changes by vancouverclinic users
#   .\Get-HalcyonAuditLog.ps1 -AuthObject $auth -Filter "policy" | Where-Object { $_ -match "vancouverclinic" }
#
#   # Custom time window
#   .\Get-HalcyonAuditLog.ps1 -AuthObject $auth -HoursBack 48 -Filter "policy"
#
#   # Target a specific tenant
#   .\Get-HalcyonAuditLog.ps1 -AuthObject $auth -TargetTenantId "b30d3702-780f-4322-8990-3f76049ed5a5" -Filter "policy"
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: Admin
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
##############################################################################

#Requires -Version 5.1

param(
    [PSCustomObject]$AuthObject,
    [string]$AccessToken,
    [string]$TenantId,

    # Target a specific tenant (overrides TenantId from auth for the API header)
    [string]$TargetTenantId,

    # How far back to look (default 24 hours)
    [int]$HoursBack = 24,

    # Optional keyword filter applied to the CSV output after download
    [string]$Filter,

    # How often to poll the job status (seconds)
    [int]$PollIntervalSeconds = 5,

    # Maximum time to wait for the report to complete (seconds)
    [int]$TimeoutSeconds = 120,

    # Save the raw CSV to disk
    [switch]$SaveCsv,

    # Path to save CSV (default: timestamped file in current directory)
    [string]$CsvPath
)

$ErrorActionPreference = "Stop"
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12'
}

# Dot-source the shared JWT helper for token expiry checks
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

# Resolve auth
if ($AuthObject) {
    if (-not $AccessToken) { $AccessToken = $AuthObject.AccessToken }
    if (-not $TenantId)    { $TenantId    = $AuthObject.TenantId    }
}
if (-not $AccessToken -or -not $TenantId) {
    Write-Error "Auth required. Pass -AuthObject from Get-HalcyonBearerToken.ps1."
}

##############################################################################
# Token expiry check -- auto-refresh if access token is within 60 seconds of
# expiry or already expired. Requires RefreshToken on the AuthObject.
# If tokens were supplied directly (-AccessToken/-TenantId) with no AuthObject,
# refresh is not possible -- a warning is shown and the script continues.
##############################################################################

$accessInfo = Get-HalcyonTokenExpiry -Token $AccessToken

if ($accessInfo.SecondsRemaining -lt 60) {

    $refreshToken = if ($AuthObject) { $AuthObject.RefreshToken } else { $null }

    if (-not $refreshToken) {
        Write-Host ""
        if ($accessInfo.IsExpired) {
            Write-Host "  [WARN] Access token is expired and no RefreshToken is available." -ForegroundColor Yellow
            Write-Host "         The API call will likely return 401. Re-authenticate with Get-HalcyonBearerToken.ps1." -ForegroundColor Yellow
        } else {
            Write-Host "  [WARN] Access token expires in $($accessInfo.SecondsRemaining)s. Pass -AuthObject to enable auto-refresh." -ForegroundColor Yellow
        }
        Write-Host ""
    }
    else {
        $refreshInfo = Get-HalcyonTokenExpiry -Token $refreshToken
        if ($refreshInfo.IsExpired) {
            Write-Host ""
            Write-Host "  [FAIL] Both access and refresh tokens are expired." -ForegroundColor Red
            Write-Host "         Re-authenticate with Get-HalcyonBearerToken.ps1." -ForegroundColor Yellow
            Write-Host ""
            exit 1
        }
        if ($accessInfo.IsExpired) {
            Write-Host "  [TOKEN] Access token expired -- refreshing..." -ForegroundColor Yellow
        } else {
            Write-Host "  [TOKEN] Access token expires in $($accessInfo.SecondsRemaining)s -- refreshing proactively..." -ForegroundColor DarkCyan
        }
        try {
            $newAuth = & (Join-Path $PSScriptRoot "Invoke-HalcyonTokenRefresh.ps1") `
                -RefreshToken $refreshToken -TenantId $TenantId -silent
            $AccessToken = $newAuth.AccessToken
            if ($AuthObject) {
                $AuthObject.AccessToken      = $newAuth.AccessToken
                $AuthObject.RefreshToken     = $newAuth.RefreshToken
                $AuthObject.AccessExpiresAt  = $newAuth.AccessExpiresAt
                $AuthObject.RefreshExpiresAt = $newAuth.RefreshExpiresAt
            }
            Write-Host "  [TOKEN] Refreshed. New expiry: $($newAuth.AccessExpiresAt)" -ForegroundColor Green
        }
        catch {
            Write-Host ""
            Write-Host "  [FAIL] Token auto-refresh failed: $_" -ForegroundColor Red
            Write-Host "         Re-authenticate with Get-HalcyonBearerToken.ps1." -ForegroundColor Yellow
            Write-Host ""
            exit 1
        }
    }
}

$effectiveTenantId = if ($TargetTenantId) { $TargetTenantId } else { $TenantId }

$headers = @{
    "Authorization" = "Bearer $AccessToken"
    "X-TenantID"    = $effectiveTenantId
    "Content-Type"  = "application/json"
}

$baseUrl = "https://api.halcyon.ai"

Write-Host ""
Write-Host "=== Halcyon Audit Log Export ===" -ForegroundColor Cyan
Write-Host "  Tenant    : $effectiveTenantId"
Write-Host "  Window    : Last $HoursBack hours"
if ($Filter) {
    Write-Host "  Filter    : '$Filter'" -ForegroundColor Yellow
}
Write-Host ""

##############################################################################
# Step 1 -- Submit the export request
##############################################################################

$since = (Get-Date).ToUniversalTime().AddHours(-$HoursBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "  [SUBMIT] Requesting audit log export since $since..." -ForegroundColor Yellow

$body = @{
    filters = @(
        @{
            operator  = "After"
            timestamp = $since
        }
    )
    sorting = @{
        sortBy    = "Timestamp"
        sortOrder = "Desc"
    }
} | ConvertTo-Json -Depth 5

try {
    $submitResponse = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/v2/audit-logs/export" `
        -Headers $headers `
        -Body $body

    Write-Host "  [SUBMIT] Raw response:" -ForegroundColor DarkCyan
    Write-Host ($submitResponse | ConvertTo-Json -Depth 5) -ForegroundColor DarkCyan
}
catch {
    $code = $_.Exception.Response.StatusCode.value__
    Write-Host "  [FAIL] Export request failed (HTTP $code): $_" -ForegroundColor Red
    if ($code -eq 403) {
        Write-Host "         This endpoint requires Admin RBAC." -ForegroundColor Yellow
    }
    exit 1
}

$reportId = $submitResponse.reportId
if (-not $reportId) {
    Write-Host "  [FAIL] No reportId in response." -ForegroundColor Red
    exit 1
}

Write-Host "  [SUBMIT] Report ID: $reportId" -ForegroundColor Green

##############################################################################
# Step 2 -- Poll for completion
##############################################################################

Write-Host ""
Write-Host "  [POLL] Waiting for report to complete..." -ForegroundColor Yellow

$elapsed     = 0
$jobStatus   = $null
$jobResponse = $null

while ($elapsed -lt $TimeoutSeconds) {
    Start-Sleep -Seconds $PollIntervalSeconds
    $elapsed += $PollIntervalSeconds

    try {
        $jobResponse = Invoke-RestMethod -Method Get `
            -Uri "$baseUrl/v2/jobs/$reportId" `
            -Headers $headers

        $jobStatus = $jobResponse.status
        Write-Host "  [POLL] ${elapsed}s -- Status: $jobStatus" -ForegroundColor $(
            switch ($jobStatus) {
                "Completed" { "Green"  }
                "Failed"    { "Red"    }
                "Pending"   { "Yellow" }
                default     { "White"  }
            }
        )

        if ($jobStatus -in @("Completed", "Failed", "Deleted")) { break }
    }
    catch {
        Write-Host "  [POLL] Error checking job: $_" -ForegroundColor Yellow
    }
}

if ($jobStatus -ne "Completed") {
    Write-Host ""
    Write-Host "  [FAIL] Report did not complete. Final status: $jobStatus" -ForegroundColor Red
    Write-Host "  Full job response:" -ForegroundColor Yellow
    Write-Host ($jobResponse | ConvertTo-Json -Depth 5)
    exit 1
}

Write-Host ""
Write-Host "  [COMPLETE] Full job response:" -ForegroundColor Green
Write-Host ($jobResponse | ConvertTo-Json -Depth 5) -ForegroundColor DarkCyan

##############################################################################
# Step 3 -- Attempt download
# The spec does not document a download URL field on the job response.
# We inspect the response for URL-like fields and try common patterns.
##############################################################################

Write-Host ""
Write-Host "  [DOWNLOAD] Attempting to retrieve CSV..." -ForegroundColor Yellow

$csvContent  = $null
$downloadUrl = $null

# Check job response properties for any URL-like field
$possibleUrlFields = @("downloadUrl", "url", "reportUrl", "fileUrl", "link", "href", "location")
foreach ($field in $possibleUrlFields) {
    if ($jobResponse.$field) {
        $downloadUrl = $jobResponse.$field
        Write-Host "  [DOWNLOAD] Found URL in field '$field': $downloadUrl" -ForegroundColor Green
        break
    }
}

# If nothing found, try common REST patterns
if (-not $downloadUrl) {
    Write-Host "  [DOWNLOAD] No URL field found. Trying common download patterns..." -ForegroundColor Yellow

    $candidates = @(
        "$baseUrl/v2/audit-logs/export/$reportId",
        "$baseUrl/v2/audit-logs/$reportId",
        "$baseUrl/v2/jobs/$reportId/download",
        "$baseUrl/v2/jobs/$reportId/report"
    )

    foreach ($url in $candidates) {
        try {
            Write-Host "  [DOWNLOAD] Trying: $url" -ForegroundColor DarkCyan
            $resp = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                $csvContent  = $resp.Content
                $downloadUrl = $url
                Write-Host "  [DOWNLOAD] Success: $url" -ForegroundColor Green
                break
            }
        }
        catch {
            $code = $_.Exception.Response.StatusCode.value__
            Write-Host "  [DOWNLOAD] $url -- HTTP $code" -ForegroundColor DarkGray
        }
    }
}
else {
    try {
        $resp       = Invoke-WebRequest -Method Get -Uri $downloadUrl -Headers $headers
        $csvContent = $resp.Content
    }
    catch {
        Write-Host "  [FAIL] Could not download from $downloadUrl : $_" -ForegroundColor Red
    }
}

if (-not $csvContent) {
    Write-Host ""
    Write-Host "  [NOTE] Report completed (ID: $reportId) but download URL not discovered." -ForegroundColor Yellow
    Write-Host "         Review the full job response above for any URL fields." -ForegroundColor Yellow
    Write-Host "         You may need to confirm the download endpoint with Halcyon support." -ForegroundColor Yellow
    exit 0
}

##############################################################################
# Step 4 -- Parse CSV and filter
##############################################################################

Write-Host ""
Write-Host "  [PARSE] Processing CSV..." -ForegroundColor Yellow

if ($SaveCsv) {
    if (-not $CsvPath) {
        $CsvPath = "halcyon-audit-$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    $csvContent | Out-File -FilePath $CsvPath -Encoding UTF8
    Write-Host "  [SAVE] CSV saved to: $CsvPath" -ForegroundColor Green
}

$rows = $csvContent | ConvertFrom-Csv
Write-Host "  [PARSE] Total rows: $($rows.Count)"

if ($Filter) {
    $rows = $rows | Where-Object {
        ($_.PSObject.Properties.Value | Where-Object { $_ -match $Filter }).Count -gt 0
    }
    Write-Host "  [FILTER] Rows matching '$Filter': $($rows.Count)" -ForegroundColor $(
        if ($rows.Count -gt 0) { "Green" } else { "Yellow" }
    )
}

if ($rows.Count -eq 0) {
    Write-Host ""
    Write-Host "  No matching records found." -ForegroundColor Yellow
}
else {
    Write-Host ""
    Write-Host "--- Matching Audit Log Entries ---" -ForegroundColor Yellow
    Write-Host ""
    $rows | Format-Table -AutoSize
}

Write-Host ""
return $rows