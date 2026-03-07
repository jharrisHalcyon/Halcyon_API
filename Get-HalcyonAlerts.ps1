##############################################################################
# Get-HalcyonAlerts.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-02-26
# Version : v1.3
#
# Retrieves alerts from the Halcyon API with rich filtering, automatic
# pagination, and flexible output options. Designed for SIEM ingestion
# pipelines, POV closeout reporting, and interactive investigation.
#
# Output formats:
#   JSON (default) -- full fidelity, SIEM-ready (Splunk, Elastic, Sentinel)
#   CSV            -- flattened, Excel-friendly
#
# Pagination:
#   By default, retrieves one page (up to 100 results). Use -AllPages to
#   walk all pages automatically. For large tenants, combine -AllPages with
#   date filters to keep result sets manageable.
#
# Filters available:
#   -Type            : BadBehavior | BruteForceAttempt | Dxp |
#                      MaliciousExecutable | VulnerableDriver
#   -Action          : Block | Report
#   -TriageStatus    : New | Reviewed
#   -DisplayStatus   : Hidden | Visible
#   -FirstSeenAfter  / -FirstSeenBefore
#   -LastSeenAfter   / -LastSeenBefore
#   -OffendingSha256 : partial SHA256 prefix match (1-64 hex chars)
#   -AlertId         : one or more specific alert IDs
#
# Usage:
#
#   All alerts, last 24 hours, JSON to console:
#     .\Get-HalcyonAlerts.ps1 -AuthObject $auth -LastSeenAfter (Get-Date).AddDays(-1)
#
#   All pages, save to JSON file:
#     .\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -OutFile "alerts.json"
#
#   POV closeout -- blocked actions only, all pages, since POV start:
#     .\Get-HalcyonAlerts.ps1 -AuthObject $auth -Action Block `
#         -FirstSeenAfter "2026-02-10" -AllPages -OutFile "pov_blocked_alerts.json"
#
#   Hunt a specific hash:
#     .\Get-HalcyonAlerts.ps1 -AuthObject $auth -OffendingSha256 "d3f1164e" -AllPages
#
#   Export as CSV for Excel:
#     .\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -Format CSV `
#         -OutFile "alerts.csv"
#
#   SIEM pipeline (returns PSCustomObject array for further processing):
#     $alerts = .\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -silent
#     $alerts | Where-Object { $_.action -eq "Block" }
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: ReadOnly or higher
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
# Endpoint:
#   GET https://api.halcyon.ai/v2/alerts
#
##############################################################################

#Requires -Version 5.1

param(
    # Auth -- pass the object returned by Get-HalcyonBearerToken.ps1
    # or Invoke-HalcyonTokenRefresh.ps1
    [PSCustomObject]$AuthObject,

    # Or supply tokens directly
    [string]$AccessToken,
    [string]$TenantId,

    # --- Filters ---

    # Alert type filter
    [ValidateSet("BadBehavior", "BruteForceAttempt", "Dxp", "MaliciousExecutable", "VulnerableDriver")]
    [string]$Type,

    # Action filter
    [ValidateSet("Block", "Report")]
    [string]$Action,

    # Triage status filter
    [ValidateSet("New", "Reviewed")]
    [string]$TriageStatus,

    # Display status filter
    [ValidateSet("Hidden", "Visible")]
    [string]$DisplayStatus,

    # Date range filters -- accept strings or DateTime objects
    [datetime]$FirstSeenAfter,
    [datetime]$FirstSeenBefore,
    [datetime]$LastSeenAfter,
    [datetime]$LastSeenBefore,

    # SHA256 prefix filter (1-64 hex chars, partial match supported)
    [ValidatePattern('^\b[A-Fa-f0-9]{1,64}\b$')]
    [string[]]$OffendingSha256,

    # One or more specific alert IDs (64-char hex)
    [ValidatePattern('^\b[A-Fa-f0-9]{64}\b$')]
    [string[]]$AlertId,

    # --- Pagination ---

    # Page to start on (default: 1)
    [int]$Page = 1,

    # Results per page -- API accepts 10, 30, 50, 100
    [ValidateSet(10, 30, 50, 100)]
    [int]$PageSize = 100,

    # Walk all pages automatically and return the full result set
    [switch]$AllPages,

    # --- Sort ---
    [ValidateSet("Action", "AlertId", "AssetCount", "Count", "FirstSeen", "Kind", "LastSeen", "OffendingSha256")]
    [string]$SortBy = "LastSeen",

    [ValidateSet("Asc", "Desc")]
    [string]$SortOrder = "Desc",

    # --- Output ---

    # Output format: JSON (default) or CSV
    [ValidateSet("JSON", "CSV")]
    [string]$Format = "JSON",

    # Write output to a file. If not specified, results are written to the
    # pipeline as PSCustomObject array and summary to console.
    [string]$OutFile,

    # Suppress decorative console output. Errors and warnings always show.
    [switch]$silent
)

$ErrorActionPreference = "Stop"
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12'
}

# Dot-source the shared JWT helper for token expiry checks
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

##############################################################################
# Resolve auth
##############################################################################

if ($AuthObject) {
    if (-not $AccessToken) { $AccessToken = $AuthObject.AccessToken }
    if (-not $TenantId)    { $TenantId    = $AuthObject.TenantId    }
}

if (-not $AccessToken) {
    Write-Error "AccessToken is required. Pass -AuthObject from Get-HalcyonBearerToken.ps1 or supply -AccessToken directly."
}
if (-not $TenantId) {
    Write-Error "TenantId is required. Pass -AuthObject from Get-HalcyonBearerToken.ps1 or supply -TenantId directly."
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

$headers = @{
    "Authorization" = "Bearer $AccessToken"
    "X-TenantID"    = $TenantId
}

##############################################################################
# Build query string helper
##############################################################################

function Build-AlertQuery {
    param([int]$PageNum)

    $query = [System.Web.HttpUtility]::ParseQueryString("")
    $query["page"]     = $PageNum
    $query["pageSize"] = $PageSize
    $query["sortBy"]   = $SortBy
    $query["sortOrder"] = $SortOrder

    if ($Type)          { $query["type"]          = $Type          }
    if ($Action)        { $query["action"]         = $Action        }
    if ($TriageStatus)  { $query["triageStatus"]   = $TriageStatus  }
    if ($DisplayStatus) { $query["displayStatus"]  = $DisplayStatus }

    if ($FirstSeenAfter)  { $query["firstSeenAfter"]  = $FirstSeenAfter.ToUniversalTime().ToString("o")  }
    if ($FirstSeenBefore) { $query["firstSeenBefore"] = $FirstSeenBefore.ToUniversalTime().ToString("o") }
    if ($LastSeenAfter)   { $query["lastSeenAfter"]   = $LastSeenAfter.ToUniversalTime().ToString("o")   }
    if ($LastSeenBefore)  { $query["lastSeenBefore"]  = $LastSeenBefore.ToUniversalTime().ToString("o")  }

    # Array parameters -- append each value separately
    foreach ($id in $AlertId)        { $query.Add("alertId",        $id) }
    foreach ($sha in $OffendingSha256) { $query.Add("offendingSha256", $sha) }

    $uriBuilder = New-Object System.UriBuilder("https://api.halcyon.ai/v2/alerts")
    $uriBuilder.Query = $query.ToString()
    return $uriBuilder.Uri.AbsoluteUri
}

##############################################################################
# Fetch pages
##############################################################################

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Halcyon Alert Retrieval ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tenant ID    : $TenantId"
    Write-Host "  Format       : $Format"
    if ($Type)          { Write-Host "  Type Filter  : $Type" }
    if ($Action)        { Write-Host "  Action       : $Action" }
    if ($TriageStatus)  { Write-Host "  Triage       : $TriageStatus" }
    if ($DisplayStatus) { Write-Host "  Display      : $DisplayStatus" }
    if ($LastSeenAfter)   { Write-Host "  Last Seen After  : $LastSeenAfter" }
    if ($LastSeenBefore)  { Write-Host "  Last Seen Before : $LastSeenBefore" }
    if ($FirstSeenAfter)  { Write-Host "  First Seen After  : $FirstSeenAfter" }
    if ($FirstSeenBefore) { Write-Host "  First Seen Before : $FirstSeenBefore" }
    if ($OffendingSha256) { Write-Host "  SHA256 Prefix : $($OffendingSha256 -join ', ')" }
    if ($AllPages)      { Write-Host "  Pagination   : All pages (pageSize=$PageSize)" }
    else                { Write-Host "  Pagination   : Page $Page (pageSize=$PageSize)" }
    Write-Host ""
}

$allAlerts   = [System.Collections.Generic.List[object]]::new()
$currentPage = $Page
$totalPages  = 1

do {
    $uri = Build-AlertQuery -PageNum $currentPage

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            401 { Write-Error "Unauthorized (401) -- Your access token may have expired. Run Invoke-HalcyonTokenRefresh.ps1." }
            403 { Write-Error "Forbidden (403) -- ReadOnly RBAC role or higher is required." }
            default { Write-Error "Request failed (HTTP $statusCode): $_" }
        }
    }

    # Determine total page count from first response
    if ($currentPage -eq $Page -and $response.pagination.totalPages) {
        $totalPages = $response.pagination.totalPages
        if (-not $silent) {
            Write-Host "  Total alerts : $($response.pagination.totalItems)" -ForegroundColor White
            Write-Host "  Total pages  : $totalPages (fetching $(if ($AllPages) { 'all' } else { 'page 1 only' }))" -ForegroundColor White
            Write-Host ""
        }
    }

    if ($response.items) {
        $allAlerts.AddRange($response.items)
    }

    if (-not $silent -and $AllPages -and $totalPages -gt 1) {
        Write-Host "  Fetched page $currentPage / $totalPages ($($allAlerts.Count) alerts so far)..." -ForegroundColor DarkCyan
    }

    $currentPage++

} while ($AllPages -and $currentPage -le $totalPages)

if (-not $silent) {
    Write-Host ""
    Write-Host "  Retrieved $($allAlerts.Count) alert(s)." -ForegroundColor Green
    Write-Host ""
}

##############################################################################
# Format and output
##############################################################################

if ($Format -eq "JSON") {

    $json = $allAlerts | ConvertTo-Json -Depth 10

    if ($OutFile) {
        $json | Out-File -FilePath $OutFile -Encoding UTF8
        if (-not $silent) {
            Write-Host "  Saved to : $OutFile" -ForegroundColor Green
        }
    }
    else {
        Write-Output $json
    }

}
elseif ($Format -eq "CSV") {

    # Flatten top-level fields for CSV -- nested objects are serialized as strings
    # SHA256 lives at summary.artifact.sha256 (not a top-level field)
    $flat = $allAlerts | ForEach-Object {
        $alert = $_
        [PSCustomObject]@{
            id               = $alert.id
            kind             = $alert.kind
            alertType        = $alert.alertType
            action           = $alert.action
            displayStatus    = $alert.displayStatus
            triageStatus     = $alert.triageStatus
            firstOccurredAt  = $alert.firstOccurredAt
            lastOccurredAt   = $alert.lastOccurredAt
            totalOccurrences = $alert.totalOccurrences
            assetCount       = $alert.assetCount
            tenantId         = $alert.tenantId
            sha256           = $alert.summary.artifact.sha256
        }
    }

    if ($OutFile) {
        $flat | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
        if (-not $silent) {
            Write-Host "  Saved to : $OutFile" -ForegroundColor Green
        }
    }
    else {
        $flat | ConvertTo-Csv -NoTypeInformation
    }
}

##############################################################################
# Return PSCustomObject array to pipeline for further processing
##############################################################################

return $allAlerts.ToArray()
