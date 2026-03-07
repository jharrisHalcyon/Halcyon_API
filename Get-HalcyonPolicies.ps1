##############################################################################
# Get-HalcyonPolicies.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-03-05
# Version : v1.0
#
# Retrieves policies from the Halcyon tenant.
#
# The list endpoint returns summaries only (name, ID, owner, isDefault).
# Use -Id to get a single policy with full settings, or -IncludeSettings to
# fetch full settings for every returned policy (one extra API call per policy).
#
# Terminology used in this toolkit:
#   "policy"          = what the API calls a "policy group"
#   "policy settings" = the 7 individual protection knobs inside a policy
#
# Usage:
#
#   List all policies:
#     .\Get-HalcyonPolicies.ps1 -AuthObject $auth
#
#   Get full settings for a specific policy by ID:
#     .\Get-HalcyonPolicies.ps1 -AuthObject $auth -Id "uuid"
#
#   List all policies with full settings:
#     .\Get-HalcyonPolicies.ps1 -AuthObject $auth -IncludeSettings
#
#   Filter by name (contains match):
#     .\Get-HalcyonPolicies.ps1 -AuthObject $auth -Name "Strict"
#
#   Walk all pages:
#     .\Get-HalcyonPolicies.ps1 -AuthObject $auth -AllPages
#
#   Save to JSON:
#     .\Get-HalcyonPolicies.ps1 -AuthObject $auth -IncludeSettings -OutFile "policies.json"
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: ReadOnly or higher
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
# Endpoints:
#   GET https://api.halcyon.ai/v2/policy-groups
#   GET https://api.halcyon.ai/v2/policy-groups/{id}
#
##############################################################################

#Requires -Version 5.1

param(
    [PSCustomObject]$AuthObject,
    [string]$AccessToken,
    [string]$TenantId,

    # Retrieve a single policy by UUID -- returns full settings
    [string]$Id,

    # Client-side name filter (case-insensitive contains match)
    [string]$Name,

    # Walk all pages of the list endpoint
    [switch]$AllPages,

    # Fetch full settings for every returned policy (one extra API call per policy)
    [switch]$IncludeSettings,

    [string]$OutFile,
    [switch]$silent
)

$ErrorActionPreference = "Stop"
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12'
}
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

##############################################################################
# Resolve auth
##############################################################################

if ($AuthObject) {
    if (-not $AccessToken) { $AccessToken = $AuthObject.AccessToken }
    if (-not $TenantId)    { $TenantId    = $AuthObject.TenantId    }
}
if (-not $AccessToken) { Write-Error "AccessToken is required. Pass -AuthObject from Get-HalcyonBearerToken.ps1 or supply -AccessToken directly." }
if (-not $TenantId)    { Write-Error "TenantId is required. Pass -AuthObject from Get-HalcyonBearerToken.ps1 or supply -TenantId directly." }

##############################################################################
# Token expiry check -- auto-refresh if access token is within 60 seconds of
# expiry or already expired. Requires RefreshToken on the AuthObject.
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
            Write-Host ""; Write-Host "  [FAIL] Both access and refresh tokens are expired." -ForegroundColor Red
            Write-Host "         Re-authenticate with Get-HalcyonBearerToken.ps1." -ForegroundColor Yellow; Write-Host ""; exit 1
        }
        if ($accessInfo.IsExpired) { Write-Host "  [TOKEN] Access token expired -- refreshing..." -ForegroundColor Yellow }
        else { Write-Host "  [TOKEN] Access token expires in $($accessInfo.SecondsRemaining)s -- refreshing proactively..." -ForegroundColor DarkCyan }
        try {
            $newAuth = & (Join-Path $PSScriptRoot "Invoke-HalcyonTokenRefresh.ps1") -RefreshToken $refreshToken -TenantId $TenantId -silent
            $AccessToken = $newAuth.AccessToken
            if ($AuthObject) {
                $AuthObject.AccessToken = $newAuth.AccessToken; $AuthObject.RefreshToken = $newAuth.RefreshToken
                $AuthObject.AccessExpiresAt = $newAuth.AccessExpiresAt; $AuthObject.RefreshExpiresAt = $newAuth.RefreshExpiresAt
            }
            Write-Host "  [TOKEN] Refreshed. New expiry: $($newAuth.AccessExpiresAt)" -ForegroundColor Green
        }
        catch {
            Write-Host ""; Write-Host "  [FAIL] Token auto-refresh failed: $_" -ForegroundColor Red
            Write-Host "         Re-authenticate with Get-HalcyonBearerToken.ps1." -ForegroundColor Yellow; Write-Host ""; exit 1
        }
    }
}

$headers = @{ "Authorization" = "Bearer $AccessToken"; "X-TenantID" = $TenantId }

##############################################################################
# Helpers
##############################################################################

$settingNames = [ordered]@{
    executionGuard                       = "Execution Prevention"
    tamperGuard                          = "Tamper Guard"
    dataExfiltrationVolumetricProtection = "Data Exfil - Volumetric"
    dataExfiltrationNefariousPeer        = "Data Exfil - Nefarious Peer"
    halcyonLastGasp                      = "Halcyon Last Gasp"
    sidekick                             = "Sidekick"
    kernelGuard                          = "Kernel Guard"
}

function Get-StateColor ([string]$State) {
    switch ($State) { "Prevention" { "Green" } "Detection" { "Cyan" } "Disabled" { "DarkGray" } default { "White" } }
}

function Show-PolicyDetail ($p) {
    Write-Host ""
    Write-Host "  Policy      : $($p.name)" -ForegroundColor Cyan
    Write-Host "  ID          : $($p.id)"
    Write-Host "  Owner       : $(if ($p.owner) { $p.owner } else { '' })"
    Write-Host "  Default     : $(if ($p.isDefault) { 'Yes' } else { 'No' })"
    if ($p.description) { Write-Host "  Description : $($p.description)" }
    if ($p.policies) {
        Write-Host ""
        Write-Host ("  {0}  {1}" -f "Setting".PadRight(36), "State") -ForegroundColor Yellow
        Write-Host ("  {0}  {1}" -f ("-" * 36), ("-" * 10)) -ForegroundColor DarkGray
        foreach ($key in $settingNames.Keys) {
            $setting = $p.policies.$key
            $state   = $setting.state
            $extra   = ""
            if ($key -eq "dataExfiltrationVolumetricProtection" -and $setting.settings.uploadNetworkThresholdInBytes) {
                $extra = "  (threshold: $([math]::Round($setting.settings.uploadNetworkThresholdInBytes / 1GB, 1)) GB)"
            }
            Write-Host ("  {0}  {1}{2}" -f $settingNames[$key].PadRight(36), $state, $extra) -ForegroundColor (Get-StateColor $state)
        }
    }
    else {
        Write-Host "  (no settings -- use -IncludeSettings or -Id to retrieve them)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

##############################################################################
# Single policy by ID
##############################################################################

if ($Id) {
    if (-not $silent) { Write-Host ""; Write-Host "=== Halcyon Policy ===" -ForegroundColor Cyan; Write-Host "  Tenant ID : $TenantId" }
    try {
        $policy = Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/policy-groups/$Id" -Headers $headers
    }
    catch {
        $sc = $_.Exception.Response.StatusCode.value__
        switch ($sc) {
            401 { Write-Error "Unauthorized (401) -- Access token may have expired." }
            403 { Write-Error "Forbidden (403) -- ReadOnly RBAC role or higher is required." }
            404 { Write-Error "Not Found (404) -- Policy ID not found: $Id" }
            default { Write-Error "Request failed (HTTP $sc): $_" }
        }
    }
    if (-not $silent) { Show-PolicyDetail $policy }
    if ($OutFile) { $policy | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutFile -Encoding UTF8; if (-not $silent) { Write-Host "  Saved to : $OutFile" -ForegroundColor Green } }
    return $policy
}

##############################################################################
# List policies
##############################################################################

if (-not $silent) {
    Write-Host ""; Write-Host "=== Halcyon Policies ===" -ForegroundColor Cyan; Write-Host ""
    Write-Host "  Tenant ID   : $TenantId"
    if ($Name)            { Write-Host "  Name Filter : $Name" }
    if ($IncludeSettings) { Write-Host "  Settings    : Fetching full detail per policy" -ForegroundColor DarkCyan }
    if ($AllPages)        { Write-Host "  Pagination  : All pages" } else { Write-Host "  Pagination  : Page 1 only (use -AllPages for all)" }
    Write-Host ""
}

$allPolicies = [System.Collections.Generic.List[object]]::new()
$currentPage = 1
$totalPages  = 1

do {
    try {
        $response = Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/policy-groups?page=$currentPage&pageSize=100" -Headers $headers
    }
    catch {
        $sc = $_.Exception.Response.StatusCode.value__
        switch ($sc) {
            401 { Write-Error "Unauthorized (401) -- Access token may have expired." }
            403 { Write-Error "Forbidden (403) -- ReadOnly RBAC role or higher is required." }
            default { Write-Error "Request failed (HTTP $sc): $_" }
        }
    }
    if ($currentPage -eq 1 -and $response.pagination.totalPages) { $totalPages = $response.pagination.totalPages }
    if ($response.items) { $allPolicies.AddRange($response.items) }
    $currentPage++
} while ($AllPages -and $currentPage -le $totalPages)

if ($Name) {
    $allPolicies = [System.Collections.Generic.List[object]]($allPolicies | Where-Object { $_.name -like "*$Name*" })
}

if ($IncludeSettings) {
    $detailed = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $allPolicies) {
        try {
            $detailed.Add((Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/policy-groups/$($p.id)" -Headers $headers))
        }
        catch {
            Write-Host "  [WARN] Could not fetch settings for '$($p.name)': $_" -ForegroundColor Yellow
            $detailed.Add($p)
        }
    }
    $allPolicies = $detailed
}

if (-not $silent) {
    if ($IncludeSettings) {
        foreach ($p in $allPolicies) { Show-PolicyDetail $p }
    }
    else {
        Write-Host ("  {0}  {1}  {2}  {3}" -f "Name".PadRight(35), "Owner".PadRight(8), "Default".PadRight(7), "ID") -ForegroundColor Yellow
        Write-Host ("  {0}  {1}  {2}  {3}" -f ("-" * 35), ("-" * 8), ("-" * 7), ("-" * 36)) -ForegroundColor DarkGray
        foreach ($p in $allPolicies) {
            $color = if ($p.owner -eq "System") { "DarkCyan" } else { "White" }
            Write-Host ("  {0}  {1}  {2}  {3}" -f $p.name.PadRight(35), "$($p.owner)".PadRight(8), "$(if ($p.isDefault) { 'Yes' } else { 'No' })".PadRight(7), $p.id) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host "  Retrieved $($allPolicies.Count) policy(ies)." -ForegroundColor Green
        Write-Host "  Use -IncludeSettings to display full settings, or -Id <uuid> for a single policy." -ForegroundColor DarkGray
    }
    Write-Host ""
}

if ($OutFile) {
    $allPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutFile -Encoding UTF8
    if (-not $silent) { Write-Host "  Saved to : $OutFile" -ForegroundColor Green; Write-Host "" }
}

return $allPolicies.ToArray()
