##############################################################################
# Remove-HalcyonOverride.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-02-24
# Version : v1.1
#
# Deletes a Halcyon override by its numeric override ID.
#
# The override ID is returned in the response when you create an override
# using New-HalcyonOverride.ps1 -- capture it from the pipeline:
#
#   $result = .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate ...
#   $result.id   # <-- this is the ID you need to delete it
#
# You can also find override IDs by listing overrides in the console or by
# running Get-HalcyonOverrides.ps1 (when available).
#
# Usage:
#
#   Delete by ID:
#     .\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId 1234
#
#   Full add/remove test cycle:
#     $auth   = .\Get-HalcyonBearerToken.ps1
#     $result = .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
#                   -Thumbprint "971382847ad8b5978070c4fc248efae266d87a1b"
#     .\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId $result.id
#
#   Preview without deleting (-WhatIf):
#     .\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId 1234 -WhatIf
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: Admin
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
# Endpoint:
#   DELETE https://api.halcyon.ai/v2/overrides/{overrideId}
#
##############################################################################

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    # Auth -- pass the object returned by Get-HalcyonBearerToken.ps1
    # or Invoke-HalcyonTokenRefresh.ps1
    [PSCustomObject]$AuthObject,

    # Or supply tokens directly
    [string]$AccessToken,
    [string]$TenantId,

    # Numeric override ID returned by New-HalcyonOverride.ps1 or the console
    [Parameter(Mandatory)]
    [int]$OverrideId
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

##############################################################################
# Preview and confirm
##############################################################################

Write-Host ""
Write-Host "=== Remove Halcyon Override ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Override ID  : $OverrideId"
Write-Host "  Tenant ID    : $TenantId"
Write-Host ""

if ($PSCmdlet.ShouldProcess("DELETE /v2/overrides/$OverrideId", "Delete override $OverrideId")) {

    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $AccessToken"
        "X-TenantID"    = $TenantId
    }

    try {
        $response = Invoke-RestMethod -Method Delete `
            -Uri "https://api.halcyon.ai/v2/overrides/$OverrideId" `
            -Headers $headers
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            401 { Write-Error "Unauthorized (401) -- Your access token may have expired. Run Invoke-HalcyonTokenRefresh.ps1." }
            403 { Write-Error "Forbidden (403) -- Your account requires Admin RBAC role to delete overrides." }
            404 { Write-Error "Not Found (404) -- Override ID $OverrideId does not exist or has already been deleted." }
            default { Write-Error "Request failed (HTTP $statusCode): $_" }
        }
    }

    Write-Host "Override $OverrideId deleted successfully." -ForegroundColor Green
    Write-Host ""

    return $response
}