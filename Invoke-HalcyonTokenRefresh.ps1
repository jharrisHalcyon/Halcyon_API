##############################################################################
# Invoke-HalcyonTokenRefresh.ps1
# Author  : Jim Harris -- Halcyon Senior SA
# Date    : 2026-02-24
# Version : v1.2
#
# Exchanges a Halcyon refresh token for a new access token and refresh token
# pair. Handles expiry checking, warning thresholds, and optional continuous
# refresh loop for long-running integrations.
#
# Background -- why this script exists:
#   The Halcyon auth response returns only two fields: accessToken and
#   refreshToken. Both are JWTs with expiry baked into the payload as 'exp'
#   claims. No top-level TTL field is returned. Current TTLs are:
#     Access token   :  5 minutes
#     Refresh token  : 15 minutes
#
#   Any SOC integration, automation, or long-running script must refresh
#   the access token before it expires. If both tokens expire, the service
#   account must re-authenticate from scratch using Get-HalcyonBearerToken.ps1.
#
# Output modes:
#
#   Default (-TokenOnly not set):
#     Returns a PSCustomObject with AccessToken, RefreshToken, TenantId,
#     AccessExpiresAt, and RefreshExpiresAt. Use this when building automation
#     that passes $auth between scripts, since subsequent refresh calls need
#     the full state -- not just the access token.
#
#     $auth = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth
#     $auth = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth   # next cycle
#
#   -TokenOnly:
#     Returns only the access token string. Console output is minimal --
#     one status line with expiry times, no banner, no token echo. Use this
#     for simple one-shot cases where you just need a fresh bearer token and
#     are not managing a refresh loop.
#
#     $token = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -TokenOnly
#     Invoke-RestMethod -Headers @{ "Authorization" = "Bearer $token" } ...
#
# Usage:
#
#   Interactive (prompts for tokens):
#     .\Invoke-HalcyonTokenRefresh.ps1
#
#   Pipeline (pass auth object from Get-HalcyonBearerToken.ps1):
#     $auth = .\Get-HalcyonBearerToken.ps1
#     $auth = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth
#
#   Token only -- simple bearer string for use in API calls:
#     $token = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -TokenOnly
#
#   Pass tokens directly:
#     .\Invoke-HalcyonTokenRefresh.ps1 -RefreshToken $rt -TenantId $tid
#
#   Continuous refresh loop (refresh every N seconds, Ctrl+C to stop):
#     $auth = .\Get-HalcyonBearerToken.ps1
#     .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -Loop -IntervalSeconds 240
#
#   Suppress all decorative output (errors and warnings still show):
#     $auth = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -silent
#
#   Recommended loop interval is slightly less than the access token TTL.
#   Default is 240 seconds (4 minutes) to give a 60-second safety margin
#   against the current 5-minute access token TTL.
#
# Requires:
#   PowerShell 5.1+
#   Valid non-expired Halcyon refresh token
#   Outbound HTTPS to api.halcyon.ai
#   ConvertFrom-HalcyonJwt.ps1 in the same directory
#
# Endpoint:
#   POST https://api.halcyon.ai/identity/auth/refresh
#
##############################################################################

#Requires -Version 5.1

param(
    # Accept a structured auth object returned by Get-HalcyonBearerToken.ps1
    # or a previous run of this script
    [PSCustomObject]$AuthObject,

    # Or pass tokens individually
    [string]$RefreshToken,
    [string]$TenantId,

    # Continuous refresh loop mode for long-running integrations
    [switch]$Loop,
    [int]$IntervalSeconds = 240,

    # Return only the access token string instead of the full auth object.
    # Console output is minimal when this flag is set -- suitable for use
    # inside larger scripts that just need a fresh bearer token.
    [switch]$TokenOnly,

    # Suppress all decorative console output. Errors and warnings are always
    # shown regardless. When combined with -TokenOnly, nothing is written to
    # the console at all on success.
    [switch]$silent,

    # Warn if access token has less than this many seconds remaining
    [int]$WarnThresholdSeconds = 60
)

$ErrorActionPreference = "Stop"

# Dot-source the shared JWT helper from the same directory as this script
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

##############################################################################
# Resolve inputs -- AuthObject takes priority over individual parameters
##############################################################################

if ($AuthObject) {
    if (-not $RefreshToken) { $RefreshToken = $AuthObject.RefreshToken }
    if (-not $TenantId)     { $TenantId     = $AuthObject.TenantId     }
}

# Fall back to interactive prompts if still missing
if (-not $TenantId) {
    $TenantId = Read-Host "Enter Tenant ID"
}
if (-not $RefreshToken) {
    $RefreshToken = Read-Host "Enter Refresh Token"
}

if (-not $TenantId -or -not $RefreshToken) {
    Write-Host "[FAIL] Tenant ID and Refresh Token are both required." -ForegroundColor Red
    exit 1
}

##############################################################################
# Core refresh function -- called once per cycle
##############################################################################

function Invoke-SingleRefresh {
    param(
        [string]$CurrentRefreshToken,
        [string]$CurrentTenantId
    )

    # Check the refresh token before attempting the call
    try {
        $refreshInfo = Get-HalcyonTokenExpiry -Token $CurrentRefreshToken -Label "Refresh Token"

        if ($refreshInfo.IsExpired) {
            Write-Host ""
            Write-Host "[FAIL] Refresh token has expired. You must re-authenticate." -ForegroundColor Red
            Write-Host "       Run Get-HalcyonBearerToken.ps1 to obtain a new token pair." -ForegroundColor Yellow
            return $null
        }

        if ($refreshInfo.SecondsRemaining -lt $WarnThresholdSeconds) {
            Write-Host "[WARN] Refresh token expires in $($refreshInfo.SecondsRemaining) seconds -- acting now." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[WARN] Could not decode refresh token for pre-check: $_" -ForegroundColor Yellow
        Write-Host "       Attempting refresh anyway..." -ForegroundColor Yellow
    }

    # POST to the refresh endpoint
    $Headers = @{
        "Content-Type" = "application/json"
        "X-TenantID"   = $CurrentTenantId
    }

    $Body = @{
        refreshToken = $CurrentRefreshToken
    } | ConvertTo-Json

    try {
        $Response = Invoke-RestMethod -Method Post `
            -Uri "https://api.halcyon.ai/identity/auth/refresh" `
            -Headers $Headers `
            -Body $Body
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 401 -or $statusCode -eq 403) {
            Write-Host ""
            Write-Host "[FAIL] Refresh token rejected (HTTP $statusCode)." -ForegroundColor Red
            Write-Host "       The token may have expired or been invalidated." -ForegroundColor Yellow
            Write-Host "       Run Get-HalcyonBearerToken.ps1 to obtain a new token pair." -ForegroundColor Yellow
        }
        else {
            Write-Host "[FAIL] Refresh request failed: $_" -ForegroundColor Red
        }
        return $null
    }
    finally {
        Remove-Variable Body -ErrorAction SilentlyContinue
    }

    if (-not $Response.accessToken) {
        Write-Host "[FAIL] No access token in refresh response. Check your refresh token and Tenant ID." -ForegroundColor Red
        return $null
    }

    # Decode the new tokens
    $newAccessInfo  = Get-HalcyonTokenExpiry -Token $Response.accessToken  -Label "Access Token"
    $newRefreshInfo = Get-HalcyonTokenExpiry -Token $Response.refreshToken -Label "Refresh Token"

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if (-not $silent) {
        if ($TokenOnly) {
            # Minimal output -- one status line, no banner, no token echo
            Write-Host "[$timestamp] Refreshed -- Access expires: $($newAccessInfo.ExpiresAt)  |  Refresh expires: $($newRefreshInfo.ExpiresAt)" -ForegroundColor $(if ($newAccessInfo.SecondsRemaining -lt $WarnThresholdSeconds) { 'Yellow' } else { 'Green' })
        }
        else {
            Write-Host ""
            Write-Host "[$timestamp] Token refresh successful" -ForegroundColor Green
            Write-Host "  Access Token  -- Expires: $($newAccessInfo.ExpiresAt)  |  TTL: $($newAccessInfo.TtlSeconds)s  |  Remaining: $($newAccessInfo.SecondsRemaining)s" -ForegroundColor $(if ($newAccessInfo.SecondsRemaining -lt $WarnThresholdSeconds) { 'Yellow' } else { 'Green' })
            Write-Host "  Refresh Token -- Expires: $($newRefreshInfo.ExpiresAt)  |  TTL: $($newRefreshInfo.TtlSeconds)s  |  Remaining: $($newRefreshInfo.SecondsRemaining)s" -ForegroundColor $(if ($newRefreshInfo.SecondsRemaining -lt $WarnThresholdSeconds) { 'Yellow' } else { 'Cyan' })
        }
    }

    return [PSCustomObject]@{
        AccessToken        = $Response.accessToken
        RefreshToken       = $Response.refreshToken
        TenantId           = $CurrentTenantId
        AccessExpiresAt    = $newAccessInfo.ExpiresAt
        RefreshExpiresAt   = $newRefreshInfo.ExpiresAt
    }
}

##############################################################################
# Single refresh or loop mode
##############################################################################

if (-not $Loop) {

    if (-not $silent -and -not $TokenOnly) {
        Write-Host ""
        Write-Host "=== Halcyon Token Refresh ===" -ForegroundColor Cyan
    }

    $result = Invoke-SingleRefresh -CurrentRefreshToken $RefreshToken -CurrentTenantId $TenantId

    if (-not $result) {
        exit 1
    }

    if ($TokenOnly) {
        return $result.AccessToken
    }
    else {
        if (-not $silent) {
            Write-Host ""
            Write-Host "Bearer Token:" -ForegroundColor Yellow
            Write-Host $result.AccessToken -ForegroundColor White
            Write-Host ""
        }
        return $result
    }

}
else {

    if (-not $silent) {
        Write-Host ""
        Write-Host "=== Halcyon Token Refresh -- Loop Mode ===" -ForegroundColor Cyan
        Write-Host "Refresh interval : $IntervalSeconds seconds"
        Write-Host "Press Ctrl+C to stop."
        Write-Host ""
    }

    $currentRefreshToken = $RefreshToken
    $currentTenantId     = $TenantId

    while ($true) {
        $result = Invoke-SingleRefresh `
            -CurrentRefreshToken $currentRefreshToken `
            -CurrentTenantId     $currentTenantId

        if (-not $result) {
            Write-Host ""
            Write-Host "Loop stopped -- re-authentication required." -ForegroundColor Red
            exit 1
        }

        $currentRefreshToken = $result.RefreshToken

        if ($TokenOnly) {
            $result.AccessToken
        }
        else {
            $result
        }

        if (-not $silent) {
            Write-Host "  Next refresh in $IntervalSeconds seconds..." -ForegroundColor DarkCyan
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}