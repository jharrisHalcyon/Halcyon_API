##############################################################################
# Get-HalcyonWhoAmI.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-02-25
# Version : v1.1
#
# Diagnostic script. Calls three identity endpoints to display the current
# user's profile, effective role, and full role list for the authenticated
# tenant. Useful for confirming RBAC level before attempting operations that
# require elevated permissions.
#
# RBAC levels (lowest to highest):
#   ReadOnly    -- read-only access to most resources
#   User        -- basic operational access
#   PowerUser   -- create overrides, manage tags, generate install tokens
#   Admin       -- delete overrides, manage policy groups, export audit logs
#   TenantAdmin -- create and delete tenants
#
# Endpoints called:
#   GET /identity/user                  -- profile (email, name)
#   GET /identity/user/effective-role   -- effective role in current tenant
#   GET /identity/user/roles            -- all roles across all tenants
#
# Usage:
#   $auth = .\Get-HalcyonBearerToken.ps1
#   .\Get-HalcyonWhoAmI.ps1 -AuthObject $auth
#
#   Or pass tokens directly:
#   .\Get-HalcyonWhoAmI.ps1 -AccessToken $token -TenantId $tid
#
##############################################################################

#Requires -Version 5.1

param(
    [PSCustomObject]$AuthObject,
    [string]$AccessToken,
    [string]$TenantId
)

$ErrorActionPreference = "Stop"

# Dot-source the shared JWT helper for token expiry checks
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

# Resolve auth
if ($AuthObject) {
    if (-not $AccessToken) { $AccessToken = $AuthObject.AccessToken }
    if (-not $TenantId)    { $TenantId    = $AuthObject.TenantId    }
}
if (-not $AccessToken -or -not $TenantId) {
    Write-Host ""
    Write-Host "  [FAIL] Auth required. Pass -AuthObject from Get-HalcyonBearerToken.ps1." -ForegroundColor Red
    Write-Host ""
    exit 1
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
        # No refresh token available -- warn if expired, continue either way
        if ($accessInfo.IsExpired) {
            Write-Warning "Access token is expired and no RefreshToken is available. The API call will likely fail with 401. Re-authenticate with Get-HalcyonBearerToken.ps1."
        } else {
            Write-Warning "Access token expires in $($accessInfo.SecondsRemaining) seconds. No RefreshToken available to auto-refresh -- pass -AuthObject to enable auto-refresh."
        }
    }
    else {
        # Check refresh token before attempting
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

            # Update local variable used to build headers
            $AccessToken = $newAuth.AccessToken

            # Update AuthObject in place so the caller's $auth reflects the new tokens
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
    "Content-Type"  = "application/json"
}

$baseUrl = "https://api.halcyon.ai"

function Invoke-HalcyonGet {
    param([string]$Path, [string]$Label)
    try {
        return Invoke-RestMethod -Method Get -Uri "$baseUrl$Path" -Headers $headers
    }
    catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  [FAIL] $Label (HTTP $code): $_" -ForegroundColor Red
        return $null
    }
}

Write-Host ""
Write-Host "=== Halcyon Identity Check ===" -ForegroundColor Cyan
Write-Host "  Tenant : $TenantId"
Write-Host ""

##############################################################################
# 1. User profile
##############################################################################

Write-Host "--- User Profile ---" -ForegroundColor Yellow
$user = Invoke-HalcyonGet -Path "/identity/user" -Label "Get Current User"

if ($user) {
    Write-Host "  ID         : $($user.id)"
    Write-Host "  Email      : $($user.email)"
    Write-Host "  Name       : $($user.firstName) $($user.lastName)".Trim()
    Write-Host "  Role       : $($user.role)" -ForegroundColor $(
        switch ($user.role) {
            "TenantAdmin" { "Magenta" }
            "Admin"       { "Green"   }
            "PowerUser"   { "Cyan"    }
            "User"        { "White"   }
            "ReadOnly"    { "DarkCyan"}
            default       { "White"   }
        }
    )
}

##############################################################################
# 2. Effective role in this tenant
##############################################################################

Write-Host ""
Write-Host "--- Effective Role (this tenant) ---" -ForegroundColor Yellow
$effective = Invoke-HalcyonGet -Path "/identity/user/effective-role" -Label "Get Effective Role"

if ($effective) {
    Write-Host "  Group        : $($effective.group)"
    Write-Host "  Access Level : $($effective.accessLevel)" -ForegroundColor $(
        switch ($effective.accessLevel) {
            "TenantAdmin" { "Magenta" }
            "Admin"       { "Green"   }
            "PowerUser"   { "Cyan"    }
            "User"        { "White"   }
            "ReadOnly"    { "DarkCyan"}
            default       { "White"   }
        }
    )
}

##############################################################################
# 3. All roles
##############################################################################

Write-Host ""
Write-Host "--- All Assigned Roles ---" -ForegroundColor Yellow
$roles = Invoke-HalcyonGet -Path "/identity/user/roles" -Label "Get All Roles"

if ($roles -and $roles.Count -gt 0) {
    foreach ($r in $roles) {
        $color = switch ($r.accessLevel) {
            "TenantAdmin" { "Magenta" }
            "Admin"       { "Green"   }
            "PowerUser"   { "Cyan"    }
            "User"        { "White"   }
            "ReadOnly"    { "DarkCyan"}
            default       { "White"   }
        }
        Write-Host ("  {0,-40} {1}" -f $r.group, $r.accessLevel) -ForegroundColor $color
    }
}
elseif ($roles) {
    Write-Host "  No roles returned." -ForegroundColor Yellow
}

##############################################################################
# Summary -- what this RBAC level can do
##############################################################################

$level = if ($effective) { $effective.accessLevel } elseif ($user) { $user.role } else { $null }

if ($level) {
    Write-Host ""
    Write-Host "--- Capability Summary ---" -ForegroundColor Yellow

    $caps = [ordered]@{
        "Read alerts, events, assets, overrides"  = $true
        "Create overrides"                        = $level -in @("PowerUser","Admin","TenantAdmin")
        "Manage tags"                             = $level -in @("User","PowerUser","Admin","TenantAdmin")
        "Generate install tokens"                 = $level -in @("PowerUser","Admin","TenantAdmin")
        "Delete overrides"                        = $level -in @("Admin","TenantAdmin")
        "Manage policy groups"                    = $level -in @("Admin","TenantAdmin")
        "Export audit logs"                       = $level -in @("Admin","TenantAdmin")
        "Create / delete tenants"                 = $level -eq "TenantAdmin"
    }

    foreach ($cap in $caps.GetEnumerator()) {
        $tick  = if ($cap.Value) { "[YES]" } else { "[ NO]" }
        $color = if ($cap.Value) { "Green" } else { "DarkGray" }
        Write-Host ("  {0}  {1}" -f $tick, $cap.Key) -ForegroundColor $color
    }
}

Write-Host ""

# Return structured object for pipeline use
[PSCustomObject]@{
    Id            = $user.id
    Email         = $user.email
    Name          = "$($user.firstName) $($user.lastName)".Trim()
    Role          = $user.role
    EffectiveRole = $effective.accessLevel
    EffectiveGroup= $effective.group
    AllRoles      = $roles
}