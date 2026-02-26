##############################################################################
# Get-HalcyonWhoAmI.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-02-25
# Version : v1.0
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

# Resolve auth
if ($AuthObject) {
    if (-not $AccessToken) { $AccessToken = $AuthObject.AccessToken }
    if (-not $TenantId)    { $TenantId    = $AuthObject.TenantId    }
}
if (-not $AccessToken -or -not $TenantId) {
    Write-Error "Auth required. Pass -AuthObject from Get-HalcyonBearerToken.ps1."
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