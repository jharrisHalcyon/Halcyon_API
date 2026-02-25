##############################################################################
# Remove-HalcyonOverride.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-02-24
# Version : v1.0
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