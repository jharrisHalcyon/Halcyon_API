##############################################################################
# Remove-HalcyonDevice.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-02-26
# Version : v1.0
#
# Marks a device for deletion in the Halcyon console. The API returns 202
# (Accepted) -- deletion is asynchronous and may take a moment to reflect
# in the console.
#
# This script is designed to work alongside Get-HalcyonDevices.ps1 for
# VDI hygiene workflows. Use Get-HalcyonDevices.ps1 -FindDuplicates to
# identify stale registrations, then pipe or iterate the results here.
#
# CAUTION:
#   Only delete devices you are certain are stale. Deleting an active
#   endpoint will require reinstallation of the Halcyon agent to restore
#   protection and console visibility. Always review the stale candidate
#   list before deleting, and use -WhatIf to preview first.
#
# Usage:
#
#   Delete a single device by ID (with confirmation prompt):
#     .\Remove-HalcyonDevice.ps1 -AuthObject $auth `
#         -DeviceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#
#   Preview without deleting (-WhatIf):
#     .\Remove-HalcyonDevice.ps1 -AuthObject $auth `
#         -DeviceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -WhatIf
#
#   Skip confirmation prompt (for scripted use):
#     .\Remove-HalcyonDevice.ps1 -AuthObject $auth `
#         -DeviceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -Confirm:$false
#
#   Pipeline from Get-HalcyonDevices.ps1 duplicate detection:
#     $stale = .\Get-HalcyonDevices.ps1 -AuthObject $auth `
#                  -FindDuplicates -AllPages -silent |
#              Where-Object { $_.duplicateStatus -eq "Stale" }
#
#     # Preview first
#     $stale | ForEach-Object {
#         .\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId $_.id -WhatIf
#     }
#
#     # Then execute after review
#     $stale | ForEach-Object {
#         .\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId $_.id -Confirm:$false
#     }
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: PowerUser or Admin
#
# Endpoint:
#   DELETE https://api.halcyon.ai/v1/device/{device_id}
#
##############################################################################

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    # Auth -- pass the object returned by Get-HalcyonBearerToken.ps1
    [PSCustomObject]$AuthObject,

    # Or supply tokens directly
    [string]$AccessToken,
    [string]$TenantId,

    # Device UUID to delete. Use Get-HalcyonDevices.ps1 -FindDuplicates to
    # retrieve stale candidate IDs.
    [Parameter(Mandatory)]
    [string]$DeviceId,

    # Suppress decorative console output
    [switch]$silent
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
# Preview and execute
##############################################################################

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Remove Halcyon Device ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Device ID  : $DeviceId"
    Write-Host "  Tenant ID  : $TenantId"
    Write-Host ""
    Write-Host "  NOTE: Deletion is asynchronous. The device will be marked for removal" -ForegroundColor Yellow
    Write-Host "        and will disappear from the console shortly after this call." -ForegroundColor Yellow
    Write-Host ""
}

if ($PSCmdlet.ShouldProcess("DELETE /v1/device/$DeviceId", "Mark device for deletion")) {

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "X-TenantID"    = $TenantId
    }

    try {
        $response = Invoke-RestMethod -Method Delete `
            -Uri "https://api.halcyon.ai/v1/device/$DeviceId" `
            -Headers $headers
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            401 { Write-Error "Unauthorized (401) -- Access token may have expired. Run Invoke-HalcyonTokenRefresh.ps1." }
            403 { Write-Error "Forbidden (403) -- PowerUser or Admin RBAC role is required to delete devices." }
            404 { Write-Error "Not Found (404) -- Device ID not found: $DeviceId" }
            default { Write-Error "Request failed (HTTP $statusCode): $_" }
        }
    }

    if (-not $silent) {
        Write-Host "Device marked for deletion." -ForegroundColor Green
        Write-Host "  Device ID : $DeviceId"
        Write-Host ""
    }

    return $response
}
