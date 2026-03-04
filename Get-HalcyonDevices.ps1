##############################################################################
# Get-HalcyonDevices.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-02-26
# Version : v1.2
#
# Retrieves devices (endpoints) registered in a Halcyon tenant. Supports
# standard listing with filters as well as a dedicated duplicate detection
# mode for identifying stale VDI registrations.
#
# VDI / Duplicate Detection (-FindDuplicates):
#   In VDI environments, an agent can register multiple times under the same
#   hostname, each time creating a new Asset ID with a new registration date.
#   Only the most recently active registration is valid -- older ones are
#   stale orphans that consume license count and clutter the console.
#
#   -FindDuplicates groups all devices by name. For any name appearing more
#   than once, it marks the device with the most recent heartbeat as the
#   keeper and flags all others as stale candidates for removal.
#
#   Additionally, -HeartbeatThresholdDays flags devices with no heartbeat in
#   the specified number of days, whether or not they are duplicates.
#
#   Output includes a 'duplicateStatus' field on each device:
#     Unique    -- only one device with this name
#     Keeper    -- newest heartbeat in a duplicate group
#     Stale     -- older registration in a duplicate group
#     NoContact -- no heartbeat within the threshold window
#
#   Use Remove-HalcyonDevice.ps1 to act on the stale IDs returned.
#
# Usage:
#
#   List all devices:
#     .\Get-HalcyonDevices.ps1 -AuthObject $auth -AllPages
#
#   Find duplicate registrations (VDI hygiene):
#     .\Get-HalcyonDevices.ps1 -AuthObject $auth -FindDuplicates -AllPages
#
#   Find duplicates and devices with no heartbeat in 14 days:
#     .\Get-HalcyonDevices.ps1 -AuthObject $auth -FindDuplicates `
#         -HeartbeatThresholdDays 14 -AllPages
#
#   Preview stale IDs for removal (pipe to Remove-HalcyonDevice.ps1):
#     $stale = .\Get-HalcyonDevices.ps1 -AuthObject $auth -FindDuplicates `
#                  -AllPages -silent |
#              Where-Object { $_.duplicateStatus -eq "Stale" }
#     $stale | ForEach-Object {
#         .\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId $_.id -WhatIf
#     }
#
#   Filter by name substring:
#     .\Get-HalcyonDevices.ps1 -AuthObject $auth -Name "VDIPOOL" -AllPages
#
#   Filter by operating system:
#     .\Get-HalcyonDevices.ps1 -AuthObject $auth -OperatingSystem "Windows 11"
#
#   Save full device list as JSON:
#     .\Get-HalcyonDevices.ps1 -AuthObject $auth -AllPages -OutFile "devices.json"
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: ReadOnly or higher
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
# Endpoints:
#   GET https://api.halcyon.ai/search/devices        (list)
#   GET https://api.halcyon.ai/search/devices/{id}   (single device detail)
#
##############################################################################

#Requires -Version 5.1

param(
    # Auth -- pass the object returned by Get-HalcyonBearerToken.ps1
    [PSCustomObject]$AuthObject,

    # Or supply tokens directly
    [string]$AccessToken,
    [string]$TenantId,

    # --- Filters ---

    # Device name substring filter (case-insensitive contains)
    [string]$Name,

    # Operating system name filter
    [string]$OperatingSystem,

    # Agent version filter
    [string]$AgentVersion,

    # Generic search term matched against device properties
    [string]$Search,

    # --- Pagination ---

    [int]$Page = 1,

    [ValidateSet(10, 30, 50, 100)]
    [int]$PageSize = 100,

    # Walk all pages automatically
    [switch]$AllPages,

    # --- Sort ---
    [ValidateSet("agentVersion", "deploymentGroupName", "heartbeat", "name", "osName", "policyGroupName", "registeredDate")]
    [string]$SortBy = "registeredDate",

    [ValidateSet("Asc", "Desc")]
    [string]$SortOrder = "Desc",

    # --- Duplicate Detection ---

    # Group devices by name and flag stale duplicate registrations.
    # Particularly useful for VDI environments.
    [switch]$FindDuplicates,

    # Devices with no heartbeat within this many days are flagged as NoContact.
    # Only evaluated when -FindDuplicates is set. Default: 7 days.
    [int]$HeartbeatThresholdDays = 7,

    # --- Output ---

    # Write output to a file as JSON
    [string]$OutFile,

    # Suppress decorative console output
    [switch]$silent
)

$ErrorActionPreference = "Stop"

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

function Build-DeviceQuery {
    param([int]$PageNum)

    $query = [System.Web.HttpUtility]::ParseQueryString("")
    $query["page"]      = $PageNum
    $query["pageSize"]  = $PageSize
    $query["sortBy"]    = $SortBy
    $query["sortOrder"] = $SortOrder

    if ($Name)            { $query["name"]            = $Name            }
    if ($OperatingSystem) { $query["operatingSystem"] = $OperatingSystem }
    if ($AgentVersion)    { $query["agentVersion"]    = $AgentVersion    }
    if ($Search)          { $query["search"]          = $Search          }

    $uriBuilder = New-Object System.UriBuilder("https://api.halcyon.ai/search/devices")
    $uriBuilder.Query = $query.ToString()
    return $uriBuilder.Uri.AbsoluteUri
}

##############################################################################
# Console header
##############################################################################

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Halcyon Device Retrieval ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tenant ID         : $TenantId"
    if ($FindDuplicates) {
        Write-Host "  Mode              : Duplicate Detection (threshold: $HeartbeatThresholdDays days)" -ForegroundColor Yellow
    }
    if ($Name)            { Write-Host "  Name Filter       : $Name" }
    if ($OperatingSystem) { Write-Host "  OS Filter         : $OperatingSystem" }
    if ($AgentVersion)    { Write-Host "  Agent Version     : $AgentVersion" }
    if ($AllPages)        { Write-Host "  Pagination        : All pages (pageSize=$PageSize)" }
    else                  { Write-Host "  Pagination        : Page $Page (pageSize=$PageSize)" }
    Write-Host ""
}

##############################################################################
# Fetch pages
##############################################################################

$allDevices  = [System.Collections.Generic.List[object]]::new()
$currentPage = $Page
$totalPages  = 1

do {
    $uri = Build-DeviceQuery -PageNum $currentPage

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            401 { Write-Error "Unauthorized (401) -- Access token may have expired. Run Invoke-HalcyonTokenRefresh.ps1." }
            403 { Write-Error "Forbidden (403) -- ReadOnly RBAC role or higher is required." }
            default { Write-Error "Request failed (HTTP $statusCode): $_" }
        }
    }

    if ($currentPage -eq $Page -and $response.pagination.totalPages) {
        $totalPages = $response.pagination.totalPages
        if (-not $silent) {
            Write-Host "  Total devices : $($response.pagination.totalItems)" -ForegroundColor White
            Write-Host "  Total pages   : $totalPages (fetching $(if ($AllPages) { 'all' } else { 'page 1 only' }))" -ForegroundColor White
            Write-Host ""
        }
    }

    if ($response.items) {
        $allDevices.AddRange($response.items)
    }

    if (-not $silent -and $AllPages -and $totalPages -gt 1) {
        Write-Host "  Fetched page $currentPage / $totalPages ($($allDevices.Count) devices so far)..." -ForegroundColor DarkCyan
    }

    $currentPage++

} while ($AllPages -and $currentPage -le $totalPages)

if (-not $silent) {
    Write-Host ""
    Write-Host "  Retrieved $($allDevices.Count) device(s)." -ForegroundColor Green
}

##############################################################################
# Duplicate detection
##############################################################################

if ($FindDuplicates) {

    $heartbeatCutoff = (Get-Date).AddDays(-$HeartbeatThresholdDays)

    # Group by name (case-insensitive)
    $byName = $allDevices | Group-Object -Property { $_.name.ToLower() }

    $annotated = [System.Collections.Generic.List[object]]::new()

    foreach ($group in $byName) {

        if ($group.Count -eq 1) {
            $device = $group.Group[0]
            $status = "Unique"

            # Still check heartbeat threshold even for unique devices
            if ($device.heartbeat) {
                $hb = [datetime]$device.heartbeat
                if ($hb -lt $heartbeatCutoff) { $status = "NoContact" }
            }
            else {
                $status = "NoContact"
            }

            $annotated.Add([PSCustomObject]@{
                id              = $device.id
                name            = $device.name
                os_name         = $device.os_name
                agent_version   = $device.agent_version
                registered_date = $device.registered_date
                heartbeat       = $device.heartbeat
                duplicateStatus = $status
            })

        }
        else {
            # Sort by heartbeat descending -- most recent is keeper
            $sorted = $group.Group | Sort-Object -Property {
                if ($_.heartbeat) { [datetime]$_.heartbeat } else { [datetime]::MinValue }
            } -Descending

            $isFirst = $true
            foreach ($device in $sorted) {
                if ($isFirst) {
                    $status  = "Keeper"
                    $isFirst = $false
                }
                else {
                    $status = "Stale"
                }

                # Keeper also checked against heartbeat threshold
                if ($status -eq "Keeper" -and $device.heartbeat) {
                    $hb = [datetime]$device.heartbeat
                    if ($hb -lt $heartbeatCutoff) { $status = "NoContact" }
                }
                elseif ($status -eq "Keeper" -and -not $device.heartbeat) {
                    $status = "NoContact"
                }

                $annotated.Add([PSCustomObject]@{
                    id              = $device.id
                    name            = $device.name
                    os_name         = $device.os_name
                    agent_version   = $device.agent_version
                    registered_date = $device.registered_date
                    heartbeat       = $device.heartbeat
                    duplicateStatus = $status
                })
            }
        }
    }

    $staleCount     = ($annotated | Where-Object { $_.duplicateStatus -eq "Stale"     }).Count
    $noContactCount = ($annotated | Where-Object { $_.duplicateStatus -eq "NoContact" }).Count

    if (-not $silent) {
        Write-Host ""
        Write-Host "--- Duplicate Detection Summary ---" -ForegroundColor Yellow
        Write-Host "  Unique devices    : $(($annotated | Where-Object { $_.duplicateStatus -eq 'Unique'    }).Count)"
        Write-Host "  Keeper (newest)   : $(($annotated | Where-Object { $_.duplicateStatus -eq 'Keeper'    }).Count)"
        Write-Host "  Stale (duplicate) : $staleCount" -ForegroundColor $(if ($staleCount     -gt 0) { "Red"    } else { "Green" })
        Write-Host "  No Heartbeat      : $noContactCount" -ForegroundColor $(if ($noContactCount -gt 0) { "Yellow" } else { "Green" })
        Write-Host ""

        if ($staleCount -gt 0) {
            Write-Host "  Stale device IDs (candidates for Remove-HalcyonDevice.ps1):" -ForegroundColor Red
            $annotated | Where-Object { $_.duplicateStatus -eq "Stale" } | ForEach-Object {
                Write-Host "    $($_.id)  |  $($_.name)  |  Last heartbeat: $($_.heartbeat)" -ForegroundColor Red
            }
            Write-Host ""
        }
    }

    # Persist annotated list as output
    $allDevices = $annotated
}

##############################################################################
# File output
##############################################################################

if ($OutFile) {
    $allDevices | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutFile -Encoding UTF8
    if (-not $silent) {
        Write-Host "  Saved to : $OutFile" -ForegroundColor Green
        Write-Host ""
    }
}

return $allDevices
