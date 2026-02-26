##############################################################################
# Get-HalcyonOverrides.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-02-26
# Version : v1.0
#
# Retrieves the override list for a Halcyon tenant with rich filtering.
# Useful for hygiene audits, POV closeout verification, and confirming that
# API-created overrides match what is displayed in the console.
#
# Provides the read side of the override management toolkit:
#   Get-HalcyonOverrides.ps1   -- list and filter (this script)
#   New-HalcyonOverride.ps1    -- create
#   Remove-HalcyonOverride.ps1 -- delete
#
# Filters available:
#   -Kind              : Certificate | Dns | Driver | File | IpAddress
#   -Action            : Allow | Block | Bypass (multiple allowed)
#   -TargetKind        : Asset | Tenant
#   -AssetId           : show overrides for a specific asset (UUID)
#   -AssetName         : show overrides for a specific asset (name)
#   -AlertId           : show overrides linked to an alert
#   -CreatedAfter      / -CreatedBefore
#   -CreatedBy         : filter by creator email or username
#   -CertThumbprint    : filter by certificate thumbprint
#   -CertSubjectDN     : filter by certificate subject DN
#   -OffendingSha256   : filter by file/driver SHA256 prefix
#   -FileCopyright     : filter by file copyright field
#   -FileProductName   : filter by file product name field
#   -OffendingCidr     : filter by IP/CIDR rule
#   -OffendingDns      : filter by DNS rule
#
# Usage:
#
#   List all overrides (tenant-wide, all pages):
#     .\Get-HalcyonOverrides.ps1 -AuthObject $auth -AllPages
#
#   Show only Certificate overrides:
#     .\Get-HalcyonOverrides.ps1 -AuthObject $auth -Kind Certificate -AllPages
#
#   Audit all Allow and Bypass overrides created in the last 30 days:
#     .\Get-HalcyonOverrides.ps1 -AuthObject $auth -Action Allow,Bypass `
#         -CreatedAfter (Get-Date).AddDays(-30) -AllPages
#
#   Find all overrides for a specific asset:
#     .\Get-HalcyonOverrides.ps1 -AuthObject $auth `
#         -AssetId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#
#   Hunt by SHA256:
#     .\Get-HalcyonOverrides.ps1 -AuthObject $auth -OffendingSha256 "d3f1164e"
#
#   Save to JSON for review:
#     .\Get-HalcyonOverrides.ps1 -AuthObject $auth -AllPages -OutFile "overrides.json"
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: ReadOnly or higher
#
# Endpoint:
#   GET https://api.halcyon.ai/v2/overrides
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

    # Artifact kind filter
    [ValidateSet("Certificate", "Dns", "Driver", "File", "IpAddress")]
    [string]$Kind,

    # Action filter -- accepts multiple values, e.g. -Action Allow,Bypass
    [ValidateSet("Allow", "Block", "Bypass")]
    [string[]]$Action,

    # Target scope filter
    [ValidateSet("Asset", "Tenant")]
    [string]$TargetKind,

    # Filter to overrides for a specific asset (UUID)
    [string]$AssetId,

    # Filter to overrides for a specific asset (name)
    [string]$AssetName,

    # Filter to overrides linked to a specific alert (64-char hex)
    [ValidatePattern('^\b[A-Fa-f0-9]{64}\b$')]
    [string]$AlertId,

    # Date range for override creation
    [datetime]$CreatedAfter,
    [datetime]$CreatedBefore,

    # Filter by creator email or username
    [string]$CreatedBy,

    # Certificate-specific filters
    [string]$CertThumbprint,
    [string]$CertSubjectDN,

    # File/Driver-specific filters
    [string]$OffendingSha256,
    [string]$FileCopyright,
    [string]$FileProductName,

    # IpAddress-specific filter
    [string]$OffendingCidr,

    # DNS-specific filter
    [string]$OffendingDns,

    # --- Pagination ---

    [int]$Page = 1,

    [ValidateSet(10, 30, 50, 100)]
    [int]$PageSize = 100,

    # Walk all pages automatically
    [switch]$AllPages,

    # --- Sort ---
    [ValidateSet("Action", "AlertId", "AssetId", "AssetName", "CertificateSubjectDN", "CreatedAt", "CreatedBy", "FileCopyright", "FileProductName", "TargetKind")]
    [string]$SortBy = "CreatedAt",

    [ValidateSet("Asc", "Desc")]
    [string]$SortOrder = "Desc",

    # --- Output ---

    # Write results to a JSON file
    [string]$OutFile,

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

$headers = @{
    "Authorization" = "Bearer $AccessToken"
    "X-TenantID"    = $TenantId
}

##############################################################################
# Build query string helper
##############################################################################

function Build-OverrideQuery {
    param([int]$PageNum)

    $query = [System.Web.HttpUtility]::ParseQueryString("")
    $query["page"]      = $PageNum
    $query["pageSize"]  = $PageSize
    $query["sortBy"]    = $SortBy
    $query["sortOrder"] = $SortOrder

    if ($Kind)            { $query["kind"]                  = $Kind            }
    if ($TargetKind)      { $query["targetKind"]            = $TargetKind      }
    if ($AssetId)         { $query["assetId"]               = $AssetId         }
    if ($AssetName)       { $query["assetName"]             = $AssetName       }
    if ($AlertId)         { $query["alertId"]               = $AlertId         }
    if ($CreatedBy)       { $query["createdBy"]             = $CreatedBy       }
    if ($CertThumbprint)  { $query["certificateThumbprint"] = $CertThumbprint  }
    if ($CertSubjectDN)   { $query["certificateSubjectDN"]  = $CertSubjectDN   }
    if ($OffendingSha256) { $query["offendingSha256"]        = $OffendingSha256 }
    if ($FileCopyright)   { $query["fileCopyright"]          = $FileCopyright   }
    if ($FileProductName) { $query["fileProductName"]        = $FileProductName }
    if ($OffendingCidr)   { $query["offendingCidrRule"]      = $OffendingCidr   }
    if ($OffendingDns)    { $query["offendingDnsRule"]       = $OffendingDns    }

    if ($CreatedAfter)  { $query["createdAfter"]  = $CreatedAfter.ToUniversalTime().ToString("o")  }
    if ($CreatedBefore) { $query["createdBefore"] = $CreatedBefore.ToUniversalTime().ToString("o") }

    # Action supports multiple values
    foreach ($a in $Action) { $query.Add("action", $a) }

    $uriBuilder = New-Object System.UriBuilder("https://api.halcyon.ai/v2/overrides")
    $uriBuilder.Query = $query.ToString()
    return $uriBuilder.Uri.AbsoluteUri
}

##############################################################################
# Console header
##############################################################################

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Halcyon Override List ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tenant ID    : $TenantId"
    if ($Kind)         { Write-Host "  Kind         : $Kind"         }
    if ($Action)       { Write-Host "  Action       : $($Action -join ', ')" }
    if ($TargetKind)   { Write-Host "  Target       : $TargetKind"   }
    if ($AssetId)      { Write-Host "  Asset ID     : $AssetId"      }
    if ($AssetName)    { Write-Host "  Asset Name   : $AssetName"    }
    if ($CreatedBy)    { Write-Host "  Created By   : $CreatedBy"    }
    if ($CreatedAfter) { Write-Host "  Created After  : $CreatedAfter"  }
    if ($CreatedBefore){ Write-Host "  Created Before : $CreatedBefore" }
    if ($AllPages)     { Write-Host "  Pagination   : All pages (pageSize=$PageSize)" }
    else               { Write-Host "  Pagination   : Page $Page (pageSize=$PageSize)" }
    Write-Host ""
}

##############################################################################
# Fetch pages
##############################################################################

$allOverrides = [System.Collections.Generic.List[object]]::new()
$currentPage  = $Page
$totalPages   = 1

do {
    $uri = Build-OverrideQuery -PageNum $currentPage

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

    if ($currentPage -eq $Page -and $response.totalPages) {
        $totalPages = $response.totalPages
        if (-not $silent) {
            Write-Host "  Total overrides : $($response.total)" -ForegroundColor White
            Write-Host "  Total pages     : $totalPages (fetching $(if ($AllPages) { 'all' } else { 'page 1 only' }))" -ForegroundColor White
            Write-Host ""
        }
    }

    if ($response.items) {
        $allOverrides.AddRange($response.items)
    }

    if (-not $silent -and $AllPages -and $totalPages -gt 1) {
        Write-Host "  Fetched page $currentPage / $totalPages ($($allOverrides.Count) overrides so far)..." -ForegroundColor DarkCyan
    }

    $currentPage++

} while ($AllPages -and $currentPage -le $totalPages)

if (-not $silent) {
    Write-Host ""
    Write-Host "  Retrieved $($allOverrides.Count) override(s)." -ForegroundColor Green
    Write-Host ""
}

##############################################################################
# File output
##############################################################################

if ($OutFile) {
    $allOverrides | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutFile -Encoding UTF8
    if (-not $silent) {
        Write-Host "  Saved to : $OutFile" -ForegroundColor Green
        Write-Host ""
    }
}

return $allOverrides.ToArray()
