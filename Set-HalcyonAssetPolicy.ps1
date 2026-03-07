##############################################################################
# Set-HalcyonAssetPolicy.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-03-05
# Version : v1.1
#
# Applies a policy to Halcyon assets. Supports two targeting modes:
#
#   Tag / Search Group  -- applies to all assets carrying a given tag.
#                          This maps to Search Groups in the Halcyon console.
#
#   Asset list          -- applies to specific assets by ID or hostname,
#                          from a comma-separated string, CSV file, or
#                          one-per-line list file.
#
# The policy can be specified by name (-Policy) or directly by UUID
# (-PolicyId). When using -Policy, the name must match exactly
# (case-insensitive). Run Get-HalcyonPolicies.ps1 to see available policies.
#
# The batch operation is asynchronous. This script polls until the job
# completes or fails.
#
# Usage:
#
#   Apply policy to all assets in a Search Group (tag):
#     .\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth `
#         -Tag "jimbo" -Policy "Harris-Prevent"
#
#   Apply policy to specific assets by hostname:
#     .\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth `
#         -Assets "DESKTOP-OHIMIC7, Win0-d6c006" -Policy "Harris-Prevent"
#
#   Apply policy to assets by ID:
#     .\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth `
#         -Assets "uuid1, uuid2" -PolicyId "uuid-of-policy"
#
#   Apply policy from a CSV file:
#     .\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth `
#         -CsvFile "assets.csv" -Policy "Harris-Prevent"
#
#   Apply policy from a one-per-line list file:
#     .\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth `
#         -ListFile "hostnames.txt" -Policy "Detection"
#
#   Preview without applying (-WhatIf):
#     .\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth `
#         -Tag "jimbo" -Policy "Detection" -WhatIf
#
#   Skip confirmation prompt (for scripted use):
#     .\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth `
#         -Tag "jimbo" -Policy "Harris-Prevent" -Confirm:$false
#
# CSV format:
#   Must have a header row. Column priority: id > assetId > name > hostname.
#   If none match, the first column is used.
#
# List file format:
#   One asset ID or hostname per line. Blank lines and '#' comments ignored.
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: PowerUser or Admin
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
# Endpoints:
#   GET  https://api.halcyon.ai/v2/policy-groups          (policy name lookup)
#   POST https://api.halcyon.ai/v2/assets/search          (hostname resolution + preview)
#   POST https://api.halcyon.ai/v2/assets/batch           (apply policy)
#   GET  https://api.halcyon.ai/v2/jobs/{jobId}           (poll for completion)
#
##############################################################################

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [PSCustomObject]$AuthObject,
    [string]$AccessToken,
    [string]$TenantId,

    # --- Targeting (provide exactly one) ---

    # Tag / Search Group name -- applies to all assets with this tag
    [string]$Tag,

    # Comma-separated asset IDs or hostnames
    [string]$Assets,

    # CSV file with id or name column
    [string]$CsvFile,

    # One asset ID or hostname per line
    [string]$ListFile,

    # --- Policy (provide exactly one) ---

    # Policy name -- looked up by exact name (case-insensitive)
    [string]$Policy,

    # Policy UUID -- skips name lookup
    [string]$PolicyId,

    [int]$PollIntervalSeconds = 3,
    [int]$TimeoutSeconds      = 120,
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
# Validate parameters
##############################################################################

$targetCount = @($Tag, $Assets, $CsvFile, $ListFile) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($targetCount -eq 0) { Write-Error "A target is required: -Tag, -Assets, -CsvFile, or -ListFile." }
if ($targetCount -gt 1 -and $Tag) { Write-Error "-Tag cannot be combined with -Assets, -CsvFile, or -ListFile. Use one targeting mode." }

if (-not $Policy -and -not $PolicyId) { Write-Error "A policy is required: -Policy (name) or -PolicyId (UUID)." }
if ($Policy -and $PolicyId)           { Write-Error "Specify either -Policy or -PolicyId, not both." }

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
# Token expiry check
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

$headers = @{ "Authorization" = "Bearer $AccessToken"; "X-TenantID" = $TenantId; "Content-Type" = "application/json" }

##############################################################################
# Helper -- parse asset identifiers from all input sources
##############################################################################

function Read-AssetIdentifiers {
    $ids = [System.Collections.Generic.List[string]]::new()

    if ($Assets) {
        $Assets -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { $ids.Add($_) }
    }
    if ($CsvFile) {
        if (-not (Test-Path $CsvFile)) { Write-Error "CSV file not found: $CsvFile" }
        $csv = Import-Csv -Path $CsvFile
        if ($csv.Count -eq 0) { Write-Error "CSV file is empty: $CsvFile" }
        $col = $null
        foreach ($try in @('id', 'assetId', 'name', 'hostname')) {
            $found = $csv[0].PSObject.Properties.Name | Where-Object { $_ -ieq $try } | Select-Object -First 1
            if ($found) { $col = $found; break }
        }
        if (-not $col) { $col = $csv[0].PSObject.Properties.Name | Select-Object -First 1 }
        $csv | ForEach-Object { $v = $_.$col.Trim(); if ($v) { $ids.Add($v) } }
    }
    if ($ListFile) {
        if (-not (Test-Path $ListFile)) { Write-Error "List file not found: $ListFile" }
        Get-Content -Path $ListFile |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') } |
            ForEach-Object { $ids.Add($_) }
    }

    return ($ids | Sort-Object -Unique)
}

##############################################################################
# Helper -- resolve hostnames to asset IDs
##############################################################################

$uuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Resolve-ToAssetIds ([string[]]$Identifiers) {
    $resolvedIds = [System.Collections.Generic.List[string]]::new()
    $hostnames   = [System.Collections.Generic.List[string]]::new()
    $details     = [System.Collections.Generic.List[object]]::new()

    foreach ($i in $Identifiers) {
        if ($i -match $uuidPattern) { $resolvedIds.Add($i) } else { $hostnames.Add($i) }
    }

    if ($hostnames.Count -gt 0) {
        Write-Host "  [RESOLVE] Looking up $($hostnames.Count) hostname(s)..." -ForegroundColor DarkCyan

        $filters = @($hostnames | ForEach-Object { @{ operator = "Contains"; name = $_ } })
        $body = @{
            operator   = if ($filters.Count -gt 1) { "Or" } else { "And" }
            filters    = $filters
            pagination = @{ page = 1; pageSize = 100 }
            sorting    = @{ sortBy = "Name"; sortOrder = "Asc" }
        } | ConvertTo-Json -Depth 5

        try {
            $resp = Invoke-RestMethod -Method Post -Uri "https://api.halcyon.ai/v2/assets/search" -Headers $headers -Body $body
        }
        catch { Write-Error "Hostname resolution failed: $_" }

        foreach ($hostname in $hostnames) {
            $m = @($resp.items | Where-Object { $_.name -ieq $hostname })
            if ($m.Count -eq 0) {
                Write-Host "  [WARN] Hostname not found: '$hostname'" -ForegroundColor Yellow
            }
            elseif ($m.Count -gt 1) {
                Write-Host "  [WARN] Multiple assets match '$hostname' -- skipping. Use asset ID." -ForegroundColor Yellow
            }
            else {
                $resolvedIds.Add($m[0].id)
                $details.Add($m[0])
                Write-Host ("  [RESOLVE] {0,-30} -> {1}" -f $hostname, $m[0].id) -ForegroundColor DarkCyan
            }
        }
    }

    return @{ Ids = $resolvedIds.ToArray(); Details = $details.ToArray() }
}

##############################################################################
# Resolve policy ID from name
##############################################################################

if ($Policy) {
    if (-not $silent) { Write-Host ""; Write-Host "  [LOOKUP] Resolving policy name '$Policy'..." -ForegroundColor DarkCyan }

    $resolvedPolicyId = $null
    $pgPage = 1; $pgTotal = 1

    do {
        try {
            $pgResp = Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/policy-groups?page=$pgPage&pageSize=100" -Headers $headers
        }
        catch { Write-Error "Failed to retrieve policy list: $_" }

        if ($pgPage -eq 1 -and $pgResp.pagination.totalPages) { $pgTotal = $pgResp.pagination.totalPages }

        $match = @($pgResp.items | Where-Object { $_.name -ieq $Policy })
        if ($match.Count -gt 1) { Write-Error "Multiple policies matched '$Policy'. Use -PolicyId to specify by UUID." }
        if ($match.Count -eq 1) { $resolvedPolicyId = $match[0].id; break }

        $pgPage++
    } while ($pgPage -le $pgTotal)

    if (-not $resolvedPolicyId) {
        Write-Host ""; Write-Host "  [FAIL] No policy found with name '$Policy'." -ForegroundColor Red
        Write-Host "         Run Get-HalcyonPolicies.ps1 to see available policy names." -ForegroundColor Yellow; Write-Host ""; exit 1
    }

    $PolicyId   = $resolvedPolicyId
    $policyName = $Policy
    if (-not $silent) { Write-Host "  [LOOKUP] Resolved: $PolicyId" -ForegroundColor Green }
}
else {
    # Verify PolicyId and fetch name for display
    try {
        $pg = Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/policy-groups/$PolicyId" -Headers $headers
        $policyName = $pg.name
    }
    catch {
        $sc = $_.Exception.Response.StatusCode.value__
        if ($sc -eq 404) { Write-Error "Policy ID not found: $PolicyId" }
        else { Write-Error "Failed to verify policy (HTTP $sc): $_" }
    }
}

##############################################################################
# Targeting mode: Tag / Search Group
##############################################################################

if ($Tag) {

    # Preview assets in the tag
    $searchBody = @{
        filters    = @(@{ operator = "Equals"; tag = $Tag })
        pagination = @{ page = 1; pageSize = 100 }
        sorting    = @{ sortBy = "Name"; sortOrder = "Asc" }
    } | ConvertTo-Json -Depth 5

    try {
        $preview = Invoke-RestMethod -Method Post -Uri "https://api.halcyon.ai/v2/assets/search" -Headers $headers -Body $searchBody
    }
    catch { Write-Error "Asset search failed: $_" }

    $totalAssets  = if ($preview.pagination) { $preview.pagination.totalItems } else { 0 }
    $previewItems = if ($preview.items) { $preview.items } else { @() }

    if (-not $silent) {
        Write-Host ""; Write-Host "=== Set Asset Policy ===" -ForegroundColor Cyan; Write-Host ""
        Write-Host "  Target     : Tag / Search Group '$Tag'"
        Write-Host "  Policy     : $policyName"
        Write-Host "  Policy ID  : $PolicyId"
        Write-Host "  Tenant ID  : $TenantId"
        Write-Host ""
    }

    if ($totalAssets -eq 0) {
        Write-Host "  [WARN] No assets found with tag '$Tag'. Nothing to do." -ForegroundColor Yellow
        Write-Host ""; exit 0
    }

    if (-not $silent) {
        Write-Host "  Assets in Search Group '$Tag' ($totalAssets total):" -ForegroundColor Yellow
        foreach ($a in $previewItems) {
            $cur = if ($a.policyGroup) { $a.policyGroup.name } else { "(none)" }
            Write-Host ("    {0,-30}  current: {1}" -f $a.name, $cur)
        }
        if ($totalAssets -gt $previewItems.Count) {
            Write-Host "    ... and $($totalAssets - $previewItems.Count) more"
        }
        Write-Host ""
    }

    if ($PSCmdlet.ShouldProcess("Search Group '$Tag' ($totalAssets asset(s))", "Apply policy '$policyName'")) {

        $batchBody = @{
            targets = @{ operator = "And"; filters = @(@{ operator = "Equals"; tag = $Tag }) }
            updates = @{ policyGroupId = $PolicyId }
        } | ConvertTo-Json -Depth 5

        try {
            $batchResp = Invoke-RestMethod -Method Post -Uri "https://api.halcyon.ai/v2/assets/batch" -Headers $headers -Body $batchBody
        }
        catch {
            $sc = $_.Exception.Response.StatusCode.value__
            switch ($sc) {
                401 { Write-Error "Unauthorized (401) -- Access token may have expired." }
                403 { Write-Error "Forbidden (403) -- PowerUser or Admin RBAC role is required." }
                default { Write-Error "Batch request failed (HTTP $sc): $_" }
            }
        }

        $jobId = $batchResp.jobId
        if (-not $silent) { Write-Host "  [JOB] Submitted. Job ID: $jobId" -ForegroundColor DarkCyan; Write-Host "  [JOB] Polling..." -ForegroundColor DarkCyan }

        $elapsed = 0; $jobDone = $false; $jobStatus = $null
        while (-not $jobDone -and $elapsed -lt $TimeoutSeconds) {
            Start-Sleep -Seconds $PollIntervalSeconds; $elapsed += $PollIntervalSeconds
            try { $jobResp = Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/jobs/$jobId" -Headers $headers; $jobStatus = $jobResp.status }
            catch { Write-Host "  [WARN] Poll failed: $_" -ForegroundColor Yellow; continue }
            if (-not $silent) { Write-Host "  [JOB] Status: $jobStatus (${elapsed}s)" -ForegroundColor DarkCyan }
            if ($jobStatus -in @("Completed", "Failed", "Deleted")) { $jobDone = $true }
        }

        Write-Host ""
        if ($jobStatus -eq "Completed") { Write-Host "  [DONE] Policy '$policyName' applied to $totalAssets asset(s) in Search Group '$Tag'." -ForegroundColor Green }
        elseif ($jobStatus -eq "Failed") { Write-Host "  [FAIL] Batch job failed. Job ID: $jobId" -ForegroundColor Red }
        elseif (-not $jobDone) { Write-Host "  [WARN] Job still running after ${TimeoutSeconds}s. Job ID: $jobId" -ForegroundColor Yellow }
        else { Write-Host "  [WARN] Unexpected job status '$jobStatus'. Job ID: $jobId" -ForegroundColor Yellow }
        Write-Host ""

        return $batchResp
    }

}

##############################################################################
# Targeting mode: Asset list (IDs / hostnames / CSV / file)
##############################################################################

else {

    $identifiers = Read-AssetIdentifiers
    if ($identifiers.Count -eq 0) { Write-Error "No asset identifiers found in the provided input." }

    $resolved = Resolve-ToAssetIds -Identifiers $identifiers
    $assetIds = $resolved.Ids

    if ($assetIds.Count -eq 0) {
        Write-Host "  [WARN] No valid asset IDs could be resolved. Nothing to do." -ForegroundColor Yellow; exit 0
    }

    if (-not $silent) {
        Write-Host ""; Write-Host "=== Set Asset Policy ===" -ForegroundColor Cyan; Write-Host ""
        Write-Host "  Target     : Asset list ($($assetIds.Count) asset(s))"
        Write-Host "  Policy     : $policyName"
        Write-Host "  Policy ID  : $PolicyId"
        Write-Host "  Tenant ID  : $TenantId"
        Write-Host ""
        Write-Host "  Asset IDs:" -ForegroundColor Yellow
        foreach ($id in $assetIds) { Write-Host "    $id" }
        Write-Host ""
    }

    if ($PSCmdlet.ShouldProcess("$($assetIds.Count) asset(s)", "Apply policy '$policyName'")) {

        $batchBody = @{
            targets = @{ assetIds = [System.Collections.Generic.List[string]]$assetIds }
            updates = @{ policyGroupId = $PolicyId }
        } | ConvertTo-Json -Depth 5

        try {
            $batchResp = Invoke-RestMethod -Method Post -Uri "https://api.halcyon.ai/v2/assets/batch" -Headers $headers -Body $batchBody
        }
        catch {
            $sc = $_.Exception.Response.StatusCode.value__
            switch ($sc) {
                401 { Write-Error "Unauthorized (401) -- Access token may have expired." }
                403 { Write-Error "Forbidden (403) -- PowerUser or Admin RBAC role is required." }
                default { Write-Error "Batch request failed (HTTP $sc): $_" }
            }
        }

        $jobId = $batchResp.jobId
        if (-not $silent) { Write-Host "  [JOB] Submitted. Job ID: $jobId" -ForegroundColor DarkCyan; Write-Host "  [JOB] Polling..." -ForegroundColor DarkCyan }

        $elapsed = 0; $jobDone = $false; $jobStatus = $null
        while (-not $jobDone -and $elapsed -lt $TimeoutSeconds) {
            Start-Sleep -Seconds $PollIntervalSeconds; $elapsed += $PollIntervalSeconds
            try { $jobResp = Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/jobs/$jobId" -Headers $headers; $jobStatus = $jobResp.status }
            catch { Write-Host "  [WARN] Poll failed: $_" -ForegroundColor Yellow; continue }
            if (-not $silent) { Write-Host "  [JOB] Status: $jobStatus (${elapsed}s)" -ForegroundColor DarkCyan }
            if ($jobStatus -in @("Completed", "Failed", "Deleted")) { $jobDone = $true }
        }

        Write-Host ""
        if ($jobStatus -eq "Completed") { Write-Host "  [DONE] Policy '$policyName' applied to $($assetIds.Count) asset(s)." -ForegroundColor Green }
        elseif ($jobStatus -eq "Failed") { Write-Host "  [FAIL] Batch job failed. Job ID: $jobId" -ForegroundColor Red }
        elseif (-not $jobDone) { Write-Host "  [WARN] Job still running after ${TimeoutSeconds}s. Job ID: $jobId" -ForegroundColor Yellow }
        else { Write-Host "  [WARN] Unexpected job status '$jobStatus'. Job ID: $jobId" -ForegroundColor Yellow }
        Write-Host ""

        return $batchResp
    }
}
