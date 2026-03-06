##############################################################################
# Set-HalcyonAssetTag.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-03-05
# Version : v1.0
#
# Adds or removes tags on Halcyon assets. Tags are the underlying mechanism
# for Search Groups in the Halcyon console.
#
# Assets can be specified by ID or hostname (or a mix). Hostnames are resolved
# to asset IDs automatically via the assets search API. Multiple assets can
# be passed as a comma-separated string, a CSV file, or a one-per-line list.
#
# The batch operation is asynchronous. This script polls until the job
# completes or fails.
#
# Usage:
#
#   Tag assets by asset ID:
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -Assets "uuid1, uuid2" -AddTag "prod"
#
#   Tag assets by hostname:
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -Assets "DESKTOP-OHIMIC7, Win0-d6c006" -AddTag "jimbo"
#
#   Mix of IDs and hostnames:
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -Assets "DESKTOP-OHIMIC7, uuid-of-another" -AddTag "vdi-pool-a"
#
#   Tag assets from a CSV file (must have an 'id' or 'name' column):
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -CsvFile "assets.csv" -AddTag "prod"
#
#   Tag assets from a one-per-line text file:
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -ListFile "hostnames.txt" -AddTag "vdi"
#
#   Add and remove tags in one call:
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -Assets "DESKTOP-OHIMIC7" -AddTag "prod" -RemoveTag "staging"
#
#   Preview without applying (-WhatIf):
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -Assets "DESKTOP-OHIMIC7" -AddTag "prod" -WhatIf
#
#   Skip confirmation prompt:
#     .\Set-HalcyonAssetTag.ps1 -AuthObject $auth `
#         -Assets "DESKTOP-OHIMIC7" -AddTag "prod" -Confirm:$false
#
# CSV format:
#   The CSV must have a header row. Column priority for asset lookup:
#   id > assetId > name > hostname. If none match, the first column is used.
#
# List file format:
#   One asset ID or hostname per line. Blank lines and lines starting with
#   '#' are ignored.
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: PowerUser or Admin
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
# Endpoints:
#   POST https://api.halcyon.ai/v2/assets/search  (hostname resolution + preview)
#   POST https://api.halcyon.ai/v2/assets/batch   (apply tags)
#   GET  https://api.halcyon.ai/v2/jobs/{jobId}   (poll for completion)
#
##############################################################################

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [PSCustomObject]$AuthObject,
    [string]$AccessToken,
    [string]$TenantId,

    # Asset targets -- provide one or more of the following
    [string]$Assets,      # Comma-separated asset IDs or hostnames
    [string]$CsvFile,     # CSV file with id or name column
    [string]$ListFile,    # One asset ID or hostname per line

    # Tag operations -- provide at least one
    [string]$AddTag,      # Comma-separated tags to add
    [string]$RemoveTag,   # Comma-separated tags to remove

    [int]$PollIntervalSeconds = 3,
    [int]$TimeoutSeconds      = 120,
    [switch]$silent
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

##############################################################################
# Validate parameters
##############################################################################

if (-not $Assets -and -not $CsvFile -and -not $ListFile) {
    Write-Error "At least one asset source is required: -Assets, -CsvFile, or -ListFile."
}
if (-not $AddTag -and -not $RemoveTag) {
    Write-Error "At least one tag operation is required: -AddTag or -RemoveTag."
}

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
        catch {
            Write-Error "Hostname resolution failed: $_"
        }

        foreach ($hostname in $hostnames) {
            $matches = @($resp.items | Where-Object { $_.name -ieq $hostname })
            if ($matches.Count -eq 0) {
                Write-Host "  [WARN] Hostname not found: '$hostname'" -ForegroundColor Yellow
            }
            elseif ($matches.Count -gt 1) {
                Write-Host "  [WARN] Multiple assets match '$hostname' -- skipping. Use the asset ID instead." -ForegroundColor Yellow
            }
            else {
                $resolvedIds.Add($matches[0].id)
                Write-Host ("  [RESOLVE] {0,-30} -> {1}" -f $hostname, $matches[0].id) -ForegroundColor DarkCyan
            }
        }
    }

    return $resolvedIds.ToArray()
}

##############################################################################
# Parse and resolve
##############################################################################

$identifiers = Read-AssetIdentifiers
if ($identifiers.Count -eq 0) { Write-Error "No asset identifiers found in the provided input." }

$assetIds = Resolve-ToAssetIds -Identifiers $identifiers
if ($assetIds.Count -eq 0) {
    Write-Host "  [WARN] No valid asset IDs could be resolved. Nothing to do." -ForegroundColor Yellow
    exit 0
}

# Parse tag lists
$tagsToAdd    = if ($AddTag)    { @($AddTag    -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() }
$tagsToRemove = if ($RemoveTag) { @($RemoveTag -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() }

##############################################################################
# Display preview
##############################################################################

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Set Asset Tag ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Assets resolved : $($assetIds.Count)"
    if ($tagsToAdd.Count -gt 0)    { Write-Host "  Tags to add     : $($tagsToAdd -join ', ')"    -ForegroundColor Green }
    if ($tagsToRemove.Count -gt 0) { Write-Host "  Tags to remove  : $($tagsToRemove -join ', ')" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "  Asset IDs:" -ForegroundColor Yellow
    foreach ($id in $assetIds) { Write-Host "    $id" }
    Write-Host ""
}

##############################################################################
# Confirm and execute
##############################################################################

$tagSummary = @()
if ($tagsToAdd.Count -gt 0)    { $tagSummary += "add: $($tagsToAdd -join ', ')" }
if ($tagsToRemove.Count -gt 0) { $tagSummary += "remove: $($tagsToRemove -join ', ')" }

if ($PSCmdlet.ShouldProcess("$($assetIds.Count) asset(s)", "Tag operation -- $($tagSummary -join ' | ')")) {

    $updates = @{}
    if ($tagsToAdd.Count -gt 0)    { $updates['tagsToAdd']    = $tagsToAdd    }
    if ($tagsToRemove.Count -gt 0) { $updates['tagsToRemove'] = $tagsToRemove }

    $batchBody = @{
        targets = @{ assetIds = $assetIds }
        updates = $updates
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

    if (-not $silent) {
        Write-Host "  [JOB] Submitted. Job ID: $jobId" -ForegroundColor DarkCyan
        Write-Host "  [JOB] Polling for completion..." -ForegroundColor DarkCyan
    }

    $elapsed   = 0
    $jobDone   = $false
    $jobStatus = $null

    while (-not $jobDone -and $elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        try {
            $jobResp   = Invoke-RestMethod -Method Get -Uri "https://api.halcyon.ai/v2/jobs/$jobId" -Headers $headers
            $jobStatus = $jobResp.status
        }
        catch { Write-Host "  [WARN] Poll attempt failed: $_" -ForegroundColor Yellow; continue }

        if (-not $silent) { Write-Host "  [JOB] Status: $jobStatus (${elapsed}s elapsed)" -ForegroundColor DarkCyan }
        if ($jobStatus -in @("Completed", "Failed", "Deleted")) { $jobDone = $true }
    }

    Write-Host ""
    if ($jobStatus -eq "Completed") {
        Write-Host "  [DONE] Tag operation applied to $($assetIds.Count) asset(s)." -ForegroundColor Green
    }
    elseif ($jobStatus -eq "Failed") {
        Write-Host "  [FAIL] Batch job failed. Check the Halcyon console for details. Job ID: $jobId" -ForegroundColor Red
    }
    elseif (-not $jobDone) {
        Write-Host "  [WARN] Job still running after ${TimeoutSeconds}s. Job ID: $jobId" -ForegroundColor Yellow
        Write-Host "         The operation may still complete -- check the console." -ForegroundColor Yellow
    }
    else {
        Write-Host "  [WARN] Job ended with unexpected status '$jobStatus'. Job ID: $jobId" -ForegroundColor Yellow
    }
    Write-Host ""

    return $batchResp
}
