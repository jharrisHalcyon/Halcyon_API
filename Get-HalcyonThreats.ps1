##############################################################################
# Get-HalcyonThreats.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-03-02
# Version : v1.0
#
# Retrieves threat details from the Halcyon API for one or more SHA256 hashes.
# Threat IDs in Halcyon are the SHA256 hash of the file -- the same value
# returned as offendingSha256 on alert objects.
#
# For each threat ID provided, the script calls:
#   GET /v1/threat/{threat_id}           -- core info (name, type, size, hashes,
#                                           cert list, available/allowed status)
#   GET /v1/threat/{threat_id}/summary   -- artifact scoring and signature details
#                                           (opt-in via -IncludeSummary)
#   GET /v1/threat/{threat_id}/download  -- pre-signed download URL for the sample
#                                           (opt-in via -GetDownloadUrl)
#
# Common workflow -- look up threats from alert data:
#   $alerts  = .\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -silent
#   $hashes  = $alerts | Select-Object -ExpandProperty offendingSha256 -Unique
#   $threats = .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes
#
# Usage:
#
#   Single threat lookup:
#     .\Get-HalcyonThreats.ps1 -AuthObject $auth `
#         -ThreatId "d3f1164e8c5e6b1f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f"
#
#   Multiple hashes at once:
#     .\Get-HalcyonThreats.ps1 -AuthObject $auth `
#         -ThreatId @("abc123...","def456...")
#
#   Include artifact scoring and signature details:
#     .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hash -IncludeSummary
#
#   Get pre-signed download URL for the sample (requires User RBAC or higher):
#     .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hash -GetDownloadUrl
#
#   Full detail -- threat info + summary + download URL:
#     .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hash `
#         -IncludeSummary -GetDownloadUrl
#
#   Save results to JSON:
#     .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes `
#         -IncludeSummary -OutFile "threats.json"
#
#   Export as CSV (flattened):
#     .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes `
#         -Format CSV -OutFile "threats.csv"
#
#   Pipeline from Get-HalcyonAlerts.ps1 -- look up every unique hash from alerts:
#     $auth    = .\Get-HalcyonBearerToken.ps1
#     $alerts  = .\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -silent
#     $hashes  = $alerts | Select-Object -ExpandProperty offendingSha256 -Unique |
#                Where-Object { $_ }
#     $threats = .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes `
#                    -IncludeSummary -OutFile "threats.json"
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: ReadOnly or higher (User required for -GetDownloadUrl)
#
# Endpoints:
#   GET https://api.halcyon.ai/v1/threat/{threat_id}
#   GET https://api.halcyon.ai/v1/threat/{threat_id}/summary
#   GET https://api.halcyon.ai/v1/threat/{threat_id}/download
#
##############################################################################

#Requires -Version 5.1

param(
    # Auth -- pass the object returned by Get-HalcyonBearerToken.ps1
    # or Invoke-HalcyonTokenRefresh.ps1
    [PSCustomObject]$AuthObject,

    # Or supply tokens directly
    [string]$AccessToken,
    [string]$TenantId,

    # One or more SHA256 hashes (64 hex chars) -- the threat_id in the API.
    # This is the same value as offendingSha256 on alert objects.
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ThreatId,

    # Also call /v1/threat/{id}/summary for each threat.
    # Returns: score, adjustedScore, hasValidSignature, certificate chain.
    # RBAC: ReadOnly
    [switch]$IncludeSummary,

    # Also call /v1/threat/{id}/download for each threat.
    # Returns a pre-signed download_url for the malware sample.
    # RBAC: User or higher
    [switch]$GetDownloadUrl,

    # --- Output ---

    # Output format: JSON (default) or CSV
    [ValidateSet("JSON", "CSV")]
    [string]$Format = "JSON",

    # Write output to a file. If not specified, results are written to the
    # pipeline as PSCustomObject array and summary to console.
    [string]$OutFile,

    # Suppress decorative console output. Errors and warnings always show.
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

$baseUrl = "https://api.halcyon.ai"

##############################################################################
# Console header
##############################################################################

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Halcyon Threat Lookup ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tenant ID      : $TenantId"
    Write-Host "  Threat IDs     : $($ThreatId.Count) hash(es) to look up"
    if ($IncludeSummary)  { Write-Host "  Include Summary  : Yes (score, signature, cert chain)" -ForegroundColor DarkCyan }
    if ($GetDownloadUrl)  { Write-Host "  Download URL     : Yes (requires User RBAC or higher)"  -ForegroundColor DarkCyan }
    Write-Host "  Format         : $Format"
    Write-Host ""
}

##############################################################################
# Helper -- call one endpoint and return the response, or $null on error
##############################################################################

function Invoke-ThreatGet {
    param(
        [string]$Uri,
        [string]$Label
    )
    try {
        return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            401 { Write-Warning "[$Label] Unauthorized (401) -- Access token may have expired. Run Invoke-HalcyonTokenRefresh.ps1." }
            403 { Write-Warning "[$Label] Forbidden (403) -- Insufficient RBAC role." }
            404 { Write-Warning "[$Label] Not Found (404) -- Threat not in Halcyon sample store: $Label" }
            default { Write-Warning "[$Label] Request failed (HTTP $statusCode): $_" }
        }
        return $null
    }
}

##############################################################################
# Fetch each threat
##############################################################################

$results = [System.Collections.Generic.List[object]]::new()
$idx     = 0

foreach ($id in $ThreatId) {

    $idx++
    $shortId = $id.Substring(0, [Math]::Min(16, $id.Length)) + "..."

    if (-not $silent) {
        Write-Host "  [$idx/$($ThreatId.Count)] Looking up $shortId" -ForegroundColor DarkCyan
    }

    ##########################################################################
    # Core threat info -- GET /v1/threat/{threat_id}
    ##########################################################################

    $threatResp = Invoke-ThreatGet -Uri "$baseUrl/v1/threat/$id" -Label $shortId

    if (-not $threatResp) {
        # Build a minimal placeholder so the result set is complete
        $results.Add([PSCustomObject]@{
            threatId    = $id
            found       = $false
            available   = $false
            allowed     = $false
            name        = $null
            file_type   = $null
            file_size   = $null
            sha1        = $null
            md5         = $null
            certificates = @()
            summary     = $null
            downloadUrl = $null
        })
        continue
    }

    # The v1 endpoint wraps the payload: response.data contains the ThreatResponse
    $threat = if ($threatResp.data) { $threatResp.data } else { $threatResp }

    ##########################################################################
    # Artifact summary -- GET /v1/threat/{threat_id}/summary  (optional)
    ##########################################################################

    $summary = $null

    if ($IncludeSummary) {
        $summaryResp = Invoke-ThreatGet -Uri "$baseUrl/v1/threat/$id/summary" -Label "$shortId/summary"
        if ($summaryResp) {
            $summary = $summaryResp
        }
    }

    ##########################################################################
    # Download URL -- GET /v1/threat/{threat_id}/download  (optional)
    ##########################################################################

    $downloadUrl = $null

    if ($GetDownloadUrl) {
        $dlResp = Invoke-ThreatGet -Uri "$baseUrl/v1/threat/$id/download" -Label "$shortId/download"
        if ($dlResp) {
            $dlData      = if ($dlResp.data) { $dlResp.data } else { $dlResp }
            $downloadUrl = $dlData.download_url
        }
    }

    ##########################################################################
    # Assemble result object
    ##########################################################################

    $result = [PSCustomObject]@{
        threatId     = $id
        found        = $true
        available    = $threat.available
        allowed      = $threat.allowed
        name         = $threat.name
        file_type    = $threat.file_type
        file_size    = $threat.file_size
        sha1         = $threat.sha1
        md5          = $threat.md5
        certificates = $threat.certificate_list
        summary      = $summary
        downloadUrl  = $downloadUrl
    }

    $results.Add($result)

    ##########################################################################
    # Per-threat console output
    ##########################################################################

    if (-not $silent) {
        $foundColor = if ($threat.available) { "Green" } else { "Yellow" }
        Write-Host ""
        Write-Host "  --- Threat: $shortId ---" -ForegroundColor White
        Write-Host ("  Name        : {0}" -f $(if ($threat.name)      { $threat.name }      else { "(no name)" }))
        Write-Host ("  File Type   : {0}" -f $(if ($threat.file_type) { $threat.file_type } else { "(unknown)" }))
        Write-Host ("  File Size   : {0}" -f $(if ($threat.file_size) { $threat.file_size } else { "(unknown)" }))
        Write-Host ("  SHA1        : {0}" -f $(if ($threat.sha1)      { $threat.sha1 }      else { "(none)" }))
        Write-Host ("  MD5         : {0}" -f $(if ($threat.md5)       { $threat.md5 }       else { "(none)" }))
        Write-Host "  Available   : $($threat.available)" -ForegroundColor $foundColor
        Write-Host "  Allowed     : $($threat.allowed)"  -ForegroundColor $(if ($threat.allowed) { "Yellow" } else { "Green" })

        if ($threat.certificate_list -and $threat.certificate_list.Count -gt 0) {
            Write-Host "  Certificates: $($threat.certificate_list.Count) cert(s)" -ForegroundColor DarkCyan
        }

        if ($summary) {
            Write-Host ""
            Write-Host "  [Summary]" -ForegroundColor DarkCyan
            Write-Host ("    Score           : {0}" -f $(if ($null -ne $summary.score)         { $summary.score }         else { "N/A" }))
            Write-Host ("    Adjusted Score  : {0}" -f $(if ($null -ne $summary.adjustedScore) { $summary.adjustedScore } else { "N/A" }))
            Write-Host ("    Valid Signature : {0}" -f $(if ($null -ne $summary.hasValidSignature) { $summary.hasValidSignature } else { "N/A" }))
            if ($summary.certificates -and $summary.certificates.Count -gt 0) {
                Write-Host "    Cert Chain      : $($summary.certificates.Count) entry(ies)" -ForegroundColor DarkCyan
            }
        }

        if ($downloadUrl) {
            Write-Host ""
            Write-Host "  [Download URL]" -ForegroundColor DarkCyan
            Write-Host "    $downloadUrl" -ForegroundColor DarkCyan
        }
    }
}

##############################################################################
# Summary line
##############################################################################

if (-not $silent) {
    $found     = ($results | Where-Object { $_.found      }).Count
    $available = ($results | Where-Object { $_.available  }).Count
    $allowed   = ($results | Where-Object { $_.allowed    }).Count

    Write-Host ""
    Write-Host "=== Summary ===" -ForegroundColor Cyan
    Write-Host "  Looked up  : $($ThreatId.Count)"
    Write-Host "  Found      : $found"      -ForegroundColor $(if ($found     -gt 0) { "Green"  } else { "Yellow" })
    Write-Host "  Available  : $available"  -ForegroundColor $(if ($available -gt 0) { "Green"  } else { "Yellow" })
    Write-Host "  Allowed    : $allowed"    -ForegroundColor $(if ($allowed   -gt 0) { "Yellow" } else { "Green"  })
    Write-Host ""
}

##############################################################################
# Format and output
##############################################################################

if ($Format -eq "JSON") {

    $json = $results | ConvertTo-Json -Depth 10

    if ($OutFile) {
        $json | Out-File -FilePath $OutFile -Encoding UTF8
        if (-not $silent) {
            Write-Host "  Saved to : $OutFile" -ForegroundColor Green
            Write-Host ""
        }
    }
    else {
        Write-Output $json
    }

}
elseif ($Format -eq "CSV") {

    # Flatten top-level scalar fields for CSV -- nested objects serialized as strings
    $flat = $results | ForEach-Object {
        [PSCustomObject]@{
            threatId          = $_.threatId
            found             = $_.found
            available         = $_.available
            allowed           = $_.allowed
            name              = $_.name
            file_type         = $_.file_type
            file_size         = $_.file_size
            sha1              = $_.sha1
            md5               = $_.md5
            certificateCount  = if ($_.certificates) { $_.certificates.Count } else { 0 }
            score             = if ($_.summary) { $_.summary.score }             else { $null }
            adjustedScore     = if ($_.summary) { $_.summary.adjustedScore }     else { $null }
            hasValidSignature = if ($_.summary) { $_.summary.hasValidSignature } else { $null }
            downloadUrl       = $_.downloadUrl
        }
    }

    if ($OutFile) {
        $flat | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
        if (-not $silent) {
            Write-Host "  Saved to : $OutFile" -ForegroundColor Green
            Write-Host ""
        }
    }
    else {
        $flat | ConvertTo-Csv -NoTypeInformation
    }
}

##############################################################################
# Return PSCustomObject array to pipeline for further processing
##############################################################################

return $results.ToArray()
