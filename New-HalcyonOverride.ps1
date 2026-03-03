##############################################################################
# New-HalcyonOverride.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-02-24
# Version : v1.2
#
# Creates a Halcyon override for any supported artifact type:
#   Certificate  -- Allow/Block/Bypass by certificate thumbprint (SHA1)
#   File         -- Allow/Block by file hash (SHA256)      [console tab: "Hash"]
#   Monitor      -- Bypass only by file hash (SHA256)      [console tab: "Monitor"]
#   Driver       -- Allow by driver SHA256 and/or authentihash
#   IpAddress    -- Allow/Block/Bypass by IP or CIDR range [console tab: "Host"]
#   Dns          -- Allow/Block/Bypass by hostname or domain
#
# Note on File vs Monitor:
#   At the API level, both Hash and Monitor overrides use artifact kind "File"
#   with a SHA256 hash. The only difference is the action:
#     Hash    = File + Allow or Block  (block/allow an executable by hash)
#     Monitor = File + Bypass          (exclude a file from Halcyon monitoring)
#   This script exposes Monitor as its own -Kind to make intent explicit and to
#   prevent accidentally pairing -Kind File with -Action Bypass. If you supply
#   -Kind Monitor, Bypass is enforced automatically and -Action is ignored.
#
# Overrides can be scoped to the entire tenant (default) or to a single asset.
#
# For Certificate overrides, the script accepts either:
#   1. A certificate file (.cer, .crt, .pem, .der) -- thumbprint and metadata
#      are extracted automatically and a structured note is generated to match
#      the format used by the Halcyon console.
#   2. A raw 40-character SHA1 thumbprint string -- use when you already have
#      the thumbprint and do not have the file on hand.
#
# Usage:
#
#   Certificate from file (recommended -- auto-extracts thumbprint and metadata):
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
#         -CertificatePath "C:\certs\sophos.cer"
#
#   Certificate from thumbprint directly:
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
#         -Thumbprint "971382847ad8b5978070c4fc248efae266d87a1b"
#
#   File hash -- Allow or Block an executable by SHA256:
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind File `
#         -Sha256 "d3f1164e..." -Action Allow
#
#   Monitor -- Bypass Halcyon monitoring for a file by SHA256:
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Monitor `
#         -Sha256 "3d69eca5..."
#
#   Driver:
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Driver `
#         -DriverSha256 "abc123..." -Authentihash "def456..."
#
#   IP Address or CIDR range:
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind IpAddress `
#         -Cidr "192.168.1.100"
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind IpAddress `
#         -Cidr "10.0.0.0/8"
#
#   DNS hostname:
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Dns `
#         -DnsName "internal.corp.local"
#
#   Scoped to a specific asset instead of the whole tenant:
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
#         -CertificatePath "C:\certs\sophos.cer" `
#         -TargetKind Asset -AssetId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#
#   Preview without submitting (-WhatIf):
#     .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
#         -CertificatePath "C:\certs\sophos.cer" -WhatIf
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon Bearer token (use Get-HalcyonBearerToken.ps1)
#   Outbound HTTPS to api.halcyon.ai
#   RBAC role: PowerUser or Admin
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#
# Endpoint:
#   POST https://api.halcyon.ai/v2/overrides
#
##############################################################################

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    # Auth -- pass the object returned by Get-HalcyonBearerToken.ps1
    # or Invoke-HalcyonTokenRefresh.ps1
    [PSCustomObject]$AuthObject,

    # Or supply tokens directly
    [string]$AccessToken,
    [string]$TenantId,

    # Artifact type -- use Monitor for Bypass-only file exclusions (console "Monitor" tab)
    # File and Monitor both use SHA256 at the API level; Monitor enforces Bypass automatically.
    [Parameter(Mandatory)]
    [ValidateSet("Certificate", "File", "Monitor", "Driver", "IpAddress", "Dns")]
    [string]$Kind,

    # --- Certificate parameters ---

    # Path to a certificate file (.cer, .crt, .pem, .der)
    # Thumbprint and metadata are extracted automatically.
    [string]$CertificatePath,

    # Raw SHA1 thumbprint (40 hex chars) -- use when you don't have the file
    [string]$Thumbprint,

    # --- File (Hash) parameters ---

    # SHA256 hash of the file (64 hex chars)
    [string]$Sha256,

    # --- Driver parameters ---

    # SHA256 of the driver binary (64 hex chars) -- optional if Authentihash provided
    [string]$DriverSha256,

    # Authenticode hash of the driver (64 hex chars) -- optional if DriverSha256 provided
    [string]$Authentihash,

    # --- IpAddress (Host) parameters ---

    # Single IP address or CIDR range (e.g. "192.168.1.1" or "10.0.0.0/8")
    [string]$Cidr,

    # --- DNS parameters ---

    # Hostname or domain (e.g. "internal.corp.local")
    [string]$DnsName,

    # --- Common parameters ---

    # Override action -- Allow is the most common use case
    [ValidateSet("Allow", "Block", "Bypass")]
    [string]$Action = "Allow",

    # Target scope -- Tenant applies to all assets, Asset scopes to one endpoint
    [ValidateSet("Tenant", "Asset")]
    [string]$TargetKind = "Tenant",

    # Required when TargetKind is Asset
    [string]$AssetId,

    # Optional note (max 280 chars). For Certificate overrides from a file,
    # a structured note is generated automatically if this is not provided.
    #
    # Newlines are supported -- use backtick-n in PowerShell double-quoted strings:
    #   -Note "Approved by CR-4821`nSophos endpoint agent`nContact: ops@corp.com"
    #
    # Or use a here-string for more readable multi-line notes:
    #   $note = @"
    #   Approved by CR-4821
    #   Sophos endpoint agent
    #   Contact: ops@corp.com
    #   "@
    #   .\New-HalcyonOverride.ps1 ... -Note $note
    #
    # Note: \n (backslash-n) is NOT a newline in PowerShell -- use backtick-n instead.
    # The 280 character limit includes newline characters.
    [ValidateLength(0, 280)]
    [string]$Note
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

##############################################################################
# Validate target
##############################################################################

if ($TargetKind -eq "Asset" -and -not $AssetId) {
    Write-Error "AssetId is required when TargetKind is 'Asset'."
}

if ($TargetKind -eq "Tenant" -and $AssetId) {
    Write-Warning "AssetId was provided but TargetKind is 'Tenant' -- AssetId will be ignored."
}

##############################################################################
# Monitor kind enforcement -- Bypass is the only valid action
##############################################################################

if ($Kind -eq "Monitor") {
    if ($PSBoundParameters.ContainsKey("Action") -and $Action -ne "Bypass") {
        Write-Warning "Kind 'Monitor' always uses action Bypass. The -Action parameter will be ignored."
    }
    $Action = "Bypass"
}

##############################################################################
# Build artifact block based on Kind
##############################################################################

$artifact = $null
$autoNote = $null

switch ($Kind) {

    "Certificate" {
        $resolvedThumbprint = $null

        if ($CertificatePath) {
            # Load the certificate file and extract thumbprint + metadata
            if (-not (Test-Path $CertificatePath)) {
                Write-Error "Certificate file not found: $CertificatePath"
            }

            Write-Host ""
            Write-Host "Reading certificate: $CertificatePath" -ForegroundColor Cyan

            try {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
            }
            catch {
                Write-Error "Failed to load certificate file. Ensure it is a valid .cer, .crt, .pem, or .der file. Error: $_"
            }

            $resolvedThumbprint = $cert.Thumbprint.ToLower()

            # Display cert details
            Write-Host "  Subject        : $($cert.Subject)"
            Write-Host "  Thumbprint     : $resolvedThumbprint"
            Write-Host "  Expires        : $($cert.NotAfter.ToString('MM/dd/yyyy HH:mm:ss'))"
            Write-Host "  Serial Number  : $($cert.SerialNumber)"
            Write-Host ""

            # Build a structured note matching the console format if no note was supplied
            if (-not $Note) {
                # Extract the common name or organization from Subject for the Application line
                $appName = ""
                if ($cert.Subject -match "CN=([^,]+)") {
                    $appName = $matches[1].Trim()
                }
                $orgName = ""
                if ($cert.Subject -match "O=([^,]+)") {
                    $orgName = $matches[1].Trim()
                }

                $noteLines = @(
                    "Application: $appName",
                    "Punycode: $orgName",
                    "Thumbprint: $($cert.Thumbprint.ToUpper())",
                    "Expires: $($cert.NotAfter.ToString('MM/dd/yyyy HH:mm:ss'))",
                    "CertSerialNum: $($cert.SerialNumber)"
                )
                $autoNote = ($noteLines -join "`n")

                # Trim to 280 char limit if the subject fields are unusually long
                if ($autoNote.Length -gt 280) {
                    $autoNote = $autoNote.Substring(0, 277) + "..."
                }
            }

        }
        elseif ($Thumbprint) {
            # Validate format -- must be exactly 40 hex characters
            if ($Thumbprint -notmatch '^\b[A-Fa-f0-9]{40}\b$') {
                Write-Error "Thumbprint must be exactly 40 hexadecimal characters. Got: '$Thumbprint' (length: $($Thumbprint.Length))"
            }
            $resolvedThumbprint = $Thumbprint.ToLower()
        }
        else {
            Write-Error "For Kind 'Certificate', supply either -CertificatePath or -Thumbprint."
        }

        $artifact = @{
            kind       = "Certificate"
            thumbprint = $resolvedThumbprint
        }
    }

    "File" {
        if (-not $Sha256) {
            Write-Error "For Kind 'File', -Sha256 is required (64-character hex string)."
        }
        if ($Sha256 -notmatch '^\b[A-Fa-f0-9]{64}\b$') {
            Write-Error "Sha256 must be exactly 64 hexadecimal characters. Got length: $($Sha256.Length)"
        }
        $artifact = @{
            kind   = "File"
            sha256 = $Sha256.ToLower()
        }
    }

    "Monitor" {
        # Monitor overrides use artifact kind "File" + action "Bypass" at the API level.
        # This Kind exists in the script to make intent explicit and match the console tab name.
        if (-not $Sha256) {
            Write-Error "For Kind 'Monitor', -Sha256 is required (64-character hex string)."
        }
        if ($Sha256 -notmatch '^\b[A-Fa-f0-9]{64}\b$') {
            Write-Error "Sha256 must be exactly 64 hexadecimal characters. Got length: $($Sha256.Length)"
        }
        $artifact = @{
            kind   = "File"
            sha256 = $Sha256.ToLower()
        }
    }

    "Driver" {
        if (-not $DriverSha256 -and -not $Authentihash) {
            Write-Error "For Kind 'Driver', supply at least one of -DriverSha256 or -Authentihash."
        }
        if ($DriverSha256 -and $DriverSha256 -notmatch '^\b[A-Fa-f0-9]{64}\b$') {
            Write-Error "DriverSha256 must be exactly 64 hexadecimal characters."
        }
        if ($Authentihash -and $Authentihash -notmatch '^\b[A-Fa-f0-9]{64}\b$') {
            Write-Error "Authentihash must be exactly 64 hexadecimal characters."
        }
        $artifact = @{ kind = "Driver" }
        if ($DriverSha256) { $artifact["driverSha256"]  = $DriverSha256.ToLower() }
        if ($Authentihash)  { $artifact["authentihash"] = $Authentihash.ToLower()  }
    }

    "IpAddress" {
        if (-not $Cidr) {
            Write-Error "For Kind 'IpAddress', -Cidr is required (e.g. '192.168.1.1' or '10.0.0.0/8')."
        }
        $artifact = @{
            kind = "IpAddress"
            cidr = $Cidr
        }
    }

    "Dns" {
        if (-not $DnsName) {
            Write-Error "For Kind 'Dns', -DnsName is required (e.g. 'internal.corp.local')."
        }
        $artifact = @{
            kind = "Dns"
            dns  = $DnsName
        }
    }
}

##############################################################################
# Build target block
##############################################################################

$target = @{ kind = $TargetKind }
if ($TargetKind -eq "Asset") {
    $target["id"] = $AssetId
}

##############################################################################
# Resolve final note
##############################################################################

$resolvedNote = if ($Note) { $Note } elseif ($autoNote) { $autoNote } else { $null }

##############################################################################
# Build full request body
##############################################################################

$requestBody = @{
    action   = $Action
    target   = $target
    artifact = $artifact
}

if ($resolvedNote) {
    $requestBody["note"] = $resolvedNote
}

$bodyJson = $requestBody | ConvertTo-Json -Depth 5

##############################################################################
# Preview (-WhatIf)
##############################################################################

Write-Host "=== New Halcyon Override ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Kind        : $Kind"
Write-Host "  Action      : $Action"
Write-Host "  Target      : $TargetKind$(if ($TargetKind -eq 'Asset') { " ($AssetId)" })"
Write-Host "  Tenant ID   : $TenantId"

switch ($Kind) {
    "Certificate" { Write-Host "  Thumbprint  : $($artifact.thumbprint)" }
    "File"        { Write-Host "  SHA256      : $($artifact.sha256)"      }
    "Monitor"     { Write-Host "  SHA256      : $($artifact.sha256)  [API kind: File + Bypass]" }
    "Driver"      {
        if ($artifact.driverSha256)  { Write-Host "  Driver SHA256  : $($artifact.driverSha256)" }
        if ($artifact.authentihash)  { Write-Host "  Authentihash   : $($artifact.authentihash)" }
    }
    "IpAddress"   { Write-Host "  CIDR        : $($artifact.cidr)"       }
    "Dns"         { Write-Host "  DNS Name    : $($artifact.dns)"         }
}

if ($resolvedNote) {
    Write-Host ""
    Write-Host "  Note:" -ForegroundColor DarkCyan
    $resolvedNote -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkCyan }
}

Write-Host ""

if ($PSCmdlet.ShouldProcess("POST /v2/overrides", "Create $Kind override ($Action)")) {

    ##########################################################################
    # Submit to API
    ##########################################################################

    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $AccessToken"
        "X-TenantID"    = $TenantId
    }

    try {
        $response = Invoke-RestMethod -Method Post `
            -Uri "https://api.halcyon.ai/v2/overrides" `
            -Headers $headers `
            -Body $bodyJson
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            400 { Write-Error "Bad Request (400) -- Check your input values, particularly hash lengths and formats." }
            401 { Write-Error "Unauthorized (401) -- Your access token may have expired. Run Invoke-HalcyonTokenRefresh.ps1." }
            403 { Write-Error "Forbidden (403) -- Your account requires PowerUser or Admin RBAC role to create overrides." }
            404 { Write-Error "Not Found (404) -- Tenant or Asset ID not found. Verify your TenantId and AssetId." }
            409 { Write-Error "Conflict (409) -- An override for this artifact already exists." }
            default { Write-Error "Request failed (HTTP $statusCode): $_" }
        }
    }

    ##########################################################################
    # Success output
    ##########################################################################

    Write-Host "Override created successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Override ID  : $($response.id)"
    Write-Host "  Created At   : $($response.createdAt)"
    Write-Host "  Created By   : $($response.createdBy)"
    Write-Host ""

    # Return the full response object to the pipeline
    return $response
}