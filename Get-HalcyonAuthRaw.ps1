##############################################################################
# Get-HalcyonAuthRaw.ps1
# Author  : Jim Harris -- Halcyon Senior SA
# Date    : 2026-02-24
# Version : v1.0
#
# Diagnostic script. Authenticates against the Halcyon Identity endpoint
# and dumps the COMPLETE raw JSON response to the console and optionally
# to a file. No field mapping or assumptions -- we see exactly what the
# API returns so we can identify real field names, token TTL, refresh
# token expiry, and any undocumented properties.
#
# Usage:
#   .\Get-HalcyonAuthRaw.ps1
#   .\Get-HalcyonAuthRaw.ps1 -SaveToFile
#   .\Get-HalcyonAuthRaw.ps1 -SaveToFile -OutPath "C:\temp\halcyon_auth.json"
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon console credentials (non-SSO service account)
#   Outbound HTTPS to api.halcyon.ai
#
# Endpoint:
#   POST https://api.halcyon.ai/identity/auth/login
#
##############################################################################

param(
    [switch]$SaveToFile,
    [string]$OutPath = ".\halcyon_auth_raw_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== Halcyon API Raw Auth Response Dump ===" -ForegroundColor Cyan
Write-Host "Purpose: Identify real field names and token TTL values" -ForegroundColor DarkCyan
Write-Host ""

# Prompt for credentials
$TenantId       = Read-Host "Enter Tenant ID"
$Username       = Read-Host "Enter Halcyon Login Email"
$SecurePassword = Read-Host "Enter Halcyon Password" -AsSecureString

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)

try {
    $PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    $Body = @{
        username = $Username
        password = $PlainPassword
    } | ConvertTo-Json

    $Headers = @{
        "Content-Type" = "application/json"
        "X-TenantID"   = $TenantId
    }

    Write-Host ""
    Write-Host "Sending auth request..." -ForegroundColor Yellow

    # Use Invoke-WebRequest instead of Invoke-RestMethod so we get the raw
    # HTTP response including status code and headers before any parsing
    $RawResponse = Invoke-WebRequest -Method Post `
        -Uri "https://api.halcyon.ai/identity/auth/login" `
        -Headers $Headers `
        -Body $Body `
        -UseBasicParsing

}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable PlainPassword -ErrorAction SilentlyContinue
    Remove-Variable Body          -ErrorAction SilentlyContinue
}

##############################################################################
# HTTP layer info
##############################################################################

Write-Host ""
Write-Host "--- HTTP Response ---" -ForegroundColor Magenta
Write-Host "Status Code    : $($RawResponse.StatusCode) $($RawResponse.StatusDescription)"
Write-Host ""

Write-Host "--- Response Headers ---" -ForegroundColor Magenta
foreach ($key in $RawResponse.Headers.Keys) {
    Write-Host ("  {0,-35} : {1}" -f $key, $RawResponse.Headers[$key])
}

##############################################################################
# Raw JSON body -- no property mapping, no assumptions
##############################################################################

Write-Host ""
Write-Host "--- Raw JSON Body ---" -ForegroundColor Magenta
$RawJson = $RawResponse.Content
Write-Host $RawJson -ForegroundColor White

##############################################################################
# Pretty-printed and annotated field list
##############################################################################

Write-Host ""
Write-Host "--- Parsed Field Inventory ---" -ForegroundColor Magenta

try {
    $Parsed = $RawJson | ConvertFrom-Json

    # Walk every property and display name, type, and value length/preview
    $Parsed.PSObject.Properties | ForEach-Object {
        $val = $_.Value
        $preview = if ($val -is [string] -and $val.Length -gt 80) {
            "$($val.Substring(0,40))...[length: $($val.Length)]"
        } elseif ($null -eq $val) {
            "(null)"
        } else {
            $val
        }
        Write-Host ("  {0,-30} : {1}" -f $_.Name, $preview) -ForegroundColor Green
    }
}
catch {
    Write-Host "Could not parse JSON for field inventory: $_" -ForegroundColor Red
}

##############################################################################
# TTL analysis -- try every known variation of the expiry field name
##############################################################################

Write-Host ""
Write-Host "--- TTL Analysis ---" -ForegroundColor Magenta

$ttlCandidates = @(
    "expiresIn",
    "expires_in",
    "tokenExpiry",
    "expiration",
    "exp",
    "accessTokenExpiresIn",
    "accessTokenExpiry",
    "tokenTtl"
)

$foundTtl = $false
foreach ($candidate in $ttlCandidates) {
    $val = $Parsed.$candidate
    if ($null -ne $val) {
        Write-Host "  Found TTL field   : $candidate = $val" -ForegroundColor Green
        # If it looks like seconds (reasonable range 60-86400), compute expiry time
        if ($val -is [int] -or $val -match '^\d+$') {
            $expireAt = (Get-Date).AddSeconds([int]$val)
            Write-Host "  Access token expires at : $expireAt (assuming seconds from now)" -ForegroundColor Green
        }
        $foundTtl = $true
    }
}

if (-not $foundTtl) {
    Write-Host "  No TTL field matched known candidates." -ForegroundColor Yellow
    Write-Host "  Review the Raw JSON Body above for the correct field name." -ForegroundColor Yellow
}

# Check for refresh token expiry separately
$refreshCandidates = @(
    "refreshTokenExpiresIn",
    "refresh_token_expires_in",
    "refreshExpiry",
    "refreshTokenExpiry",
    "refreshExp"
)

foreach ($candidate in $refreshCandidates) {
    $val = $Parsed.$candidate
    if ($null -ne $val) {
        Write-Host "  Found Refresh TTL : $candidate = $val" -ForegroundColor Cyan
        if ($val -is [int] -or $val -match '^\d+$') {
            $refreshExpireAt = (Get-Date).AddSeconds([int]$val)
            Write-Host "  Refresh token expires at : $refreshExpireAt" -ForegroundColor Cyan
        }
    }
}

##############################################################################
# Optional file save
##############################################################################

if ($SaveToFile) {
    try {
        # Pretty-print the JSON before saving
        $PrettyJson = $Parsed | ConvertTo-Json -Depth 10
        $PrettyJson | Out-File -FilePath $OutPath -Encoding UTF8
        Write-Host ""
        Write-Host "Raw response saved to: $OutPath" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Could not save file: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Dump Complete ===" -ForegroundColor Cyan
Write-Host ""