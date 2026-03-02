##############################################################################
# Get-HalcyonBearerToken.ps1
# Author  : Jim Harris -- Halcyon Senior SA
# Date    : 2026-02-24
# Version : v1.3
#
# Authenticates against the Halcyon Identity endpoint and returns a Bearer
# token for use in subsequent API calls. Prompts interactively for Tenant ID,
# login email, and password. Plaintext password is zeroed from memory
# immediately after the request completes.
#
# Decodes the returned JWT to display real expiry times. The Halcyon auth
# response does not include a top-level TTL field -- expiry is embedded as
# standard 'exp' claims inside the JWT payloads.
#
# Current Halcyon token TTLs (as of v1.1 validation):
#   Access token   :  5 minutes
#   Refresh token  : 15 minutes
#
# For long-running scripts or SOC integrations, use Invoke-HalcyonTokenRefresh.ps1
# to exchange the refresh token for a new access token before it expires.
#
# Optionally, place a config.cfg file in the same directory as this script to
# skip interactive prompts. Use -UseConfig to load credentials from it.
# config.cfg is excluded from source control via .gitignore.
#
# Usage:
#   .\Get-HalcyonBearerToken.ps1
#
#   Capture tokens for use in other scripts:
#   $auth = .\Get-HalcyonBearerToken.ps1
#   $auth.AccessToken
#   $auth.RefreshToken
#
#   Load credentials from config.cfg (non-interactive):
#   $auth = .\Get-HalcyonBearerToken.ps1 -UseConfig
#
#   Suppress all decorative output (errors and warnings still show):
#   $auth = .\Get-HalcyonBearerToken.ps1 -silent
#   $auth = .\Get-HalcyonBearerToken.ps1 -UseConfig -silent
#
#   Tenant ID is not displayed in the Halcyon console UI. To retrieve yours,
#   contact support@halcyon.ai with your org name and console email address.
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon console credentials (non-SSO / service account)
#   Outbound HTTPS to api.halcyon.ai
#   ConvertFrom-HalcyonJwt.ps1 in the same directory
#
# Endpoint:
#   POST https://api.halcyon.ai/identity/auth/login
#
# IMPORTANT -- SSO tenants:
#   If your tenant enforces SSO, personal credentials will not work here.
#   You need a dedicated service account provisioned outside SSO enforcement.
#   Open a ticket at support@halcyon.ai to request one.
#
##############################################################################

#Requires -Version 5.1

param(
    # Suppress all decorative console output. Errors and warnings are always
    # shown regardless. Useful when calling from automation or a test harness.
    [switch]$silent,

    # Load credentials from config.cfg instead of prompting interactively.
    # Searches for config.cfg in the script directory first, then the current
    # working directory. Expected fields: TENANTID, USERNAME, PASSWORD.
    [switch]$UseConfig
)

$ErrorActionPreference = "Stop"

# Dot-source the shared JWT helper from the same directory as this script
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Halcyon API Bearer Token Retrieval ===" -ForegroundColor Cyan
    Write-Host ""
}

##############################################################################
# Resolve credentials -- config file or interactive prompts
##############################################################################

$TenantId      = $null
$Username      = $null
$PlainPassword = $null
$bstr          = [IntPtr]::Zero

if ($UseConfig) {

    # Search for config.cfg in script directory first, then current directory
    $configPath = $null
    foreach ($candidate in @(
        (Join-Path $PSScriptRoot "config.cfg"),
        (Join-Path (Get-Location).Path "config.cfg")
    )) {
        if (Test-Path $candidate) { $configPath = $candidate; break }
    }

    if (-not $configPath) {
        Write-Error "config.cfg not found. Searched:`n  $(Join-Path $PSScriptRoot 'config.cfg')`n  $(Join-Path (Get-Location).Path 'config.cfg')"
    }

    # Parse key=value pairs, skip blank lines and comments
    $config = @{}
    Get-Content $configPath | ForEach-Object {
        if ($_ -match '^\s*([^#=]+?)\s*=\s*(.+?)\s*$') {
            $config[$matches[1].Trim()] = $matches[2].Trim()
        }
    }

    $TenantId      = $config['TENANTID']
    $Username      = $config['USERNAME']
    $PlainPassword = $config['PASSWORD']

    if (-not $TenantId)      { Write-Error "config.cfg is missing the TENANTID field."   }
    if (-not $Username)      { Write-Error "config.cfg is missing the USERNAME field."   }
    if (-not $PlainPassword) { Write-Error "config.cfg is missing the PASSWORD field."   }

    if (-not $silent) {
        Write-Host "  Config       : $configPath" -ForegroundColor DarkCyan
        Write-Host "  Tenant ID    : $TenantId"
        Write-Host "  Username     : $Username"
        Write-Host "  Password     : (loaded from config)" -ForegroundColor DarkCyan
        Write-Host ""
    }

}
else {

    # Interactive prompts
    $TenantId       = Read-Host "Enter Tenant ID"
    $Username       = Read-Host "Enter Halcyon Login Email"
    $SecurePassword = Read-Host "Enter Halcyon Password" -AsSecureString
    $bstr           = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainPassword  = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

}

##############################################################################
# Authenticate
##############################################################################

try {
    $Body = @{
        username = $Username
        password = $PlainPassword
    } | ConvertTo-Json

    $Headers = @{
        "Content-Type" = "application/json"
        "X-TenantID"   = $TenantId
    }

    $Response = Invoke-RestMethod -Method Post `
        -Uri "https://api.halcyon.ai/identity/auth/login" `
        -Headers $Headers `
        -Body $Body

}
finally {
    # Zero credentials from memory regardless of success or failure
    if ($bstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    Remove-Variable PlainPassword -ErrorAction SilentlyContinue
    Remove-Variable Body          -ErrorAction SilentlyContinue
}

if (-not $Response.accessToken) {
    Write-Host ""
    Write-Host "[FAIL] No access token returned. Check credentials and RBAC permissions." -ForegroundColor Red
    Write-Host "       If your tenant enforces SSO, a service account is required." -ForegroundColor Yellow
    exit 1
}

# Decode both JWTs to get real expiry information
$accessInfo  = Get-HalcyonTokenExpiry -Token $Response.accessToken  -Label "Access Token"
$refreshInfo = Get-HalcyonTokenExpiry -Token $Response.refreshToken -Label "Refresh Token"

if (-not $silent) {
    Write-Host ""
    Write-Host "=== Authentication Successful ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "Tenant ID        : $TenantId"
    Write-Host "User             : $($accessInfo.Email)"
    Write-Host ""
    Write-Host "--- Access Token ---" -ForegroundColor Yellow
    Write-Host "  Length         : $($Response.accessToken.Length) chars"
    Write-Host "  Issued At      : $($accessInfo.IssuedAt)"
    Write-Host "  Expires At     : $($accessInfo.ExpiresAt)"
    Write-Host "  TTL            : $($accessInfo.TtlSeconds) seconds ($([math]::Round($accessInfo.TtlSeconds / 60, 1)) min)"
    Write-Host "  Time Remaining : $($accessInfo.SecondsRemaining) seconds" -ForegroundColor $(if ($accessInfo.SecondsRemaining -lt 60) { 'Red' } else { 'Green' })
    Write-Host ""
    Write-Host "--- Refresh Token ---" -ForegroundColor Cyan
    Write-Host "  Length         : $($Response.refreshToken.Length) chars"
    Write-Host "  Expires At     : $($refreshInfo.ExpiresAt)"
    Write-Host "  TTL            : $($refreshInfo.TtlSeconds) seconds ($([math]::Round($refreshInfo.TtlSeconds / 60, 1)) min)"
    Write-Host "  Time Remaining : $($refreshInfo.SecondsRemaining) seconds" -ForegroundColor $(if ($refreshInfo.SecondsRemaining -lt 60) { 'Red' } else { 'Green' })
    Write-Host ""
    Write-Host "Use Invoke-HalcyonTokenRefresh.ps1 to renew before expiry." -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "Bearer Token:" -ForegroundColor Yellow
    Write-Host $Response.accessToken -ForegroundColor White
    Write-Host ""
}

# Return a structured object to the pipeline so callers can capture both tokens
[PSCustomObject]@{
    AccessToken        = $Response.accessToken
    RefreshToken       = $Response.refreshToken
    TenantId           = $TenantId
    AccessExpiresAt    = $accessInfo.ExpiresAt
    RefreshExpiresAt   = $refreshInfo.ExpiresAt
}
