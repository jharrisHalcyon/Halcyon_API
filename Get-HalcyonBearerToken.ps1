##############################################################################
# Get-HalcyonBearerToken.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-02-23
# Version : v1_0
#
# Authenticates against the Halcyon Identity endpoint and returns a Bearer
# token for use in subsequent API calls. Prompts interactively for Tenant ID,
# login email, and password. Plaintext password is zeroed from memory
# immediately after the request completes.
#
# Usage:
#   .\Get-HalcyonBearerToken.ps1
#
#   Capture token for use in other scripts:
#   $token = .\Get-HalcyonBearerToken.ps1
#
#   Tenant ID is not displayed in the Halcyon console UI. To retrieve yours,
#   contact support@halcyon.ai with your org name and console email address.
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon console credentials
#   Outbound HTTPS to api.halcyon.ai
#
# Endpoint:
#   POST https://api.halcyon.ai/identity/auth/login
#
##############################################################################

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== Halcyon API Bearer Token Retrieval ===" -ForegroundColor Cyan
Write-Host ""

# Prompt for required inputs
$TenantId = Read-Host "Enter Tenant ID"
$Username = Read-Host "Enter Halcyon Login Email"
$SecurePassword = Read-Host "Enter Halcyon Password" -AsSecureString

# Convert SecureString to plaintext temporarily (in-memory only)
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

    $Response = Invoke-RestMethod -Method Post `
        -Uri "https://api.halcyon.ai/identity/auth/login" `
        -Headers $Headers `
        -Body $Body

}
finally {
    # Wipe plaintext password from memory
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable PlainPassword -ErrorAction SilentlyContinue
    Remove-Variable Body -ErrorAction SilentlyContinue
}

if (-not $Response.accessToken) {
    Write-Host ""
    Write-Host "[FAIL] No access token returned. Check credentials or RBAC permissions." -ForegroundColor Red
    exit 1
}

$AccessToken  = $Response.accessToken
$RefreshToken = $Response.refreshToken
$ExpiresIn    = $Response.expiresIn

Write-Host ""
Write-Host "=== Authentication Successful ===" -ForegroundColor Green
Write-Host ""
Write-Host "Tenant ID     : $TenantId"
Write-Host "User          : $Username"
Write-Host "Token Length  : $($AccessToken.Length)"
Write-Host "Expires In    : $ExpiresIn seconds"
Write-Host ""

Write-Host "Bearer Token:" -ForegroundColor Yellow
Write-Host $AccessToken -ForegroundColor White
Write-Host ""

# Output token to pipeline so it can be captured like:
# $token = .\Get-HalcyonToken.ps1
