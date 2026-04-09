##############################################################################
# Install-HalcyonAgent.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-04-09
# Version : v1.3
#
# Installs the Halcyon Windows agent by authenticating to the Halcyon API,
# retrieving the current installer and install token for the target tenant,
# downloading the installer, and running a silent install.
#
# Usage:
#
#   Interactive (prompts for credentials):
#     .\Install-HalcyonAgent.ps1
#
#   Via auth object from Get-HalcyonBearerToken.ps1:
#     $auth = .\Get-HalcyonBearerToken.ps1
#     .\Install-HalcyonAgent.ps1 -AuthObject $auth
#
#   Via tokens directly:
#     .\Install-HalcyonAgent.ps1 -AccessToken $token -TenantId $tid
#
#   Via environment variables (unattended):
#     $env:HAL_USER   = 'admin@example.com'
#     $env:HAL_PASS   = 'yourpassword'
#     $env:HAL_TENANT = '0546ca62-47db-4319-a89e-647764941bcf'
#     .\Install-HalcyonAgent.ps1
#
#   Via config file (config.cfg in same directory):
#     .\Install-HalcyonAgent.ps1 -useConfig
#
# Requires:
#   PowerShell 5.1+
#   Elevated (Administrator) prompt
#   Outbound HTTPS to api.halcyon.ai
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#   Invoke-HalcyonTokenRefresh.ps1 (same directory -- auto-refresh)
#
# Notes:
#   Credentials supplied via HAL_PASS or config.cfg are handled as
#   SecureString and cleared from memory immediately after authentication.
#   Passing credentials on the command line exposes them in shell history
#   and process listings -- prefer environment variables or config file
#   for automation.
#
##############################################################################

#Requires -Version 5.1

param(
    # Auth -- pass the object returned by Get-HalcyonBearerToken.ps1
    [PSCustomObject]$AuthObject,

    # Or supply tokens directly
    [string]$AccessToken,
    [string]$TenantId,

    # Use config.cfg in the script directory for credentials
    [switch]$useConfig
)

$ErrorActionPreference = 'Stop'
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12'
}

$HAL_API = 'https://api.halcyon.ai'

##############################################################################
# Elevation check
##############################################################################

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[fail] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host " Halcyon API Installer for Windows" -ForegroundColor Cyan
Write-Host " ===================================" -ForegroundColor Cyan
Write-Host ""

##############################################################################
# Pre-flight: detect existing installation via service
##############################################################################

if (Get-Service -Name 'halcyonagent' -ErrorAction SilentlyContinue) {
    Write-Host "[warn]    Halcyon agent service is already running on this machine." -ForegroundColor Yellow
    Write-Host "[halcyon] Uninstall the existing agent before running this script." -ForegroundColor Cyan
    exit 1
}

##############################################################################
# Resolve auth
#
# Priority: -AuthObject > -AccessToken/-TenantId > -useConfig > env vars > prompt
##############################################################################

if ($AuthObject) {
    if (-not $AccessToken) { $AccessToken = $AuthObject.AccessToken }
    if (-not $TenantId)    { $TenantId    = $AuthObject.TenantId    }
}

if ($AccessToken -and $TenantId) {

    # Token expiry check -- auto-refresh if within 60 seconds of expiry
    . (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")
    $accessInfo = Get-HalcyonTokenExpiry -Token $AccessToken

    if ($accessInfo.SecondsRemaining -lt 60) {
        $refreshToken = if ($AuthObject) { $AuthObject.RefreshToken } else { $null }

        if (-not $refreshToken) {
            if ($accessInfo.IsExpired) {
                Write-Host "[warn]    Access token is expired and no RefreshToken is available." -ForegroundColor Yellow
                Write-Host "[warn]    Re-authenticate with Get-HalcyonBearerToken.ps1." -ForegroundColor Yellow
            } else {
                Write-Host "[warn]    Access token expires in $($accessInfo.SecondsRemaining)s. Pass -AuthObject to enable auto-refresh." -ForegroundColor Yellow
            }
        } else {
            $refreshInfo = Get-HalcyonTokenExpiry -Token $refreshToken
            if ($refreshInfo.IsExpired) {
                Write-Host "[fail] Both access and refresh tokens are expired. Re-authenticate." -ForegroundColor Red
                exit 1
            }
            if ($accessInfo.IsExpired) {
                Write-Host "  [TOKEN] Access token expired -- refreshing..." -ForegroundColor Yellow
            } else {
                Write-Host "  [TOKEN] Access token expires in $($accessInfo.SecondsRemaining)s -- refreshing proactively..." -ForegroundColor DarkCyan
            }
            $newAuth     = & (Join-Path $PSScriptRoot "Invoke-HalcyonTokenRefresh.ps1") `
                               -RefreshToken $refreshToken -TenantId $TenantId -silent
            $AccessToken = $newAuth.AccessToken
            if ($AuthObject) {
                $AuthObject.AccessToken      = $newAuth.AccessToken
                $AuthObject.RefreshToken     = $newAuth.RefreshToken
                $AuthObject.AccessExpiresAt  = $newAuth.AccessExpiresAt
                $AuthObject.RefreshExpiresAt = $newAuth.RefreshExpiresAt
            }
            Write-Host "  [TOKEN] Refreshed. New expiry: $($newAuth.AccessExpiresAt)" -ForegroundColor DarkCyan
        }
    }

    Write-Host "[halcyon] Step 1/4: Using provided auth token for tenant $TenantId ..." -ForegroundColor Cyan
    Write-Host "[ok]      Token accepted." -ForegroundColor Green

} else {

    # No token supplied -- authenticate fresh
    $halUser   = $null
    $plainPw   = $null

    if ($useConfig) {
        $configPath = Join-Path $PSScriptRoot "config.cfg"
        if (-not (Test-Path $configPath)) {
            Write-Host "[fail] config.cfg not found at: $configPath" -ForegroundColor Red
            exit 1
        }
        $cfg = Get-Content $configPath | Where-Object { $_ -match '=' } |
               ForEach-Object {
                   $parts = $_ -split '=', 2
                   [PSCustomObject]@{ Key = $parts[0].Trim(); Value = $parts[1].Trim() }
               }
        $halUser   = ($cfg | Where-Object Key -eq 'username').Value
        $plainPw   = ($cfg | Where-Object Key -eq 'password').Value
        $TenantId  = ($cfg | Where-Object Key -eq 'tenantId').Value
    } else {
        $halUser  = if ($env:HAL_USER)   { $env:HAL_USER }   else { Read-Host " Halcyon login email" }

        if ($env:HAL_PASS) {
            $securePw = ConvertTo-SecureString $env:HAL_PASS -AsPlainText -Force
            $env:HAL_PASS = $null
        } else {
            $securePw = Read-Host " Halcyon password" -AsSecureString
        }

        $bstr    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
        $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $TenantId = if ($env:HAL_TENANT) { $env:HAL_TENANT } else { Read-Host " Tenant ID (UUID)" }
    }

    Write-Host ""

    if ($TenantId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        Write-Host "[fail] Tenant ID does not look like a valid UUID: $TenantId" -ForegroundColor Red
        exit 1
    }

    Write-Host "[halcyon] Step 1/4: Authenticating as $halUser ..." -ForegroundColor Cyan

    $authBody = @{ username = $halUser; password = $plainPw } | ConvertTo-Json -Compress
    $plainPw  = $null

    try {
        $authResp = Invoke-RestMethod -Method Post `
            -Uri     "$HAL_API/identity/auth/login" `
            -Headers @{ 'Content-Type' = 'application/json'; 'X-TenantID' = $TenantId } `
            -Body    $authBody
    } catch {
        Write-Host "[fail] Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    $authBody    = $null
    $AccessToken = $authResp.accessToken

    if ([string]::IsNullOrEmpty($AccessToken)) {
        Write-Host "[fail] Authentication failed -- check credentials and tenant ID." -ForegroundColor Red
        exit 1
    }
    Write-Host "[ok]      Authenticated." -ForegroundColor Green
}

##############################################################################
# Step 2: Fetch installer info
##############################################################################

Write-Host "[halcyon] Step 2/4: Fetching Windows installer info ..." -ForegroundColor Cyan

$headers = @{ 'Authorization' = "Bearer $AccessToken"; 'X-TenantID' = $TenantId }

try {
    $resp = Invoke-RestMethod -Method Get `
        -Uri     "$HAL_API/v2/installers?pageSize=50" `
        -Headers $headers
} catch {
    Write-Host "[fail] Could not retrieve installer list: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$items    = if ($resp.items) { $resp.items } else { $resp.data }
if (-not $items -or $items.Count -eq 0) {
    Write-Host "[fail] API returned no installers. Check tenant configuration." -ForegroundColor Red
    exit 1
}

$winItems = $items | Where-Object { $_.installerType -ieq 'windows' }
if (-not $winItems) {
    Write-Host "[fail] No Windows installer found for this tenant." -ForegroundColor Red
    exit 1
}

$pkg = $winItems | Where-Object { $_.latestVersion -eq $_.version } | Select-Object -First 1
if (-not $pkg) { $pkg = $winItems | Select-Object -First 1 }

$downloadUrl  = $pkg.downloadUrl
$installToken = $pkg.installationToken
$agentVersion = $pkg.version

if ([string]::IsNullOrEmpty($downloadUrl) -or [string]::IsNullOrEmpty($installToken)) {
    Write-Host "[fail] Installer record is missing downloadUrl or installationToken." -ForegroundColor Red
    exit 1
}

Write-Host "[ok]      Found: $agentVersion" -ForegroundColor Green
Write-Host "[halcyon]   Token: $($installToken.Substring(0, [Math]::Min(8,$installToken.Length)))****************" -ForegroundColor Cyan

##############################################################################
# Step 3: Download
##############################################################################

Write-Host "[halcyon] Step 3/4: Downloading installer ..." -ForegroundColor Cyan

$workDir = Join-Path $env:TEMP "halcyon-$(Get-Random)"
New-Item -ItemType Directory -Path $workDir | Out-Null

$fileName = [IO.Path]::GetFileName(([uri]$downloadUrl).LocalPath)
if ($fileName -notmatch '\.(exe|msi)$') { $fileName = 'halcyon-setup.exe' }
$installerPath = Join-Path $workDir $fileName

try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
    $ProgressPreference = 'Continue'
} catch {
    Write-Host "[fail] Download failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "[ok]      Downloaded: $fileName" -ForegroundColor Green

##############################################################################
# Step 4: Install
#
# ProcessStartInfo sets the argument string verbatim, bypassing PowerShell's
# argument parsing -- required to preserve InstallShield /v"..." quoting.
##############################################################################

Write-Host "[halcyon] Step 4/4: Installing ..." -ForegroundColor Cyan
Write-Host ""

$logPath = Join-Path $workDir 'install.log'

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName         = $installerPath
$psi.Arguments        = "/s /v`"/qn /l*v `"$logPath`"`" /z`"ACCEPTEULA INSTALLTOKEN=$installToken`""
$psi.UseShellExecute  = $false
$psi.WorkingDirectory = $workDir

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.WaitForExit()
$exitCode = $proc.ExitCode

$installToken = $null

if ($exitCode -ne 0) {
    Write-Host "[warn]    Installer exited with code $exitCode." -ForegroundColor Yellow
    if (Test-Path $logPath) { Write-Host "[warn]    Log: $logPath" -ForegroundColor Yellow }
    Write-Host "[fail]    Installation may have failed -- check the log and the Halcyon console." -ForegroundColor Red
    exit 1
}

try { Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "[ok]      Halcyon agent installation complete." -ForegroundColor Green
Write-Host "[halcyon] Check Assets in your Halcyon console to confirm this device registered." -ForegroundColor Cyan
Write-Host ""
