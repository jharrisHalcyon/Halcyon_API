##############################################################################
# Uninstall-HalcyonAgent.ps1
# Author  : Jim Harris -- Halcyon Solutions Architect
# Date    : 2026-04-09
# Version : v1.4
#
# Silently uninstalls the Halcyon Windows agent, cleans up leftover files
# and registry keys, and optionally removes the device record from the
# Halcyon console via the API.
#
# PREREQUISITE: Tamper Guard must be disabled in the Halcyon console and
# the policy change must have propagated to the agent before running this
# script. To verify propagation, check the agent log for a recent
# UpdatePolicy entry:
#   C:\ProgramData\Halcyon\HalcyonAR\logs\agent.log
#
# Source Cache:
#   InstallShield requires the original setup EXE to be present at:
#   %LOCALAPPDATA%\Downloaded Installations\{EC26187D-45B0-4831-8824-F97450D4E231}\
#   This is maintained automatically by Windows Installer. If it is missing,
#   this script will offer to download the installer from the Halcyon API
#   and restore it.
#
# Console Removal:
#   When prompted, this script removes all console registrations matching
#   this machine's hostname. Requires the Halcyon API toolkit scripts to be
#   present in the same directory:
#     Get-HalcyonBearerToken.ps1
#     Get-HalcyonDevices.ps1
#     Remove-HalcyonDevice.ps1
#
# Usage:
#
#   Interactive:
#     .\Uninstall-HalcyonAgent.ps1
#
#   Via auth object from Get-HalcyonBearerToken.ps1:
#     $auth = .\Get-HalcyonBearerToken.ps1
#     .\Uninstall-HalcyonAgent.ps1 -AuthObject $auth
#
#   Via tokens directly:
#     .\Uninstall-HalcyonAgent.ps1 -AccessToken $token -TenantId $tid
#
#   Via environment variables:
#     $env:HAL_USER   = 'admin@example.com'
#     $env:HAL_PASS   = 'yourpassword'
#     $env:HAL_TENANT = '0546ca62-47db-4319-a89e-647764941bcf'
#     .\Uninstall-HalcyonAgent.ps1
#
#   Via config file:
#     .\Uninstall-HalcyonAgent.ps1 -useConfig
#
#   Skip console removal prompt:
#     .\Uninstall-HalcyonAgent.ps1 -SkipConsoleRemoval
#
# Requires:
#   PowerShell 5.1+
#   Elevated (Administrator) prompt
#   Tamper Guard disabled in Halcyon console (policy propagated to agent)
#   ConvertFrom-HalcyonJwt.ps1 (same directory -- token expiry checks)
#   Invoke-HalcyonTokenRefresh.ps1 (same directory -- auto-refresh)
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
    [switch]$useConfig,

    # Skip the console removal prompt entirely
    [switch]$SkipConsoleRemoval
)

$ErrorActionPreference = 'Stop'
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12'
}

$HAL_API        = 'https://api.halcyon.ai'
$halcyonGuid    = '{7A334500-AF25-4563-B67D-2F81EB315377}'
$sourceGuid     = '{EC26187D-45B0-4831-8824-F97450D4E231}'
$sourceCacheDir = "$env:LOCALAPPDATA\Downloaded Installations\$sourceGuid"

##############################################################################
# Elevation check
##############################################################################

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[fail] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host " Halcyon Agent Uninstaller  v1.4" -ForegroundColor Cyan
Write-Host " =================================" -ForegroundColor Cyan
Write-Host ""

##############################################################################
# Confirm agent is present
##############################################################################

if (-not (Get-Service -Name 'halcyonagent' -ErrorAction SilentlyContinue)) {
    Write-Host "[warn]    Halcyon agent service not found -- agent may not be installed." -ForegroundColor Yellow
    exit 0
}

$displayVersion = $null
foreach ($rp in @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$halcyonGuid",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$halcyonGuid"
)) {
    if (Test-Path $rp) {
        $displayVersion = (Get-ItemProperty $rp -ErrorAction SilentlyContinue).DisplayVersion
        break
    }
}

$versionLabel = if ($displayVersion) { "version $displayVersion" } else { "version unknown" }
Write-Host "[halcyon] Found Halcyon agent ($versionLabel)." -ForegroundColor Cyan

##############################################################################
# Tamper Guard confirmation
##############################################################################

Write-Host ""
Write-Host "[warn]    PREREQUISITE: Tamper Guard must be disabled in the Halcyon console" -ForegroundColor Yellow
Write-Host "[warn]    and the policy change must have propagated to this agent before" -ForegroundColor Yellow
Write-Host "[warn]    proceeding. Check the agent log for a recent UpdatePolicy entry:" -ForegroundColor Yellow
Write-Host "[warn]    C:\ProgramData\Halcyon\HalcyonAR\logs\agent.log" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host " Tamper Guard is disabled and propagated. Continue? [y/N]"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "[halcyon] Aborted." -ForegroundColor Cyan
    exit 0
}

##############################################################################
# Resolve auth
#
# Auth is used for two optional steps: downloading the installer if the
# source cache is missing, and removing the device from the console.
# We resolve credentials now so both steps can share the same token.
#
# Priority: -AuthObject > -AccessToken/-TenantId > -useConfig > env vars > prompt
##############################################################################

$authResolved = $false

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

    $authResolved = $true

} elseif ($useConfig -or $env:HAL_USER -or $env:HAL_PASS -or $env:HAL_TENANT) {

    # Resolve from config or env vars -- authenticate now so the token is
    # ready for both the source cache download and console removal steps
    $halUser  = $null
    $plainPw  = $null

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
        $halUser  = ($cfg | Where-Object Key -eq 'username').Value
        $plainPw  = ($cfg | Where-Object Key -eq 'password').Value
        $TenantId = ($cfg | Where-Object Key -eq 'tenantId').Value
    } else {
        $halUser  = if ($env:HAL_USER)   { $env:HAL_USER }   else { $null }
        $TenantId = if ($env:HAL_TENANT) { $env:HAL_TENANT } else { $null }
        if ($env:HAL_PASS) {
            $securePw = ConvertTo-SecureString $env:HAL_PASS -AsPlainText -Force
            $env:HAL_PASS = $null
            $bstr    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
            $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    if ($halUser -and $plainPw -and $TenantId) {
        Write-Host ""
        Write-Host "[halcyon] Authenticating as $halUser ..." -ForegroundColor Cyan
        $authBody = @{ username = $halUser; password = $plainPw } | ConvertTo-Json -Compress
        $plainPw  = $null
        try {
            $authResp    = Invoke-RestMethod -Method Post `
                -Uri     "$HAL_API/identity/auth/login" `
                -Headers @{ 'Content-Type' = 'application/json'; 'X-TenantID' = $TenantId } `
                -Body    $authBody
            $AccessToken = $authResp.accessToken
            $authResolved = $true
            Write-Host "[ok]      Authenticated." -ForegroundColor Green
        } catch {
            Write-Host "[warn]    Authentication failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "[warn]    API-dependent steps will be skipped." -ForegroundColor Yellow
        }
        $authBody = $null
    }
}

##############################################################################
# Source cache check
#
# InstallShield requires the original setup EXE at the Downloaded Installations
# path or it silently no-ops. If missing, offer to download via the API.
##############################################################################

Write-Host ""

$uninstallerExe = Get-ChildItem $sourceCacheDir -Filter "*.exe" -ErrorAction SilentlyContinue |
                  Select-Object -First 1

if (-not $uninstallerExe) {
    Write-Host "[warn]    Installer source cache not found at:" -ForegroundColor Yellow
    Write-Host "[warn]    $sourceCacheDir" -ForegroundColor Yellow
    Write-Host "[warn]    InstallShield requires this to be present or the uninstaller will" -ForegroundColor Yellow
    Write-Host "[warn]    silently do nothing." -ForegroundColor Yellow
    Write-Host ""

    $doDownload = Read-Host " Download the installer from the Halcyon API now? [y/N]"

    if ($doDownload -notmatch '^[Yy]') {
        Write-Host ""
        Write-Host "[halcyon] To restore manually, log into https://console.halcyon.ai," -ForegroundColor Cyan
        Write-Host "[halcyon] navigate to Deploy, download the Windows installer, and place it at:" -ForegroundColor Cyan
        Write-Host "[halcyon] $sourceCacheDir" -ForegroundColor Cyan
        Write-Host "[halcyon] Then re-run this script." -ForegroundColor Cyan
        exit 0
    }

    # If we don't have a token yet, prompt now
    if (-not $authResolved) {
        Write-Host ""
        $halUser  = Read-Host " Halcyon login email"
        $securePw = Read-Host " Halcyon password" -AsSecureString
        $TenantId = Read-Host " Tenant ID (UUID)"

        $bstr    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
        $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        if ($TenantId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            Write-Host "[fail] Tenant ID does not look like a valid UUID: $TenantId" -ForegroundColor Red
            exit 1
        }

        Write-Host ""
        Write-Host "[halcyon] Authenticating ..." -ForegroundColor Cyan
        $authBody = @{ username = $halUser; password = $plainPw } | ConvertTo-Json -Compress
        $plainPw  = $null
        try {
            $authResp    = Invoke-RestMethod -Method Post `
                -Uri     "$HAL_API/identity/auth/login" `
                -Headers @{ 'Content-Type' = 'application/json'; 'X-TenantID' = $TenantId } `
                -Body    $authBody
            $AccessToken = $authResp.accessToken
            $authResolved = $true
        } catch {
            Write-Host "[fail] Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
        $authBody = $null
        Write-Host "[ok]      Authenticated." -ForegroundColor Green
    }

    # Fetch installer download URL
    Write-Host "[halcyon] Fetching installer info ..." -ForegroundColor Cyan
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
    $winItems = $items | Where-Object { $_.installerType -ieq 'windows' }
    if (-not $winItems) {
        Write-Host "[fail] No Windows installer found for this tenant." -ForegroundColor Red
        exit 1
    }

    $pkg = $winItems | Where-Object { $_.latestVersion -eq $_.version } | Select-Object -First 1
    if (-not $pkg) { $pkg = $winItems | Select-Object -First 1 }

    $downloadUrl = $pkg.downloadUrl
    if ([string]::IsNullOrEmpty($downloadUrl)) {
        Write-Host "[fail] No download URL in installer record." -ForegroundColor Red
        exit 1
    }

    Write-Host "[halcyon] Downloading installer to source cache ..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $sourceCacheDir -Force | Out-Null

    $fileName = [IO.Path]::GetFileName(([uri]$downloadUrl).LocalPath)
    if ($fileName -notmatch '\.(exe|msi)$') { $fileName = 'halcyon-setup.exe' }
    $destPath = Join-Path $sourceCacheDir $fileName

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $downloadUrl -OutFile $destPath -UseBasicParsing
        $ProgressPreference = 'Continue'
    } catch {
        Write-Host "[fail] Download failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    Write-Host "[ok]      Downloaded: $fileName" -ForegroundColor Green
    $uninstallerExe = Get-Item $destPath
}

##############################################################################
# Uninstall
#
# ProcessStartInfo sets the argument string verbatim, bypassing PowerShell's
# argument parsing -- required to preserve InstallShield /v"..." quoting.
##############################################################################

Write-Host ""
Write-Host "[halcyon] Running uninstaller from: $($uninstallerExe.FullName)" -ForegroundColor Cyan

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName         = $uninstallerExe.FullName
$psi.Arguments        = '/s /v"/qn" -uninst'
$psi.UseShellExecute  = $false
$psi.WorkingDirectory = $uninstallerExe.DirectoryName

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.WaitForExit()
$exitCode = $proc.ExitCode

if ($exitCode -ne 0) {
    Write-Host ""
    Write-Host "[warn]    Uninstaller exited with code $exitCode." -ForegroundColor Yellow
    Write-Host "[warn]    This usually means Tamper Guard is still active or has not" -ForegroundColor Yellow
    Write-Host "[warn]    propagated to the agent yet. Check the agent log:" -ForegroundColor Yellow
    Write-Host "[warn]    C:\ProgramData\Halcyon\HalcyonAR\logs\agent.log" -ForegroundColor Yellow
    Write-Host "[fail]    Uninstall failed." -ForegroundColor Red
    exit 1
}

Write-Host "[ok]      Uninstaller completed." -ForegroundColor Green

##############################################################################
# Kill halcyonUI.exe -- the tray process survives the uninstaller
##############################################################################

if (Get-Process -Name 'halcyonUI' -ErrorAction SilentlyContinue) {
    Write-Host "[halcyon] Stopping halcyonUI.exe ..." -ForegroundColor Cyan
    Stop-Process -Name 'halcyonUI' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "[ok]      halcyonUI.exe stopped." -ForegroundColor Green
}

##############################################################################
# Wait for services to fully stop
##############################################################################

Write-Host "[halcyon] Waiting for services to stop ..." -ForegroundColor Cyan
Start-Sleep -Seconds 10

##############################################################################
# Cleanup -- files and registry left behind after uninstall
##############################################################################

Write-Host ""
Write-Host "[halcyon] Cleaning up leftover artifacts ..." -ForegroundColor Cyan

# File system
foreach ($p in @(
    "C:\Program Files\Halcyon",
    "C:\ProgramData\Halcyon",
    "C:\Program Files (x86)\InstallShield Installation Information\$halcyonGuid",
    "C:\Windows\System32\drivers\halcyondrvr.sys"
)) {
    if (Test-Path $p) {
        try {
            Remove-Item $p -Recurse -Force -ErrorAction Stop
            Write-Host "[ok]        Removed: $p" -ForegroundColor Green
        } catch {
            Write-Host "[warn]      Could not remove: $p -- $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Registry -- known keys
foreach ($k in @(
    "HKLM:\SOFTWARE\Halcyon",
    "HKLM:\SYSTEM\CurrentControlSet\Services\halcyonagent",
    "HKLM:\SYSTEM\CurrentControlSet\Services\halcyonar",
    "HKCR:\Installer\Products\005433A752FA36546BD7F218BE133577",
    "HKCR:\Installer\Features\005433A752FA36546BD7F218BE133577"
)) {
    if (Test-Path $k) {
        try {
            Remove-Item $k -Recurse -Force -ErrorAction Stop
            Write-Host "[ok]        Removed: $k" -ForegroundColor Green
        } catch {
            Write-Host "[warn]      Could not remove: $k -- $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Registry -- uninstall hive scan by DisplayName
# StrictMode off for property access on registry items that may lack DisplayName
Set-StrictMode -Off
foreach ($hive in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)) {
    if (Test-Path $hive) {
        foreach ($key in (Get-ChildItem $hive -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if ($props -and $props.DisplayName -and $props.DisplayName -match '^Halcyon') {
                try {
                    Remove-Item $key.PSPath -Recurse -Force -ErrorAction Stop
                    Write-Host "[ok]        Removed uninstall key: $($key.PSPath)" -ForegroundColor Green
                } catch {
                    Write-Host "[warn]      Could not remove: $($key.PSPath) -- $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
}
Set-StrictMode -Version Latest

Write-Host "[ok]      Cleanup complete." -ForegroundColor Green

##############################################################################
# Console removal
#
# Removes all console registrations matching this machine's hostname.
# All registrations are removed -- if the agent is being uninstalled, every
# registration for this hostname is by definition stale.
##############################################################################

if ($SkipConsoleRemoval) {
    Write-Host ""
    Write-Host "[halcyon] Skipping console removal (-SkipConsoleRemoval set)." -ForegroundColor Cyan
} else {
    Write-Host ""
    $doRemove = Read-Host " Remove this device from the Halcyon console? [y/N]"

    if ($doRemove -match '^[Yy]') {
        $requiredTools = @(
            'Get-HalcyonBearerToken.ps1',
            'Get-HalcyonDevices.ps1',
            'Remove-HalcyonDevice.ps1'
        )
        $missingTools = $requiredTools | Where-Object {
            -not (Test-Path (Join-Path $PSScriptRoot $_))
        }

        if ($missingTools) {
            Write-Host "[warn]    API toolkit scripts not found in script directory:" -ForegroundColor Yellow
            $missingTools | ForEach-Object { Write-Host "[warn]      Missing: $_" -ForegroundColor Yellow }
            Write-Host "[warn]    Clone the Halcyon API toolkit alongside this script, or" -ForegroundColor Yellow
            Write-Host "[warn]    remove the device manually at https://console.halcyon.ai" -ForegroundColor Yellow
        } else {
            Write-Host ""

            # Use existing token if we have one, otherwise let Get-HalcyonBearerToken prompt
            Set-StrictMode -Off
            if ($AuthObject) {
                Write-Host "[halcyon] Using existing auth token for console removal ..." -ForegroundColor Cyan
                $consoleAuth = $AuthObject
            } elseif ($authResolved -and $AccessToken -and $TenantId) {
                Write-Host "[halcyon] Using existing auth token for console removal ..." -ForegroundColor Cyan
                $consoleAuth = $null  # pass tokens directly below
            } else {
                Write-Host "[halcyon] Authenticating to Halcyon API ..." -ForegroundColor Cyan
                $consoleAuth = & "$PSScriptRoot\Get-HalcyonBearerToken.ps1" -silent
            }

            Write-Host "[halcyon] Searching for device: $env:COMPUTERNAME ..." -ForegroundColor Cyan
            if ($consoleAuth) {
                $devices = @(& "$PSScriptRoot\Get-HalcyonDevices.ps1" -AuthObject $consoleAuth `
                               -Name $env:COMPUTERNAME -silent)
            } else {
                $devices = @(& "$PSScriptRoot\Get-HalcyonDevices.ps1" `
                               -AccessToken $AccessToken -TenantId $TenantId `
                               -Name $env:COMPUTERNAME -silent)
            }
            Set-StrictMode -Version Latest

            if (-not $devices -or $devices.Count -eq 0) {
                Write-Host "[warn]    No device found matching '$env:COMPUTERNAME' in the console." -ForegroundColor Yellow
                Write-Host "[warn]    Remove it manually at https://console.halcyon.ai" -ForegroundColor Yellow
            } else {
                Write-Host "[halcyon] Found $($devices.Count) registration(s) for '$env:COMPUTERNAME' -- removing all." -ForegroundColor Cyan
                Set-StrictMode -Off
                foreach ($device in $devices) {
                    Write-Host "[halcyon]   Removing: $($device.id)  registered: $($device.registered_date)" -ForegroundColor Cyan
                    if ($consoleAuth) {
                        & "$PSScriptRoot\Remove-HalcyonDevice.ps1" -AuthObject $consoleAuth `
                            -DeviceId $device.id -Confirm:$false -silent
                    } else {
                        & "$PSScriptRoot\Remove-HalcyonDevice.ps1" `
                            -AccessToken $AccessToken -TenantId $TenantId `
                            -DeviceId $device.id -Confirm:$false -silent
                    }
                }
                Set-StrictMode -Version Latest
                Write-Host "[ok]      All console registrations removed." -ForegroundColor Green
            }
        }
    }
}

##############################################################################
# Done
##############################################################################

Write-Host ""
Write-Host "[ok]      Halcyon agent uninstall complete." -ForegroundColor Green
Write-Host "[halcyon] A reboot is recommended to finish removing the kernel driver." -ForegroundColor Cyan
Write-Host ""
