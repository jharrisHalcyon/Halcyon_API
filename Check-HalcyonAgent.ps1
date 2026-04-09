#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the current state of the Halcyon Windows agent installation.
    Inspects service, registry, and file system.

    Author  : Jim Harris -- Halcyon SA
#>

function Write-Info  ([string]$msg) { Write-Host "[halcyon] $msg" -ForegroundColor Cyan   }
function Write-Ok    ([string]$msg) { Write-Host "[ok]      $msg" -ForegroundColor Green  }
function Write-Warn  ([string]$msg) { Write-Host "[warn]    $msg" -ForegroundColor Yellow }
function Write-Miss  ([string]$msg) { Write-Host "[--]      $msg" -ForegroundColor DarkGray }

Write-Host ""
Write-Host " Halcyon Agent State Check"
Write-Host " =========================="
Write-Host ""

$halcyonGuid = '{7A334500-AF25-4563-B67D-2F81EB315377}'
$found = 0

# ------------------------------------------------------------------ #
# Services
# ------------------------------------------------------------------ #
Write-Info "Services"
foreach ($svc in @('halcyonagent', 'halcyonar')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        Write-Ok   "  $svc -- Status: $($s.Status)  StartType: $($s.StartType)"
        $found++
    } else {
        Write-Miss "  $svc -- not found"
    }
}

# ------------------------------------------------------------------ #
# Registry
# ------------------------------------------------------------------ #
Write-Host ""
Write-Info "Registry"
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$halcyonGuid",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$halcyonGuid",
    "HKLM:\SOFTWARE\Halcyon",
    "HKLM:\SYSTEM\CurrentControlSet\Services\halcyonagent",
    "HKLM:\SYSTEM\CurrentControlSet\Services\halcyonar"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $ver = (Get-ItemProperty $rp -ErrorAction SilentlyContinue).DisplayVersion
        $label = if ($ver) { " (v$ver)" } else { "" }
        Write-Ok   "  PRESENT$label -- $rp"
        $found++
    } else {
        Write-Miss "  absent  -- $rp"
    }
}

# ------------------------------------------------------------------ #
# File system
# ------------------------------------------------------------------ #
Write-Host ""
Write-Info "File System"
$paths = @(
    "C:\Program Files\Halcyon",
    "C:\Program Files (x86)\InstallShield Installation Information\$halcyonGuid",
    "C:\ProgramData\Halcyon",
    "C:\ProgramData\Halcyon\HalcyonAR\logs"
)
foreach ($p in $paths) {
    if (Test-Path $p) {
        $count = (Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Ok   "  PRESENT ($count items) -- $p"
        $found++
    } else {
        Write-Miss "  absent  -- $p"
    }
}

# ------------------------------------------------------------------ #
# Driver
# ------------------------------------------------------------------ #
Write-Host ""
Write-Info "Driver"
$driver = Get-WmiObject Win32_SystemDriver -Filter "Name='halcyonar'" -ErrorAction SilentlyContinue
if ($driver) {
    Write-Ok  "  halcyonar driver -- State: $($driver.State)  StartMode: $($driver.StartMode)"
    $found++
} else {
    Write-Miss "  halcyonar driver -- not found"
}

# ------------------------------------------------------------------ #
# Summary
# ------------------------------------------------------------------ #
Write-Host ""
if ($found -eq 0) {
    Write-Ok "No Halcyon agent artifacts found. Machine appears clean."
} else {
    Write-Warn "$found artifact(s) present. See above for details."
}
Write-Host ""
