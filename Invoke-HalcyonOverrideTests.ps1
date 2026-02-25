##############################################################################
# Invoke-HalcyonOverrideTests.ps1
# Author  : Jim Harris -- Halcyon SA
# Date    : 2026-02-24
# Version : v1.1
#
# Test harness for Halcyon override creation and deletion.
# Exercises four confirmed override types against a live tenant:
#
#   Test 1 -- Certificate (Allow)
#     Creates a self-signed certificate in the local cert store, extracts
#     the thumbprint, creates a Certificate override, pauses for console
#     verification, then deletes the override and removes the test cert.
#
#   Test 2 -- File / Hash (Allow)
#     Uses a known benign SHA256 value to create a File override, pauses,
#     then deletes it.
#
#   Test 3 -- Monitor (File + Bypass)
#     Uses a known benign SHA256 value to create a Monitor (Bypass) override,
#     pauses, then deletes it.
#
#   Test 4 -- Multi-line note
#     Creates a Certificate override using backtick-n newlines in the -Note
#     parameter. Pauses so you can verify the note renders as separate lines
#     in the console, then deletes it. Validates that \n (backslash-n) is
#     NOT treated as a newline -- the literal string is submitted and the
#     console should show it as-is with no line break.
#
# Token management:
#   Before every API call the script checks the access token TTL. If fewer
#   than 60 seconds remain it attempts a silent refresh using the refresh
#   token. If the refresh token has also expired it stops and prompts for
#   re-authentication via Get-HalcyonBearerToken.ps1.
#
# Output:
#   All output is written to the console AND to a timestamped log file in
#   the same directory as this script. The log file can be shared directly.
#
# Usage:
#   $auth = .\Get-HalcyonBearerToken.ps1
#   .\Invoke-HalcyonOverrideTests.ps1 -AuthObject $auth
#
#   Skip specific tests:
#   .\Invoke-HalcyonOverrideTests.ps1 -AuthObject $auth -SkipCertTest
#   .\Invoke-HalcyonOverrideTests.ps1 -AuthObject $auth -SkipFileTest
#   .\Invoke-HalcyonOverrideTests.ps1 -AuthObject $auth -SkipMonitorTest
#   .\Invoke-HalcyonOverrideTests.ps1 -AuthObject $auth -SkipNoteTest
#
# Requires:
#   PowerShell 5.1+
#   Valid Halcyon service account credentials (non-SSO)
#   RBAC role: Admin (delete requires Admin; create requires PowerUser or Admin)
#   ConvertFrom-HalcyonJwt.ps1 in the same directory
#   New-HalcyonOverride.ps1 in the same directory
#   Remove-HalcyonOverride.ps1 in the same directory
#
##############################################################################

#Requires -Version 5.1

[CmdletBinding()]
param(
    [PSCustomObject]$AuthObject,
    [string]$AccessToken,
    [string]$TenantId,

    [switch]$SkipCertTest,
    [switch]$SkipFileTest,
    [switch]$SkipMonitorTest,
    [switch]$SkipNoteTest
)

$ErrorActionPreference = "Stop"

# Dot-source JWT helper for token TTL checking
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")

##############################################################################
# Logging -- all output goes to console AND log file simultaneously
##############################################################################

$LogPath = Join-Path $PSScriptRoot "HalcyonOverrideTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White",
        [switch]$NoNewline
    )
    # Console
    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $ForegroundColor -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    # Log file -- strip color, add timestamp for clarity
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp  $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function Write-LogSeparator {
    Write-Log "----------------------------------------------------------------------"
}

function Write-LogCommand {
    param([string]$Command)
    Write-Log ""
    Write-Log "  COMMAND: $Command" -ForegroundColor Yellow
    Write-Log ""
}

##############################################################################
# Token management
##############################################################################

function Assert-ValidToken {
    param([PSCustomObject]$Auth)

    try {
        $info = Get-HalcyonTokenExpiry -Token $Auth.AccessToken -Label "Access Token"

        if ($info.IsExpired -or $info.SecondsRemaining -lt 60) {
            Write-Log "  [TOKEN] Access token expiring in $($info.SecondsRemaining)s -- refreshing silently..." -ForegroundColor Yellow

            # Check refresh token is still valid
            $refreshInfo = Get-HalcyonTokenExpiry -Token $Auth.RefreshToken -Label "Refresh Token"
            if ($refreshInfo.IsExpired) {
                Write-Log ""
                Write-Log "  [TOKEN] Refresh token has also expired. Re-authentication required." -ForegroundColor Red
                Write-Log "  Run: `$auth = .\Get-HalcyonBearerToken.ps1" -ForegroundColor Yellow
                Write-Log ""
                throw "Both tokens expired -- re-authentication required."
            }

            # Silent refresh
            $headers = @{
                "Content-Type" = "application/json"
                "X-TenantID"   = $Auth.TenantId
            }
            $body = @{ refreshToken = $Auth.RefreshToken } | ConvertTo-Json
            $response = Invoke-RestMethod -Method Post `
                -Uri "https://api.halcyon.ai/identity/auth/refresh" `
                -Headers $headers -Body $body

            $newInfo = Get-HalcyonTokenExpiry -Token $response.accessToken -Label "Access Token"
            Write-Log "  [TOKEN] Refreshed. New access token expires at $($newInfo.ExpiresAt)" -ForegroundColor Green

            return [PSCustomObject]@{
                AccessToken      = $response.accessToken
                RefreshToken     = $response.refreshToken
                TenantId         = $Auth.TenantId
                AccessExpiresAt  = $newInfo.ExpiresAt
                RefreshExpiresAt = (Get-HalcyonTokenExpiry -Token $response.refreshToken).ExpiresAt
            }
        }
    }
    catch {
        if ($_ -match "re-authentication required") { throw }
        Write-Log "  [TOKEN] Could not check TTL: $_ -- proceeding anyway." -ForegroundColor Yellow
    }

    return $Auth
}

##############################################################################
# Pause helper -- waits for Enter, handles token refresh on resume
##############################################################################

function Invoke-Pause {
    param(
        [string]$Message,
        [PSCustomObject]$Auth
    )
    Write-Log ""
    Write-Log "  >>> $Message" -ForegroundColor Cyan
    Write-Log "      Press Enter to continue..." -ForegroundColor Cyan
    # Log the pause without waiting
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  [PAUSED] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8

    $null = Read-Host

    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  [RESUMED]" | Out-File -FilePath $LogPath -Append -Encoding UTF8

    # Refresh token silently on resume if needed
    return (Assert-ValidToken -Auth $Auth)
}

##############################################################################
# Test result tracking
##############################################################################

$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Step,
        [bool]$Passed,
        [string]$Detail = ""
    )
    $testResults.Add([PSCustomObject]@{
        TestName = $TestName
        Step     = $Step
        Passed   = $Passed
        Detail   = $Detail
        Time     = (Get-Date -Format "HH:mm:ss")
    })
}

##############################################################################
# Resolve auth
##############################################################################

if ($AuthObject) {
    if (-not $AccessToken) { $AccessToken = $AuthObject.AccessToken }
    if (-not $TenantId)    { $TenantId    = $AuthObject.TenantId    }
}
if (-not $AccessToken -or -not $TenantId) {
    Write-Error "Auth required. Pass -AuthObject from Get-HalcyonBearerToken.ps1."
}

# Work with a local copy so we can update tokens between tests
$auth = [PSCustomObject]@{
    AccessToken  = $AccessToken
    RefreshToken = if ($AuthObject) { $AuthObject.RefreshToken } else { $null }
    TenantId     = $TenantId
}

##############################################################################
# Banner
##############################################################################

Write-Log ""
Write-Log "======================================================================"
Write-Log "  Halcyon Override API Test Harness" -ForegroundColor Cyan
Write-Log "  $(Get-Date -Format 'dddd, MMMM dd yyyy  HH:mm:ss')" -ForegroundColor Cyan
Write-Log "  Tenant  : $TenantId"
Write-Log "  Log     : $LogPath"
Write-Log "======================================================================"
Write-Log ""

##############################################################################
# TEST 1 -- Certificate override (Allow)
##############################################################################

if (-not $SkipCertTest) {

    Write-Log ""
    Write-Log "======================================================================"
    Write-Log "  TEST 1 of 3 -- Certificate Override (Allow)" -ForegroundColor Cyan
    Write-Log "======================================================================"

    $certThumbprint = $null
    $certStoreEntry = $null
    $overrideId     = $null

    try {
        # --- Create self-signed cert ---
        Write-Log ""
        Write-Log "  [SETUP] Generating self-signed test certificate..."

        $certCommand = 'New-SelfSignedCertificate -Subject "CN=HalcyonAPITest" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(1)'
        Write-LogCommand $certCommand

        $auth = Assert-ValidToken -Auth $auth
        $certStoreEntry = New-SelfSignedCertificate `
            -Subject "CN=HalcyonAPITest" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddDays(1)

        $certThumbprint = $certStoreEntry.Thumbprint.ToLower()
        Write-Log "  [SETUP] Certificate created. Thumbprint: $certThumbprint" -ForegroundColor Green
        Add-TestResult "Certificate" "Setup -- create self-signed cert" $true $certThumbprint

        # --- Create override ---
        Write-Log ""
        Write-Log "  [ADD] Creating Certificate override (Allow, Tenant scope)..."

        $addCommand = ".\New-HalcyonOverride.ps1 -AuthObject `$auth -Kind Certificate -Thumbprint `"$certThumbprint`" -Note `"Halcyon API test harness -- safe to delete`""
        Write-LogCommand $addCommand

        $auth = Assert-ValidToken -Auth $auth

        $addResult = & (Join-Path $PSScriptRoot "New-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -Kind        Certificate `
            -Thumbprint  $certThumbprint `
            -Note        "Halcyon API test harness -- safe to delete" `
            -Confirm:$false

        $overrideId = $addResult.id
        Write-Log ""
        Write-Log "  [ADD] Override created. ID: $overrideId  |  CreatedAt: $($addResult.createdAt)" -ForegroundColor Green
        Add-TestResult "Certificate" "Add override" $true "Override ID: $overrideId"

        # --- Pause for console verification ---
        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 1 ADD complete. Check the console Certificate tab for thumbprint: $certThumbprint"

        # --- Delete override ---
        Write-Log ""
        Write-Log "  [REMOVE] Deleting Certificate override ID $overrideId..."

        $removeCommand = ".\Remove-HalcyonOverride.ps1 -AuthObject `$auth -OverrideId $overrideId"
        Write-LogCommand $removeCommand

        $auth = Assert-ValidToken -Auth $auth

        & (Join-Path $PSScriptRoot "Remove-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -OverrideId  $overrideId `
            -Confirm:$false

        Write-Log "  [REMOVE] Override $overrideId deleted." -ForegroundColor Green
        Add-TestResult "Certificate" "Remove override" $true "Override ID: $overrideId"

        # --- Pause for console verification ---
        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 1 REMOVE complete. Verify the override is gone from the console Certificate tab."

    }
    catch {
        Write-Log ""
        Write-Log "  [FAIL] Test 1 error: $_" -ForegroundColor Red
        Add-TestResult "Certificate" "Error" $false "$_"
    }
    finally {
        # Clean up cert from store regardless of test outcome
        if ($certStoreEntry) {
            try {
                Remove-Item -Path "Cert:\CurrentUser\My\$($certStoreEntry.Thumbprint)" -ErrorAction Stop
                Write-Log "  [CLEANUP] Test certificate removed from cert store." -ForegroundColor DarkCyan
            }
            catch {
                Write-Log "  [CLEANUP] Could not remove test cert from store: $_ -- remove manually from Cert:\CurrentUser\My\$($certStoreEntry.Thumbprint)" -ForegroundColor Yellow
            }
        }
    }
}
else {
    Write-Log "  [SKIP] Test 1 -- Certificate (skipped via -SkipCertTest)" -ForegroundColor DarkCyan
}

##############################################################################
# TEST 2 -- File / Hash override (Allow)
##############################################################################

if (-not $SkipFileTest) {

    Write-Log ""
    Write-Log "======================================================================"
    Write-Log "  TEST 2 of 3 -- File / Hash Override (Allow)" -ForegroundColor Cyan
    Write-Log "======================================================================"

    # Benign test SHA256 -- all zeros is not a real file hash and will not match
    # anything in your environment but is valid format for API testing
    $testSha256 = "0" * 64
    $overrideId  = $null

    try {
        Write-Log ""
        Write-Log "  [ADD] Creating File override (Allow, Tenant scope)..."
        Write-Log "  Note: Using a synthetic all-zero SHA256 -- safe for testing, matches no real file."

        $addCommand = ".\New-HalcyonOverride.ps1 -AuthObject `$auth -Kind File -Sha256 `"$testSha256`" -Action Allow -Note `"Halcyon API test harness -- safe to delete`""
        Write-LogCommand $addCommand

        $auth = Assert-ValidToken -Auth $auth

        $addResult = & (Join-Path $PSScriptRoot "New-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -Kind        File `
            -Sha256      $testSha256 `
            -Action      Allow `
            -Note        "Halcyon API test harness -- safe to delete" `
            -Confirm:$false

        $overrideId = $addResult.id
        Write-Log ""
        Write-Log "  [ADD] Override created. ID: $overrideId  |  CreatedAt: $($addResult.createdAt)" -ForegroundColor Green
        Add-TestResult "File" "Add override" $true "Override ID: $overrideId  SHA256: $testSha256"

        # --- Pause ---
        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 2 ADD complete. Check the console Hash tab for SHA256 starting with 00000000."

        # --- Delete ---
        Write-Log ""
        Write-Log "  [REMOVE] Deleting File override ID $overrideId..."

        $removeCommand = ".\Remove-HalcyonOverride.ps1 -AuthObject `$auth -OverrideId $overrideId"
        Write-LogCommand $removeCommand

        $auth = Assert-ValidToken -Auth $auth

        & (Join-Path $PSScriptRoot "Remove-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -OverrideId  $overrideId `
            -Confirm:$false

        Write-Log "  [REMOVE] Override $overrideId deleted." -ForegroundColor Green
        Add-TestResult "File" "Remove override" $true "Override ID: $overrideId"

        # --- Pause ---
        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 2 REMOVE complete. Verify the override is gone from the console Hash tab."

    }
    catch {
        Write-Log ""
        Write-Log "  [FAIL] Test 2 error: $_" -ForegroundColor Red
        Add-TestResult "File" "Error" $false "$_"
    }
}
else {
    Write-Log "  [SKIP] Test 2 -- File/Hash (skipped via -SkipFileTest)" -ForegroundColor DarkCyan
}

##############################################################################
# TEST 3 -- Monitor override (File + Bypass)
##############################################################################

if (-not $SkipMonitorTest) {

    Write-Log ""
    Write-Log "======================================================================"
    Write-Log "  TEST 3 of 3 -- Monitor Override (File + Bypass)" -ForegroundColor Cyan
    Write-Log "======================================================================"

    # Different synthetic hash so it does not conflict with Test 2
    $testSha256 = "f" * 64
    $overrideId  = $null

    try {
        Write-Log ""
        Write-Log "  [ADD] Creating Monitor override (Bypass, Tenant scope)..."
        Write-Log "  Note: Using a synthetic all-F SHA256 -- safe for testing, matches no real file."
        Write-Log "  Note: At the API level this is kind=File + action=Bypass (console Monitor tab)."

        $addCommand = ".\New-HalcyonOverride.ps1 -AuthObject `$auth -Kind Monitor -Sha256 `"$testSha256`" -Note `"Halcyon API test harness -- safe to delete`""
        Write-LogCommand $addCommand

        $auth = Assert-ValidToken -Auth $auth

        $addResult = & (Join-Path $PSScriptRoot "New-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -Kind        Monitor `
            -Sha256      $testSha256 `
            -Note        "Halcyon API test harness -- safe to delete" `
            -Confirm:$false

        $overrideId = $addResult.id
        Write-Log ""
        Write-Log "  [ADD] Override created. ID: $overrideId  |  CreatedAt: $($addResult.createdAt)" -ForegroundColor Green
        Add-TestResult "Monitor" "Add override" $true "Override ID: $overrideId  SHA256: $testSha256"

        # --- Pause ---
        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 3 ADD complete. Check the console Monitor tab for SHA256 starting with ffffffff."

        # --- Delete ---
        Write-Log ""
        Write-Log "  [REMOVE] Deleting Monitor override ID $overrideId..."

        $removeCommand = ".\Remove-HalcyonOverride.ps1 -AuthObject `$auth -OverrideId $overrideId"
        Write-LogCommand $removeCommand

        $auth = Assert-ValidToken -Auth $auth

        & (Join-Path $PSScriptRoot "Remove-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -OverrideId  $overrideId `
            -Confirm:$false

        Write-Log "  [REMOVE] Override $overrideId deleted." -ForegroundColor Green
        Add-TestResult "Monitor" "Remove override" $true "Override ID: $overrideId"

        # --- Pause ---
        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 3 REMOVE complete. Verify the override is gone from the console Monitor tab."

    }
    catch {
        Write-Log ""
        Write-Log "  [FAIL] Test 3 error: $_" -ForegroundColor Red
        Add-TestResult "Monitor" "Error" $false "$_"
    }
}
else {
    Write-Log "  [SKIP] Test 3 -- Monitor (skipped via -SkipMonitorTest)" -ForegroundColor DarkCyan
}

##############################################################################
# TEST 4 -- Multi-line note validation
##############################################################################

if (-not $SkipNoteTest) {

    Write-Log ""
    Write-Log "======================================================================"
    Write-Log "  TEST 4 of 4 -- Multi-line Note Validation (Certificate)" -ForegroundColor Cyan
    Write-Log "======================================================================"
    Write-Log ""
    Write-Log "  Uses Certificate overrides because the note is viewable and editable"
    Write-Log "  in the console Certificate tab -- the only override type where note"
    Write-Log "  content is directly visible in the UI without clicking into a record."
    Write-Log ""
    Write-Log "  This test validates two things:"
    Write-Log "  1. Backtick-n (``n) renders as a real newline in the console note field."
    Write-Log "  2. Backslash-n (\n) is treated as a literal string -- no line break."

    $certA       = $null
    $certB       = $null
    $overrideId1 = $null
    $overrideId2 = $null

    try {
        # Generate two self-signed certs -- one per part
        Write-Log ""
        Write-Log "  [SETUP] Generating two self-signed test certificates..."

        $certA = New-SelfSignedCertificate `
            -Subject "CN=HalcyonNoteTestA" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddDays(1)

        $certB = New-SelfSignedCertificate `
            -Subject "CN=HalcyonNoteTestB" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddDays(1)

        Write-Log "  [SETUP] Cert A thumbprint: $($certA.Thumbprint.ToLower())" -ForegroundColor Green
        Write-Log "  [SETUP] Cert B thumbprint: $($certB.Thumbprint.ToLower())" -ForegroundColor Green

        # --- Part A -- backtick-n (correct PowerShell newline syntax) ---
        Write-Log ""
        Write-Log "  [PART A] Backtick-n note -- should render as THREE separate lines in console..."

        $backtickNote = "This is my string`nThere are many like it but`nThis one is mine."
        $addCommand   = ".\New-HalcyonOverride.ps1 -AuthObject `$auth -Kind Certificate -Thumbprint `"$($certA.Thumbprint.ToLower())`" -Note `"This is my string``nThere are many like it but``nThis one is mine.`""
        Write-LogCommand $addCommand
        Write-Log "  Note value being submitted:" -ForegroundColor DarkCyan
        $backtickNote -split "`n" | ForEach-Object { Write-Log "    |  $_" -ForegroundColor DarkCyan }

        $auth = Assert-ValidToken -Auth $auth

        $addResult1 = & (Join-Path $PSScriptRoot "New-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -Kind        Certificate `
            -Thumbprint  $certA.Thumbprint.ToLower() `
            -Note        $backtickNote `
            -Confirm:$false

        $overrideId1 = $addResult1.id
        Write-Log ""
        Write-Log "  [PART A] Override created. ID: $overrideId1  |  Thumbprint: $($certA.Thumbprint.ToLower())" -ForegroundColor Green
        Add-TestResult "Note (backtick-n)" "Add override" $true "Override ID: $overrideId1"

        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 4 PART A -- Check the console Certificate tab. Click into the note for thumbprint $($certA.Thumbprint.ToLower()). It should show THREE separate lines."

        $auth = Assert-ValidToken -Auth $auth
        & (Join-Path $PSScriptRoot "Remove-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -OverrideId  $overrideId1 `
            -Confirm:$false

        Write-Log "  [PART A] Override $overrideId1 deleted." -ForegroundColor Green
        Add-TestResult "Note (backtick-n)" "Remove override" $true "Override ID: $overrideId1"

        # --- Part B -- backslash-n (common mistake -- should render literally) ---
        Write-Log ""
        Write-Log "  [PART B] Backslash-n note -- should render as ONE line with literal \n characters..."

        $backslashNote = 'This is my string\nThere are many like it but\nThis one is mine.'
        $addCommand    = ".\New-HalcyonOverride.ps1 -AuthObject `$auth -Kind Certificate -Thumbprint `"$($certB.Thumbprint.ToLower())`" -Note 'This is my string\nThere are many like it but\nThis one is mine.'"
        Write-LogCommand $addCommand
        Write-Log "  Note value being submitted (literal -- no real newlines):" -ForegroundColor DarkCyan
        Write-Log "    |  $backslashNote" -ForegroundColor DarkCyan

        $auth = Assert-ValidToken -Auth $auth

        $addResult2 = & (Join-Path $PSScriptRoot "New-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -Kind        Certificate `
            -Thumbprint  $certB.Thumbprint.ToLower() `
            -Note        $backslashNote `
            -Confirm:$false

        $overrideId2 = $addResult2.id
        Write-Log ""
        Write-Log "  [PART B] Override created. ID: $overrideId2  |  Thumbprint: $($certB.Thumbprint.ToLower())" -ForegroundColor Green
        Add-TestResult "Note (backslash-n)" "Add override" $true "Override ID: $overrideId2"

        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 4 PART B -- Check the console Certificate tab. Click into the note for thumbprint $($certB.Thumbprint.ToLower()). It should show ONE line with literal \n characters -- no line break."

        $auth = Assert-ValidToken -Auth $auth
        & (Join-Path $PSScriptRoot "Remove-HalcyonOverride.ps1") `
            -AccessToken $auth.AccessToken `
            -TenantId    $auth.TenantId `
            -OverrideId  $overrideId2 `
            -Confirm:$false

        Write-Log "  [PART B] Override $overrideId2 deleted." -ForegroundColor Green
        Add-TestResult "Note (backslash-n)" "Remove override" $true "Override ID: $overrideId2"

        $auth = Invoke-Pause -Auth $auth `
            -Message "TEST 4 complete. Both certificate overrides should now be gone from the console Certificate tab."
    }
    catch {
        Write-Log ""
        Write-Log "  [FAIL] Test 4 error: $_" -ForegroundColor Red
        Add-TestResult "Note test" "Error" $false "$_"
    }
    finally {
        # Clean up both test certs from the store regardless of outcome
        foreach ($cert in @($certA, $certB)) {
            if ($cert) {
                try {
                    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction Stop
                    Write-Log "  [CLEANUP] Removed test cert $($cert.Subject) from cert store." -ForegroundColor DarkCyan
                }
                catch {
                    Write-Log "  [CLEANUP] Could not remove $($cert.Subject) -- remove manually from Cert:\CurrentUser\My\$($cert.Thumbprint)" -ForegroundColor Yellow
                }
            }
        }
    }
}
else {
    Write-Log "  [SKIP] Test 4 -- Multi-line note (skipped via -SkipNoteTest)" -ForegroundColor DarkCyan
}

##############################################################################
# Summary
Write-Log "======================================================================"
Write-Log ""

$passed = 0
$failed = 0

foreach ($r in $testResults) {
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    $color  = if ($r.Passed) { "Green" } else { "Red" }
    $line   = "  [{0}]  {1,-12}  {2,-30}  {3}" -f $status, $r.TestName, $r.Step, $r.Detail
    Write-Log $line -ForegroundColor $color
    if ($r.Passed) { $passed++ } else { $failed++ }
}

Write-Log ""
Write-Log "  Passed : $passed" -ForegroundColor Green
Write-Log "  Failed : $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Log ""
Write-Log "  Full log saved to:" -ForegroundColor DarkCyan
Write-Log "  $LogPath" -ForegroundColor Cyan
Write-Log "======================================================================"
Write-Log ""