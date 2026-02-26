# Halcyon API PowerShell Toolkit

PowerShell scripts for interacting with the [Halcyon](https://halcyon.ai) public API. Built and maintained by the Halcyon Solutions Engineering team.

> **Audience:** Security engineers, SOC teams, and IT administrators who want to automate Halcyon workflows via the API rather than the console.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
  - [Service Accounts and SSO](#service-accounts-and-sso)
  - [Token Lifetimes](#token-lifetimes)
  - [Token Strategy for Automation](#token-strategy-for-automation)
- [Scripts Reference](#scripts-reference)
  - [ConvertFrom-HalcyonJwt.ps1](#convertfrom-halcyonjwtps1)
  - [Get-HalcyonBearerToken.ps1](#get-halcyonbearertokenps1)
  - [Invoke-HalcyonTokenRefresh.ps1](#invoke-halcyontokenrefreshps1)
  - [New-HalcyonOverride.ps1](#new-halcyonoverrideps1)
  - [Remove-HalcyonOverride.ps1](#remove-halcyonoverrideps1)
  - [Invoke-HalcyonOverrideTests.ps1](#invoke-halcyonoverridetestsps1)
  - [Get-HalcyonWhoAmI.ps1](#get-halcyonwhoamips1)
  - [Get-HalcyonAuditLog.ps1](#get-halcyonauditlogps1)
- [Override Types](#override-types)
  - [Certificate](#certificate-overrides)
  - [File / Hash](#file--hash-overrides)
  - [Monitor](#monitor-overrides)
  - [Driver](#driver-overrides)
  - [IpAddress / Host](#ipaddress--host-overrides)
  - [Dns](#dns-overrides)
- [Working with Notes](#working-with-notes)
- [Versioning](#versioning)
- [Diagnostics](#diagnostics)

---

## Overview

This repo provides a set of composable PowerShell scripts that wrap the Halcyon REST API. Scripts are designed to be run standalone or chained together via the pipeline -- the output of one script feeds naturally into the input of the next.

```
Get-HalcyonBearerToken  -->  New-HalcyonOverride
                         -->  Remove-HalcyonOverride
                         -->  Invoke-HalcyonTokenRefresh  -->  (loop)
                         -->  Get-HalcyonWhoAmI
                         -->  Get-HalcyonAuditLog
```

All scripts follow PowerShell conventions: named parameters, `-WhatIf` support where destructive, structured `PSCustomObject` return values, and errors through the standard error stream.

---

## Prerequisites

- **PowerShell 5.1** or higher (Windows PowerShell or PowerShell 7+)
- **Outbound HTTPS** to `api.halcyon.ai` (port 443)
- **Halcyon service account** -- see [Service Accounts and SSO](#service-accounts-and-sso)
- **RBAC role:** `ReadOnly` for read operations, `PowerUser` or `Admin` for creating overrides, `Admin` for deleting overrides

All scripts must be run from the same directory, or `$PSScriptRoot` must resolve correctly, because `ConvertFrom-HalcyonJwt.ps1` is dot-sourced as a shared helper by the other scripts.

---

## Quick Start

```powershell
# 1. Authenticate and capture the auth object
$auth = .\Get-HalcyonBearerToken.ps1

# 2. Create a certificate override
$result = .\New-HalcyonOverride.ps1 -AuthObject $auth `
    -Kind Certificate `
    -CertificatePath "C:\certs\sophos.cer"

# 3. Remove it when done
.\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId $result.id
```

---

## Authentication

### Service Accounts and SSO

The Halcyon API authenticates via username and password against the `/identity/auth/login` endpoint. If your tenant enforces SSO, personal credentials will not work -- you need a dedicated **service account** provisioned outside SSO enforcement.

To request a service account, open a ticket at [support@halcyon.ai](mailto:support@halcyon.ai) with your organization name and console email address.

> **Finding your Tenant ID:** The Tenant ID is not displayed in the Halcyon console. Request it from [support@halcyon.ai](mailto:support@halcyon.ai) along with your service account.

### Token Lifetimes

The Halcyon auth response returns two JWT tokens. Expiry is embedded in the JWT payload as standard `exp` claims -- there is no top-level TTL field in the response.

| Token | Lifetime |
|---|---|
| Access Token | 5 minutes |
| Refresh Token | 15 minutes |

The `Get-HalcyonBearerToken.ps1` and `Invoke-HalcyonTokenRefresh.ps1` scripts decode these JWTs automatically and display real expiry timestamps.

### Token Strategy for Automation

For long-running scripts or SOC integrations:

1. Authenticate once with `Get-HalcyonBearerToken.ps1` and capture `$auth`
2. Before each API call, check the access token TTL
3. If under 60 seconds remaining, call `Invoke-HalcyonTokenRefresh.ps1` to get a new pair
4. The server rotates the refresh token on every refresh -- always use the latest one

```powershell
# Simple loop pattern
$auth = .\Get-HalcyonBearerToken.ps1

while ($true) {
    # ... do API work ...

    # Refresh before sleeping
    $auth = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -silent
    Start-Sleep -Seconds 240
}
```

For fully automated refresh, use the built-in `-Loop` mode in `Invoke-HalcyonTokenRefresh.ps1`.

---

## Scripts Reference

### ConvertFrom-HalcyonJwt.ps1

**Version:** v1.0  
**Purpose:** Shared helper. Decodes JWT tokens and extracts expiry metadata. Dot-sourced automatically by other scripts -- you do not call this directly.

**Exported functions:**

| Function | Returns |
|---|---|
| `ConvertFrom-HalcyonJwt -Token <string>` | Decoded JWT payload as `PSCustomObject` |
| `Get-HalcyonTokenExpiry -Token <string>` | Expiry info: `ExpiresAt`, `SecondsRemaining`, `IsExpired`, `TtlSeconds`, `Subject`, `Email` |

---

### Get-HalcyonBearerToken.ps1

**Version:** v1.2  
**Purpose:** Authenticates against the Halcyon identity endpoint. Prompts for Tenant ID, email, and password interactively. Zeroes the plaintext password from memory immediately after the request.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-silent` | switch | off | Suppress all decorative output. Errors and warnings always show. Prompts still appear. |

**Returns:** `PSCustomObject` with `AccessToken`, `RefreshToken`, `TenantId`, `AccessExpiresAt`, `RefreshExpiresAt`

**Usage:**

```powershell
# Interactive -- full output
$auth = .\Get-HalcyonBearerToken.ps1

# Silent -- prompts only, no banners or token details
$auth = .\Get-HalcyonBearerToken.ps1 -silent

# Access the token directly
$auth.AccessToken
$auth.TenantId
```

---

### Invoke-HalcyonTokenRefresh.ps1

**Version:** v1.2  
**Purpose:** Exchanges a refresh token for a new access token and refresh token pair. Supports single refresh, pipeline chaining, and a continuous loop mode for long-running integrations. The server rotates the refresh token on every call -- always use the latest one.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-RefreshToken` | string | | Refresh token string (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Loop` | switch | off | Continuous refresh loop mode |
| `-IntervalSeconds` | int | 240 | Refresh interval in loop mode (seconds) |
| `-TokenOnly` | switch | off | Return access token string instead of full auth object |
| `-silent` | switch | off | Suppress all decorative output |
| `-WarnThresholdSeconds` | int | 60 | Warn if token expires within this many seconds |

**Returns:** `PSCustomObject` (same shape as `Get-HalcyonBearerToken.ps1`) or access token string if `-TokenOnly`

**Usage:**

```powershell
# Single refresh -- pipeline pattern (most common)
$auth = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth

# Token string only -- for use directly in API calls
$token = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -TokenOnly

# Continuous loop -- refresh every 4 minutes, Ctrl+C to stop
.\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -Loop -IntervalSeconds 240

# Silent refresh inside automation
$auth = .\Invoke-HalcyonTokenRefresh.ps1 -AuthObject $auth -silent
```

---

### New-HalcyonOverride.ps1

**Version:** v1.1  
**Purpose:** Creates a Halcyon override for any supported artifact type. Supports all five API artifact kinds, tenant-wide or asset-scoped targeting, and optional notes with newline support.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | Yes* | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | Yes* | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | Yes* | Tenant ID (alternative to `-AuthObject`) |
| `-Kind` | string | Yes | Override type: `Certificate`, `File`, `Monitor`, `Driver`, `IpAddress`, `Dns` |
| `-Action` | string | No | `Allow`, `Block`, or `Bypass`. Default: `Allow`. Ignored for `-Kind Monitor` (always `Bypass`) |
| `-TargetKind` | string | No | `Tenant` (default) or `Asset` |
| `-AssetId` | string | Conditional | Required when `-TargetKind Asset` |
| `-CertificatePath` | string | Conditional | Path to `.cer`, `.crt`, `.pem`, or `.der` file |
| `-Thumbprint` | string | Conditional | 40-char SHA1 hex string (Certificate alternative to file) |
| `-Sha256` | string | Conditional | 64-char SHA256 hex string (File and Monitor) |
| `-DriverSha256` | string | Conditional | 64-char SHA256 of driver binary |
| `-Authentihash` | string | Conditional | 64-char Authenticode hash of driver |
| `-Cidr` | string | Conditional | IP address or CIDR range (IpAddress) |
| `-DnsName` | string | Conditional | Hostname or domain (Dns) |
| `-Note` | string | No | Optional note, max 280 chars. Supports newlines -- see [Working with Notes](#working-with-notes) |
| `-WhatIf` | switch | No | Preview the request without submitting |
| `-silent` | switch | No | Suppress decorative output |

*One of `-AuthObject` or both `-AccessToken` and `-TenantId` required.

**Returns:** Full API response object with `id`, `createdAt`, `createdBy`, `action`, `target`, `artifact`

> **Important:** The API deduplicates certificate overrides by thumbprint. Submitting the same thumbprint twice updates the existing override silently rather than returning a 409 conflict. This applies to all artifact types -- duplicate submissions are treated as upserts.

**Usage:**

```powershell
# Certificate from file -- auto-extracts thumbprint and generates structured note
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -CertificatePath "C:\certs\sophos.cer"

# Certificate from thumbprint
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -Thumbprint "971382847ad8b5978070c4fc248efae266d87a1b"

# File hash (Allow)
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind File `
    -Sha256 "d3f1164e..." -Action Allow

# Monitor (Bypass -- console Monitor tab)
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Monitor `
    -Sha256 "3d69eca5..."

# Scoped to a specific asset
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -Thumbprint "971382847..." -TargetKind Asset -AssetId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Preview without submitting
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -Thumbprint "971382847..." -WhatIf

# Capture the result and use the override ID
$result = .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -Thumbprint "971382847..."
Write-Host "Created override ID: $($result.id)"
```

---

### Remove-HalcyonOverride.ps1

**Version:** v1.0  
**Purpose:** Deletes a Halcyon override by its numeric ID. Requires `Admin` RBAC role.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | Yes* | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | Yes* | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | Yes* | Tenant ID (alternative to `-AuthObject`) |
| `-OverrideId` | int | Yes | Numeric override ID from the API response or console |
| `-WhatIf` | switch | No | Preview without deleting |
| `-Confirm:$false` | | No | Skip the confirmation prompt |

*One of `-AuthObject` or both `-AccessToken` and `-TenantId` required.

**Usage:**

```powershell
# Delete by ID
.\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId 1234

# Skip confirmation prompt (for scripted use)
.\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId 1234 -Confirm:$false

# Full add/remove cycle
$auth   = .\Get-HalcyonBearerToken.ps1
$result = .\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
              -Thumbprint "971382847..."
.\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId $result.id -Confirm:$false
```

---

### Invoke-HalcyonOverrideTests.ps1

**Version:** v1.1  
**Purpose:** Live test harness for override creation and deletion. Runs four test cases against a real tenant, pausing between each add and remove so you can verify the result in the console before continuing. All output is written to a timestamped log file.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `-AuthObject` | PSCustomObject | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-SkipCertTest` | switch | Skip Test 1 (Certificate) |
| `-SkipFileTest` | switch | Skip Test 2 (File / Hash) |
| `-SkipMonitorTest` | switch | Skip Test 3 (Monitor) |
| `-SkipNoteTest` | switch | Skip Test 4 (Multi-line note) |

**Test cases:**

| Test | Type | What it validates |
|---|---|---|
| 1 | Certificate | Creates a self-signed cert, submits thumbprint as Allow override, deletes. Self-signed cert is removed from the cert store on completion. |
| 2 | File / Hash | Creates an Allow override using a synthetic all-zero SHA256, deletes. |
| 3 | Monitor | Creates a Bypass override using a synthetic all-F SHA256, deletes. |
| 4 | Note | Creates a Certificate override with a multi-line backtick-n note. Verifies rendering in the console Certificate tab, deletes. |

**Usage:**

```powershell
$auth = .\Get-HalcyonBearerToken.ps1
.\Invoke-HalcyonOverrideTests.ps1 -AuthObject $auth

# Run only the note test
.\Invoke-HalcyonOverrideTests.ps1 -AuthObject $auth `
    -SkipCertTest -SkipFileTest -SkipMonitorTest
```

Log files are written to the same directory as the script with the format `HalcyonOverrideTest_YYYYMMDD_HHmmss.log`.

### Get-HalcyonWhoAmI.ps1

**Version:** v1.0
**Purpose:** Identity and RBAC diagnostic. Calls three identity endpoints in a single pass to display the current user's profile, effective role in the authenticated tenant, and all roles across all tenants. Prints a capability summary showing which operations are available at the current RBAC level.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | Yes* | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | Yes* | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | Yes* | Tenant ID (alternative to `-AuthObject`) |

*One of `-AuthObject` or both `-AccessToken` and `-TenantId` required.

**Returns:** `PSCustomObject` with `Id`, `Email`, `Name`, `Role`, `EffectiveRole`, `EffectiveGroup`, `AllRoles`

**RBAC levels (lowest to highest):**

| Level | Description |
|---|---|
| `ReadOnly` | Read-only access to most resources |
| `User` | Basic operational access |
| `PowerUser` | Create overrides, manage tags, generate install tokens |
| `Admin` | Delete overrides, manage policy groups, export audit logs |
| `TenantAdmin` | Create and delete tenants |

**Usage:**

```powershell
$auth = .\Get-HalcyonBearerToken.ps1
.\Get-HalcyonWhoAmI.ps1 -AuthObject $auth

# Capture result for pipeline use
$me = .\Get-HalcyonWhoAmI.ps1 -AuthObject $auth
Write-Host "Effective role: $($me.EffectiveRole)"
```

---

### Get-HalcyonAuditLog.ps1

**Version:** v1.0
**Purpose:** Exports the audit log for a tenant as CSV, polls until the async report job completes, downloads the result, and optionally filters rows by keyword. Useful for confirming specific actions such as policy changes by a particular user or email domain.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-TargetTenantId` | string | | Override the tenant for the API call (target a specific subtenant) |
| `-HoursBack` | int | 24 | Time window in hours |
| `-Filter` | string | | Keyword filter applied to all CSV fields after download |
| `-PollIntervalSeconds` | int | 5 | Job status polling interval |
| `-TimeoutSeconds` | int | 120 | Maximum wait time for report completion |
| `-SaveCsv` | switch | off | Write raw CSV to disk |
| `-CsvPath` | string | | Path for saved CSV (defaults to timestamped file in current directory) |

**Returns:** Array of parsed CSV rows as `PSCustomObject` (pipeline-compatible)

**Requires:** `Admin` RBAC role

**Usage:**

```powershell
# Last 24 hours, all entries
.\Get-HalcyonAuditLog.ps1 -AuthObject $auth

# Filter for policy-related changes
.\Get-HalcyonAuditLog.ps1 -AuthObject $auth -Filter "policy"

# Filter for a specific user or domain
.\Get-HalcyonAuditLog.ps1 -AuthObject $auth -Filter "vancouverclinic"

# Target a specific tenant
.\Get-HalcyonAuditLog.ps1 -AuthObject $auth `
    -TargetTenantId "b30d3702-780f-4322-8990-3f76049ed5a5" `
    -Filter "policy"

# Save raw CSV and filter output
.\Get-HalcyonAuditLog.ps1 -AuthObject $auth -HoursBack 48 -Filter "policy" -SaveCsv

# Pipeline -- further filter results in PowerShell
$rows = .\Get-HalcyonAuditLog.ps1 -AuthObject $auth -Filter "policy"
$rows | Where-Object { $_.user -match "vancouverclinic" }
```

> **Note:** The audit log export is an async job. The script submits the request, polls `GET /v2/jobs/{reportId}` until completion, then downloads the CSV. The full job response is printed to the console on completion -- this is intentional, as the download URL field name is not documented in the API spec and may need to be confirmed from a live response.

---

## Override Types

### Certificate Overrides

Block or allow executables based on their Authenticode signature. More flexible than hash overrides because a single certificate covers all executables signed with that cert, regardless of version or binary changes.

The API requires a **SHA1 thumbprint** (40 hex characters). When you supply a certificate file, the thumbprint is extracted automatically. A structured note matching the console format is also generated automatically.

Console tab: **Certificate**

```powershell
# From file -- recommended
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -CertificatePath "C:\certs\vendor.cer"

# From thumbprint
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -Thumbprint "971382847ad8b5978070c4fc248efae266d87a1b"
```

---

### File / Hash Overrides

Block or allow a specific executable at the file level using its SHA256 hash. The most precise override type -- only matches an exact binary.

Console tab: **Hash**

```powershell
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind File `
    -Sha256 "d3f1164ebc0ed68dd2afaccb5fff18b841b91a44888af4b432a1db157bbde1f1" `
    -Action Allow
```

---

### Monitor Overrides

Completely bypass Halcyon monitoring for a specific file by SHA256. Use when Halcyon's monitoring conflicts with a known-good executable. At the API level, this is a `File` artifact with action `Bypass` -- the console displays it on a separate tab for clarity.

Console tab: **Monitor**

```powershell
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Monitor `
    -Sha256 "3d69eca59713a488182fcadfccadbf02af531990a156c62b68dabfb66fca0be0"
```

> `-Action` is ignored for `-Kind Monitor` -- Bypass is always enforced.

---

### Driver Overrides

Allow loading of drivers with known vulnerabilities used to evade endpoint security controls. Halcyon identifies these drivers as used in ransomware attacks (BYOVD).

> **Use with extreme caution.** Allowing vulnerable drivers undermines endpoint security. Only use this override after thorough review and with documented approval.

Console tab: **Driver**

```powershell
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Driver `
    -DriverSha256 "abc123..." `
    -Authentihash "def456..."
```

At least one of `-DriverSha256` or `-Authentihash` is required.

---

### IpAddress / Host Overrides

Fine-tune Halcyon's data exfiltration (DXP) protections by IP address or CIDR range.

Console tab: **Host**

```powershell
# Single IP
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind IpAddress -Cidr "192.168.1.100"

# Subnet
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind IpAddress -Cidr "10.0.0.0/8"
```

---

### Dns Overrides

Fine-tune Halcyon's data exfiltration (DXP) protections by hostname or domain.

```powershell
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Dns -DnsName "internal.corp.local"
```

---

## Working with Notes

All override types support an optional `-Note` parameter (max 280 characters).

**Newlines** are supported using PowerShell's backtick-n escape sequence. Plain `\n` (backslash-n) is **not** a newline in PowerShell and will be submitted literally.

```powershell
# Backtick-n -- correct, renders as separate lines in the console
-Note "Approved by CR-4821`nSophos endpoint agent`nContact: ops@corp.com"

# Here-string -- natural multi-line syntax
$note = @"
Approved by CR-4821
Sophos endpoint agent
Contact: ops@corp.com
"@
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -Thumbprint "971382847..." -Note $note

# Backslash-n -- WRONG, submits literal \n characters
-Note "Line one\nLine two"
```

For **Certificate** overrides created from a file (`-CertificatePath`), a structured note is generated automatically if `-Note` is not supplied:

```
Application: Sophos Limited
Punycode: Sophos Limited
Thumbprint: 971382847AD8B5978070C4FC248EFAE266D87A1B
Expires: 09/03/2025 11:47:27
CertSerialNum: 3300043130B78BB58A2D65AA71000000043130
```

This matches the format used by the Halcyon console and makes API-created overrides indistinguishable from console-created ones.

---

## Versioning

Script versions follow `vMAJOR.MINOR` in the file header. The version is bumped on every meaningful change:

- **Minor bump** (`v1.0` to `v1.1`): New parameters, behavioral changes, bug fixes
- **Major bump** (`v1.x` to `v2.0`): Breaking changes to return values or required parameters

All scripts are deployed to the repository root. When updating a script, bump the version in the header comment before committing.

**Current versions:**

| Script | Version |
|---|---|
| `ConvertFrom-HalcyonJwt.ps1` | v1.0 |
| `Get-HalcyonBearerToken.ps1` | v1.2 |
| `Invoke-HalcyonTokenRefresh.ps1` | v1.2 |
| `New-HalcyonOverride.ps1` | v1.1 |
| `Remove-HalcyonOverride.ps1` | v1.0 |
| `Invoke-HalcyonOverrideTests.ps1` | v1.1 |
| `Get-HalcyonWhoAmI.ps1` | v1.0 |
| `Get-HalcyonAuditLog.ps1` | v1.0 |

---

## Diagnostics

**Get-HalcyonAuthRaw.ps1** is a diagnostic script that calls the auth endpoint and prints the raw response with no JWT decoding or formatting. Use it to inspect the raw API response or troubleshoot authentication issues.

```powershell
.\Get-HalcyonAuthRaw.ps1
```

This script is not part of the standard toolkit and is not required for normal operation.

---

*Maintained by the Halcyon Solutions Engineering team. For questions, contact your Halcyon SE or open a ticket at [support@halcyon.ai](mailto:support@halcyon.ai).*
