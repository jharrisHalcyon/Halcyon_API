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
- [Script Dependencies](#script-dependencies)
- [Scripts Reference](#scripts-reference)
  - [ConvertFrom-HalcyonJwt.ps1](#convertfrom-halcyonjwtps1)
  - [Get-HalcyonBearerToken.ps1](#get-halcyonbearertokenps1)
  - [Invoke-HalcyonTokenRefresh.ps1](#invoke-halcyontokenrefreshps1)
  - [Get-HalcyonAlerts.ps1](#get-halcyonalertsps1)
  - [Get-HalcyonDevices.ps1](#get-halcyondevicesps1)
  - [Remove-HalcyonDevice.ps1](#remove-halcyondeviceps1)
  - [Get-HalcyonOverrides.ps1](#get-halcyonoverridesps1)
  - [New-HalcyonOverride.ps1](#new-halcyonoverrideps1)
  - [Remove-HalcyonOverride.ps1](#remove-halcyonoverrideps1)
  - [Get-HalcyonWhoAmI.ps1](#get-halcyonwhoamips1)
  - [Get-HalcyonAuditLog.ps1](#get-halcyonauditlogps1)
  - [Get-HalcyonThreats.ps1](#get-halcyonthreatsp1)
  - [Get-HalcyonPolicies.ps1](#get-halcyonpoliciesps1)
  - [Set-HalcyonAssetTag.ps1](#set-halcyonassettagps1)
  - [Set-HalcyonAssetPolicy.ps1](#set-halcyonassetpolicyps1)
- [Override Types](#override-types)
  - [Certificate](#certificate-overrides)
  - [File / Hash](#file--hash-overrides)
  - [Monitor](#monitor-overrides)
  - [Driver](#driver-overrides)
  - [IpAddress / Host](#ipaddress--host-overrides)
  - [Dns](#dns-overrides)
- [Working with Notes](#working-with-notes)
- [VDI Device Hygiene](#vdi-device-hygiene)
- [SIEM Integration](#siem-integration)
- [Versioning](#versioning)
- [Diagnostics](#diagnostics)

---

## Overview

This repo provides a set of composable PowerShell scripts that wrap the Halcyon REST API. Scripts are designed to be run standalone or chained together via the pipeline -- the output of one script feeds naturally into the input of the next.

```
Get-HalcyonBearerToken  -->  Get-HalcyonAlerts  -->  Get-HalcyonThreats
                         -->  Get-HalcyonDevices  -->  Remove-HalcyonDevice
                         -->  Get-HalcyonOverrides
                         -->  New-HalcyonOverride
                         -->  Remove-HalcyonOverride
                         -->  Invoke-HalcyonTokenRefresh  -->  (loop)
                         -->  Get-HalcyonWhoAmI
                         -->  Get-HalcyonAuditLog
                         -->  Get-HalcyonThreats
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

# 2. List recent alerts
$alerts = .\Get-HalcyonAlerts.ps1 -AuthObject $auth -LastSeenAfter (Get-Date).AddDays(-7)

# 3. Check for duplicate device registrations (VDI environments)
.\Get-HalcyonDevices.ps1 -AuthObject $auth -FindDuplicates -AllPages

# 4. Create a certificate override
$result = .\New-HalcyonOverride.ps1 -AuthObject $auth `
    -Kind Certificate `
    -CertificatePath "C:\certs\sophos.cer"

# 5. Remove it when done
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

## Script Dependencies

All API scripts (except `Get-HalcyonBearerToken.ps1` and `Invoke-HalcyonTokenRefresh.ps1`) dot-source `ConvertFrom-HalcyonJwt.ps1` at startup:

```powershell
. (Join-Path $PSScriptRoot "ConvertFrom-HalcyonJwt.ps1")
```

This provides the `Get-HalcyonTokenExpiry` function used for automatic token refresh. **All scripts must reside in the same directory.** If you run a script from a different working directory, use the full path or `Set-Location` to the API folder first.

### Auto Token Refresh

Every API script checks whether the access token is within 60 seconds of expiry before making any API calls. If so:

- **With `-AuthObject`** -- the script calls `Invoke-HalcyonTokenRefresh.ps1` automatically, updates `$AuthObject` in place so the caller's reference reflects the new tokens, and proceeds transparently.
- **Without `-AuthObject`** (tokens passed directly via `-AccessToken`/`-TenantId`) -- a `[WARN]` message is printed and the script continues. Refresh is not possible without the `RefreshToken` from an `$auth` object.
- **Both tokens expired** -- the script exits with `[FAIL]` and instructs you to re-authenticate.

The caller's `$auth` object is updated in place on refresh, so long-running pipelines stay current without additional code:

```powershell
$auth = .\Get-HalcyonBearerToken.ps1

# Tokens are refreshed automatically inside each script as needed
$alerts    = .\Get-HalcyonAlerts.ps1    -AuthObject $auth -AllPages -silent
$hashes    = $alerts | ForEach-Object { $_.summary.artifact.sha256 } | Where-Object { $_ } | Sort-Object -Unique
$threats   = .\Get-HalcyonThreats.ps1  -AuthObject $auth -ThreatId $hashes -silent
$overrides = .\Get-HalcyonOverrides.ps1 -AuthObject $auth -silent
```

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

**Version:** v1.5  
**Purpose:** Authenticates against the Halcyon identity endpoint. Supports interactive prompts, a config file (`-UseConfig`), and encrypted vault storage (`-UseSecrets`). Zeroes the plaintext password from memory immediately after the request.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-silent` | switch | off | Suppress all decorative output. Errors and warnings always show. |
| `-UseConfig` | switch | off | Load credentials from `config.cfg` instead of prompting. Searches script directory first, then current directory. Expected fields: `TENANTID`, `USERNAME`, `PASSWORD`. Inline comments (`# ...`) are stripped from values. |
| `-UseSecrets` | switch | off | Load credentials from a PowerShell SecretManagement vault. Recommended for production automation. Requires `Microsoft.PowerShell.SecretManagement` + `Microsoft.PowerShell.SecretStore`. |
| `-VaultName` | string | | Name of the SecretManagement vault. If omitted, the default registered vault is used. |
| `-SecretPrefix` | string | `Halcyon` | Prefix for secret names in the vault. Reads `${Prefix}TenantId`, `${Prefix}Username`, `${Prefix}Password`. Use different prefixes to manage multiple tenants in one vault. |

**Returns:** `PSCustomObject` with `AccessToken`, `RefreshToken`, `TenantId`, `AccessExpiresAt`, `RefreshExpiresAt`

**Usage:**

```powershell
# Interactive -- prompts for Tenant ID, email, and password
$auth = .\Get-HalcyonBearerToken.ps1

# Load from config.cfg (non-interactive)
$auth = .\Get-HalcyonBearerToken.ps1 -UseConfig

# Load from SecretManagement vault
$auth = .\Get-HalcyonBearerToken.ps1 -UseSecrets -VaultName HalcyonVault

# Multiple tenants in one vault -- switch with -SecretPrefix
$auth = .\Get-HalcyonBearerToken.ps1 -UseSecrets -VaultName HalcyonVault -SecretPrefix HalcyonProd
```

**SecretManagement one-time setup:**

```powershell
# Install modules
Install-Module Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
Install-Module Microsoft.PowerShell.SecretStore       -Repository PSGallery -Force

# Register an encrypted vault (once per machine/user)
Register-SecretVault -Name HalcyonVault -ModuleName Microsoft.PowerShell.SecretStore

# Store credentials -- first Set-Secret call will prompt for a vault password
Set-Secret -Vault HalcyonVault -Name HalcyonTenantId -Secret "your-tenant-id"
Set-Secret -Vault HalcyonVault -Name HalcyonUsername  -Secret "user@example.com"
Set-Secret -Vault HalcyonVault -Name HalcyonPassword  -Secret "your-password"
```

> **Vault password:** You will be prompted to set a master password on first use. This encrypts all secrets in the vault. It is required once per PowerShell session the first time the vault is accessed. There is no recovery path if the password is lost — store it securely.

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

### Get-HalcyonAlerts.ps1

**Version:** v1.3  
**Purpose:** Retrieves alerts from the Halcyon API with filtering, automatic pagination, and flexible output options. Designed for SIEM ingestion pipelines, POV closeout reporting, and interactive investigation.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Type` | string | | `BadBehavior`, `BruteForceAttempt`, `Dxp`, `MaliciousExecutable`, `VulnerableDriver` |
| `-Action` | string | | `Block` or `Report` |
| `-TriageStatus` | string | | `New` or `Reviewed` |
| `-DisplayStatus` | string | | `Hidden` or `Visible` |
| `-FirstSeenAfter` | datetime | | Filter alerts by first occurrence start |
| `-FirstSeenBefore` | datetime | | Filter alerts by first occurrence end |
| `-LastSeenAfter` | datetime | | Filter alerts by last occurrence start |
| `-LastSeenBefore` | datetime | | Filter alerts by last occurrence end |
| `-OffendingSha256` | string[] | | SHA256 prefix filter (1-64 hex chars, partial match supported) |
| `-AlertId` | string[] | | One or more specific alert IDs (64-char hex) |
| `-Page` | int | 1 | Starting page |
| `-PageSize` | int | 100 | Results per page (10, 30, 50, 100) |
| `-AllPages` | switch | off | Walk all result pages automatically |
| `-SortBy` | string | LastSeen | `Action`, `AlertId`, `AssetCount`, `Count`, `FirstSeen`, `Kind`, `LastSeen`, `OffendingSha256` |
| `-SortOrder` | string | Desc | `Asc` or `Desc` |
| `-Format` | string | JSON | `JSON` or `CSV` |
| `-OutFile` | string | | Write output to this file path |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** Array of alert objects (PSCustomObject). Also writes to `-OutFile` if specified.

> **Output formats:** JSON (default) preserves full object fidelity including nested process trees, asset details, and artifact metadata -- use this for SIEM ingestion. CSV flattens to top-level alert fields and is better suited for human review in Excel.

**Usage:**

```powershell
# All alerts from the last 7 days
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -LastSeenAfter (Get-Date).AddDays(-7)

# All blocked alerts, all pages, saved to JSON
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -Action Block -AllPages `
    -OutFile "blocked_alerts.json"

# POV closeout -- all activity since evaluation start
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -FirstSeenAfter "2026-02-10" `
    -AllPages -OutFile "pov_alerts.json"

# Hunt a specific hash across all pages
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -OffendingSha256 "d3f1164e" -AllPages

# Export as CSV for Excel review
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -Format CSV -OutFile "alerts.csv"

# Pipeline -- filter results further in PowerShell
$alerts = .\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -silent
$alerts | Where-Object { $_.totalOccurrences -gt 10 }
```

---

### Get-HalcyonDevices.ps1

**Version:** v1.2  
**Purpose:** Retrieves registered devices from a Halcyon tenant. Includes a dedicated duplicate detection mode for VDI environments where the same hostname may appear multiple times with different Asset IDs.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Name` | string | | Device name substring filter (contains match) |
| `-OperatingSystem` | string | | OS name filter |
| `-AgentVersion` | string | | Agent version filter |
| `-Search` | string | | Generic search term matched against device properties |
| `-Page` | int | 1 | Starting page |
| `-PageSize` | int | 100 | Results per page (10, 30, 50, 100) |
| `-AllPages` | switch | off | Walk all result pages automatically |
| `-SortBy` | string | registeredDate | `agentVersion`, `heartbeat`, `name`, `osName`, `registeredDate` |
| `-SortOrder` | string | Desc | `Asc` or `Desc` |
| `-FindDuplicates` | switch | off | Enable VDI duplicate detection mode |
| `-HeartbeatThresholdDays` | int | 7 | Days without heartbeat before flagging as NoContact |
| `-OutFile` | string | | Write output to this JSON file |
| `-silent` | switch | off | Suppress decorative output |

**Duplicate status values (when `-FindDuplicates` is set):**

| Status | Meaning |
|---|---|
| `Unique` | Only one device with this name, within heartbeat threshold |
| `Keeper` | Most recently active registration in a duplicate group |
| `Stale` | Older registration in a duplicate group -- candidate for removal |
| `NoContact` | No heartbeat within `-HeartbeatThresholdDays` |

**Returns:** Array of device objects. When `-FindDuplicates` is set, each object includes a `duplicateStatus` field.

**Usage:**

```powershell
# List all devices
.\Get-HalcyonDevices.ps1 -AuthObject $auth -AllPages

# Find duplicate VDI registrations
.\Get-HalcyonDevices.ps1 -AuthObject $auth -FindDuplicates -AllPages

# Find duplicates and devices silent for more than 14 days
.\Get-HalcyonDevices.ps1 -AuthObject $auth -FindDuplicates `
    -HeartbeatThresholdDays 14 -AllPages

# Collect stale IDs for removal
$stale = .\Get-HalcyonDevices.ps1 -AuthObject $auth -FindDuplicates -AllPages -silent |
         Where-Object { $_.duplicateStatus -eq "Stale" }
```

See [VDI Device Hygiene](#vdi-device-hygiene) for the full removal workflow.

---

### Remove-HalcyonDevice.ps1

**Version:** v1.1  
**Purpose:** Marks a stale device registration for deletion. Deletion is asynchronous (202 Accepted) and will be reflected in the console shortly after the call. Designed to work in pipeline with `Get-HalcyonDevices.ps1 -FindDuplicates`.

> **CAUTION:** Only delete devices confirmed to be stale. Removing an active endpoint requires reinstallation of the Halcyon agent to restore protection and console visibility. Always use `-WhatIf` to preview before executing.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | Yes* | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | Yes* | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | Yes* | Tenant ID (alternative to `-AuthObject`) |
| `-DeviceId` | string | Yes | UUID of the device to delete |
| `-WhatIf` | switch | No | Preview without deleting |
| `-Confirm:$false` | | No | Skip the confirmation prompt |
| `-silent` | switch | No | Suppress decorative output |

*One of `-AuthObject` or both `-AccessToken` and `-TenantId` required.

**Returns:** API response object on successful deletion.

**Usage:**

```powershell
# Preview (no deletion)
.\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId "xxxxxxxx-..." -WhatIf

# Delete with confirmation prompt
.\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId "xxxxxxxx-..."

# Delete without prompt (scripted)
.\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId "xxxxxxxx-..." -Confirm:$false
```

---

### Get-HalcyonOverrides.ps1

**Version:** v1.2  
**Purpose:** Retrieves the override list for a tenant with rich filtering. Provides the read side of the override management toolkit alongside `New-HalcyonOverride.ps1` and `Remove-HalcyonOverride.ps1`. Useful for hygiene audits, POV closeout verification, and confirming that API-created overrides match what is displayed in the console.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `-AuthObject` | PSCustomObject | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | Tenant ID (alternative to `-AuthObject`) |
| `-Kind` | string | `Certificate`, `Dns`, `Driver`, `File`, `IpAddress` |
| `-Action` | string[] | `Allow`, `Block`, `Bypass` -- accepts multiple values |
| `-TargetKind` | string | `Asset` or `Tenant` |
| `-AssetId` | string | Filter to overrides for a specific asset (UUID) |
| `-AssetName` | string | Filter to overrides for a specific asset (name) |
| `-AlertId` | string | Filter to overrides linked to a specific alert (64-char hex) |
| `-CreatedAfter` | datetime | Overrides created after this date |
| `-CreatedBefore` | datetime | Overrides created before this date |
| `-CreatedBy` | string | Filter by creator email or username |
| `-CertThumbprint` | string | Filter by certificate thumbprint |
| `-CertSubjectDN` | string | Filter by certificate subject DN |
| `-OffendingSha256` | string | Filter by file or driver SHA256 prefix |
| `-FileCopyright` | string | Filter by file copyright field |
| `-FileProductName` | string | Filter by file product name |
| `-OffendingCidr` | string | Filter by IP/CIDR rule |
| `-OffendingDns` | string | Filter by DNS rule |
| `-Page` | int | Starting page (default: 1) |
| `-PageSize` | int | Results per page (default: 100) |
| `-AllPages` | switch | Walk all pages automatically |
| `-SortBy` | string | Default: CreatedAt |
| `-SortOrder` | string | `Asc` or `Desc` (default: Desc) |
| `-OutFile` | string | Write results to this JSON file |
| `-silent` | switch | Suppress decorative output |

**Returns:** Array of override objects (PSCustomObject).

**Usage:**

```powershell
# List all overrides
.\Get-HalcyonOverrides.ps1 -AuthObject $auth -AllPages

# Audit all Certificate overrides
.\Get-HalcyonOverrides.ps1 -AuthObject $auth -Kind Certificate -AllPages

# Show Allow and Bypass overrides created in the last 30 days
.\Get-HalcyonOverrides.ps1 -AuthObject $auth -Action Allow,Bypass `
    -CreatedAfter (Get-Date).AddDays(-30) -AllPages

# Find overrides for a specific asset
.\Get-HalcyonOverrides.ps1 -AuthObject $auth `
    -AssetId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Save full override list to JSON
.\Get-HalcyonOverrides.ps1 -AuthObject $auth -AllPages -OutFile "overrides_audit.json"
```

---

### New-HalcyonOverride.ps1

**Version:** v1.2  
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

**Version:** v1.1  
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

### Get-HalcyonWhoAmI.ps1

**Version:** v1.1  
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

**Version:** v1.1  
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

### Get-HalcyonThreats.ps1

**Version:** v1.1  
**Purpose:** Retrieves threat details from the Halcyon API for one or more SHA256 hashes. Threat IDs in Halcyon are the SHA256 hash of the file -- the same value found at `summary.artifact.sha256` on alert objects. Designed to be chained after `Get-HalcyonAlerts.ps1` to enrich alert data with file metadata, scoring, and sample availability.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-ThreatId` | string[] | | **Required.** One or more SHA256 hashes (64 hex chars) |
| `-IncludeSummary` | switch | off | Also call `/summary` per threat -- returns score, adjustedScore, hasValidSignature, cert chain |
| `-GetDownloadUrl` | switch | off | Also call `/download` per threat -- returns pre-signed sample download URL (requires User RBAC) |
| `-Format` | string | JSON | `JSON` or `CSV` |
| `-OutFile` | string | | Write output to this file path |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** Array of threat objects (PSCustomObject) with fields: `threatId`, `found`, `available`, `allowed`, `name`, `file_type`, `file_size`, `sha1`, `md5`, `certificates`, `summary`, `downloadUrl`

> **SHA256 field path:** The SHA256 hash on alert objects is at `summary.artifact.sha256`, not a top-level field. Always use this path when extracting hashes from alert pipeline output.

**Usage:**

```powershell
# Single threat lookup
.\Get-HalcyonThreats.ps1 -AuthObject $auth `
    -ThreatId "d3f1164e8c5e6b1f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f"

# Full detail -- core info + scoring + download URL
.\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hash `
    -IncludeSummary -GetDownloadUrl

# Pipeline from Get-HalcyonAlerts -- enrich all blocked alerts with threat data
$alerts  = .\Get-HalcyonAlerts.ps1 -AuthObject $auth -Action Block -AllPages -silent
$hashes  = $alerts | ForEach-Object { $_.summary.artifact.sha256 } |
           Where-Object { $_ } | Sort-Object -Unique
$threats = .\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes -IncludeSummary

# Save to JSON
.\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes `
    -IncludeSummary -OutFile "threats.json"

# Save to CSV (flattened -- score and signature fields included)
.\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes `
    -IncludeSummary -Format CSV -OutFile "threats.csv"

# Filter results in pipeline
$threats | Where-Object { $_.available -eq $true -and $_.allowed -eq $false } |
    Select-Object threatId, name, file_type, file_size | Format-Table -AutoSize
```

**Endpoints called:**
- `GET /v1/threat/{threat_id}` — core threat info (RBAC: ReadOnly)
- `GET /v1/threat/{threat_id}/summary` — scoring and cert chain (RBAC: ReadOnly, opt-in via `-IncludeSummary`)
- `GET /v1/threat/{threat_id}/download` — pre-signed download URL (RBAC: User, opt-in via `-GetDownloadUrl`)

---

### Get-HalcyonPolicies.ps1

**Version:** v1.0
**Purpose:** Retrieves policies from the Halcyon tenant. The list endpoint returns summaries (name, ID, owner, isDefault). Use `-Id` for a single policy with full settings, or `-IncludeSettings` to fetch full settings for every returned policy (one extra API call per policy).

> **Terminology:** What the API calls a "policy group" is referred to as a "policy" in this toolkit. The individual protection knobs inside a policy (Execution Prevention, Tamper Guard, etc.) are called "policy settings".

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Id` | string | | UUID of a specific policy — returns full settings |
| `-Name` | string | | Client-side name filter (case-insensitive contains match) |
| `-AllPages` | switch | off | Walk all pages of results |
| `-IncludeSettings` | switch | off | Fetch full policy settings for each returned policy (N+1 calls) |
| `-OutFile` | string | | Write output to this file path (JSON) |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** Array of policy objects (PSCustomObject). Summary objects include `id`, `name`, `owner`, `isDefault`. Detail objects add a `policies` property containing the 7 policy setting knobs.

**Usage:**

```powershell
# List all policies
.\Get-HalcyonPolicies.ps1 -AuthObject $auth

# Get full settings for one policy
.\Get-HalcyonPolicies.ps1 -AuthObject $auth -Id "uuid"

# List all with full settings
.\Get-HalcyonPolicies.ps1 -AuthObject $auth -IncludeSettings

# Filter by name
.\Get-HalcyonPolicies.ps1 -AuthObject $auth -Name "Strict"

# Save to JSON
.\Get-HalcyonPolicies.ps1 -AuthObject $auth -IncludeSettings -OutFile "policies.json"
```

**Endpoints called:**
- `GET /v2/policy-groups` — list all policies (RBAC: ReadOnly)
- `GET /v2/policy-groups/{id}` — single policy with full settings (RBAC: ReadOnly)

---

### Set-HalcyonAssetTag.ps1

**Version:** v1.0
**Purpose:** Adds or removes tags on Halcyon assets. Tags are the underlying mechanism for Search Groups in the Halcyon console. Assets can be specified by ID or hostname (or a mix) via a comma-separated string, a CSV file, or a one-per-line list file. The batch operation is asynchronous; the script polls until the job completes.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Assets` | string | | Comma-separated asset IDs or hostnames |
| `-CsvFile` | string | | CSV file with `id`, `assetId`, `name`, or `hostname` column |
| `-ListFile` | string | | One asset ID or hostname per line (blank lines and `#` comments ignored) |
| `-AddTag` | string | | Comma-separated tags to add |
| `-RemoveTag` | string | | Comma-separated tags to remove |
| `-PollIntervalSeconds` | int | 3 | How often to poll for job completion |
| `-TimeoutSeconds` | int | 120 | Max wait time before giving up on polling |
| `-WhatIf` | switch | off | Preview without applying |
| `-silent` | switch | off | Suppress decorative output |

At least one asset source (`-Assets`, `-CsvFile`, or `-ListFile`) and at least one tag operation (`-AddTag` or `-RemoveTag`) are required. Hostnames are resolved to asset IDs automatically via the assets search API.

**Returns:** The batch job response object (`jobId`, `status`).

**Usage:**

```powershell
# Add a tag by hostname
.\Set-HalcyonAssetTag.ps1 -AuthObject $auth -Assets "DESKTOP-OHIMIC7" -AddTag "prod"

# Add and remove tags in one call
.\Set-HalcyonAssetTag.ps1 -AuthObject $auth -Assets "DESKTOP-OHIMIC7" -AddTag "prod" -RemoveTag "staging"

# Tag from a CSV file
.\Set-HalcyonAssetTag.ps1 -AuthObject $auth -CsvFile "assets.csv" -AddTag "vdi-pool-a"

# Tag from a list file
.\Set-HalcyonAssetTag.ps1 -AuthObject $auth -ListFile "hostnames.txt" -AddTag "prod"

# Preview without applying
.\Set-HalcyonAssetTag.ps1 -AuthObject $auth -Assets "DESKTOP-OHIMIC7" -AddTag "prod" -WhatIf

# Skip confirmation prompt
.\Set-HalcyonAssetTag.ps1 -AuthObject $auth -Assets "DESKTOP-OHIMIC7" -AddTag "prod" -Confirm:$false
```

**Endpoints called:**
- `POST /v2/assets/search` — hostname resolution (RBAC: ReadOnly)
- `POST /v2/assets/batch` — apply tag changes (RBAC: PowerUser)
- `GET /v2/jobs/{jobId}` — poll for completion

---

### Set-HalcyonAssetPolicy.ps1

**Version:** v1.0
**Purpose:** Applies a Halcyon policy to a set of assets. Two targeting modes: by Search Group tag (applies to all assets with that tag), or by explicit asset list (comma-separated IDs/hostnames, CSV file, or list file). The policy can be specified by name or UUID. Requires PowerUser RBAC.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Tag` | string | | Target assets by Search Group tag (mutually exclusive with `-Assets`/`-CsvFile`/`-ListFile`) |
| `-Assets` | string | | Comma-separated asset IDs or hostnames |
| `-CsvFile` | string | | CSV file with `id`, `assetId`, `name`, or `hostname` column |
| `-ListFile` | string | | One asset ID or hostname per line |
| `-Policy` | string | | Policy name (exact, case-insensitive) |
| `-PolicyId` | string | | Policy UUID (alternative to `-Policy`) |
| `-PollIntervalSeconds` | int | 3 | How often to poll for job completion |
| `-TimeoutSeconds` | int | 120 | Max wait time before giving up on polling |
| `-WhatIf` | switch | off | Preview without applying |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** The batch job response object (`jobId`, `status`).

**Usage:**

```powershell
# Apply policy to all assets in a Search Group (by tag)
.\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth -Tag "vdi-pool-a" -Policy "Prevention"

# Apply policy to specific assets by hostname
.\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth -Assets "DESKTOP-OHIMIC7, Win0-d6c006" -Policy "Prevention"

# Apply policy to assets from a CSV file
.\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth -CsvFile "assets.csv" -Policy "Harris-Prevent"

# Specify policy by UUID instead of name
.\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth -Tag "prod" -PolicyId "uuid"

# Preview without applying
.\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth -Tag "jimbo" -Policy "Detection" -WhatIf
```

**Endpoints called:**
- `GET /v2/policy-groups` — policy name resolution (RBAC: ReadOnly)
- `POST /v2/assets/search` — tag preview and hostname resolution (RBAC: ReadOnly)
- `POST /v2/assets/batch` — apply policy assignment (RBAC: PowerUser)
- `GET /v2/jobs/{jobId}` — poll for completion

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

## VDI Device Hygiene

In VDI environments, Halcyon agents can register multiple times under the same hostname as machines are rebuilt or re-imaged. Each registration creates a new Asset ID. Only the most recently active registration is valid -- older entries are orphans that consume license count and clutter the console.

**Recommended workflow:**

```powershell
# Step 1 -- authenticate
$auth = .\Get-HalcyonBearerToken.ps1

# Step 2 -- find all stale registrations
$stale = .\Get-HalcyonDevices.ps1 -AuthObject $auth `
             -FindDuplicates -HeartbeatThresholdDays 7 -AllPages -silent |
         Where-Object { $_.duplicateStatus -eq "Stale" }

# Step 3 -- review before acting
$stale | Select-Object id, name, heartbeat, registered_date

# Step 4 -- preview deletions
$stale | ForEach-Object {
    .\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId $_.id -WhatIf
}

# Step 5 -- execute after review
$stale | ForEach-Object {
    .\Remove-HalcyonDevice.ps1 -AuthObject $auth -DeviceId $_.id -Confirm:$false
}
```

The `duplicateStatus` field on each device tells you exactly why it was flagged:

- `Stale` -- older duplicate registration, safe to remove
- `NoContact` -- no heartbeat within the threshold, investigate before removing
- `Keeper` -- the active registration in a duplicate group, do not remove
- `Unique` -- no duplicates found for this hostname

---

## SIEM Integration

`Get-HalcyonAlerts.ps1` is designed for SIEM ingestion pipelines. JSON output preserves full alert object fidelity including nested process trees, asset details, and artifact metadata.

**Daily pull pattern (Splunk, Elastic, Sentinel):**

```powershell
$filename = "halcyon_alerts_{0}.json" -f (Get-Date -Format "yyyyMMdd_HHmmss")

$auth = .\Get-HalcyonBearerToken.ps1 -silent
.\Get-HalcyonAlerts.ps1 -AuthObject $auth `
    -LastSeenAfter (Get-Date).AddHours(-24) `
    -AllPages -Format JSON -OutFile $filename -silent
```

The resulting file is a flat JSON array ready for ingestion by any SIEM that accepts JSON input. For incremental pulls, use `-LastSeenAfter` with the timestamp of your last successful run to avoid duplicate ingestion.

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
| `Get-HalcyonBearerToken.ps1` | v1.5 |
| `Invoke-HalcyonTokenRefresh.ps1` | v1.2 |
| `Get-HalcyonAlerts.ps1` | v1.3 |
| `Get-HalcyonDevices.ps1` | v1.2 |
| `Remove-HalcyonDevice.ps1` | v1.1 |
| `Get-HalcyonOverrides.ps1` | v1.2 |
| `New-HalcyonOverride.ps1` | v1.2 |
| `Remove-HalcyonOverride.ps1` | v1.1 |
| `Get-HalcyonWhoAmI.ps1` | v1.1 |
| `Get-HalcyonAuditLog.ps1` | v1.1 |
| `Get-HalcyonThreats.ps1` | v1.1 |
| `Get-HalcyonPolicies.ps1` | v1.0 |
| `Set-HalcyonAssetTag.ps1` | v1.1 |
| `Set-HalcyonAssetPolicy.ps1` | v1.1 |

---

## Diagnostics

**Get-HalcyonAuthRaw.ps1** is a diagnostic script that calls the auth endpoint and prints the raw response with no JWT decoding or formatting. Use it to inspect the raw API response or troubleshoot authentication issues.

```powershell
.\Get-HalcyonAuthRaw.ps1
```

This script is not part of the standard toolkit and is not required for normal operation.

---

*Maintained by the Halcyon Solutions Engineering team. For questions, contact your Halcyon SE or open a ticket at [support@halcyon.ai](mailto:support@halcyon.ai).*