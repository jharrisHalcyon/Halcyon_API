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
  - [Install-HalcyonAgent.ps1](#install-halcyonagentps1)
  - [Uninstall-HalcyonAgent.ps1](#uninstall-halcyonagentps1)
  - [Check-HalcyonAgent.ps1](#check-halcyonagentps1)
- [Override Types](#override-types)
  - [Certificate](#certificate-overrides)
  - [File / Hash](#file--hash-overrides)
  - [Monitor](#monitor-overrides)
  - [Driver](#driver-overrides)
  - [IpAddress / Host](#ipaddress--host-overrides)
  - [Dns](#dns-overrides)
- [Working with Notes](#working-with-notes)
- [VDI Device Hygiene](#vdi-device-hygiene)
- [Agent Lifecycle](#agent-lifecycle)
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
                         -->  Install-HalcyonAgent
                         -->  Uninstall-HalcyonAgent
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

# 4. Install the Halcyon agent on this machine using the existing auth session
.\Install-HalcyonAgent.ps1 -AuthObject $auth

# 5. Create a certificate override
$result = .\New-HalcyonOverride.ps1 -AuthObject $auth `
    -Kind Certificate `
    -CertificatePath "C:\certs\sophos.cer"

# 6. Remove it when done
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

**Returns:** `PSCustomObject` with `AccessToken`, `RefreshToken`, `TenantId`, `AccessExpiresAt`, `RefreshExpiresAt`

**Usage:**

```powershell
# Interactive -- full output
$auth = .\Get-HalcyonBearerToken.ps1

# Silent -- prompts only, no banners or token details
$auth = .\Get-HalcyonBearerToken.ps1 -silent

# From config file
$auth = .\Get-HalcyonBearerToken.ps1 -UseConfig

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

### Get-HalcyonAlerts.ps1

**Version:** v1.3  
**Purpose:** Retrieves alerts from a Halcyon tenant with flexible filtering, pagination, and output format options. Supports JSON export for SIEM ingestion.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-AlertId` | string | | UUID of a specific alert |
| `-Level` | string | | `Warning` or `Block` |
| `-TriageStatus` | string | | `New`, `InProgress`, `Resolved`, `FalsePositive` |
| `-DisplayStatus` | string | | `Visible` or `Hidden` |
| `-LastSeenAfter` | datetime | | Filter alerts last seen after this time |
| `-LastSeenBefore` | datetime | | Filter alerts last seen before this time |
| `-AllPages` | switch | off | Walk all result pages automatically |
| `-PageSize` | int | 100 | Results per page |
| `-Format` | string | `Object` | `Object` or `JSON` |
| `-OutFile` | string | | Write output to this file path |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** Array of alert objects or JSON string if `-Format JSON`

**Usage:**

```powershell
# Alerts from the last 7 days
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -LastSeenAfter (Get-Date).AddDays(-7)

# Block-level alerts only
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -Level Block -AllPages

# Export to JSON for SIEM
.\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -Format JSON -OutFile "alerts.json" -silent
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
| `-SortBy` | string | `registeredDate` | `agentVersion`, `heartbeat`, `name`, `osName`, `registeredDate` |
| `-SortOrder` | string | `Desc` | `Asc` or `Desc` |
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

# Find a specific device by hostname
.\Get-HalcyonDevices.ps1 -AuthObject $auth -Name "DESKTOP-ABC123"
```

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
**Purpose:** Retrieves overrides from a Halcyon tenant with filtering by type, action, and target.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Kind` | string | | Filter by override type: `Certificate`, `File`, `Monitor`, `Driver`, `IpAddress`, `Dns` |
| `-Action` | string | | Filter by action: `Allow`, `Block`, `Bypass` |
| `-AllPages` | switch | off | Walk all result pages |
| `-PageSize` | int | 100 | Results per page |
| `-OutFile` | string | | Write output to this JSON file |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** Array of override objects.

**Usage:**

```powershell
# All overrides
.\Get-HalcyonOverrides.ps1 -AuthObject $auth -AllPages

# Certificate overrides only
.\Get-HalcyonOverrides.ps1 -AuthObject $auth -Kind Certificate
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
| `-Kind` | string | Yes | `Certificate`, `File`, `Monitor`, `Driver`, `IpAddress`, `Dns` |
| `-Action` | string | No | `Allow`, `Block`, or `Bypass`. Default: `Allow`. Ignored for `-Kind Monitor` |
| `-TargetKind` | string | No | `Tenant` (default) or `Asset` |
| `-AssetId` | string | Conditional | Required when `-TargetKind Asset` |
| `-CertificatePath` | string | Conditional | Path to `.cer`, `.crt`, `.pem`, or `.der` file |
| `-Thumbprint` | string | Conditional | 40-char SHA1 hex string |
| `-Sha256` | string | Conditional | 64-char SHA256 hex string (File and Monitor) |
| `-DriverSha256` | string | Conditional | 64-char SHA256 of driver binary |
| `-Authentihash` | string | Conditional | 64-char Authenticode hash of driver |
| `-Cidr` | string | Conditional | IP address or CIDR range (IpAddress) |
| `-DnsName` | string | Conditional | Hostname or domain (Dns) |
| `-Note` | string | No | Optional note, max 280 chars |
| `-WhatIf` | switch | No | Preview without submitting |
| `-silent` | switch | No | Suppress decorative output |

**Returns:** Full API response object with `id`, `createdAt`, `createdBy`, `action`, `target`, `artifact`

**Usage:**

```powershell
# Certificate from file
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -CertificatePath "C:\certs\sophos.cer"

# File hash
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind File `
    -Sha256 "d3f1164e..." -Action Allow

# Preview without submitting
.\New-HalcyonOverride.ps1 -AuthObject $auth -Kind Certificate `
    -Thumbprint "971382847..." -WhatIf
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
| `-OverrideId` | int | Yes | Numeric override ID |
| `-WhatIf` | switch | No | Preview without deleting |
| `-Confirm:$false` | | No | Skip the confirmation prompt |

**Usage:**

```powershell
.\Remove-HalcyonOverride.ps1 -AuthObject $auth -OverrideId 1234 -Confirm:$false
```

---

### Get-HalcyonWhoAmI.ps1

**Version:** v1.1  
**Purpose:** Identity and RBAC diagnostic. Calls three identity endpoints in a single pass to display the current user's profile, effective role in the authenticated tenant, and all roles across all tenants.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | Yes* | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | Yes* | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | Yes* | Tenant ID (alternative to `-AuthObject`) |

**Returns:** `PSCustomObject` with `Id`, `Email`, `Name`, `Role`, `EffectiveRole`, `EffectiveGroup`, `AllRoles`

**Usage:**

```powershell
$auth = .\Get-HalcyonBearerToken.ps1
.\Get-HalcyonWhoAmI.ps1 -AuthObject $auth
```

---

### Get-HalcyonAuditLog.ps1

**Version:** v1.1  
**Purpose:** Exports the audit log for a tenant as CSV, polls until the async report job completes, downloads the result, and optionally filters rows by keyword.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-HoursBack` | int | 24 | Time window in hours |
| `-Filter` | string | | Keyword filter applied to all CSV fields after download |
| `-PollIntervalSeconds` | int | 5 | Job status polling interval |
| `-TimeoutSeconds` | int | 120 | Maximum wait time for report completion |
| `-SaveCsv` | switch | off | Write raw CSV to disk |
| `-CsvPath` | string | | Path for saved CSV |
| `-silent` | switch | off | Suppress decorative output |

**Requires:** `Admin` RBAC role

**Usage:**

```powershell
# Last 24 hours
.\Get-HalcyonAuditLog.ps1 -AuthObject $auth

# Filter for policy changes
.\Get-HalcyonAuditLog.ps1 -AuthObject $auth -Filter "policy" -HoursBack 48
```

---

### Get-HalcyonThreats.ps1

**Version:** v1.1  
**Purpose:** Retrieves threat intelligence records from the Halcyon threat database by SHA256 hash. Useful for enriching alert data with known threat classification and metadata.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-ThreatId` | string[] | | One or more SHA256 hashes to look up |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** Array of threat objects.

**Usage:**

```powershell
# Look up a specific hash
.\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId "d3f1164e..."

# Pipe hashes from alerts
$hashes = .\Get-HalcyonAlerts.ps1 -AuthObject $auth -AllPages -silent |
          ForEach-Object { $_.summary.artifact.sha256 } | Where-Object { $_ } | Sort-Object -Unique
.\Get-HalcyonThreats.ps1 -AuthObject $auth -ThreatId $hashes
```

---

### Get-HalcyonPolicies.ps1

**Version:** v1.0  
**Purpose:** Retrieves policies from the Halcyon tenant. The list endpoint returns summaries (name, ID, owner, isDefault). Use `-Id` for a single policy with full settings, or `-IncludeSettings` to fetch full settings for every returned policy.

> **Terminology:** What the API calls a "policy group" is referred to as a "policy" in this toolkit. The individual protection knobs inside a policy (Execution Prevention, Tamper Guard, etc.) are called "policy settings".

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Id` | string | | UUID of a specific policy -- returns full settings |
| `-Name` | string | | Client-side name filter (case-insensitive contains match) |
| `-AllPages` | switch | off | Walk all pages of results |
| `-IncludeSettings` | switch | off | Fetch full policy settings for each returned policy (N+1 calls) |
| `-OutFile` | string | | Write output to this file path (JSON) |
| `-silent` | switch | off | Suppress decorative output |

**Returns:** Array of policy objects.

**Usage:**

```powershell
# List all policies
.\Get-HalcyonPolicies.ps1 -AuthObject $auth

# Get full settings for a policy by name
.\Get-HalcyonPolicies.ps1 -AuthObject $auth -Name "Prevention" -IncludeSettings
```

---

### Set-HalcyonAssetTag.ps1

**Version:** v1.1  
**Purpose:** Applies Search Group tags to assets. Supports targeting by existing tag, explicit asset list, CSV file, or list file.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Tag` | string | | Target assets by existing Search Group tag |
| `-Assets` | string | | Comma-separated asset IDs or hostnames |
| `-CsvFile` | string | | CSV file with id, assetId, name, or hostname column |
| `-ListFile` | string | | One asset ID or hostname per line |
| `-AddTags` | string[] | | Tags to add |
| `-RemoveTags` | string[] | | Tags to remove |
| `-WhatIf` | switch | off | Preview without applying |
| `-silent` | switch | off | Suppress decorative output |

**Usage:**

```powershell
.\Set-HalcyonAssetTag.ps1 -AuthObject $auth -Assets "DESKTOP-ABC123" -AddTags "pov","pilot"
```

---

### Set-HalcyonAssetPolicy.ps1

**Version:** v1.1  
**Purpose:** Applies a Halcyon policy to a set of assets. Two targeting modes: by Search Group tag or by explicit asset list. The policy can be specified by name or UUID. Requires PowerUser RBAC.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-Tag` | string | | Target assets by Search Group tag |
| `-Assets` | string | | Comma-separated asset IDs or hostnames |
| `-CsvFile` | string | | CSV file with id, assetId, name, or hostname column |
| `-ListFile` | string | | One asset ID or hostname per line |
| `-Policy` | string | | Policy name (exact, case-insensitive) |
| `-PolicyId` | string | | Policy UUID (alternative to `-Policy`) |
| `-WhatIf` | switch | off | Preview without applying |
| `-silent` | switch | off | Suppress decorative output |

**Usage:**

```powershell
# Apply by hostname
.\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth -Assets "Win0-d6c006" -Policy "Prevention"

# Apply to all assets in a Search Group
.\Set-HalcyonAssetPolicy.ps1 -AuthObject $auth -Tag "pov" -Policy "Detection"
```

---

### Install-HalcyonAgent.ps1

**Version:** v1.3  
**Purpose:** Installs the Halcyon Windows agent on the local machine by authenticating to the Halcyon API, retrieving the current installer and install token for the target tenant, downloading the installer, and running a silent install. Supports the full toolkit auth pattern -- pass an existing `$auth` object to skip re-authentication.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-useConfig` | switch | off | Load credentials from `config.cfg` in the script directory |

**Notes:**
- Requires an elevated (Administrator) prompt
- Exits with a warning if the Halcyon agent service is already running
- Access token is auto-refreshed if within 60 seconds of expiry when `-AuthObject` is passed
- If no auth parameters are supplied, falls back to environment variables (`HAL_USER`, `HAL_PASS`, `HAL_TENANT`) or interactive prompts
- Can be run standalone without the rest of the toolkit if not passing `-AuthObject`

**Endpoints called:**
- `POST /identity/auth/login` -- authentication (when not using `-AuthObject`)
- `GET /v2/installers` -- retrieve installer download URL and install token

**Usage:**

```powershell
# Using an existing auth session (recommended)
$auth = .\Get-HalcyonBearerToken.ps1
.\Install-HalcyonAgent.ps1 -AuthObject $auth

# Via environment variables (unattended)
$env:HAL_USER   = 'admin@example.com'
$env:HAL_PASS   = 'yourpassword'
$env:HAL_TENANT = '0546ca62-47db-4319-a89e-647764941bcf'
.\Install-HalcyonAgent.ps1

# Via config file
.\Install-HalcyonAgent.ps1 -useConfig

# Interactive (prompts for credentials)
.\Install-HalcyonAgent.ps1
```

---

### Uninstall-HalcyonAgent.ps1

**Version:** v1.4  
**Purpose:** Silently uninstalls the Halcyon Windows agent, cleans up leftover files and registry keys, and optionally removes all console registrations for this machine via the API. Supports the full toolkit auth pattern.

**PREREQUISITE:** Tamper Guard must be disabled in the Halcyon console and the policy change must have propagated to the agent before running this script. Verify propagation by checking the agent log for a recent `UpdatePolicy` entry:
```
C:\ProgramData\Halcyon\HalcyonAR\logs\agent.log
```

**Source Cache:** InstallShield requires the original setup EXE to be present at `%LOCALAPPDATA%\Downloaded Installations\{EC26187D-45B0-4831-8824-F97450D4E231}\`. This is maintained automatically by Windows Installer. If it is missing, the script offers to download the installer from the API and restore it.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AuthObject` | PSCustomObject | | Auth object from `Get-HalcyonBearerToken.ps1` |
| `-AccessToken` | string | | Access token (alternative to `-AuthObject`) |
| `-TenantId` | string | | Tenant ID (alternative to `-AuthObject`) |
| `-useConfig` | switch | off | Load credentials from `config.cfg` in the script directory |
| `-SkipConsoleRemoval` | switch | off | Skip the console removal prompt entirely |

**What it cleans up:**
- Halcyon services (`halcyonagent`, `halcyonar`)
- `halcyonUI.exe` tray process (survives the uninstaller, killed explicitly)
- `C:\Program Files\Halcyon`
- `C:\ProgramData\Halcyon`
- InstallShield registration directory
- Kernel driver file (`halcyondrvr.sys`)
- All Halcyon registry keys across both 32-bit and 64-bit hives
- All console registrations matching this machine's hostname (optional, via API)

**Console removal:** Requires `Get-HalcyonBearerToken.ps1`, `Get-HalcyonDevices.ps1`, and `Remove-HalcyonDevice.ps1` to be present in the same directory. All registrations matching the current hostname are removed -- if the agent is being uninstalled, every registration for this hostname is by definition stale.

**Usage:**

```powershell
# Using an existing auth session (recommended -- handles console removal without re-prompting)
$auth = .\Get-HalcyonBearerToken.ps1
.\Uninstall-HalcyonAgent.ps1 -AuthObject $auth

# Interactive (will prompt for credentials if console removal is requested)
.\Uninstall-HalcyonAgent.ps1

# Skip console removal
.\Uninstall-HalcyonAgent.ps1 -AuthObject $auth -SkipConsoleRemoval

# Via config file
.\Uninstall-HalcyonAgent.ps1 -useConfig
```

---

### Check-HalcyonAgent.ps1

**Version:** v1.1  
**Purpose:** Inspects the current state of the Halcyon Windows agent installation. Checks services, registry keys, file system paths, and the kernel driver. No authentication required -- reads local system state only. Useful before and after install/uninstall to confirm machine state.

**Parameters:** None

**What it checks:**
- Services: `halcyonagent`, `halcyonar`
- Registry: uninstall keys (32-bit and 64-bit), `HKLM:\SOFTWARE\Halcyon`, service control manager entries
- File system: `C:\Program Files\Halcyon`, `C:\ProgramData\Halcyon`, InstallShield directory
- Kernel driver: `halcyonar` via WMI

**Usage:**

```powershell
# Run from an elevated prompt
.\Check-HalcyonAgent.ps1
```

**Example output (fully installed):**
```
 Halcyon Agent State Check
 ==========================

[halcyon] Services
[ok]        halcyonagent -- Status: Running  StartType: Automatic
[ok]        halcyonar -- Status: Running  StartType: System

[halcyon] Registry
[ok]        PRESENT (v2.0.2602.28) -- HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{7A334500-...}
...

[warn]    11 artifact(s) present. See above for details.
```

**Example output (clean machine):**
```
[ok]      No Halcyon agent artifacts found. Machine appears clean.
```

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

## Agent Lifecycle

For POV engagements and lab environments, the install/uninstall/check scripts provide a complete agent lifecycle workflow from the command line.

**Full install cycle:**

```powershell
# Authenticate once
$auth = .\Get-HalcyonBearerToken.ps1

# Confirm machine is clean before installing
.\Check-HalcyonAgent.ps1

# Install
.\Install-HalcyonAgent.ps1 -AuthObject $auth

# Confirm installed
.\Check-HalcyonAgent.ps1
```

**Full uninstall cycle:**

```powershell
# Confirm state before uninstalling
.\Check-HalcyonAgent.ps1

# Uninstall (Tamper Guard must be disabled in console first)
.\Uninstall-HalcyonAgent.ps1 -AuthObject $auth

# Confirm clean -- a reboot may be needed to fully remove the kernel driver
.\Check-HalcyonAgent.ps1
```

**Notes:**
- `Uninstall-HalcyonAgent.ps1` removes all console registrations for this hostname by default. This is intentional -- if the agent is being uninstalled, every registration for this hostname is stale.
- A reboot after uninstall is recommended to complete kernel driver removal. The `Check-HalcyonAgent.ps1` script will show any remaining artifacts.
- The `Check-HalcyonAgent.ps1` script requires no authentication and can be run at any point to inspect machine state.

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
| `Install-HalcyonAgent.ps1` | v1.3 |
| `Uninstall-HalcyonAgent.ps1` | v1.4 |
| `Check-HalcyonAgent.ps1` | v1.1 |

---

## Diagnostics

**Get-HalcyonAuthRaw.ps1** is a diagnostic script that calls the auth endpoint and prints the raw response with no JWT decoding or formatting. Use it to inspect the raw API response or troubleshoot authentication issues.

```powershell
.\Get-HalcyonAuthRaw.ps1
```

This script is not part of the standard toolkit and is not required for normal operation.

---

*Maintained by the Halcyon Solutions Engineering team. For questions, contact your Halcyon SE or open a ticket at [support@halcyon.ai](mailto:support@halcyon.ai).*
