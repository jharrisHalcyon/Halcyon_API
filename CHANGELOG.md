# Changelog

All notable changes to the Halcyon API PowerShell Toolkit are documented here.

---

## [Unreleased] -- 2026-02-26

### Added

**Get-HalcyonAlerts.ps1 (v1.0)**
- New script for retrieving alerts from the Halcyon API.
- Full filter support: `-Type`, `-Action`, `-TriageStatus`, `-DisplayStatus`, date ranges (`-FirstSeenAfter`, `-FirstSeenBefore`, `-LastSeenAfter`, `-LastSeenBefore`), `-OffendingSha256` (partial prefix match), and `-AlertId` for specific alert lookup.
- Automatic pagination via `-AllPages` switch; single-page mode by default.
- Output formats: JSON (default, SIEM-ready) and CSV (flattened, Excel-friendly).
- `-OutFile` parameter for writing results directly to disk.
- Returns PSCustomObject array to pipeline for further PowerShell processing.
- Designed for SIEM ingestion pipelines, POV closeout reporting, and hash hunting.

**Get-HalcyonDevices.ps1 (v1.0)**
- New script for retrieving registered devices (endpoints) from a Halcyon tenant.
- Standard listing with filters: `-Name` (substring), `-OperatingSystem`, `-AgentVersion`, `-Search` (generic).
- `-FindDuplicates` mode for VDI hygiene: groups devices by name, flags stale registrations vs. the most recently active heartbeat (Keeper/Stale/Unique/NoContact).
- `-HeartbeatThresholdDays` configures the window for NoContact flagging (default: 7 days).
- Outputs device list with annotated `duplicateStatus` field when in duplicate detection mode.
- Stale candidate IDs are printed to console and returned to pipeline for use with `Remove-HalcyonDevice.ps1`.

**Remove-HalcyonDevice.ps1 (v1.0)**
- New script for marking stale device registrations for deletion.
- Companion to `Get-HalcyonDevices.ps1 -FindDuplicates` for VDI hygiene workflows.
- Supports `-WhatIf` (preview without deletion) and `-Confirm:$false` (skip prompt for scripted use).
- `ConfirmImpact = High` -- defaults to prompting interactively when run in a terminal.
- Targets `/v1/device/{device_id}` (DELETE), returns 202 Accepted (async deletion).
- RBAC: PowerUser or Admin required.

**Get-HalcyonOverrides.ps1 (v1.0)**
- New script providing the read side of the override management toolkit.
- Full filter support: `-Kind`, `-Action` (multi-value), `-TargetKind`, `-AssetId`, `-AssetName`, `-AlertId`, `-CreatedAfter`, `-CreatedBefore`, `-CreatedBy`, `-CertThumbprint`, `-CertSubjectDN`, `-OffendingSha256`, `-FileCopyright`, `-FileProductName`, `-OffendingCidr`, `-OffendingDns`.
- Automatic pagination via `-AllPages`.
- `-OutFile` for JSON file output.
- Returns PSCustomObject array to pipeline.

**Invoke-HalcyonNewScriptTests.ps1 (v1.0)**
- New test harness covering all four new scripts with 10 test cases.
- Tests 1-4: Get-HalcyonAlerts (basic list, filtered, JSON file output, CSV file output).
- Tests 5-6: Get-HalcyonDevices (basic list, duplicate detection mode).
- Tests 7-8: Get-HalcyonOverrides (basic list, Kind=Certificate filter).
- Test 9: Remove-HalcyonDevice -WhatIf (always non-destructive).
- Test 10: Remove-HalcyonDevice live delete (opt-in via `-RunRemoveTest` and `-StaleDeviceId`).
- Writes timestamped log file alongside results.

---

## Previous Releases

### [v1.1] -- 2026-02-24

**New scripts:**
- `Get-HalcyonAuditLog.ps1` (v1.0) -- async CSV export of tenant audit log with polling, keyword filtering, and optional file save.
- `Get-HalcyonWhoAmI.ps1` (v1.0) -- identity and RBAC diagnostic across three identity endpoints.
- `Get-HalcyonAuthRaw.ps1` (diagnostic) -- raw auth response inspection tool.

**Updated scripts:**
- `Get-HalcyonBearerToken.ps1` -- v1.1 to v1.2: improved JWT decode output, token TTL display.
- `Invoke-HalcyonTokenRefresh.ps1` -- v1.1 to v1.2: added `-Loop` mode, `-TokenOnly` switch, `-WarnThresholdSeconds`.
- `Invoke-HalcyonOverrideTests.ps1` -- v1.0 to v1.1: added multi-line note test case (Test 4).

### [v1.0] -- 2026-02-24

Initial release.

**Scripts:**
- `ConvertFrom-HalcyonJwt.ps1` (v1.0) -- shared JWT decode helper.
- `Get-HalcyonBearerToken.ps1` (v1.1) -- interactive authentication.
- `Invoke-HalcyonTokenRefresh.ps1` (v1.1) -- token refresh with loop support.
- `New-HalcyonOverride.ps1` (v1.1) -- override creation for all artifact types with Target scope support.
- `Remove-HalcyonOverride.ps1` (v1.0) -- override deletion by ID.
- `Invoke-HalcyonOverrideTests.ps1` (v1.0) -- test harness for override scripts.
