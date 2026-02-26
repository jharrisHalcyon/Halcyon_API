# Changelog

All notable changes to the Halcyon API PowerShell Toolkit are documented here.

Versions are per-script. Each script maintains its own version number in its file header. A change to one script does not bump the version of unrelated scripts.

---

## 2026-02-25

### Get-HalcyonWhoAmI.ps1 -- v1.0

Initial release.

- Diagnostic script. Calls three identity endpoints in a single pass: `GET /identity/user` (profile), `GET /identity/user/effective-role` (role in current tenant), `GET /identity/user/roles` (all roles across all tenants).
- Prints a color-coded capability summary mapping the current RBAC level to specific operations: override creation, override deletion, tag management, install token generation, policy group management, audit log export, and tenant creation.
- Color coding by access level: TenantAdmin (magenta), Admin (green), PowerUser (cyan), User (white), ReadOnly (dark cyan).
- Returns a structured `PSCustomObject` for pipeline use containing `Id`, `Email`, `Name`, `Role`, `EffectiveRole`, `EffectiveGroup`, `AllRoles`.
- Note: the `role` field on `GET /identity/user` does not populate for all account types. `EffectiveRole` from `GET /identity/user/effective-role` is the authoritative value.
- Live test confirmed: service account has `Admin` effective role across two tenants. `TenantAdmin` is not assigned -- tenant creation and deletion require a separate request to Halcyon support.

---

### Get-HalcyonAuditLog.ps1 -- v1.0

Initial release.

- Exports the audit log for a tenant via `POST /v2/audit-logs/export` with an optional timestamp window (default: last 24 hours).
- Async job pattern: submits export request, receives `reportId`, polls `GET /v2/jobs/{reportId}` at configurable intervals until status is `Completed`, `Failed`, or `Deleted`.
- On completion, attempts to auto-discover the CSV download URL by inspecting the job response for known URL field names (`downloadUrl`, `url`, `reportUrl`, `fileUrl`, `link`, `href`, `location`) and then trying common REST endpoint patterns if no URL field is found. Full job response is always printed to console to aid in URL discovery if auto-detection fails.
- Parses the downloaded CSV using `ConvertFrom-Csv` and applies an optional `-Filter` keyword across all fields in every row.
- `-SaveCsv` switch writes the raw CSV to a timestamped file before filtering.
- `-TargetTenantId` parameter allows targeting a specific subtenant independently of the authenticated tenant.
- Returns filtered rows as `PSCustomObject` array for pipeline use.
- Requires `Admin` RBAC.

---

## 2026-02-24

### ConvertFrom-HalcyonJwt.ps1 -- v1.0

Initial release.

- `ConvertFrom-HalcyonJwt` function decodes a JWT payload to a `PSCustomObject` without requiring external libraries. Handles base64url padding and character substitution natively.
- `Get-HalcyonTokenExpiry` function returns structured expiry metadata: `ExpiresAt`, `IssuedAt`, `SecondsRemaining`, `IsExpired`, `TtlSeconds`, `Subject`, `Email`.
- Dot-sourceable by other scripts via `$PSScriptRoot`.
- Confirmed against live Halcyon API: access token TTL is 300 seconds (5 minutes), refresh token TTL is 900 seconds (15 minutes). Neither value is present as a top-level field in the auth response -- both are embedded as `exp` claims in the JWT payloads.

---

### Get-HalcyonAuthRaw.ps1 -- v1.0

Initial release.

- Diagnostic script. Calls `/identity/auth/login` and prints the raw response with no JWT decoding or formatting.
- Used to confirm that the Halcyon auth response contains only `accessToken` and `refreshToken` fields. The `expiresIn` field documented in the OpenAPI spec is not present in actual responses.
- Not part of the standard toolkit. Intended for troubleshooting and API discovery.

---

### Get-HalcyonBearerToken.ps1 -- v1.0

Initial release.

- Interactive authentication against `/identity/auth/login`.
- Prompts for Tenant ID, login email, and password.
- Plaintext password zeroed from memory immediately after the request via `Marshal.ZeroFreeBSTR`.
- Returns `PSCustomObject` with `AccessToken`, `RefreshToken`, `TenantId`, `AccessExpiresAt`, `RefreshExpiresAt`.

### Get-HalcyonBearerToken.ps1 -- v1.1

- Integrated `ConvertFrom-HalcyonJwt.ps1` helper to decode both JWTs on receipt.
- Added display of real expiry timestamps, TTL in seconds and minutes, and time remaining with color coding (red if under 60 seconds).
- Added SSO warning in comments directing users to request a service account via `support@halcyon.ai`.

### Get-HalcyonBearerToken.ps1 -- v1.2

- Added `-silent` switch. Suppresses all decorative output -- banners, token details, expiry info, bearer token echo. Errors and warnings always show. Prompts always show.
- Fixed author title to `Halcyon SA` for consistency across the toolkit.

---

### Invoke-HalcyonTokenRefresh.ps1 -- v1.0

Initial release.

- Exchanges a refresh token for a new access token and refresh token pair via `/identity/auth/refresh`.
- Pre-flight expiry check on the refresh token before each API call.
- Handles token rotation -- the server issues a new refresh token on every refresh.
- Three usage modes: interactive (prompts for tokens), pipeline (accepts `PSCustomObject` from `Get-HalcyonBearerToken.ps1`), and loop mode (`-Loop` with configurable `-IntervalSeconds`, default 240s).
- Returns `PSCustomObject` maintaining full auth state across cycles.

### Invoke-HalcyonTokenRefresh.ps1 -- v1.1

- Added `-TokenOnly` switch. Returns only the access token string instead of the full auth object. Console output is minimal when set -- one status line with expiry times, no banner, no token echo.
- In loop mode, `-TokenOnly` emits the access token string on each cycle rather than the full object.

### Invoke-HalcyonTokenRefresh.ps1 -- v1.2

- Added `-silent` switch. Suppresses all decorative output in both single-refresh and loop modes. The "Loop stopped -- re-authentication required" error message always shows regardless.
- When combined with `-TokenOnly`, nothing is written to the console on success.
- Fixed author title to `Halcyon SA` for consistency across the toolkit.

---

### New-HalcyonOverride.ps1 -- v1.0

Initial release.

- Creates overrides via `POST /v2/overrides` for five artifact types: `Certificate`, `File`, `Driver`, `IpAddress`, `Dns`.
- For Certificate overrides, accepts either a certificate file (`.cer`, `.crt`, `.pem`, `.der`) or a raw 40-character SHA1 thumbprint. When a file is supplied, thumbprint and metadata are extracted using `X509Certificate2` and a structured note is generated automatically matching the Halcyon console format.
- Override scope: `Tenant` (default) or `Asset` (requires `-AssetId`).
- Action: `Allow` (default), `Block`, or `Bypass`.
- Optional `-Note` parameter, max 280 characters.
- `-WhatIf` support via `[CmdletBinding(SupportsShouldProcess)]`.
- Explicit error messages for all expected HTTP error codes: 400, 401, 403, 404, 409.

### New-HalcyonOverride.ps1 -- v1.1

- Added `Monitor` as a first-class `-Kind` value. Maps to `File` artifact with `Bypass` action at the API level, matching the Halcyon console Monitor tab. `-Action` is ignored when `-Kind Monitor` is set -- Bypass is enforced automatically. Warning emitted if `-Action` is supplied with a non-Bypass value.
- Updated `-Kind` parameter comment to document the File vs Monitor distinction and the API-level mapping.
- Updated `-Note` parameter comment to document newline syntax: backtick-n (`` `n ``) produces a real newline; backslash-n (`\n`) is treated as a literal string. Includes here-string example for multi-line notes. Notes that the 280 character limit includes newline characters.
- Confirmed via live API testing: duplicate thumbprint submissions are treated as upserts -- the existing override is updated silently rather than returning a 409 conflict. Documented in parameter comments and README.
- Fixed author title to `Halcyon SA` for consistency across the toolkit.

---

### Remove-HalcyonOverride.ps1 -- v1.0

Initial release.

- Deletes an override by numeric ID via `DELETE /v2/overrides/{overrideId}`.
- Accepts `-AuthObject` from `Get-HalcyonBearerToken.ps1` or direct `-AccessToken` and `-TenantId` parameters.
- `ConfirmImpact = "High"` -- PowerShell prompts for confirmation before deleting. Use `-Confirm:$false` to suppress in scripted contexts.
- `-WhatIf` support.
- Explicit error messages for 401, 403, and 404.

---

### Invoke-HalcyonOverrideTests.ps1 -- v1.0

Initial release.

- Live test harness exercising three override types against a real tenant: Certificate (Allow), File/Hash (Allow), Monitor (File + Bypass).
- Test 1 generates a self-signed certificate (`CN=HalcyonAPITest`) in `Cert:\CurrentUser\My`, extracts the thumbprint, creates the override, and removes the cert from the store in a `finally` block regardless of test outcome.
- Tests 2 and 3 use synthetic SHA256 values (all-zeros and all-F's respectively) that are valid format but match no real files.
- Pauses between add and remove in each test for console verification.
- Silent token auto-refresh before every API call. Stops cleanly with a re-auth prompt if both tokens expire.
- All output written to console and to a timestamped log file (`HalcyonOverrideTest_YYYYMMDD_HHmmss.log`).
- Pass/fail summary table at completion.
- Per-test skip switches: `-SkipCertTest`, `-SkipFileTest`, `-SkipMonitorTest`.

### Invoke-HalcyonOverrideTests.ps1 -- v1.1

- Added Test 4: multi-line note validation using a Certificate override. Generates a self-signed cert (`CN=HalcyonNoteTestA`), submits a backtick-n note, and pauses for visual verification in the console Certificate tab.
- Removed Test 4 Part B (backslash-n comparison) following live testing confirmation that backtick-n is the correct newline syntax. The `\n` behavior is documented in `New-HalcyonOverride.ps1` comments and the README instead.
- Added `-SkipNoteTest` skip switch.
- Live testing finding documented: the API deduplicates certificate overrides by thumbprint. Duplicate thumbprint submissions update the existing override silently rather than returning 409. Originally surfaced when Test 4 Part A and Part B used the same cert -- Part B overwrote Part A's note with no error.
- Fixed author title to `Halcyon SA` for consistency across the toolkit.

---

