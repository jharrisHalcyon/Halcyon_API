# Halcyon API Examples

PowerShell scripts for interacting with the Halcyon platform API. These samples are provided as working reference implementations to help your team get started building integrations, automations, and operational tooling against the Halcyon API.

---

## Requirements

- PowerShell 5.1 or later
- Valid Halcyon console credentials (email and password)
- Your Halcyon Tenant ID (see below)
- Outbound HTTPS access to `api.halcyon.ai`

---

## Finding Your Tenant ID

Your Tenant ID is required for all API calls. It is not displayed in the Halcyon console UI directly.

**To retrieve your Tenant ID, contact Halcyon Support:**

> **support@halcyon.ai**

Include your organization name and the email address associated with your Halcyon console account. Support will provide your Tenant ID promptly.

---

## Scripts

### `Get-HalcyonBearerToken.ps1`

Authenticates against the Halcyon Identity endpoint and returns a Bearer token for use in subsequent API calls.

**What it does:**

- Prompts for Tenant ID, login email, and password
- Sends a POST to `https://api.halcyon.ai/identity/auth/login`
- Returns the access token, refresh token, and expiration window
- Handles secure credential input and wipes plaintext password from memory immediately after the request

**Usage:**

```powershell
.\Get-HalcyonBearerToken.ps1
```

**Interactive prompts:**

```
Enter Tenant ID            : <your-tenant-id>
Enter Halcyon Login Email  : user@yourcompany.com
Enter Halcyon Password     : ********
```

**Successful output:**

```
=== Authentication Successful ===

Tenant ID     : <your-tenant-id>
User          : user@yourcompany.com
Token Length  : 1234
Expires In    : 3600 seconds

Bearer Token:
eyJhbGciOiJSUzI1NiIsInR5cCI...
```

**Capturing the token for use in other scripts:**

The access token is written to the pipeline, so you can capture it directly:

```powershell
$token = .\Get-HalcyonBearerToken.ps1
```

You can then pass `$token` as a Bearer token header in subsequent API calls.

---

## Security Notes

- Credentials are entered interactively and are never stored to disk
- Passwords are handled as `SecureString` and the plaintext value is zeroed from memory immediately after the API request completes
- Do not hardcode credentials in scripts or commit them to source control
- Tokens expire per the `expiresIn` value returned -- plan to re-authenticate in long-running scripts

---

## More Halcyon API Resources

For full API documentation, endpoint references, and additional integration guidance, reach out to your Halcyon Solutions Engineer or contact:

> **support@halcyon.ai**

---

## Contributing

Additional example scripts will be added to this repository over time covering areas such as device management, alert retrieval, policy configuration, and reporting. If you have a specific use case or integration you would like to see covered, contact your Halcyon SE team.

---

*Halcyon -- Ransomware Prevention and Recovery Platform*  
*These samples are provided as reference implementations. Always test in a non-production environment before deploying.*