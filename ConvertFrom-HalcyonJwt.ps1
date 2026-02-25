##############################################################################
# ConvertFrom-HalcyonJwt.ps1
# Author  : Jim Harris -- Halcyon Senior SA
# Date    : 2026-02-24
# Version : v1.0
#
# Shared helper. Decodes a JWT (JSON Web Token) and returns the payload as
# a PowerShell object. No external libraries required -- JWTs are standard
# base64url-encoded JSON and PowerShell can decode them natively.
#
# JWT structure:  header.payload.signature
# Only the payload section is decoded here. The signature is intentionally
# not verified -- this is for display and TTL calculation only. Signature
# verification happens server-side when you present the token to the API.
#
# Usage (dot-source into another script):
#   . .\ConvertFrom-HalcyonJwt.ps1
#   $payload = ConvertFrom-HalcyonJwt -Token $myToken
#   Write-Host $payload.exp
#
# Returned payload fields of interest for Halcyon tokens:
#   exp   -- Unix timestamp when the token expires
#   iat   -- Unix timestamp when the token was issued
#   sub   -- Subject (user ID)
#   email -- Authenticated user email
#   typ   -- Token type (Bearer or Refresh)
#
# Note on TTL:
#   Halcyon access tokens currently have a 5-minute TTL.
#   Refresh tokens currently have a 15-minute TTL.
#   Neither value is returned as a top-level field in the auth response --
#   both are embedded as 'exp' claims inside the JWT payload.
#
##############################################################################

function ConvertFrom-HalcyonJwt {
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    # Split on dot -- JWT has exactly three segments
    $parts = $Token.Split('.')
    if ($parts.Count -ne 3) {
        throw "Invalid JWT format. Expected 3 segments separated by dots, got $($parts.Count)."
    }

    # Base64url uses - and _ instead of + and /
    # PowerShell's [Convert]::FromBase64String needs standard base64
    # Padding with = is also required to reach a multiple of 4 characters
    $base64 = $parts[1] -replace '-', '+' -replace '_', '/'
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '='  }
    }

    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String($base64)
        )
        return ($decoded | ConvertFrom-Json)
    }
    catch {
        throw "Failed to decode JWT payload: $_"
    }
}

function Get-HalcyonTokenExpiry {
    <#
    .SYNOPSIS
        Returns a human-readable expiry summary for a Halcyon JWT.
    .DESCRIPTION
        Decodes the token, converts the 'exp' Unix timestamp to local time,
        and returns a small object with the expiry datetime and seconds
        remaining. Negative SecondsRemaining means the token is already
        expired.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Token,

        [string]$Label = "Token"
    )

    $payload        = ConvertFrom-HalcyonJwt -Token $Token
    $expireAt       = [System.DateTimeOffset]::FromUnixTimeSeconds($payload.exp).LocalDateTime
    $issuedAt       = [System.DateTimeOffset]::FromUnixTimeSeconds($payload.iat).LocalDateTime
    $secondsRemain  = [int]($expireAt - (Get-Date)).TotalSeconds
    $ttlSeconds     = [int]($expireAt - $issuedAt).TotalSeconds

    return [PSCustomObject]@{
        Label            = $Label
        Type             = $payload.typ
        IssuedAt         = $issuedAt
        ExpiresAt        = $expireAt
        TtlSeconds       = $ttlSeconds
        SecondsRemaining = $secondsRemain
        IsExpired        = ($secondsRemain -le 0)
        Subject          = $payload.sub
        Email            = $payload.email
    }
}