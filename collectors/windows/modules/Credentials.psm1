# Credentials.psm1 — endpoint credential persistence.
#
# Security rules (mirrors collectors/linux credentials.py):
#   - never hardcode, print, or log credentials
#   - never accept a credential as a command-line argument
#   - the credential file is protected twice over:
#       1. Windows DPAPI (ConvertFrom/To-SecureString, CurrentUser scope):
#          ciphertext is bound to the Windows identity that wrote it, so the
#          file alone is useless to another account or another machine.
#          On Windows PowerShell 5.1 and PS7 this is the platform DPAPI.
#       2. An explicit ACL on the file + directory limited to the current SID
#          (inheritance disabled).
#   - rotation overwrites in place (atomic: temp file + Move-Item)
#   - loading REFUSES a file whose ACL grants access to other principals or
#     whose data cannot be decrypted under the current identity.
#
# The collector must therefore run under the SAME Windows identity that
# performed enrollment (service account — see README/docs).

Set-StrictMode -Version Latest

class EitopCredentialError : System.Exception {
    EitopCredentialError([string]$Message) : base($Message) {}
}

function Get-EitopCredentialField {
    # Local strict-mode-safe property read (works for JSON objects + hashtables)
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    $null
}

function Get-EitopCurrentSid {
    ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
}

function Test-EitopIsWindows {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }  # PS 5.1 = Windows only
    [bool]$PSVersionTable.Platform -and $PSVersionTable.Platform -eq 'Win32NT'
}

function Protect-EitopSecret {
    # DPAPI CurrentUser encryption. Non-Windows dev/test hosts are supported
    # only for mocked unit tests (callers mock this function there).
    param([Parameter(Mandatory)][securestring]$Secret)
    ConvertFrom-SecureString -SecureString $Secret
}

function Unprotect-EitopSecret {
    param([Parameter(Mandatory)][string]$Protected)
    $sec = ConvertTo-SecureString -String $Protected
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Set-EitopCredentialAcl {
    # Restrict file + directory to the current user only (Windows only).
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-EitopIsWindows)) { return }
    $sid = Get-EitopCurrentSid
    & icacls.exe $Path /inheritance:r /grant:r "${sid}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw [EitopCredentialError]::new("Failed to set ACL on $Path (icacls rc=$LASTEXITCODE)")
    }
}

function Test-EitopCredentialAcl {
    # True when only the current SID has rights to the file.
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-EitopIsWindows)) { return $true }  # ACL checks are Windows-only
    $sid = Get-EitopCurrentSid
    $out = & icacls.exe $Path 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { return $false }
    # Every explicit entry must be our SID; deny/allow entries for others fail.
    foreach ($line in ($out -split "(`r`n|`n)")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\d+ (success|failure)') { continue }
        if ($trimmed -eq '' -and -not $env:TEMP) { continue }
        if ($trimmed -match '^(Successfully|Failed)') { continue }
        if ($trimmed -notmatch 'S-\d-\d+-\d+') { continue }
        if ($trimmed -notmatch [regex]::Escape($sid)) { return $false }
    }
    return $true
}

function Save-EitopCredential {
    # Atomic write: temp file (created with restrictive ACL) then rename.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$EndpointId,
        [Parameter(Mandatory)][string]$Credential
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-EitopCredentialAcl -Path $dir
    }

    $protected = Protect-EitopSecret -Secret (ConvertTo-SecureString -String $Credential -AsPlainText -Force)
    # NOTE: plaintext exists only inside the transient securestring above.
    $payload = [pscustomobject]@{
        endpoint_id = $EndpointId
        credential  = $protected       # DPAPI ciphertext, NOT the raw secret
        protected   = 'dpapi-currentuser'
        version     = 1
    } | ConvertTo-Json -Compress

    $tmp = "$Path.tmp"
    Set-Content -LiteralPath $tmp -Value $payload -Encoding UTF8
    Set-EitopCredentialAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $Path -Force
    Set-EitopCredentialAcl -Path $Path
}

function Read-EitopCredential {
    # Refuses: missing file, foreign/weak ACL, undecryptable payload.
    # Returns plain values only to the in-memory caller; never logged here.
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw [EitopCredentialError]::new("Credential file not found: $Path - run enrollment first.")
    }
    if (-not (Test-EitopCredentialAcl -Path $Path)) {
        throw [EitopCredentialError]::new(
            "Credential file $Path is accessible to other principals; reset ACL to the service account only.")
    }

    try {
        $data = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw [EitopCredentialError]::new("Credential file $Path is unreadable: $($_.Exception.Message)")
    }
    # Strict-mode-safe property reads (missing keys → "invalid content")
    $endpointId = [string](Get-EitopCredentialField -Object $data -Name 'endpoint_id')
    $protected = [string](Get-EitopCredentialField -Object $data -Name 'credential')
    if (-not $endpointId -or -not $protected) {
        throw [EitopCredentialError]::new("Credential file $Path has invalid content.")
    }

    try {
        $credential = Unprotect-EitopSecret -Protected $protected
    } catch {
        throw [EitopCredentialError]::new(
            "Credential file $Path cannot be decrypted under the current identity - " +
            'the collector must run as the Windows account that enrolled it.')
    }

    [pscustomobject]@{ endpoint_id = $endpointId; credential = $credential }
}

function Remove-EitopCredential {
    param([Parameter(Mandatory)][string]$Path)
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

Export-ModuleMember -Function `
    Save-EitopCredential, Read-EitopCredential, Remove-EitopCredential, `
    Protect-EitopSecret, Unprotect-EitopSecret, Set-EitopCredentialAcl, `
    Test-EitopCredentialAcl, Get-EitopCurrentSid, Test-EitopIsWindows
