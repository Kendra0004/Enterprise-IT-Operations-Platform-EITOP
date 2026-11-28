# Phase 6 audit — credential platform hardening tests.
#
# Kept SEPARATE from Credentials.Tests.ps1 so the W2 platform guard can be
# exercised UNMOCKED (that file mocks Protect/Unprotect on non-Windows
# hosts to test Save/Read logic).

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/Credentials.psm1') -Force
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:IsWin = Test-EitopIsWindows
}

Describe 'W2: DPAPI platform guard' {
    It 'refuses to protect credentials on non-Windows (no fake obfuscation)' {
        if ($script:IsWin) {
            $p = Protect-EitopSecret -Secret (ConvertTo-SecureString 'eitop_ep_secret' -AsPlainText -Force)
            $p | Should -Not -BeNullOrEmpty
            return
        }
        { Protect-EitopSecret -Secret (ConvertTo-SecureString 'eitop_ep_secret' -AsPlainText -Force) } |
            Should -Throw -ExpectedMessage '*Windows-only*'
    }

    It 'refuses to decrypt credentials on non-Windows' {
        if ($script:IsWin) { return }  # Windows path covered by roundtrip tests
        { Unprotect-EitopSecret -Protected 'anything' } |
            Should -Throw -ExpectedMessage '*Windows-only*'
    }

    It 'never silently falls back to reversible ConvertFrom-SecureString output' {
        if ($script:IsWin) { return }
        { Protect-EitopSecret -Secret (ConvertTo-SecureString 'x' -AsPlainText -Force) } |
            Should -Throw
    }
}

Describe 'W1: ACL identity normalization fails closed' {
    It 'returns the SID string for a SecurityIdentifier input' {
        if (-not $script:IsWin) {
            Set-ItResult -Skipped -Because 'Windows principal types are unsupported on this platform'
            return
        }
        $sid = [System.Security.Principal.SecurityIdentifier]::new(
            'S-1-5-21-3623811015-3361044348-30300820-1013')
        Get-EitopRuleSid -IdentityReference $sid |
            Should -Be 'S-1-5-21-3623811015-3361044348-30300820-1013'
    }

    It 'returns the raw value for an unresolvable principal (never matches ours)' {
        # A name that cannot translate to a SID must not crash under
        # strict mode and must never equal the current user's SID.
        $raw = Get-EitopRuleSid -IdentityReference 'NOSUCH\Account'
        $raw | Should -Be 'NOSUCH\Account'
        if ($script:IsWin) { $raw | Should -Not -Be (Get-EitopCurrentSid) }
    }

    It 'returns empty string for null input' {
        Get-EitopRuleSid -IdentityReference $null | Should -Be ''
    }

    It 'parses the structured ACL (Get-Acl), not icacls text (W1 regression)' {
        # Inspect CODE, not comments — the header comment legitimately
        # explains why icacls text parsing was removed.
        $code = Get-CodeOnlyText -Path (Join-Path $script:Root 'modules/Credentials.psm1')
        $fn = [regex]::Match($code, '(?s)function Test-EitopCredentialAcl.*?(?=function Save-EitopCredential)').Value
        $fn | Should -Not -BeNullOrEmpty
        $fn | Should -Match 'Get-Acl'
        $fn | Should -Not -Match 'icacls'
        # Every rule must be checked — the check must not skip unnamed entries.
        $fn | Should -Match 'foreach \(\$rule in \$acl\.Access\)'
    }
}

Describe 'W7: credential directory ACL applied every save' {
    BeforeAll {
        # Save/Read logic under test needs the crypto + ACL side effects
        # mocked (non-Windows host: no DPAPI, no icacls).
        Mock -ModuleName Credentials Protect-EitopSecret {
            param($Secret)
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
            try {
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
            'TESTENC:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain))
        }
        Mock -ModuleName Credentials Set-EitopCredentialAcl { }
    }

    It 'applies the ACL to a PRE-EXISTING parent directory on every save' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("eitop-w7-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $path = Join-Path $dir 'credentials.json'
        try {
            Save-EitopCredential -Path $path -EndpointId 'ep-1' -Credential 'eitop_ep_x'
            Test-Path $path | Should -BeTrue
            # The directory ACL must be set even though this call did NOT
            # create the directory (older code only ACL'd new dirs).
            Should -Invoke -CommandName Set-EitopCredentialAcl -ModuleName Credentials -Times 1 -Exactly `
                -ParameterFilter { $Path -eq $dir }
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'still creates a missing parent directory and secures it' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("eitop-w7b-" + [guid]::NewGuid())
        $path = Join-Path $dir 'credentials.json'
        try {
            Save-EitopCredential -Path $path -EndpointId 'ep-1' -Credential 'eitop_ep_x'
            Test-Path $path | Should -BeTrue
            Should -Invoke -CommandName Set-EitopCredentialAcl -ModuleName Credentials -Times 1 -Exactly `
                -ParameterFilter { $Path -eq $dir }
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Read refuses when the parent directory ACL exposes other principals' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("eitop-w7c-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $path = Join-Path $dir 'credentials.json'
        try {
            Save-EitopCredential -Path $path -EndpointId 'ep-1' -Credential 'eitop_ep_x'
            Mock -ModuleName Credentials Test-EitopCredentialAcl {
                param($Path)
                $Path -ne $dir   # file OK, directory "leaks"
            }
            { Read-EitopCredential -Path $path } |
                Should -Throw -ExpectedMessage '*Directory*accessible to other principals*'
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
