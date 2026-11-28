# Credential storage tests: roundtrip, refusal, rotation, no-leak guarantees.
# DPAPI is Windows-only; the Protect/Unprotect seam keeps these tests
# cross-platform while Windows behavior is documented as unverified here.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/Credentials.psm1') -Force
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Cred = 'eitop_ep_livecredential0000000000000000000'

    if (-not (Test-EitopIsWindows)) {
        # Phase 6 audit W2: Protect/Unprotect-EitopSecret now THROW on
        # non-Windows (ConvertFrom-SecureString there is reversible
        # obfuscation, not DPAPI). These tests exercise Save/Read LOGIC
        # (atomicity, ACL refusal, payload shape) on a non-Windows host,
        # so the platform primitive is mocked HERE ONLY — the real
        # platform guard itself is tested unmocked in
        # Credentials.Platform.Tests.ps1.
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
        Mock -ModuleName Credentials Unprotect-EitopSecret {
            param($Protected)
            if (-not $Protected.StartsWith('TESTENC:')) { throw 'simulated decrypt failure' }
            [Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($Protected.Substring(8)))
        }
    }
}

Describe 'Save/Read roundtrip' {
    It 'writes, protects and reads back the credential' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-test-" + [guid]::NewGuid() + '.json')
        try {
            Save-EitopCredential -Path $path -EndpointId 'ep-123' -Credential $script:Cred
            $stored = Read-EitopCredential -Path $path
            $stored.endpoint_id | Should -Be 'ep-123'
            $stored.credential | Should -Be $script:Cred
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'never writes the raw credential into the file' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-test-" + [guid]::NewGuid() + '.json')
        try {
            Save-EitopCredential -Path $path -EndpointId 'ep-123' -Credential $script:Cred
            $raw = Get-Content -LiteralPath $path -Raw
            $raw | Should -Not -Match ([regex]::Escape($script:Cred))
            $raw | Should -Match 'dpapi-currentuser'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'rotation overwrites atomically with no temp file left behind' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-test-" + [guid]::NewGuid() + '.json')
        try {
            Save-EitopCredential -Path $path -EndpointId 'ep-1' -Credential 'eitop_ep_old'
            Save-EitopCredential -Path $path -EndpointId 'ep-1' -Credential 'eitop_ep_new'
            (Read-EitopCredential -Path $path).credential | Should -Be 'eitop_ep_new'
            Test-Path "$path.tmp" | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$path.tmp" -Force -ErrorAction SilentlyContinue
        }
    }

    It 'creates the parent directory when missing' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("eitop-dir-" + [guid]::NewGuid())
        $path = Join-Path $dir 'credentials.json'
        try {
            Save-EitopCredential -Path $path -EndpointId 'ep-1' -Credential 'eitop_ep_x'
            Test-Path $path | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Protect/Unprotect roundtrip (platform primitive)' {
    It 'converts a securestring to protected text and back' {
        if (-not (Test-EitopIsWindows)) {
            # W2: the real platform primitive refuses off-Windows, and the
            # file-wide mock only intercepts module-internal calls (Save/
            # Read roundtrips above) — the direct call hits the real guard.
            # Windows behavior is exercised here; DPAPI itself remains
            # documented-unverified on this CI host.
            Set-ItResult -Skipped -Because 'DPAPI requires Windows (Phase 6 W2)'
            return
        }
        $protected = Protect-EitopSecret -Secret (ConvertTo-SecureString 'eitop_ep_secret' -AsPlainText -Force)
        $protected | Should -Not -Match 'eitop_ep_secret'
        Unprotect-EitopSecret -Protected $protected | Should -Be 'eitop_ep_secret'
    }
}

Describe 'Read refusal paths' {
    It 'refuses a missing file with an actionable message' {
        $missing = Join-Path ([IO.Path]::GetTempPath()) ("eitop-missing-" + [guid]::NewGuid() + '.json')
        { Read-EitopCredential -Path $missing } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'refuses corrupt JSON' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-test-" + [guid]::NewGuid() + '.json')
        try {
            Set-Content -LiteralPath $path -Value '{not json'
            { Read-EitopCredential -Path $path } | Should -Throw -ExpectedMessage '*unreadable*'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'refuses missing fields' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-test-" + [guid]::NewGuid() + '.json')
        try {
            Set-Content -LiteralPath $path -Value '{"endpoint_id":"ep-1"}'
            { Read-EitopCredential -Path $path } | Should -Throw -ExpectedMessage '*invalid content*'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'refuses a payload that cannot be decrypted under this identity' {
        # Simulate: file written by a different account (DPAPI blob mismatch)
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-test-" + [guid]::NewGuid() + '.json')
        try {
            $payload = [pscustomobject]@{
                endpoint_id = 'ep-1'
                credential  = 'AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAfakeblob'
                protected   = 'dpapi-currentuser'
                version     = 1
            } | ConvertTo-Json -Compress
            Set-Content -LiteralPath $path -Value $payload
            { Read-EitopCredential -Path $path } | Should -Throw -ExpectedMessage '*current identity*'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'credential hygiene' {
    It 'Remove clears the file and is idempotent' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-test-" + [guid]::NewGuid() + '.json')
        Save-EitopCredential -Path $path -EndpointId 'ep-1' -Credential 'eitop_ep_x'
        Remove-EitopCredential -Path $path
        Test-Path $path | Should -BeFalse
        Remove-EitopCredential -Path $path   # no error
    }

    It 'no module or entry script prints credential values' {
        $files = Get-ChildItem (Join-Path $script:Root 'modules') -Filter '*.psm1'
        $files += Get-Item (Join-Path $script:Root 'eitop-collector.ps1')
        foreach ($file in $files) {
            $code = Get-CodeOnlyText -Path $file.FullName
            # No Write-* of a credential value / stored secret / enrollment token
            $code | Should -Not -Match 'Write-\w+[^\r\n]*(\$stored\.credential|EITOP_ENROLL_TOKEN)' `
                -Because "$($file.Name) must never print credential or token values"
            $code | Should -Not -Match 'Write-\w+[^\r\n]*\.credential\b' `
                -Because "$($file.Name) must never print credential properties"
        }
    }

    It 'enrollment token is never accepted as a script parameter' {
        $content = Get-Content (Join-Path $script:Root 'eitop-collector.ps1') -Raw
        # param() block must not declare -Token / -Credential
        $paramBlock = ($content -split '^\)', 2, 'Multiline')[0]
        $paramBlock | Should -Not -Match '(?<!\w)-Token\b'
        $paramBlock | Should -Not -Match '(?<!\w)-Credential\b'
        $paramBlock | Should -Not -Match '(?<!\w)-Secret\b'
    }
}
