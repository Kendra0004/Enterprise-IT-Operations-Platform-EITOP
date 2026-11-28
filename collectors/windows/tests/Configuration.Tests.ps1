# Configuration tests: JSON parsing, validation, env overrides.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/Configuration.psm1') -Force
    $script:ValidJson = @'
{
  "server_url": "http://localhost:8080",
  "interval_seconds": 120,
  "heartbeat_interval_seconds": 30,
  "timeout_seconds": 15,
  "max_retries": 3,
  "credential_file": "C:\\temp\\creds.json"
}
'@
}

Describe 'Read-EitopConfig' {
    It 'loads a valid config file' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-cfg-" + [guid]::NewGuid() + '.json')
        try {
            Set-Content -LiteralPath $path -Value $script:ValidJson
            $cfg = Read-EitopConfig -Path $path
            $cfg.server_url | Should -Be 'http://localhost:8080'
            $cfg.interval_seconds | Should -Be 120
            $cfg.heartbeat_interval_seconds | Should -Be 30
            $cfg.timeout_seconds | Should -Be 15
            $cfg.max_retries | Should -Be 3
            $cfg.credential_file | Should -Be 'C:\temp\creds.json'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fails clearly when no config exists' {
        { Read-EitopConfig -Path (Join-Path ([IO.Path]::GetTempPath()) 'nope-nope.json') } |
            Should -Throw -ExpectedMessage '*No config file found*'
    }

    It 'fails on invalid JSON' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-cfg-" + [guid]::NewGuid() + '.json')
        try {
            Set-Content -LiteralPath $path -Value '{broken'
            { Read-EitopConfig -Path $path } | Should -Throw -ExpectedMessage '*Cannot read config*'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fails when server_url is missing' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-cfg-" + [guid]::NewGuid() + '.json')
        try {
            Set-Content -LiteralPath $path -Value '{"interval_seconds": 60}'
            { Read-EitopConfig -Path $path } | Should -Throw -ExpectedMessage '*server_url*'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'applies EITOP_SERVER_URL over the file value' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-cfg-" + [guid]::NewGuid() + '.json')
        $oldServer = $env:EITOP_SERVER_URL
        try {
            Set-Content -LiteralPath $path -Value $script:ValidJson
            $env:EITOP_SERVER_URL = 'https://prod.example:8443'
            (Read-EitopConfig -Path $path).server_url | Should -Be 'https://prod.example:8443'
        } finally {
            $env:EITOP_SERVER_URL = $oldServer
            if ($null -eq $oldServer) { Remove-Item Env:EITOP_SERVER_URL -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'uses EITOP_CONFIG when set' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ("eitop-cfg-" + [guid]::NewGuid() + '.json')
        $oldConfig = $env:EITOP_CONFIG
        $oldServer = $env:EITOP_SERVER_URL
        try {
            Set-Content -LiteralPath $path -Value $script:ValidJson
            $env:EITOP_CONFIG = $path
            Remove-Item Env:EITOP_SERVER_URL -ErrorAction SilentlyContinue
            (Read-EitopConfig).interval_seconds | Should -Be 120
        } finally {
            $env:EITOP_CONFIG = $oldConfig
            $env:EITOP_SERVER_URL = $oldServer
            if ($null -eq $oldConfig) { Remove-Item Env:EITOP_CONFIG -ErrorAction SilentlyContinue }
            if ($null -eq $oldServer) { Remove-Item Env:EITOP_SERVER_URL -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'New-EitopConfig validation' {
    It 'rejects non-http(s) URLs' {
        { New-EitopConfig -ServerUrl 'ftp://files.example' -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*http*'
        { New-EitopConfig -ServerUrl 'file:///etc/passwd' -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*http*'
    }

    It 'rejects intervals below the 10s floor' {
        { New-EitopConfig -ServerUrl 'https://x' -IntervalSeconds 5 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*interval_seconds*'
        { New-EitopConfig -ServerUrl 'https://x' -HeartbeatIntervalSeconds 5 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*heartbeat*'
    }

    It 'rejects out-of-range retries and timeouts' {
        { New-EitopConfig -ServerUrl 'https://x' -MaxRetries 0 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*max_retries*'
        { New-EitopConfig -ServerUrl 'https://x' -MaxRetries 99 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*max_retries*'
        { New-EitopConfig -ServerUrl 'https://x' -TimeoutSeconds 0 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*timeout*'
    }

    It 'normalizes trailing slashes on server_url' {
        (New-EitopConfig -ServerUrl 'https://host:8080/' -CredentialFile 'x').server_url |
            Should -Be 'https://host:8080'
    }

    # Phase 6 audit W3: https everywhere except loopback.
    It 'rejects plaintext http to a non-loopback host' {
        { New-EitopConfig -ServerUrl 'http://server.example:8080' -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*https*'
        { New-EitopConfig -ServerUrl 'http://10.0.0.5' -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*https*'
    }

    It 'allows plaintext http only for loopback hosts' {
        (New-EitopConfig -ServerUrl 'http://localhost:8080/' -CredentialFile 'x').server_url |
            Should -Be 'http://localhost:8080'
        (New-EitopConfig -ServerUrl 'http://127.0.0.1:8000' -CredentialFile 'x').server_url |
            Should -Be 'http://127.0.0.1:8000'
        (New-EitopConfig -ServerUrl 'https://prod.example:8443' -CredentialFile 'x').server_url |
            Should -Be 'https://prod.example:8443'
    }

    # Phase 6 audit L7-parity: userinfo must never reach an error message.
    It 'redacts userinfo in validation errors' {
        try {
            New-EitopConfig -ServerUrl 'http://alice:hunter2@remote.example' -CredentialFile 'x'
            throw 'expected validation failure'
        } catch {
            $_.Exception.Message | Should -Not -Match 'hunter2'
            $_.Exception.Message | Should -Match '\*\*\*:\*\*\*@'
        }
        try {
            New-EitopConfig -ServerUrl 'ftp://alice:hunter2@files.example' -CredentialFile 'x'
            throw 'expected validation failure'
        } catch {
            $_.Exception.Message | Should -Not -Match 'hunter2'
        }
    }
}
