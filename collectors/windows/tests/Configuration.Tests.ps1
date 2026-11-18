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
        { New-EitopConfig -ServerUrl 'http://x' -IntervalSeconds 5 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*interval_seconds*'
        { New-EitopConfig -ServerUrl 'http://x' -HeartbeatIntervalSeconds 5 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*heartbeat*'
    }

    It 'rejects out-of-range retries and timeouts' {
        { New-EitopConfig -ServerUrl 'http://x' -MaxRetries 0 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*max_retries*'
        { New-EitopConfig -ServerUrl 'http://x' -MaxRetries 99 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*max_retries*'
        { New-EitopConfig -ServerUrl 'http://x' -TimeoutSeconds 0 -CredentialFile 'x' } |
            Should -Throw -ExpectedMessage '*timeout*'
    }

    It 'normalizes trailing slashes on server_url' {
        (New-EitopConfig -ServerUrl 'http://host:8080/' -CredentialFile 'x').server_url |
            Should -Be 'http://host:8080'
    }
}
