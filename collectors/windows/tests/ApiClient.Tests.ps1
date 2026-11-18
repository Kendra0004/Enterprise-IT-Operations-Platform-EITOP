# API client tests: request construction, auth, retry/backoff, error handling.
# All HTTP goes through an injected invoker — no network, no server.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/ApiClient.psm1') -Force
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Cred = 'eitop_ep_testcredential0000000000000000000'

    function New-TestConfig {
        [pscustomobject]@{
            server_url                 = 'http://server.example:8080'
            interval_seconds           = 300
            heartbeat_interval_seconds = 60
            timeout_seconds            = 15.0
            max_retries                = 3
            credential_file            = '/tmp/unused.json'
        }
    }

    function New-RecordingInvoker {
        # param($Method,$Uri,$Headers,$Body,$TimeoutSec) → sequence of results
        param([scriptblock]$Responder, [System.Collections.ArrayList]$Calls, [System.Collections.ArrayList]$Sleeps)
        # GetNewClosure: bind $Responder/$Calls/$Sleeps at creation time so the
        # block works when invoked from inside the module's function scope.
        return {
            param($Method, $Uri, $Headers, $Body, $TimeoutSec)
            $null = $Calls.Add([pscustomobject]@{
                    method = $Method; uri = $Uri; headers = $Headers; body = $Body; timeout = $TimeoutSec
                })
            & $Responder $Method $Uri $Headers $Body ($Calls.Count)
        }.GetNewClosure()
    }
}

Describe 'request construction' {
    BeforeEach {
        $script:cfg = New-TestConfig
        $script:Calls = [System.Collections.ArrayList]::new()
        $script:Sleeps = [System.Collections.ArrayList]::new()
    }

    It 'posts heartbeat JSON to the exact agent route with a bearer header' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n) [pscustomobject]@{ kind = 'response'; status = 200; data = @{ endpoint_id = 'ep-1' } }
        }
        $null = Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
            -Body @{ agent_version = '0.1.0' } -Credential $script:Cred -Invoker $invoker -Sleep { }

        $call = $script:Calls[0]
        $call.uri | Should -Be 'http://server.example:8080/api/v1/agent/heartbeat'
        $call.method | Should -Be 'POST'
        $call.headers['Authorization'] | Should -Be "Bearer $($script:Cred)"
        $call.headers['User-Agent'] | Should -Match 'eitop-collector'
        $call.body | Should -Match '"agent_version"'
        $call.timeout | Should -Be 15.0
    }

    It 'never puts the credential in the URL' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n) [pscustomobject]@{ kind = 'response'; status = 200; data = @{} }
        }
        Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/inventory' `
            -Body @{ system = @{} } -Credential $script:Cred -Invoker $invoker -Sleep { } -MaxRetries 0
        $script:Calls[0].uri | Should -Not -Match ([regex]::Escape($script:Cred))
    }

    It 'omits Authorization when no credential given (enroll)' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n) [pscustomobject]@{ kind = 'response'; status = 201; data = @{} }
        }
        Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/enroll' `
            -Body @{ token = 'tok' } -Invoker $invoker -Sleep { } -MaxRetries 0
        $script:Calls[0].headers.ContainsKey('Authorization') | Should -BeFalse
    }
}

Describe 'retry and backoff behavior' {
    BeforeEach {
        $script:cfg = New-TestConfig
        $script:Calls = [System.Collections.ArrayList]::new()
        $script:Sleeps = [System.Collections.ArrayList]::new()
        $script:Sleep = { param($s) $null = $script:Sleeps.Add($s) }
    }

    It 'does not retry 401 (bad credential is permanent)' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n)
            [pscustomobject]@{ kind = 'response'; status = 401; data = @{ title = 'Not authenticated' } }
        }
        { Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
                -Body @{} -Credential $script:Cred -Invoker $invoker -Sleep $script:Sleep } |
            Should -Throw
        $script:Calls.Count | Should -Be 1
        $script:Sleeps.Count | Should -Be 0
    }

    It 'retries 503 with exponential backoff then succeeds' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n)
            if ($n -lt 3) { return [pscustomobject]@{ kind = 'response'; status = 503; data = @{ title = 'Unavailable' } } }
            [pscustomobject]@{ kind = 'response'; status = 200; data = @{ ok = $true } }
        }
        $result = Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
            -Body @{} -Credential $script:Cred -Invoker $invoker -Sleep $script:Sleep
        $script:Calls.Count | Should -Be 3
        @($script:Sleeps) | Should -Be @(1.0, 2.0)
        $result.data.ok | Should -BeTrue
    }

    It 'retries transport errors (timeouts/refused)' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n)
            if ($n -eq 1) { return [pscustomobject]@{ kind = 'error'; error = 'timeout' } }
            [pscustomobject]@{ kind = 'response'; status = 200; data = @{} }
        }
        Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
            -Body @{} -Credential $script:Cred -Invoker $invoker -Sleep $script:Sleep
        $script:Calls.Count | Should -Be 2
    }

    It 'gives up after max_retries+1 attempts' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n)
            [pscustomobject]@{ kind = 'response'; status = 503; data = @{ title = 'Unavailable' } }
        }
        { Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
                -Body @{} -Credential $script:Cred -Invoker $invoker -Sleep $script:Sleep } |
            Should -Throw
        $script:Calls.Count | Should -Be 4   # 1 + max_retries(3)
    }

    It 'caps backoff at 60 seconds' {
        Get-EitopBackoffDelay -Attempt 0 | Should -Be 1.0
        Get-EitopBackoffDelay -Attempt 1 | Should -Be 2.0
        Get-EitopBackoffDelay -Attempt 4 | Should -Be 16.0
        Get-EitopBackoffDelay -Attempt 20 | Should -Be 60.0
    }

    It 'retries 429 (enrollment rate limit is transient for the client)' {
        $invoker = New-RecordingInvoker -Calls $script:Calls -Sleeps $script:Sleeps -Responder {
            param($m, $u, $h, $b, $n)
            if ($n -eq 1) { return [pscustomobject]@{ kind = 'response'; status = 429; data = @{ title = 'Too Many Requests' } } }
            [pscustomobject]@{ kind = 'response'; status = 201; data = @{ ok = 1 } }
        }
        Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/enroll' `
            -Body @{ token = 'x' } -Invoker $invoker -Sleep $script:Sleep
        $script:Calls.Count | Should -Be 2
    }
}

Describe 'error handling' {
    BeforeEach {
        $script:cfg = New-TestConfig
    }

    It 'surfaces RFC 9457 problem title/detail without any credential text' {
        $invoker = {
            param($m, $u, $h, $b, $n)
            [pscustomobject]@{ kind = 'response'; status = 401; data = @{ title = 'Not authenticated'; detail = 'Missing or invalid endpoint credential.' } }
        }
        try {
            Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
                -Body @{} -Credential $script:Cred -Invoker $invoker -Sleep { } -MaxRetries 0
            throw 'expected failure'
        } catch {
            $_.Exception.Message | Should -Match 'Not authenticated'
            $_.Exception.Message | Should -Not -Match ([regex]::Escape($script:Cred))
            $_.Exception.StatusCode | Should -Be 401
        }
    }

    It 'handles non-JSON error bodies gracefully' {
        $invoker = {
            param($m, $u, $h, $b, $n)
            [pscustomobject]@{ kind = 'response'; status = 500; data = $null; raw = '<html>gateway exploded</html>' }
        }
        { Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
                -Body @{} -Credential $script:Cred -Invoker $invoker -Sleep { } -MaxRetries 0 } |
            Should -Throw
        try {
            Invoke-EitopApiRequest -Config $script:cfg -Method POST -Path '/api/v1/agent/heartbeat' `
                -Body @{} -Credential $script:Cred -Invoker $invoker -Sleep { } -MaxRetries 0
        } catch { $_.Exception.Message | Should -Match 'HTTP 500' }
    }

    It 'Get-EitopProblemMessage parses problem+json payloads' {
        $result = [pscustomobject]@{
            kind = 'response'; status = 422
            data = @{ title = 'Validation error'; detail = 'invalid type' }
        }
        Get-EitopProblemMessage -Result $result | Should -Be 'HTTP 422: Validation error invalid type'
    }

    It 'enroll validates the response contains credential + endpoint_id' {
        $invoker = {
            param($m, $u, $h, $b, $n)
            [pscustomobject]@{ kind = 'response'; status = 201; data = @{ endpoint_id = 'ep-1' } }
        }
        { Invoke-EitopEnroll -Config $script:cfg -Token 'tok-1234567890abcdef' `
                -SystemInfo @{ hostname = 'h' } -Invoker $invoker -Sleep { } } |
            Should -Throw
    }

    It 'enroll posts the token in the body, not a header' {
        $captured = [System.Collections.ArrayList]::new()
        $invoker = {
            param($m, $u, $h, $b, $n)
            $null = $captured.Add($b)
            [pscustomobject]@{ kind = 'response'; status = 201; data = @{ endpoint_id = 'ep-1'; credential = 'eitop_ep_x' } }
        }.GetNewClosure()
        $null = Invoke-EitopEnroll -Config $script:cfg -Token 'tok-1234567890abcdef' `
            -SystemInfo @{ hostname = 'web01'; os = 'windows' } -Invoker $invoker -Sleep { }
        $captured.Count | Should -Be 1
        $captured[0] | Should -Match '"token"'
        $captured[0] | Should -Match 'tok-1234567890abcdef'
        $captured[0] | Should -Match 'web01'
    }
}

Describe 'no server-supplied execution' {
    It 'modules contain no Invoke-Expression / iex / Add-Type of remote data' {
        $files = Get-ChildItem (Join-Path $script:Root 'modules') -Filter '*.psm1'
        $files += Get-Item (Join-Path $script:Root 'eitop-collector.ps1')
        foreach ($file in $files) {
            $code = Get-CodeOnlyText -Path $file.FullName
            $code | Should -Not -Match 'Invoke-Expression' -Because "$($file.Name) must not eval strings"
            $code | Should -Not -Match '(?<![\w-])iex\s' -Because "$($file.Name) must not use iex"
            $code | Should -Not -Match 'Add-Type\s+-TypeDefinition' -Because "$($file.Name) must not compile code"
        }
    }
}
