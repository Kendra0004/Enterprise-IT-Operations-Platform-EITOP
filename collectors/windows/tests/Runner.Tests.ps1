# Runner tests: payload assembly, enrollment/rotation flows, daemon loop.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    foreach ($module in @('Configuration', 'Credentials', 'ApiClient',
            'SystemInventory', 'HardwareInventory', 'NetworkInventory',
            'SoftwareInventory', 'Runner')) {
        Import-Module (Join-Path $script:Root "modules\$module.psm1") -Force
    }
    $script:Fixtures = Join-Path $PSScriptRoot '..\fixtures'

    function Get-FakeSections {
        # Fixed sections so payload tests never touch CIM/registry.
        @{
            system   = [pscustomobject]@{
                hostname = 'WEB01'; fqdn = 'web01.example.com'; os = 'windows'
                distribution = 'Windows 11 Pro'; distribution_version = '24H2'
                os_version = 'Microsoft Windows 11 Pro'; os_arch = '64-bit'
                kernel = '10.0.26100'; uptime_seconds = 9000
            }
            hardware = [pscustomobject]@{
                report     = [pscustomobject]@{
                    manufacturer = 'QEMU'; model = 'Standard PC'; serial_number = $null
                    cpu_model = 'Intel Xeon'; cpu_cores = 8; memory_bytes = 8589934592; disk_bytes = 107374182400
                }
                facts      = @{ 'hardware.cpu_physical_cores' = '8' }
                filesystems = @([pscustomobject]@{ mount = 'C:'; fstype = 'NTFS'; total_bytes = 1000; used_bytes = 400 })
            }
            network  = [pscustomobject]@{
                report = [pscustomobject]@{
                    interfaces    = @([pscustomobject]@{ name = 'Ethernet'; mac = '52:54:00:12:34:56'; ipv4 = @('192.0.2.10'); ipv6 = @(); is_up = $true })
                    ip_addresses  = @('192.0.2.10')
                    mac_addresses = @('52:54:00:12:34:56')
                }
                facts  = @{ 'network.interface_descriptions' = '{"Ethernet":"Intel NIC"}' }
            }
            software = [pscustomobject]@{
                packages = @([pscustomobject]@{ name = '7-Zip'; version = '24.07'; package_manager = 'registry-hklm64' })
                details  = @()
                facts    = @{ 'software.count' = '1' }
            }
        }
    }

    function New-RunnerConfig {
        [pscustomobject]@{
            server_url                 = 'http://server.example:8080'
            interval_seconds           = 100
            heartbeat_interval_seconds = 30
            timeout_seconds            = 15.0
            max_retries                = 3
            credential_file            = '/tmp/unused.json'
        }
    }
}

Describe 'Get-EitopInventoryPayload' {
    BeforeEach {
        $s = Get-FakeSections
        $script:payload = Get-EitopInventoryPayload `
            -SystemCollector { $s.system } `
            -HardwareCollector { $s.hardware } `
            -NetworkCollector { $s.network } `
            -SoftwareCollector { $s.software }
    }

    It 'emits exactly the AgentInventoryRequest top-level keys' {
        @($script:payload.Keys | Sort-Object) |
            Should -Be (@('system', 'hardware', 'network', 'filesystems', 'packages', 'facts') | Sort-Object)
    }

    It 'carries collector facts merged with module facts' {
        $script:payload.facts['collector.version'] | Should -Be (Get-EitopAgentVersion)
        $script:payload.facts['hardware.cpu_physical_cores'] | Should -Be '8'
        $script:payload.facts['network.interface_descriptions'] | Should -Match 'Intel NIC'
        $script:payload.facts['software.count'] | Should -Be '1'
        $script:payload.facts['collector.runtime'] | Should -Match 'powershell-'
    }

    It 'contains no endpoint identifier anywhere (authz is credential-only)' {
        $json = $script:payload | ConvertTo-Json -Depth 8
        $json | Should -Not -Match 'endpoint_id'
        $json | Should -Not -Match 'credential'
    }

    It 'keeps filesystems/packages as arrays in JSON' {
        $json = $script:payload | ConvertTo-Json -Depth 8 -Compress
        $json | Should -Match '"filesystems":\['
        $json | Should -Match '"packages":\['
        $json | Should -Match '"interfaces":\['
    }

    It 'serializes cleanly to JSON at depth 8 without errors' {
        { $script:payload | ConvertTo-Json -Depth 8 } | Should -Not -Throw
    }
}

Describe 'Get-EitopEnrollPayload' {
    It 'builds the exact AgentEnrollRequest key set' {
        $system = (Get-FakeSections).system
        $body = Get-EitopEnrollPayload -Token 'tok-1234567890abcdef' -SystemSection $system
        @($body.Keys | Sort-Object) |
            Should -Be (@('token', 'hostname', 'fqdn', 'os', 'os_version', 'os_arch',
                    'kernel_version', 'agent_version') | Sort-Object)
        $body.token | Should -Be 'tok-1234567890abcdef'
        $body.os | Should -Be 'windows'
        $body.kernel_version | Should -Be '10.0.26100'
    }
}

Describe 'Invoke-EitopEnrollFlow' {
    It 'saves the issued credential and never returns/prints it' {
        $cfg = New-RunnerConfig
        $saved = [System.Collections.ArrayList]::new()
        $enrollArgs = [System.Collections.ArrayList]::new()

        $result = Invoke-EitopEnrollFlow -Config $cfg -Token 'tok-1234567890abcdef' `
            -EnrollAction {
                param($a)
                $null = $enrollArgs.Add($a)
                [pscustomobject]@{ endpoint_id = 'ep-9'; credential = 'eitop_ep_issuedsecret000000' }
            }.GetNewClosure() `
            -CredentialSaver {
                param($Path, $EndpointId, $Credential)
                $null = $saved.Add([pscustomobject]@{ path = $Path; id = $EndpointId; cred = $Credential })
            }.GetNewClosure()

        $result.endpoint_id | Should -Be 'ep-9'
        $result.credential | Should -BeNullOrEmpty   # never returned to the console
        @($saved).Count | Should -Be 1
        $saved[0].cred | Should -Be 'eitop_ep_issuedsecret000000'
        $saved[0].id | Should -Be 'ep-9'
        # the token went into the enroll action (in memory only)
        @($enrollArgs).Count | Should -Be 1
        $enrollArgs[0].Token | Should -Be 'tok-1234567890abcdef'
        $enrollArgs[0].SystemInfo.ContainsKey('token') | Should -BeFalse
    }
}

Describe 'Invoke-EitopRotateFlow' {
    It 'persists the rotated credential via the saver' {
        $cfg = New-RunnerConfig
        $saved = [System.Collections.ArrayList]::new()
        $result = Invoke-EitopRotateFlow -Config $cfg -Credential 'eitop_ep_old' `
            -RotateAction { param($a) [pscustomobject]@{ endpoint_id = 'ep-9'; credential = 'eitop_ep_new' } } `
            -CredentialSaver {
                param($Path, $EndpointId, $Credential)
                $null = $saved.Add($Credential)
            }.GetNewClosure()
        $result.endpoint_id | Should -Be 'ep-9'
        @($saved).Count | Should -Be 1
        $saved[0] | Should -Be 'eitop_ep_new'
    }
}

Describe 'Start-EitopLoop' {
    BeforeEach {
        $script:cfg = New-RunnerConfig
        $script:hb = [System.Collections.ArrayList]::new()
        $script:inv = [System.Collections.ArrayList]::new()
        $script:sleeps = [System.Collections.ArrayList]::new()
    }

    It 'runs heartbeat and inventory then stops after MaxIterations' {
        $out = Start-EitopLoop -Config $script:cfg -Credential 'eitop_ep_x' `
            -HeartbeatAction { param($c) $null = $script:hb.Add($c) } `
            -InventoryAction { param($c) $null = $script:inv.Add($c) } `
            -Sleep { param($s) $null = $script:sleeps.Add($s) } `
            -Now { 1000 } `
            -MaxIterations 2
        @($script:hb).Count | Should -Be 1    # scheduled once, then next-fire is future
        @($script:inv).Count | Should -Be 1
        @($script:sleeps).Count | Should -BeGreaterThan 0   # idle slicing observed
        $out | Should -Be 'stopped'
    }

    It 'backs off exponentially on failures and keeps trying' {
        $script:attempt = [System.Collections.ArrayList]::new()
        $null = Start-EitopLoop -Config $script:cfg -Credential 'eitop_ep_x' `
            -HeartbeatAction { param($c) $null = $script:attempt.Add('hb') } `
            -InventoryAction { param($c) throw 'server exploded' } `
            -Sleep { param($s) $null = $script:sleeps.Add($s); Set-EitopRunnerStop } `
            -Now { 1000 } `
            -MaxIterations 1
        # inventory failure logged + backed off: base 30s * 2^Failures(1) = 60s
        @($script:sleeps) | Should -Contain 60
    }

    It 'computes capped loop backoff' {
        Get-EitopLoopDelay -Failures 1 -BaseInterval 60 | Should -Be 120
        Get-EitopLoopDelay -Failures 3 -BaseInterval 60 | Should -Be 480
        Get-EitopLoopDelay -Failures 30 -BaseInterval 60 | Should -Be 3600
    }

    It 'stops cleanly on credential errors without retrying' {
        $heartbeats = [System.Collections.ArrayList]::new()
        $missing = Join-Path ([IO.Path]::GetTempPath()) 'eitop-definitely-missing.json'
        $null = Start-EitopLoop -Config $script:cfg -Credential 'eitop_ep_x' `
            -HeartbeatAction {
                param($c)
                $null = $heartbeats.Add('x')
                # Real EitopCredentialError (thrown by Credentials module)
                Read-EitopCredential -Path $missing
            }.GetNewClosure() -InventoryAction { param($c) } `
            -Sleep { param($s) } -Now { 1000 } -MaxIterations 3 `
            -ErrorVariable errs -ErrorAction SilentlyContinue
        @($heartbeats).Count | Should -Be 1   # stopped after first credential failure
        $allErrors = (@($errs) | ForEach-Object { $_.ToString() }) -join ' | '
        $allErrors | Should -Match 'credential_error'
        $allErrors | Should -Match 'run enrollment first'
        $allErrors | Should -Not -Match 'eitop_ep_x'
    }

    It 'passes the credential only to injected actions (memory-only)' {
        $seen = [System.Collections.ArrayList]::new()
        $null = Start-EitopLoop -Config $script:cfg -Credential 'eitop_ep_verysecret' `
            -HeartbeatAction { param($c) $null = $seen.Add($c) } `
            -InventoryAction { param($c) } `
            -Sleep { param($s) Set-EitopRunnerStop } -Now { 1000 } -MaxIterations 1
        @($seen) | Should -Contain 'eitop_ep_verysecret'   # reached the action...
        $seen.Count | Should -Be 1                          # ...and nothing else
    }
}
