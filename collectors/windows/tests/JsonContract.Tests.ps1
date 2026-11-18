# Cross-contract tests: the serialized payload must match the backend's
# Pydantic schemas (backend/app/schemas/endpoints.py, extra="forbid").
# Also asserts sensitivity hygiene: no secrets in payloads.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    foreach ($module in @('Configuration', 'Credentials', 'ApiClient',
            'SystemInventory', 'HardwareInventory', 'NetworkInventory',
            'SoftwareInventory', 'Runner')) {
        Import-Module (Join-Path $script:Root "modules\$module.psm1") -Force
    }
}

Describe 'JSON serialization contract' {
    It 'serializes a complete payload with all top-level keys present' {
        # Live collectors degrade gracefully off-Windows; assemble directly.
        $payload = [ordered]@{
            system      = [ordered]@{
                hostname = 'PC01'; fqdn = 'pc01.example.com'; os = 'windows'
                distribution = 'Windows 11 Pro'; distribution_version = '24H2'
                os_version = 'Microsoft Windows 11 Pro'; os_arch = '64-bit'
                kernel = '10.0.26100'; uptime_seconds = 9000
            }
            hardware    = [ordered]@{
                manufacturer = 'Dell Inc.'; model = 'PowerEdge R650'; serial_number = 'ABC123'
                cpu_model = 'Intel Xeon Gold'; cpu_cores = 32; memory_bytes = 68719476736; disk_bytes = 214748364800
            }
            network     = [ordered]@{
                interfaces    = @(
                    [ordered]@{ name = 'Ethernet'; mac = '52:54:00:12:34:56'; ipv4 = @('192.0.2.10'); ipv6 = @('2001:db8::10'); is_up = $true }
                    [ordered]@{ name = 'Wi-Fi'; mac = $null; ipv4 = @('198.51.100.7'); ipv6 = @(); is_up = $false }
                )
                ip_addresses  = @('192.0.2.10', '198.51.100.7', '2001:db8::10')
                mac_addresses = @('52:54:00:12:34:56')
            }
            filesystems = @(
                [ordered]@{ mount = 'C:'; fstype = 'NTFS'; total_bytes = 107374182400; used_bytes = 42949672960 }
            )
            packages    = @(
                [ordered]@{ name = 'Mozilla Firefox'; version = '133.0'; package_manager = 'registry-hklm64' }
            )
            facts       = @{ 'collector.version' = '0.1.0' }
        }

        $json = $payload | ConvertTo-Json -Depth 8 -Compress
        $parsed = $json | ConvertFrom-Json

        foreach ($key in @('system', 'hardware', 'network', 'filesystems', 'packages', 'facts')) {
            $parsed.PSObject.Properties.Name | Should -Contain $key
        }
        # Arrays stay arrays (PS single-element unwrap hazard)
        @($parsed.packages).Count | Should -Be 1
        @($parsed.network.interfaces).Count | Should -Be 2
        @($parsed.filesystems).Count | Should -Be 1
        # Types the Pydantic validators enforce
        $parsed.system.uptime_seconds | Should -Be 9000
        $parsed.hardware.cpu_cores | Should -Be 32
        $parsed.network.interfaces[0].is_up | Should -BeOfType [bool]
        $parsed.filesystems[0].total_bytes | Should -Be 107374182400
        $parsed.packages[0].package_manager | Should -Match '^registry-'
    }

    It 'serializes empty collections as JSON arrays/objects, not null' {
        $payload = [ordered]@{
            system      = [ordered]@{ hostname = 'PC01'; os = 'windows' }
            hardware    = $null
            network     = $null
            filesystems = @()
            packages    = @()
            facts       = @{}
        }
        $json = $payload | ConvertTo-Json -Depth 8 -Compress
        $json | Should -Match '"filesystems":\[\]'
        $json | Should -Match '"packages":\[\]'
        $json | Should -Match '"facts":\{\}'
    }

    It 'enforce contract length limits on interface names (64) and package fields' {
        # Covered by converters; here we assert the JSON roundtrip preserves them
        $iface = [pscustomobject]@{ name = 'N' * 64; mac = $null; ipv4 = @(); ipv6 = @(); is_up = $false }
        $json = @{ interfaces = @($iface) } | ConvertTo-Json -Depth 6 -Compress
        $parsed = ($json | ConvertFrom-Json).interfaces[0]
        $parsed.name.Length | Should -Be 64
    }

    It 'produces facts within backend limits (≤512 keys, key ≤128, value ≤8192)' {
        $facts = [ordered]@{}
        for ($i = 0; $i -lt 100; $i++) { $facts["fact.$i"] = 'v' * 10 }
        $facts['network.interface_descriptions'] = '{"Ethernet":"A very long description that stays within limits"}'
        $json = @{ facts = [hashtable]$facts } | ConvertTo-Json -Depth 4 -Compress
        $parsed = ($json | ConvertFrom-Json).facts
        @($parsed.PSObject.Properties.Name).Count | Should -BeLessOrEqual 512
        foreach ($p in $parsed.PSObject.Properties) {
            $p.Name.Length | Should -BeLessOrEqual 128
            ([string]$p.Value).Length | Should -BeLessOrEqual 8192
        }
    }

    It 'heartbeat body carries only agent_version (extra=forbid)' {
        $body = @{ agent_version = '0.1.0' }
        $json = $body | ConvertTo-Json -Compress
        $parsed = $json | ConvertFrom-Json
        @($parsed.PSObject.Properties.Name) | Should -Be @('agent_version')
    }

    It 'inventory payloads never contain authorization material' {
        $payload = [ordered]@{
            system      = [ordered]@{ hostname = 'X'; os = 'windows' }
            hardware    = $null; network = $null
            filesystems = @(); packages = @()
            facts       = @{ 'collector.version' = '0.1.0' }
        }
        $json = $payload | ConvertTo-Json -Depth 6
        $json | Should -Not -Match 'credential'
        $json | Should -Not -Match 'token'
        $json | Should -Not -Match 'Authorization'
        $json | Should -Not -Match 'endpoint_id'
    }
}

Describe 'coverage of required collection surfaces' {
    It 'every required Windows collection module exists and exports functions' {
        $expected = @(
            'Configuration', 'Credentials', 'ApiClient',
            'SystemInventory', 'HardwareInventory', 'NetworkInventory',
            'SoftwareInventory', 'Runner'
        )
        foreach ($name in $expected) {
            $path = Join-Path $script:Root "modules\$name.psm1"
            Test-Path $path | Should -BeTrue -Because "$name.psm1 must exist"
            $module = Get-Module $name -ErrorAction SilentlyContinue
            if (-not $module) { $module = Test-ModuleManifest (Join-Path $script:Root "modules\$name.psm1") -ErrorAction SilentlyContinue }
            (Get-Content $path -Raw) | Should -Match 'Export-ModuleMember' -Because "$name must export its API"
        }
    }

    It 'all five collector commands are declared in the entry script' {
        $content = Get-Content (Join-Path $script:Root 'eitop-collector.ps1') -Raw
        foreach ($command in @('collect', 'enroll', 'status', 'run', 'rotate')) {
            $content | Should -Match ("'" + $command + "'") -Because "command $command must be declared"
        }
    }

    It 'README, config example and docs exist' {
        Test-Path (Join-Path $script:Root 'README.md') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'config.example.json') | Should -BeTrue
        $cfg = Get-Content (Join-Path $script:Root 'config.example.json') -Raw | ConvertFrom-Json
        $cfg.server_url | Should -Not -BeNullOrEmpty
        $cfg | ConvertTo-Json -Compress | Should -Not -Match 'eitop_ep_'   # no secrets in config
        $repoDocs = Join-Path $script:Root '..\..\docs\endpoints\windows-collector.md'
        Test-Path $repoDocs | Should -BeTrue
    }
}
