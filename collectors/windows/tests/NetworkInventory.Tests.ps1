# Network inventory parsing tests — fixtures only, no CIM/Windows required.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/NetworkInventory.psm1') -Force
    Import-Module (Join-Path $script:Root 'modules/SystemInventory.psm1') -Force  # Get-CimProperty
    $script:Fixtures = Join-Path $PSScriptRoot '..\fixtures'

    function Get-NetworkFixture {
        param([string]$Name)
        $data = Get-Content (Join-Path $script:Fixtures $Name) -Raw | ConvertFrom-Json
        [pscustomobject]@{ configurations = @($data.configurations); adapters = @($data.adapters) }
    }
}

Describe 'ConvertTo-NetworkReport with fixture' {
    BeforeAll {
        $script:result = ConvertTo-NetworkReport -Source (Get-NetworkFixture 'network_adapters.json')
        $script:report = $script:result.report
        $script:byName = @{}
        foreach ($iface in @($script:report.interfaces)) { $script:byName[$iface.name] = $iface }
    }

    It 'collects interface names, descriptions, MACs, IPs and status' {
        $script:byName.Count | Should -Be 2   # IP-disabled ghost adapter excluded
        $script:byName.ContainsKey('Ethernet') | Should -BeTrue
        $script:byName.ContainsKey('Wi-Fi') | Should -BeTrue

        $eth = $script:byName['Ethernet']
        $eth.mac | Should -Be '52:54:00:12:34:56'
        $eth.ipv4 | Should -Be @('192.0.2.10')
        $eth.ipv6 | Should -Be @('2001:db8::10')
        $eth.is_up | Should -BeTrue   # NetConnectionStatus 2
    }

    It 'splits IPv4 and IPv6 correctly per interface' {
        $wifi = $script:byName['Wi-Fi']
        $wifi.ipv4 | Should -Be @('198.51.100.7')
        $wifi.ipv6 | Should -BeNullOrEmpty
        $wifi.is_up | Should -BeTrue
    }

    It 'aggregates unique IP and MAC lists' {
        $script:report.ip_addresses | Should -Be @('192.0.2.10', '198.51.100.7', '2001:db8::10')
        $script:report.mac_addresses | Should -Be @('52:54:00:12:34:56', 'A4:BB:6D:00:11:22')
    }

    It 'reports descriptions through facts (contract has no description field)' {
        $json = $script:result.facts['network.interface_descriptions']
        $json | Should -Not -BeNullOrEmpty
        $map = $json | ConvertFrom-Json
        $map.'Ethernet' | Should -Be 'Intel(R) Ethernet Connection X722 for 1GbE'
        $map.'Wi-Fi' | Should -Be 'Intel(R) Wi-Fi 6 AX201 160MHz'
    }

    It 'emits exactly the NetworkReport contract keys' {
        $expected = @('interfaces', 'ip_addresses', 'mac_addresses') | Sort-Object
        @($script:report.PSObject.Properties.Name | Sort-Object) | Should -Be $expected
        foreach ($iface in @($script:report.interfaces)) {
            @($iface.PSObject.Properties.Name | Sort-Object) |
                Should -Be (@('name', 'mac', 'ipv4', 'ipv6', 'is_up') | Sort-Object)
        }
    }

    It 'never collects Wi-Fi profiles, passwords or other sensitive data' {
        $serialized = $script:result | ConvertTo-Json -Depth 8
        $serialized | Should -Not -Match 'password'
        $serialized | Should -Not -Match 'psk'
        $serialized | Should -Not -Match 'profile'
    }
}

Describe 'ConvertTo-NetworkReport edge cases' {
    It 'returns an empty structured report when no sources exist' {
        $result = ConvertTo-NetworkReport -Source ([pscustomobject]@{ configurations = @(); adapters = @() })
        @($result.report.interfaces).Count | Should -Be 0
        @($result.report.ip_addresses).Count | Should -Be 0
        @($result.report.mac_addresses).Count | Should -Be 0
        $result.facts.Count | Should -Be 0
    }

    It 'handles a null adapter list (status lookup degrades to IP heuristic)' {
        $result = ConvertTo-NetworkReport -Source ([pscustomobject]@{
                configurations = @([pscustomobject]@{
                        InterfaceIndex = 7; Description = 'NIC'; MACAddress = 'AA:BB:CC:DD:EE:FF'
                        IPEnabled = $true; IPAddress = @('203.0.113.5'); SettingID = 'guid-7'
                    })
                adapters = $null
            })
        @($result.report.interfaces).Count | Should -Be 1
        $result.report.interfaces[0].name | Should -Be 'guid-7'   # SettingID fallback
        $result.report.interfaces[0].is_up | Should -BeTrue
    }

    It 'drops the all-zero MAC and handles duplicate addresses' {
        $result = ConvertTo-NetworkReport -Source ([pscustomobject]@{
                configurations = @([pscustomobject]@{
                        InterfaceIndex = 7; Description = 'NIC'; MACAddress = '00:00:00:00:00:00'
                        IPEnabled = $true; IPAddress = @('10.0.0.1', '10.0.0.1'); SettingID = 'guid-7'
                    })
                adapters = @([pscustomobject]@{ InterfaceIndex = 7; Index = 7; NetConnectionID = 'Eth0'; NetConnectionStatus = 0 })
            })
        $iface = $result.report.interfaces[0]
        $iface.name | Should -Be 'Eth0'
        $iface.mac | Should -BeNullOrEmpty
        @($iface.ipv4).Count | Should -Be 1   # deduped
        $iface.is_up | Should -BeFalse        # status 0 = disconnected
    }

    It 'truncates over-long interface names to the contract limit (64)' {
        $longName = 'N' * 100
        $result = ConvertTo-NetworkReport -Source ([pscustomobject]@{
                configurations = @([pscustomobject]@{
                        InterfaceIndex = 7; Description = 'NIC'; MACAddress = 'AA:BB:CC:DD:EE:FF'
                        IPEnabled = $true; IPAddress = @('10.0.0.1'); SettingID = 'g'
                    })
                adapters = @([pscustomobject]@{ InterfaceIndex = 7; Index = 7; NetConnectionID = $longName; NetConnectionStatus = 2 })
            })
        $result.report.interfaces[0].name.Length | Should -Be 64
    }

    It 'flags disconnected status even with stale IPs' {
        $result = ConvertTo-NetworkReport -Source ([pscustomobject]@{
                configurations = @([pscustomobject]@{
                        InterfaceIndex = 7; Description = 'NIC'; MACAddress = 'AA:BB:CC:DD:EE:FF'
                        IPEnabled = $true; IPAddress = @('10.0.0.1'); SettingID = 'g'
                    })
                adapters = @([pscustomobject]@{ InterfaceIndex = 7; Index = 7; NetConnectionID = 'Eth'; NetConnectionStatus = 4 })
            })
        $result.report.interfaces[0].is_up | Should -BeFalse   # 4 = hardware disabled
    }
}
