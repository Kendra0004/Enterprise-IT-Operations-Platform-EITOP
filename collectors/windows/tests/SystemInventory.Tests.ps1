# System inventory parsing tests — fixtures only, no CIM/Windows required.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/SystemInventory.psm1') -Force
    $script:Fixtures = Join-Path $PSScriptRoot '..\fixtures'

    function Get-FixtureSource {
        param([string]$Name)
        $data = Get-Content (Join-Path $script:Fixtures $Name) -Raw | ConvertFrom-Json
        [pscustomobject]@{
            os       = $data.os
            cs       = $data.cs
            hostname = $data.hostname
            utc_now  = [DateTime]::Parse($data.utc_now).ToUniversalTime()
        }
    }
}

Describe 'ConvertTo-SystemReport' {
    BeforeAll {
        $script:source = Get-FixtureSource 'system_win11.json'
        $script:report = ConvertTo-SystemReport -Source $script:source -Fqdn 'web01.example.com'
    }

    It 'maps the full Win11 fixture to contract fields' {
        $script:report.hostname | Should -Be 'WEB01'
        $script:report.fqdn | Should -Be 'web01.example.com'
        $script:report.os | Should -Be 'windows'
        $script:report.distribution | Should -Be 'Windows 11 Pro'
        $script:report.distribution_version | Should -Be '24H2'
        $script:report.os_version | Should -Be 'Microsoft Windows 11 Pro'
        $script:report.os_arch | Should -Be '64-bit'
        $script:report.kernel | Should -Be '10.0.26100'
    }

    It 'computes uptime from LastBootUpTime against the injected clock' {
        # booted 08:30:00, now 11:00:00 UTC → 2.5h
        $script:report.uptime_seconds | Should -Be 9000
    }

    It 'emits exactly the SystemReport contract keys (extra=forbid server-side)' {
        $expected = @('hostname', 'fqdn', 'os', 'distribution', 'distribution_version',
            'os_version', 'os_arch', 'kernel', 'uptime_seconds') | Sort-Object
        @($script:report.PSObject.Properties.Name | Sort-Object) | Should -Be $expected
    }

    It 'derives fqdn from the computer-system DNSHostName when not provided' {
        $report = ConvertTo-SystemReport -Source $script:source
        $report.fqdn | Should -Be 'web01.example.com'
    }
}

Describe 'ConvertTo-SystemReport with missing CIM properties' {
    It 'returns nulls instead of throwing when the OS object is null' {
        $source = [pscustomobject]@{ os = $null; cs = $null; hostname = 'H'; utc_now = [DateTime]::UtcNow }
        $report = ConvertTo-SystemReport -Source $source
        $report.os | Should -Be 'windows'
        $report.hostname | Should -Be 'H'
        $report.distribution | Should -BeNullOrEmpty
        $report.kernel | Should -BeNullOrEmpty
        $report.uptime_seconds | Should -BeNullOrEmpty
    }

    It 'ignores partial OS objects (no boot time / no build)' {
        $source = [pscustomobject]@{
            os       = [pscustomobject]@{ Caption = 'Microsoft Windows Server 2022 Datacenter'; Version = '10.0.20348' }
            cs       = $null
            hostname = 'SRV1'
            utc_now  = [DateTime]::UtcNow
        }
        $report = ConvertTo-SystemReport -Source $source
        $report.distribution | Should -Be 'Windows Server 2022 Datacenter'
        $report.kernel | Should -Be '10.0.20348'
        $report.uptime_seconds | Should -BeNullOrEmpty
        $report.os_arch | Should -BeNullOrEmpty
    }

    It 'clamps uptime to zero for a boot time in the future' {
        $source = [pscustomobject]@{
            os       = [pscustomobject]@{ LastBootUpTime = '2030-01-01T00:00:00' }
            cs       = $null
            hostname = 'H'
            utc_now  = [DateTime]::Parse('2026-11-18T11:00:00Z').ToUniversalTime()
        }
        (ConvertTo-SystemReport -Source $source).uptime_seconds | Should -Be 0
    }

    It 'returns null uptime for an unparseable boot time' {
        $source = [pscustomobject]@{
            os       = [pscustomobject]@{ LastBootUpTime = 'garbage' }
            cs       = $null
            hostname = 'H'
            utc_now  = [DateTime]::UtcNow
        }
        (ConvertTo-SystemReport -Source $source).uptime_seconds | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-EitopUtcDateTime' {
    It 'normalizes DateTime with Kind=Local' {
        $dt = [DateTime]::SpecifyKind([DateTime]::Parse('2026-11-18 08:30:00'), [DateTimeKind]::Local)
        $utc = ConvertTo-EitopUtcDateTime $dt
        $utc.Kind | Should -Be ([DateTimeKind]::Utc)
        $utc | Should -Be $dt.ToUniversalTime()
    }

    It 'parses ISO strings as UTC with AdjustToUniversal' {
        $utc = ConvertTo-EitopUtcDateTime '2026-11-18T08:30:00Z'
        $utc | Should -Be ([DateTime]::Parse('2026-11-18T08:30:00Z').ToUniversalTime())
    }

    It 'parses DMTF-style timestamps' {
        $utc = ConvertTo-EitopUtcDateTime '20261118083000.000000+060'
        $utc | Should -Not -BeNullOrEmpty
        $utc.Year | Should -Be 2026
    }

    It 'returns null for junk' {
        ConvertTo-EitopUtcDateTime 'not-a-date' | Should -BeNullOrEmpty
        ConvertTo-EitopUtcDateTime $null | Should -BeNullOrEmpty
    }
}

Describe 'Get-CimProperty' {
    It 'returns null for a null object' {
        Get-CimProperty -Object $null -Name 'Caption' | Should -BeNullOrEmpty
    }
    It 'returns null for a missing property (strict mode safe)' {
        Get-CimProperty -Object ([pscustomobject]@{}) -Name 'Nope' | Should -BeNullOrEmpty
    }
    It 'returns null for empty-string values' {
        Get-CimProperty -Object ([pscustomobject]@{ Caption = '' }) -Name 'Caption' | Should -BeNullOrEmpty
    }
    It 'returns real values' {
        Get-CimProperty -Object ([pscustomobject]@{ Caption = 'X' }) -Name 'Caption' | Should -Be 'X'
    }
}
