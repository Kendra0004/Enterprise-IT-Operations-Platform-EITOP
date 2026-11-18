# Hardware inventory parsing tests — fixtures only, no CIM/Windows required.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/HardwareInventory.psm1') -Force
    Import-Module (Join-Path $script:Root 'modules/SystemInventory.psm1') -Force  # Get-CimProperty
    $script:Fixtures = Join-Path $PSScriptRoot '..\fixtures'

    function Get-HardwareFixture {
        param([string]$Name)
        $data = Get-Content (Join-Path $script:Fixtures $Name) -Raw | ConvertFrom-Json
        [pscustomobject]@{
            processors = @($data.processors)
            cs         = @($data.cs)
            bios       = @($data.bios)
            disks      = @($data.disks)
            volumes    = @($data.volumes)
        }
    }
}

Describe 'ConvertTo-HardwareReport with dual-socket fixture' {
    BeforeAll {
        $script:result = ConvertTo-HardwareReport -Source (Get-HardwareFixture 'hardware_dual_socket.json')
    }

    It 'reports the CPU model and sums logical cores across sockets' {
        $script:result.report.cpu_model | Should -Be 'Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz'
        $script:result.report.cpu_cores | Should -Be 32   # logical, Linux parity
        $script:result.facts['hardware.cpu_physical_cores'] | Should -Be '16'
    }

    It 'maps chassis identity and memory' {
        $script:result.report.manufacturer | Should -Be 'Dell Inc.'
        $script:result.report.model | Should -Be 'PowerEdge R650'
        $script:result.report.serial_number | Should -Be 'ABC123XYZ'
        $script:result.report.memory_bytes | Should -Be 68719476736
    }

    It 'sums physical disk capacity and keeps only fixed volumes' {
        $script:result.report.disk_bytes | Should -Be 214748364800
        $mounts = @($script:result.filesystems | ForEach-Object { $_.mount })
        $mounts | Should -Contain 'C:'
        $mounts | Should -Contain 'D:'
        $mounts | Should -Not -Contain 'E:'   # DriveType 5 (optical) excluded
    }

    It 'computes volume usage from Size-FreeSpace' {
        $c = $script:result.filesystems | Where-Object { $_.mount -eq 'C:' }
        $c.total_bytes | Should -Be 107374182400
        $c.used_bytes | Should -Be 42949672960
        $d = $script:result.filesystems | Where-Object { $_.mount -eq 'D:' }
        $d.used_bytes | Should -Be 0
    }

    It 'emits exactly the HardwareReport contract keys' {
        $expected = @('manufacturer', 'model', 'serial_number', 'cpu_model',
            'cpu_cores', 'memory_bytes', 'disk_bytes') | Sort-Object
        @($script:result.report.PSObject.Properties.Name | Sort-Object) | Should -Be $expected
    }
}

Describe 'ConvertTo-HardwareReport with missing/empty CIM data' {
    It 'degrades to nulls/empty for an all-empty source' {
        $source = [pscustomobject]@{ processors = @(); cs = @(); bios = @(); disks = @(); volumes = @() }
        $result = ConvertTo-HardwareReport -Source $source
        $result.report.cpu_model | Should -BeNullOrEmpty
        $result.report.cpu_cores | Should -BeNullOrEmpty
        $result.report.memory_bytes | Should -BeNullOrEmpty
        $result.report.disk_bytes | Should -BeNullOrEmpty
        $result.report.manufacturer | Should -BeNullOrEmpty
        $result.report.serial_number | Should -BeNullOrEmpty
        @($result.filesystems).Count | Should -Be 0
        @($result.facts.Keys).Count | Should -Be 0
    }

    It 'tolerates processor entries missing core counts' {
        $source = [pscustomobject]@{
            processors = @([pscustomobject]@{ Name = 'Unknown' })
            cs         = @([pscustomobject]@{ TotalPhysicalMemory = 'not-a-number' })
            bios       = @()
            disks      = @()
            volumes    = @()
        }
        $result = ConvertTo-HardwareReport -Source $source
        $result.report.cpu_model | Should -Be 'Unknown'
        $result.report.cpu_cores | Should -BeNullOrEmpty
    }

    It 'nulls placeholder serial numbers' {
        foreach ($placeholder in @('To be filled by O.E.M.', '0', 'System Serial Number', 'Default string')) {
            $source = [pscustomobject]@{
                processors = @(); cs = @()
                bios = @([pscustomobject]@{ SerialNumber = $placeholder })
                disks = @(); volumes = @()
            }
            (ConvertTo-HardwareReport -Source $source).report.serial_number |
                Should -BeNullOrEmpty -Because "placeholder '$placeholder' means unavailable"
        }
    }

    It 'nulls a missing CIM class result (Get-CimInstance failure → empty arrays)' {
        $source = [pscustomobject]@{ processors = $null; cs = $null; bios = $null; disks = $null; volumes = $null }
        $result = ConvertTo-HardwareReport -Source $source
        $result.report | Should -Not -BeNullOrEmpty
        @($result.filesystems).Count | Should -Be 0
    }

    It 'skips volumes with null sizes without throwing' {
        $source = [pscustomobject]@{
            processors = @(); cs = @(); bios = @(); disks = @()
            volumes = @([pscustomobject]@{ DriveType = 3; DeviceID = 'C:'; Size = $null; FreeSpace = $null; FileSystem = $null })
        }
        $result = ConvertTo-HardwareReport -Source $source
        @($result.filesystems).Count | Should -Be 1
        $result.filesystems[0].total_bytes | Should -Be 0
        $result.filesystems[0].used_bytes | Should -Be 0
        $result.filesystems[0].fstype | Should -Be ''
    }
}
