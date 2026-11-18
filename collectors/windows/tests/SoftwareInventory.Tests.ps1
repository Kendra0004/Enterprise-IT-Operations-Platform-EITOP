# Software registry parsing tests — fixtures only, no Windows registry required.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:Root 'modules/SoftwareInventory.psm1') -Force
    Import-Module (Join-Path $script:Root 'modules/SystemInventory.psm1') -Force  # Get-CimProperty
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Fixtures = Join-Path $PSScriptRoot '..\fixtures'
    $script:SoftwareFixture = Get-Content (Join-Path $script:Fixtures 'software_entries.json') -Raw | ConvertFrom-Json
}

Describe 'Get-UninstallRegistryPaths' {
    It 'targets the three uninstall registry locations' {
        $paths = @(Get-UninstallRegistryPaths)
        $paths.Count | Should -Be 3
        ($paths | ForEach-Object { $_.path }) | Should -Contain 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        ($paths | ForEach-Object { $_.path }) | Should -Contain 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        ($paths | ForEach-Object { $_.path }) | Should -Contain 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    }

    It 'encodes scope in package_manager (≤32 chars, contract limit)' {
        foreach ($location in (Get-UninstallRegistryPaths)) {
            $location.scope | Should -BeIn @('registry-hklm64', 'registry-hklm32', 'registry-hkcu')
            $location.scope.Length | Should -BeLessOrEqual 32
        }
    }

    It 'never uses Win32_Product (MSI consistency-check side effects)' {
        $files = Get-ChildItem (Join-Path $script:Root 'modules') -Filter '*.psm1' -Recurse
        $files += Get-Item (Join-Path $script:Root 'eitop-collector.ps1')
        foreach ($file in $files) {
            (Get-CodeOnlyText -Path $file.FullName) | Should -Not -Match 'Win32_Product' `
                -Because "$($file.Name) must not query Win32_Product"
        }
    }
}

Describe 'ConvertTo-PackageReports with fixture (dedup + filters)' {
    BeforeAll {
        $script:result = ConvertTo-PackageReports -Entries $script:SoftwareFixture
        $script:byName = @{}
        foreach ($p in @($script:result.packages)) { $script:byName[$p.name] = $p }
    }

    It 'keeps exactly the expected applications' {
        $names = @($script:result.packages | ForEach-Object { $_.name })
        $names | Should -Contain '7-Zip 24.07 (x64)'
        $names | Should -Contain 'Mozilla Firefox'
        $names | Should -Contain 'Old 32-bit Tool'
        $names | Should -Contain 'Microsoft Visual C++ 2015-2022 Redistributable (x64)'
        $names.Count | Should -Be 4
    }

    It 'dedups Firefox across HKLM and HKCU, preferring HKLM' {
        $firefox = @($script:result.packages | Where-Object { $_.name -eq 'Mozilla Firefox' })
        $firefox.Count | Should -Be 1
        $firefox[0].package_manager | Should -Be 'registry-hklm64'   # precedence 3, not hkcu
    }

    It 'filters SystemComponent, patches, update releases and nameless entries' {
        $names = @($script:result.packages | ForEach-Object { $_.name })
        $names | Should -Not -Contain 'Hidden System Component'
        $names | Should -Not -Contain 'Patch KB123456'
        $names | Should -Not -Contain 'Security Update for Windows'
    }

    It 'emits exactly the PackageReport contract keys' {
        foreach ($p in @($script:result.packages)) {
            @($p.PSObject.Properties.Name | Sort-Object) |
                Should -Be (@('name', 'version', 'package_manager') | Sort-Object)
        }
    }

    It 'carries publisher, install date and scope in local details' {
        $zip = @($script:result.details | Where-Object { $_.name -like '7-Zip*' })[0]
        $zip.publisher | Should -Be 'Igor Pavlov'
        $zip.install_date | Should -Be '20260115'
        $zip.scope | Should -Be 'registry-hklm64'
        # entries without InstallDate degrade to null
        $tool = @($script:result.details | Where-Object { $_.name -eq 'Old 32-bit Tool' })[0]
        $tool.install_date | Should -BeNullOrEmpty
    }

    It 'reports software.count fact' {
        $script:result.facts['software.count'] | Should -Be '4'
    }
}

Describe 'ConvertTo-PackageReports edge cases' {
    It 'returns empty collections for zero entries' {
        $result = ConvertTo-PackageReports -Entries @()
        @($result.packages).Count | Should -Be 0
        @($result.details).Count | Should -Be 0
        $result.facts['software.count'] | Should -Be '0'
    }

    It 'prefers the highest-precedence hive when the same app exists thrice' {
        $entries = @(
            [pscustomobject]@{ scope = 'registry-hkcu'; precedence = 1; raw = [pscustomobject]@{ DisplayName = 'App X'; DisplayVersion = '1.0' } }
            [pscustomobject]@{ scope = 'registry-hklm32'; precedence = 2; raw = [pscustomobject]@{ DisplayName = 'APP X'; DisplayVersion = '1.0' } }
            [pscustomobject]@{ scope = 'registry-hklm64'; precedence = 3; raw = [pscustomobject]@{ DisplayName = 'App x'; DisplayVersion = '1.0' } }
        )
        $result = ConvertTo-PackageReports -Entries $entries
        @($result.packages).Count | Should -Be 1
        $result.packages[0].package_manager | Should -Be 'registry-hklm64'
    }

    It 'keeps same-name different-version entries as distinct packages' {
        $entries = @(
            [pscustomobject]@{ scope = 'registry-hklm64'; precedence = 3; raw = [pscustomobject]@{ DisplayName = 'App'; DisplayVersion = '1.0' } }
            [pscustomobject]@{ scope = 'registry-hklm64'; precedence = 3; raw = [pscustomobject]@{ DisplayName = 'App'; DisplayVersion = '2.0' } }
        )
        @( (ConvertTo-PackageReports -Entries $entries).packages ).Count | Should -Be 2
    }

    It 'truncates over-long names/versions to contract limits' {
        $entries = @(
            [pscustomobject]@{
                scope = 'registry-hklm64'; precedence = 3
                raw   = [pscustomobject]@{ DisplayName = 'N' * 500; DisplayVersion = 'V' * 300 }
            }
        )
        $p = (ConvertTo-PackageReports -Entries $entries).packages[0]
        $p.name.Length | Should -Be 255
        $p.version.Length | Should -Be 128
    }

    It 'skips malformed entries lacking DisplayName entirely' {
        $entries = @(
            [pscustomobject]@{ scope = 'registry-hklm64'; precedence = 3; raw = [pscustomobject]@{ DisplayVersion = '1.0' } }
            [pscustomobject]@{ scope = 'registry-hklm64'; precedence = 3; raw = $null }
        )
        # raw=$null: Test-IncludeSoftwareEntry must not throw
        @( (ConvertTo-PackageReports -Entries $entries).packages ).Count | Should -Be 0
    }

    It 'treats SystemComponent as string "1" too (registry polymorphism)' {
        $entries = @(
            [pscustomobject]@{ scope = 'registry-hklm64'; precedence = 3; raw = [pscustomobject]@{ DisplayName = 'X'; SystemComponent = '1' } }
        )
        @( (ConvertTo-PackageReports -Entries $entries).packages ).Count | Should -Be 0
    }
}

Describe 'Get-InstalledSoftwareRaw reader seam' {
    It 'aggregates entries from the injected reader across locations' {
        $reader = {
            param($location)
            @([pscustomobject]@{
                    scope = $location.scope; precedence = $location.precedence
                    raw = [pscustomobject]@{ DisplayName = "From $($location.scope)" }
                })
        }
        $entries = Get-InstalledSoftwareRaw -EntryReader $reader
        @($entries).Count | Should -Be 3
        @($entries | ForEach-Object { $_.scope }) | Should -Be @('registry-hklm64', 'registry-hklm32', 'registry-hkcu')
    }

    It 'missing hive degrades to empty (default reader swallows Get-ChildItem errors)' {
        # HKLM: provider does not exist on this test platform → must not throw
        $entries = Get-InstalledSoftwareRaw -Locations @(
            [pscustomobject]@{ path = 'HKLM:\SOFTWARE\NoSuchHive'; scope = 'registry-hklm64'; precedence = 3 }
        )
        @($entries).Count | Should -Be 0
    }
}
