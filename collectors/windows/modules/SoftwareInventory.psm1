# SoftwareInventory.psm1 — installed applications from the registry.
#
# Sources (NO Win32_Product — it triggers MSI consistency checks/repairs):
#   HKLM 64-bit: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
#   HKLM 32-bit: HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
#   HKCU:        HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall
#
# Collected per entry: DisplayName, DisplayVersion, Publisher,
# InstallDate (yyyyMMdd), installation scope (hive).
#
# Contract (backend PackageReport, extra="forbid"): name, version,
# package_manager. Scope is encoded in package_manager as
#   registry-hklm64 | registry-hklm32 | registry-hkcu
# Publisher and install date are returned in `details` for local `collect`
# output (see docs/endpoints/windows-collector.md — known API limitation).
#
# Dedup: key = Name+Version (case-insensitive). Same app in several hives →
# keep highest-precedence source (hklm64 > hklm32 > hkcu). Entries without
# DisplayName, marked SystemComponent, or belonging to a patch (ParentKeyName
# / ReleaseType Update) are excluded.
#
# Registry access is isolated behind -EntryReader so unit tests can feed
# fixtures on any OS.

Set-StrictMode -Version Latest

function Get-UninstallRegistryPaths {
    # Canonical uninstall locations (asserted by tests: Win32_Product unused).
    [CmdletBinding()]
    param()
    @(
        [pscustomobject]@{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';        scope = 'registry-hklm64'; precedence = 3 }
        [pscustomobject]@{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; scope = 'registry-hklm32'; precedence = 2 }
        [pscustomobject]@{ path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall';        scope = 'registry-hkcu';   precedence = 1 }
    )
}

function Get-UninstallEntriesFromRegistry {
    # Default reader: enumerate uninstall keys, read each key's properties.
    # A missing hive/key skips that source (no throw).
    param([Parameter(Mandatory)]$Location)
    $entries = @()
    $keys = @()
    try { $keys = @(Get-ChildItem -LiteralPath $Location.path -ErrorAction Stop) }
    catch { return @() }  # hive absent (32-bit OS, restricted account) → skip
    foreach ($key in $keys) {
        try { $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop }
        catch { continue }
        $entries += [pscustomobject]@{
            scope      = $Location.scope
            precedence = $Location.precedence
            raw        = $props
        }
    }
    $entries
}

function Get-InstalledSoftwareRaw {
    # Read raw entries from all sources (reader injectable for tests).
    [CmdletBinding()]
    param(
        [scriptblock]$EntryReader,
        $Locations    # default: canonical registry paths
    )
    if (-not $Locations) { $Locations = Get-UninstallRegistryPaths }
    if (-not $EntryReader) { $EntryReader = ${function:Get-UninstallEntriesFromRegistry} }

    $entries = @()
    foreach ($location in @($Locations)) {
        $entries += @(& $EntryReader $location)
    }
    $entries
}

function Test-IncludeSoftwareEntry {
    # Filter rules for a raw registry entry.
    param([AllowNull()]$Raw)
    if ($null -eq $Raw) { return $false }
    $p = $Raw
    if (-not (Get-CimProperty -Object $p -Name 'DisplayName')) { return $false }
    $systemComponent = Get-CimProperty -Object $p -Name 'SystemComponent'
    if ($null -ne $systemComponent -and [int]$systemComponent -eq 1) { return $false }
    if (Get-CimProperty -Object $p -Name 'ParentKeyName') { return $false }  # MSI patch
    $releaseType = Get-CimProperty -Object $p -Name 'ReleaseType'
    if ($releaseType -and [string]$releaseType -in @('Update', 'Hotfix', 'Security Update')) { return $false }
    return $true
}

function ConvertTo-PackageReports {
    # Pure converter: raw entries → contract packages + full local details.
    # Dedup by Name+Version (case-insensitive), highest precedence wins.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Entries)

    $best = @{}   # "name\u0000version" (lowercase) → entry
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        $raw = $entry.raw
        if ($null -eq $raw) { continue }
        if (-not (Test-IncludeSoftwareEntry -Raw $raw)) { continue }

        $name = ([string](Get-CimProperty -Object $raw -Name 'DisplayName')).Trim()
        $version = [string](Get-CimProperty -Object $raw -Name 'DisplayVersion')
        if (-not $name) { continue }
        if ($name.Length -gt 255) { $name = $name.Substring(0, 255) }
        if ($version.Length -gt 128) { $version = $version.Substring(0, 128) }

        $key = ($name + [char]0 + $version).ToLowerInvariant()
        $precedence = [int]$entry.precedence
        if ($best.ContainsKey($key) -and [int]$best[$key].precedence -ge $precedence) { continue }
        $best[$key] = $entry
    }

    $packages = @()
    $details = @()
    foreach ($key in ($best.Keys | Sort-Object)) {
        $entry = $best[$key]
        $raw = $entry.raw
        $name = ([string](Get-CimProperty -Object $raw -Name 'DisplayName')).Trim()
        if ($name.Length -gt 255) { $name = $name.Substring(0, 255) }
        $version = [string](Get-CimProperty -Object $raw -Name 'DisplayVersion')
        if ($version.Length -gt 128) { $version = $version.Substring(0, 128) }
        $publisher = Get-CimProperty -Object $raw -Name 'Publisher'
        $installDate = Get-CimProperty -Object $raw -Name 'InstallDate'

        $packages += [pscustomobject]@{
            name            = $name
            version         = $version
            package_manager = [string]$entry.scope
        }
        $details += [pscustomobject]@{
            name         = $name
            version      = $version
            publisher    = if ($publisher) { [string]$publisher } else { $null }
            install_date = if ($installDate) { [string]$installDate } else { $null }
            scope        = [string]$entry.scope
        }
    }

    [pscustomobject]@{
        packages = $packages
        details  = $details
        facts    = @{ 'software.count' = [string]$packages.Count }
    }
}

function Get-SoftwareInventory {
    # Convenience: read + convert (both seams injectable for tests).
    param([scriptblock]$EntryReader, $Locations)
    $entries = Get-InstalledSoftwareRaw -EntryReader $EntryReader -Locations $Locations
    ConvertTo-PackageReports -Entries $entries
}

Export-ModuleMember -Function `
    Get-UninstallRegistryPaths, Get-UninstallEntriesFromRegistry, Get-InstalledSoftwareRaw, `
    Test-IncludeSoftwareEntry, ConvertTo-PackageReports, Get-SoftwareInventory
