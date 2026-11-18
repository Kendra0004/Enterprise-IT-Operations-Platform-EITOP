# SystemInventory.psm1 — Windows system/OS facts.
#
# Contract fields (backend SystemReport, extra="forbid" — exact keys only):
#   hostname, fqdn, os, distribution, distribution_version, os_version,
#   os_arch, kernel, uptime_seconds
#
# Field mapping (documented in docs/endpoints/windows-collector.md):
#   hostname             = NetBIOS computer name
#   fqdn                 = DNS host entry (null when unavailable)
#   os                   = "windows"
#   distribution         = Caption minus "Microsoft " prefix (edition name)
#   distribution_version = DisplayVersion (e.g. 24H2) / ReleaseId fallback
#   os_version           = full Caption (PRETTY_NAME equivalent)
#   kernel               = OS Version + "." + BuildNumber (e.g. 10.0.26100)
#   os_arch              = OSArchitecture (e.g. 64-bit)
#   uptime_seconds       = now - LastBootUpTime
#
# All CIM access is isolated in Get-SystemSourceData so tests can feed
# fixtures without any Windows/CIM present.

Set-StrictMode -Version Latest

function Get-SystemSourceData {
    # Live CIM query (Windows only). Any missing property degrades to $null.
    $os = $null
    $cs = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { }
    [pscustomobject]@{
        os        = $os
        cs        = $cs
        hostname  = $env:COMPUTERNAME
        utc_now   = [DateTime]::UtcNow
    }
}

function ConvertTo-SystemReport {
    # Pure converter: fixture-friendly, no CIM, no network.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Source,
        [string]$Fqdn
    )

    $os = $Source.os
    $cs = $Source.cs

    $caption = Get-CimProperty -Object $os -Name 'Caption'
    $version = Get-CimProperty -Object $os -Name 'Version'
    $build = Get-CimProperty -Object $os -Name 'BuildNumber'
    $arch = Get-CimProperty -Object $os -Name 'OSArchitecture'
    $displayVersion = Get-CimProperty -Object $os -Name 'DisplayVersion'
    $releaseId = Get-CimProperty -Object $os -Name 'ReleaseId'
    $bootTime = Get-CimProperty -Object $os -Name 'LastBootUpTime'

    $distribution = $null
    if ($caption) { $distribution = ([string]$caption) -replace '^Microsoft\s+', '' }

    $distributionVersion = $null
    if ($displayVersion) { $distributionVersion = [string]$displayVersion }
    elseif ($releaseId) { $distributionVersion = [string]$releaseId }

    $kernel = $null
    if ($version) { $kernel = [string]$version }        # "10.0.26100" already contains the build
    elseif ($build) { $kernel = [string]$build }

    $uptime = $null
    if ($bootTime) {
        try {
            $bootUtc = ConvertTo-EitopUtcDateTime $bootTime
            if ($bootUtc) {
                # Future/unparseable-relative boot times clamp to 0, not null
                $uptime = [int][math]::Max(0, ($Source.utc_now - $bootUtc).TotalSeconds)
            }
        } catch { $uptime = $null }  # unparseable boot time → null, not a crash
    }

    $hostname = $Source.hostname
    if (-not $hostname) { $hostname = [System.Net.Dns]::GetHostName() }

    [pscustomobject]@{
        hostname             = [string]$hostname
        fqdn                 = if ($Fqdn) { $Fqdn } elseif ($cs -and $cs.PSObject.Properties['DNSHostName'] -and $cs.DNSHostName) { [string]$cs.DNSHostName } else { $null }
        os                   = 'windows'
        distribution         = $distribution
        distribution_version = $distributionVersion
        os_version           = if ($caption) { [string]$caption } else { $null }
        os_arch              = if ($arch) { [string]$arch } else { $null }
        kernel               = $kernel
        uptime_seconds       = $uptime
    }
}

function Get-CimProperty {
    # Safe property read: missing CIM property / $null object → $null.
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop -and $null -ne $prop.Value -and [string]$prop.Value -ne '') { return $prop.Value }
    $null
}

function ConvertTo-EitopUtcDateTime {
    # CIM dates may be DateTime (local, DMTF-style) or DMTF string; normalize to UTC.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Utc) { return $Value }
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        # Unspecified: assume local machine time (CIM convention)
        return ([DateTime]::SpecifyKind($Value, [DateTimeKind]::Local)).ToUniversalTime()
    }
    $text = [string]$Value
    $dtf = [Globalization.CultureInfo]::InvariantCulture
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeLocal
    try { return [DateTime]::Parse($text, $dtf, $styles) } catch { }
    try {
        # DMTF timestamp: yyyymmddHHmmss.ffffff:000
        if ($text -match '^(\d{14})') {
            return [DateTime]::ParseExact($Matches[1], 'yyyyMMddHHmmss', $dtf,
                [Globalization.DateTimeStyles]::AssumeLocal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
        }
    } catch { }
    $null
}

function Get-EitopFqdn {
    # FQDN best effort; null on failure (no DNS dependency).
    param([string]$HostName)
    if (-not $HostName) { return $null }
    try {
        $entry = [System.Net.Dns]::GetHostEntry($HostName)
        if ($entry.HostName) { return [string]$entry.HostName }
    } catch { }
    $null
}

Export-ModuleMember -Function Get-SystemSourceData, ConvertTo-SystemReport, Get-CimProperty, ConvertTo-EitopUtcDateTime, Get-EitopFqdn
