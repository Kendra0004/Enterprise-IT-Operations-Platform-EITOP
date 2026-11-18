# NetworkInventory.psm1 — network interfaces.
#
# Contract fields (backend NetworkReport, extra="forbid"):
#   interfaces[] { name, mac, ipv4[], ipv6[], is_up }, ip_addresses[],
#   mac_addresses[]
#
# Sources: Win32_NetworkAdapterConfiguration (IP-enabled adapters: MAC, IPs,
# descriptions) joined with Win32_NetworkAdapter (connection status).
#
# Collected: interface name, description, MAC, IPv4, IPv6, status.
# NEVER collected: Wi-Fi profiles/passwords, saved credentials, ARP/DNS
# caches, or any other sensitive network state.
#
# The backend interface object has no "description" field (extra="forbid"),
# so descriptions are reported through facts["network.interface_descriptions"]
# as a compact JSON map {name: description} (fact values ≤ 8192 chars).

Set-StrictMode -Version Latest

function Get-NetworkSourceData {
    $config = @()
    $adapters = @()
    try { $config = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop) } catch { }
    try { $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop) } catch { }
    [pscustomobject]@{ configurations = $config; adapters = $adapters }
}

function ConvertTo-NetworkReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Source)

    # status by adapter Index: NetConnectionStatus 2 = connected
    $statusByIndex = @{}
    foreach ($adapter in @($Source.adapters)) {
        $idx = Get-CimProperty -Object $adapter -Name 'Index'
        if ($null -eq $idx) { continue }
        $conn = Get-CimProperty -Object $adapter -Name 'NetConnectionStatus'
        $statusByIndex[[int]$idx] = if ($null -ne $conn) { [int]$conn } else { $null }
    }

    $interfaces = @()
    $ips = New-Object System.Collections.Generic.List[string]
    $macs = New-Object System.Collections.Generic.List[string]
    $descriptions = [ordered]@{}

    foreach ($cfg in @($Source.configurations)) {
        $ipEnabled = Get-CimProperty -Object $cfg -Name 'IPEnabled'
        if (-not $ipEnabled) { continue }

        $index = Get-CimProperty -Object $cfg -Name 'InterfaceIndex'
        $settingId = Get-CimProperty -Object $cfg -Name 'SettingID'
        $description = Get-CimProperty -Object $cfg -Name 'Description'
        $mac = Get-CimProperty -Object $cfg -Name 'MACAddress'

        # Friendly name: prefer the adapter's NetConnectionID ("Ethernet"),
        # fall back to SettingID (stable GUID) then description.
        $name = $null
        if ($null -ne $index) {
            $adapter = @($Source.adapters) | Where-Object {
                (Get-CimProperty -Object $_ -Name 'InterfaceIndex') -eq $index -or
                (Get-CimProperty -Object $_ -Name 'Index') -eq $index
            } | Select-Object -First 1
            if ($adapter) { $name = Get-CimProperty -Object $adapter -Name 'NetConnectionID' }
        }
        if (-not $name -and $settingId) { $name = [string]$settingId }
        if (-not $name -and $description) { $name = [string]$description }
        if (-not $name) { continue }
        if ($name.Length -gt 64) { $name = $name.Substring(0, 64) }

        $ipv4 = New-Object System.Collections.Generic.List[string]
        $ipv6 = New-Object System.Collections.Generic.List[string]
        $addresses = Get-CimProperty -Object $cfg -Name 'IPAddress'
        foreach ($address in @($addresses)) {
            if (-not $address) { continue }
            $value = [string]$address
            if ($value -match ':') { if (-not $ipv6.Contains($value)) { $ipv6.Add($value) } }
            else { if (-not $ipv4.Contains($value)) { $ipv4.Add($value) } }
        }

        # Limit per contract: ≤64 addresses per interface
        while ($ipv4.Count -gt 64) { $ipv4.RemoveAt($ipv4.Count - 1) }
        while ($ipv6.Count -gt 64) { $ipv6.RemoveAt($ipv6.Count - 1) }

        $status = $null
        if ($null -ne $index -and $statusByIndex.ContainsKey([int]$index)) {
            $status = $statusByIndex[[int]$index]
        }
        # Fallback: IP-enabled with addresses ⇒ treat as up when status unknown
        $isUp = if ($null -ne $status) { $status -eq 2 } else { ($ipv4.Count + $ipv6.Count) -gt 0 }

        $macClean = $null
        if ($mac) {
            $macClean = ([string]$mac).Trim()
            if ($macClean -eq '00:00:00:00:00:00') { $macClean = $null }
            elseif ($macClean.Length -gt 32) { $macClean = $macClean.Substring(0, 32) }
        }

        $interfaces += [pscustomobject]@{
            name  = $name
            mac   = $macClean
            ipv4  = @($ipv4)
            ipv6  = @($ipv6)
            is_up = [bool]$isUp
        }
        if ($description) { $descriptions[$name] = ([string]$description).Substring(0, [math]::Min(255, ([string]$description).Length)) }
        foreach ($address in $ipv4) { if (-not $ips.Contains($address)) { $ips.Add($address) } }
        foreach ($address in $ipv6) { if (-not $ips.Contains($address)) { $ips.Add($address) } }
        if ($macClean -and -not $macs.Contains($macClean)) { $macs.Add($macClean) }

        if ($interfaces.Count -ge 64) { break }  # contract cap
    }

    $facts = @{}
    if ($descriptions.Count -gt 0) {
        $json = $descriptions | ConvertTo-Json -Compress
        if ($json.Length -le 8192) { $facts['network.interface_descriptions'] = $json }
    }

    [pscustomobject]@{
        report = [pscustomobject]@{
            interfaces    = $interfaces
            ip_addresses  = @($ips | Sort-Object -Unique)
            mac_addresses = @($macs | Sort-Object -Unique)
        }
        facts = $facts
    }
}

Export-ModuleMember -Function Get-NetworkSourceData, ConvertTo-NetworkReport
