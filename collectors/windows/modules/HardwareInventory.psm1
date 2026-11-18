# HardwareInventory.psm1 — CPU, memory, chassis, disks, volumes.
#
# Contract fields (backend HardwareReport, extra="forbid"):
#   manufacturer, model, serial_number, cpu_model, cpu_cores, memory_bytes,
#   disk_bytes   + filesystems[] (mount/fstype/total_bytes/used_bytes)
#
# Mapping:
#   cpu_model     = Win32_Processor.Name (first socket; joined if multiple)
#   cpu_cores     = sum NumberOfLogicalProcessors  (parity with Linux collector,
#                   which reports logical CPUs under cpu_cores)
#   facts: hardware.cpu_physical_cores = sum NumberOfCores
#   memory_bytes  = Win32_ComputerSystem.TotalPhysicalMemory
#   manufacturer  = Win32_ComputerSystem.Manufacturer
#   model         = Win32_ComputerSystem.Model
#   serial_number = Win32_BIOS.SerialNumber (null/placeholder → null)
#   disk_bytes    = sum of physical disks Win32_DiskDrive.Size
#   filesystems   = fixed logical volumes (DriveType=3): capacity + usage
#
# Missing/inaccessible CIM properties degrade to $null/0 — never throw.

Set-StrictMode -Version Latest

function Get-HardwareSourceData {
    $out = @{}
    foreach ($pair in @(
            @('processors', 'Win32_Processor'),
            @('cs', 'Win32_ComputerSystem'),
            @('bios', 'Win32_BIOS'),
            @('disks', 'Win32_DiskDrive'),
            @('volumes', 'Win32_LogicalDisk')
        )) {
        try { $out[$pair[0]] = @(Get-CimInstance -ClassName $pair[1] -ErrorAction Stop) }
        catch { $out[$pair[0]] = @() }
    }
    [pscustomobject]$out
}

function ConvertTo-HardwareReport {
    # Pure converter over fixture objects. Returns @{ report=...; facts=... }.
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Source)

    $processors = @($Source.processors)
    $cs = $Source.cs | Select-Object -First 1
    $bios = $Source.bios | Select-Object -First 1

    # --- CPU --------------------------------------------------------------
    $cpuModel = $null
    $logical = 0
    $physical = 0
    foreach ($cpu in $processors) {
        if (-not $cpuModel) { $cpuModel = Get-CimProperty -Object $cpu -Name 'Name' }
        $l = (Get-CimProperty -Object $cpu -Name 'NumberOfLogicalProcessors') -as [int]
        if ($null -ne $l) { $logical += $l }
        $p = (Get-CimProperty -Object $cpu -Name 'NumberOfCores') -as [int]
        if ($null -ne $p) { $physical += $p }
    }
    if ($logical -le 0) { $logical = $null }

    # --- Memory / chassis --------------------------------------------------
    $memoryRaw = Get-CimProperty -Object $cs -Name 'TotalPhysicalMemory'
    $memory = if ($null -ne $memoryRaw) { $memoryRaw -as [int64] } else { $null }
    $manufacturer = Get-CimProperty -Object $cs -Name 'Manufacturer'
    $model = Get-CimProperty -Object $cs -Name 'Model'

    # --- Serial ------------------------------------------------------------
    $serial = Get-CimProperty -Object $bios -Name 'SerialNumber'
    if ($serial) {
        $serial = ([string]$serial).Trim()
        if ($serial -in @('0', 'To be filled by O.E.M.', 'System Serial Number', 'None', 'Default string')) {
            $serial = $null
        }
        if ($serial -and $serial.Length -gt 128) { $serial = $serial.Substring(0, 128) }
    }

    # --- Physical disk capacity -------------------------------------------
    $diskTotal = [int64]0
    foreach ($disk in @($Source.disks)) {
        $size = (Get-CimProperty -Object $disk -Name 'Size') -as [int64]
        if ($null -ne $size) { $diskTotal += $size }
    }
    $diskBytes = if ($diskTotal -gt 0) { $diskTotal } else { $null }

    # --- Fixed volumes → filesystems --------------------------------------
    $filesystems = @()
    foreach ($vol in @($Source.volumes)) {
        $driveType = (Get-CimProperty -Object $vol -Name 'DriveType') -as [int]
        if ($null -eq $driveType -or $driveType -ne 3) { continue }  # local fixed disk only
        $device = Get-CimProperty -Object $vol -Name 'DeviceID'
        if (-not $device) { continue }
        $size = (Get-CimProperty -Object $vol -Name 'Size') -as [int64]
        $free = (Get-CimProperty -Object $vol -Name 'FreeSpace') -as [int64]
        $fsType = Get-CimProperty -Object $vol -Name 'FileSystem'
        $total = if ($null -ne $size) { $size } else { 0 }
        $used = if ($null -ne $size -and $null -ne $free) { $size - $free } else { 0 }
        $filesystems += [pscustomobject]@{
            mount       = [string]$device       # e.g. "C:"
            fstype      = if ($fsType) { [string]$fsType } else { '' }
            total_bytes = [int64]$total
            used_bytes  = [math]::Max([int64]0, $used)
        }
    }

    $report = [pscustomobject]@{
        manufacturer = if ($manufacturer) { [string]$manufacturer } else { $null }
        model        = if ($model) { [string]$model } else { $null }
        serial_number = $serial
        cpu_model    = if ($cpuModel) { [string]$cpuModel } else { $null }
        cpu_cores    = $logical
        memory_bytes = $memory
        disk_bytes   = $diskBytes
    }

    $facts = @{}
    if ($physical -gt 0) { $facts['hardware.cpu_physical_cores'] = [string]$physical }

    [pscustomobject]@{ report = $report; facts = $facts; filesystems = $filesystems }
}

Export-ModuleMember -Function Get-HardwareSourceData, ConvertTo-HardwareReport
