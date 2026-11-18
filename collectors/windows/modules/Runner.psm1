# Runner.psm1 — orchestration: payload assembly, enrollment, loops.
#
# Safety rules:
#   - server responses are parsed as DATA only; nothing in this module ever
#     interprets response content as a command (no Invoke-Expression, ever)
#   - credentials flow through memory + protected file only; never logged,
#     never in arguments that are later printed
#   - stop flag honored between 1-second sleep slices (graceful SIGINT-ish)
#
# All external effects (API calls, file writes, clock, sleep) are injectable
# scriptblocks so unit tests run without Windows, network, or a real clock.

Set-StrictMode -Version Latest

$script:AgentVersion = '0.1.0'
$script:MaxLoopBackoff = 3600  # seconds

function Get-EitopAgentVersion { $script:AgentVersion }

function Set-EitopRunnerStop {
    $script:StopRequested = $true
}
$script:StopRequested = $false

function Get-EitopInventoryPayload {
    <#
        .DESCRIPTION
        Build the AgentInventoryRequest body. Key set matches the backend
        schema exactly (extra="forbid" on the server enforces the contract).
        All collectors are injectable for tests.
    #>
    [CmdletBinding()]
    param(
        [scriptblock]$SystemCollector = { Get-EitopSystemSection },
        [scriptblock]$HardwareCollector = { Get-EitopHardwareSection },
        [scriptblock]$NetworkCollector = { Get-EitopNetworkSection },
        [scriptblock]$SoftwareCollector = { Get-SoftwareInventory }
    )

    $system = & $SystemCollector
    $hardware = & $HardwareCollector    # @{ report; facts; filesystems }
    $network = & $NetworkCollector      # @{ report; facts }
    $software = & $SoftwareCollector    # @{ packages; details; facts }

    $facts = [ordered]@{
        'collector.version'          = $script:AgentVersion
        'collector.runtime'          = "powershell-$($PSVersionTable.PSVersion)"
        'collector.platform'         = [string]$PSVersionTable.Platform
    }
    foreach ($source in @($hardware.facts, $network.facts, $software.facts)) {
        if ($null -eq $source) { continue }
        foreach ($key in @($source.Keys)) {
            if ($facts.Count -ge 512) { break }
            $facts[$key] = [string]$source[$key]
        }
    }

    [ordered]@{
        system      = $system
        hardware    = $hardware.report
        network     = $network.report
        filesystems = @($hardware.filesystems)
        packages    = @($software.packages)
        facts       = [hashtable]$facts
    }
}

function Get-EitopEnrollPayload {
    # AgentEnrollRequest keys (extra="forbid": token + these, nothing else).
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)]$SystemSection
    )
    [ordered]@{
        token          = $Token
        hostname       = [string]$SystemSection.hostname
        fqdn           = $SystemSection.fqdn
        os             = [string]$SystemSection.os
        os_version     = $SystemSection.os_version
        os_arch        = $SystemSection.os_arch
        kernel_version = $SystemSection.kernel
        agent_version  = $script:AgentVersion
    }
}

function Get-EitopSystemSection {
    $source = Get-SystemSourceData
    $fqdn = Get-EitopFqdn -HostName $source.hostname
    ConvertTo-SystemReport -Source $source -Fqdn $fqdn
}

function Get-EitopHardwareSection { ConvertTo-HardwareReport -Source (Get-HardwareSourceData) }
function Get-EitopNetworkSection { ConvertTo-NetworkReport -Source (Get-NetworkSourceData) }

# --- Flows ------------------------------------------------------------------

function Invoke-EitopEnrollFlow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Token,     # in-memory only, never logged
        [scriptblock]$EnrollAction,               # test seam (default: ApiClient)
        [scriptblock]$CredentialSaver             # test seam (default: file+DPAPI)
    )
    if (-not $EnrollAction) { $EnrollAction = ${function:Invoke-EitopEnroll} }
    if (-not $CredentialSaver) { $CredentialSaver = ${function:Save-EitopCredential} }

    $systemSection = Get-EitopSystemSection
    $body = Get-EitopEnrollPayload -Token $Token -SystemSection $systemSection
    # Split token out so the API action signature matches ApiClient.psm1
    $systemInfo = @{}
    foreach ($key in $body.Keys) { if ($key -ne 'token') { $systemInfo[$key] = $body[$key] } }

    $result = & $EnrollAction @{
        Config     = $Config
        Token      = $Token
        SystemInfo = $systemInfo
    }
    & $CredentialSaver -Path $Config.credential_file -EndpointId ([string]$result.endpoint_id) `
        -Credential ([string]$result.credential)
    [pscustomobject]@{
        endpoint_id = [string]$result.endpoint_id
        credential  = $null   # never returned to the console
    }
}

function Invoke-EitopHeartbeatFlow {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Credential,
        [scriptblock]$HeartbeatAction
    )
    if (-not $HeartbeatAction) { $HeartbeatAction = ${function:Invoke-EitopHeartbeat} }
    & $HeartbeatAction @{
        Config        = $Config
        Credential    = $Credential
        AgentVersion  = $script:AgentVersion
    }
}

function Invoke-EitopInventoryFlow {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Credential,
        [scriptblock]$InventoryAction,
        [scriptblock]$PayloadBuilder
    )
    if (-not $InventoryAction) { $InventoryAction = ${function:Invoke-EitopInventory} }
    if (-not $PayloadBuilder) { $PayloadBuilder = ${function:Get-EitopInventoryPayload} }
    $payload = & $PayloadBuilder
    & $InventoryAction @{
        Config     = $Config
        Credential = $Credential
        Inventory  = $payload
    }
}

function Invoke-EitopRotateFlow {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Credential,
        [scriptblock]$RotateAction,
        [scriptblock]$CredentialSaver
    )
    if (-not $RotateAction) { $RotateAction = ${function:Invoke-EitopRotateCredential} }
    if (-not $CredentialSaver) { $CredentialSaver = ${function:Save-EitopCredential} }
    $result = & $RotateAction @{ Config = $Config; Credential = $Credential }
    & $CredentialSaver -Path $Config.credential_file -EndpointId ([string]$result.endpoint_id) `
        -Credential ([string]$result.credential)
    [pscustomobject]@{ endpoint_id = [string]$result.endpoint_id }
}

# --- Daemon loop ---------------------------------------------------------------

function Get-EitopLoopDelay {
    # Exponential backoff for repeated failures: base * 2^n, capped at 1 hour.
    param(
        [Parameter(Mandatory)][int]$Failures,
        [Parameter(Mandatory)][int]$BaseInterval
    )
    [int][math]::Min($BaseInterval * [math]::Pow(2, [math]::Min($Failures, 8)), $script:MaxLoopBackoff)
}

function Start-EitopLoop {
    <#
        .DESCRIPTION
        Heartbeat + inventory loop. Injectable clock/sleep/actions/max
        iterations make it fully unit-testable without real time.
        -MaxIterations 0 = run until Stop-EitopRunner (production default).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Credential,
        [Parameter(Mandatory)][scriptblock]$HeartbeatAction,
        [Parameter(Mandatory)][scriptblock]$InventoryAction,
        [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
        [scriptblock]$Now = { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() },
        [int]$MaxIterations = 0,               # 0 = forever
        [int]$Failures = 0
    )
    $script:StopRequested = $false
    $nextHeartbeat = 0
    $nextInventory = 0
    $iterations = 0

    while (-not $script:StopRequested) {
        if ($MaxIterations -gt 0) {
            $iterations++
            if ($iterations -gt $MaxIterations) { break }
        }
        # NOTE: never store into $now — it would clobber the $Now scriptblock
        $tick = & $Now
        try {
            if ($tick -ge $nextHeartbeat) {
                & $HeartbeatAction $Credential
                $nextHeartbeat = $tick + [int]$Config.heartbeat_interval_seconds
            }
            if ($tick -ge $nextInventory) {
                & $InventoryAction $Credential
                $nextInventory = $tick + [int]$Config.interval_seconds
            }
            $Failures = 0
        } catch {
            $Failures++
            if ($_.Exception.GetType().Name -eq 'EitopCredentialError') {
                # missing/undecryptable/revoked-marked credential → stop cleanly
                Write-Error "credential_error: $($_.Exception.Message)"
                return
            }
            $delay = Get-EitopLoopDelay -Failures $Failures -BaseInterval ([int]$Config.heartbeat_interval_seconds)
            $status = 0
            if ($_.Exception.PSObject.Properties['StatusCode']) { $status = $_.Exception.StatusCode }
            # Log path/status/attempt only — never headers, bodies, or secrets.
            Write-Warning "submission_failed attempt=$Failures next_retry=${delay}s status=$status"
            & $Sleep $delay
            continue
        }

        # Idle in 1s slices so Stop-EitopRunner is honored promptly.
        $slept = 0
        while ($slept -lt 5 -and -not $script:StopRequested) {
            & $Sleep 1
            $slept++
        }
    }
    Write-Output 'stopped'
}

Export-ModuleMember -Function `
    Get-EitopInventoryPayload, Get-EitopEnrollPayload, Get-EitopSystemSection, `
    Get-EitopHardwareSection, Get-EitopNetworkSection, `
    Invoke-EitopEnrollFlow, Invoke-EitopHeartbeatFlow, Invoke-EitopInventoryFlow, `
    Invoke-EitopRotateFlow, Start-EitopLoop, Get-EitopLoopDelay, `
    Set-EitopRunnerStop, Get-EitopAgentVersion
