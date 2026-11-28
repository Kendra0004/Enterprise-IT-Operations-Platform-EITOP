# Configuration.psm1 — load + validate collector configuration (JSON).
#
# Parity with the Linux collector's config.py:
#   - no secrets ever live in the config file
#   - EITOP_CONFIG / EITOP_SERVER_URL environment overrides
#   - strict validation with clear errors
#
# Windows PowerShell 5.1+ and PowerShell 7 compatible.

Set-StrictMode -Version Latest

function Get-EitopDefaultConfigPaths {
    $paths = @()
    if ($env:ProgramData) { $paths += (Join-Path $env:ProgramData 'EITOP\collector.json') }
    $paths += (Join-Path $PSScriptRoot '..\config.json')
    $paths
}

class EitopConfigError : System.Exception {
    EitopConfigError([string]$Message) : base($Message) {}
}

function Read-EitopConfig {
    [CmdletBinding()]
    param(
        [string]$Path
    )

    $candidates = @()
    if ($Path) { $candidates += $Path }
    if ($env:EITOP_CONFIG) { $candidates += $env:EITOP_CONFIG }

    $chosen = $null
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $chosen = $candidate; break }
    }
    if (-not $chosen -and -not $Path -and -not $env:EITOP_CONFIG) {
        foreach ($candidate in (Get-EitopDefaultConfigPaths)) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $chosen = $candidate; break }
        }
    }
    if (-not $chosen) {
        throw [EitopConfigError]::new(
            'No config file found. Pass -Config, set EITOP_CONFIG, or create config.json (see config.example.json).')
    }

    try {
        $raw = Get-Content -LiteralPath $chosen -Raw -Encoding UTF8
        $data = $raw | ConvertFrom-Json
    } catch {
        throw [EitopConfigError]::new("Cannot read config ${chosen}: $($_.Exception.Message)")
    }

    if ($null -eq $data -or $null -eq $data.PSObject.Properties['server_url']) {
        throw [EitopConfigError]::new("${chosen}: server_url is required")
    }

    $serverUrl = if ($env:EITOP_SERVER_URL) { $env:EITOP_SERVER_URL } else { [string]$data.server_url }

    $interval = 300
    if ($data.PSObject.Properties['interval_seconds']) { $interval = [int]$data.interval_seconds }
    $heartbeat = 60
    if ($data.PSObject.Properties['heartbeat_interval_seconds']) { $heartbeat = [int]$data.heartbeat_interval_seconds }
    $timeout = 30.0
    if ($data.PSObject.Properties['timeout_seconds']) { $timeout = [double]$data.timeout_seconds }
    $retries = 5
    if ($data.PSObject.Properties['max_retries']) { $retries = [int]$data.max_retries }
    $credFile = if ($env:ProgramData) { Join-Path $env:ProgramData 'EITOP\credentials.json' } else { 'eitop_credentials.json' }
    if ($data.PSObject.Properties['credential_file']) { $credFile = [string]$data.credential_file }

    return New-EitopConfig `
        -ServerUrl $serverUrl `
        -IntervalSeconds $interval `
        -HeartbeatIntervalSeconds $heartbeat `
        -TimeoutSeconds $timeout `
        -MaxRetries $retries `
        -CredentialFile $credFile `
        -SourcePath ([string]$chosen)
}

function Get-EitopRedactedUrl {
    # Strip userinfo (user:password@) before a URL can reach an error
    # message or log line (parity with the Linux collector, L7).
    param([Parameter(Mandatory)][string]$Url)
    if ($Url -match '^(?<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?<userinfo>[^/?#]*)@') {
        return ($Url -replace [regex]::Escape($Matches['scheme'] + $Matches['userinfo'] + '@'),
            ($Matches['scheme'] + '***:***@'))
    }
    return $Url
}

function New-EitopConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServerUrl,
        [int]$IntervalSeconds = 300,
        [int]$HeartbeatIntervalSeconds = 60,
        [double]$TimeoutSeconds = 30.0,
        [int]$MaxRetries = 5,
        [Parameter(Mandatory)][string]$CredentialFile,
        [string]$SourcePath = ''
    )

    $url = $ServerUrl.TrimEnd('/')
    if ($url -notmatch '^https?://') {
        throw [EitopConfigError]::new("server_url must be http(s), got: $(Get-EitopRedactedUrl -Url $url)")
    }
    # Phase 6 audit W3 (parity with Linux L1): the collector sends the
    # endpoint credential as a bearer token — plaintext http to a remote
    # host is sniffable. Only loopback may stay http (dev/demo stacks).
    if ($url -match '^http://') {
        $uri = $null
        try { $uri = [Uri]$url } catch { $uri = $null }
        $hostName = if ($uri) { $uri.Host.Trim('[', ']') } else { '' }
        $isLoopback = $hostName -eq 'localhost' -or $hostName -eq '::1' -or $hostName -like '127.*'
        if (-not $isLoopback) {
            throw [EitopConfigError]::new(
                "server_url must use https for non-loopback hosts (plaintext http is only allowed for localhost): $(Get-EitopRedactedUrl -Url $url)")
        }
    }
    if ($IntervalSeconds -lt 10) { throw [EitopConfigError]::new('interval_seconds must be >= 10') }
    if ($HeartbeatIntervalSeconds -lt 10) { throw [EitopConfigError]::new('heartbeat_interval_seconds must be >= 10') }
    if ($TimeoutSeconds -le 0) { throw [EitopConfigError]::new('timeout_seconds must be > 0') }
    if ($MaxRetries -lt 1 -or $MaxRetries -gt 10) { throw [EitopConfigError]::new('max_retries must be between 1 and 10') }

    [pscustomobject]@{
        server_url                 = $url
        interval_seconds           = $IntervalSeconds
        heartbeat_interval_seconds = $HeartbeatIntervalSeconds
        timeout_seconds            = $TimeoutSeconds
        max_retries                = $MaxRetries
        credential_file            = $CredentialFile
        source_path                = $SourcePath
    }
}

Export-ModuleMember -Function Read-EitopConfig, New-EitopConfig, Get-EitopDefaultConfigPaths, Get-EitopRedactedUrl
