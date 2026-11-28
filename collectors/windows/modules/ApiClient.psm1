# ApiClient.psm1 — HTTP client for the EITOP agent API.
#
# Contract: docs/endpoints/api.md  (same routes/payloads as the Linux agent)
#
# - agent credential only in the Authorization header, never in the URL,
#   never in a log line, never in an error message
# - retries: network errors, timeouts, 429/5xx with capped exponential
#   backoff (1s * 2^n, cap 60s); other 4xx fail immediately
# - failures surfaced as EitopApiError carrying status + problem title/detail
# - server responses are DATA ONLY: nothing here ever interprets response
#   content as a command
#
# Windows PowerShell 5.1 compatible (TLS 1.2 pinned for .NET Framework).

Set-StrictMode -Version Latest

class EitopApiError : System.Exception {
    [int]$StatusCode
    EitopApiError([string]$Message, [int]$StatusCode) : base($Message) {
        $this.StatusCode = $StatusCode
    }
}

$script:BackoffBase = 1.0
$script:BackoffCap = 60.0
$script:RetryableStatus = @(429, 500, 502, 503, 504)

function Enable-EitopTls12 {
    # Windows PowerShell 5.1 may default to TLS 1.0 (dead on modern
    # servers). Phase 6 audit W6: pin the protocol to TLS 1.2 EXACTLY —
    # the previous "-bor Tls12" kept whatever legacy flags were already
    # set (SSL3/TLS1.0/TLS1.1), leaving a downgrade path open. .NET
    # Framework on PS 5.1 has no TLS 1.3 enum, so 1.2 is the ceiling
    # there; PowerShell 7 / .NET Core ignores ServicePointManager and
    # uses the OS defaults (TLS 1.2+).
    if ($PSVersionTable.PSEdition -ne 'Desktop') { return }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch { }
}

function Get-EitopBackoffDelay {
    param([Parameter(Mandatory)][int]$Attempt)  # 0-based retry index
    $delay = $script:BackoffBase * [math]::Pow(2, $Attempt)
    [math]::Min($delay, $script:BackoffCap)
}

function Invoke-EitopApiRequest {
    <#
        .DESCRIPTION
        Core request with retry. $Credential is attached as a bearer header
        only; it is never echoed into exceptions or logs (error messages carry
        method, path and HTTP problem text exclusively).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Body,
        [string]$Credential,
        [int]$MaxRetries = -1,
        [scriptblock]$Invoker,        # test seam: param($Method,$Uri,$Headers,$Body,$TimeoutSec)
        [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }
    )

    if ($MaxRetries -lt 0) { $MaxRetries = [int]$Config.max_retries }
    $uri = "$($Config.server_url)$Path"
    $headers = @{ 'User-Agent' = 'eitop-collector/0.1 (windows)' }
    if ($Credential) { $headers['Authorization'] = "Bearer $Credential" }

    $jsonBody = $null
    if ($null -ne $Body) {
        $jsonBody = $Body | ConvertTo-Json -Depth 8 -Compress
    }

    if (-not $Invoker) { $Invoker = ${function:Get-EitopDefaultInvoker} }
    Enable-EitopTls12

    $lastError = 'request failed'
    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        if ($attempt -gt 0) {
            $delay = Get-EitopBackoffDelay -Attempt ($attempt - 1)
            Write-Verbose "retry_backoff path=$Path attempt=$attempt delay=${delay}s"
            & $Sleep $delay
        }

        $result = & $Invoker $Method $uri $headers $jsonBody ([double]$Config.timeout_seconds)

        if ($result.kind -eq 'error') {
            # transport failure (timeout / DNS / refused)
            # Phase 6 audit W8: the warning previously carried a fixed
            # message with no cause — include the transport error (which
            # never contains credentials) with control characters stripped
            # so network text cannot forge log lines. The same sanitized
            # cause goes into the final exception message.
            $safeErr = "$($result.error)" -replace '[\r\n\t\x00-\x1f\x7f]+', ' '
            if ($safeErr.Length -gt 200) { $safeErr = $safeErr.Substring(0, 200) }
            $lastError = "network error: $safeErr"
            Write-Warning "request_network_error path=$Path attempt=$attempt error=$safeErr"
            continue
        }

        $status = [int]$result.status
        # Phase 6 audit W5/L3: 3xx is an error, never a detour we obey —
        # the collector talks to exactly one configured origin.
        if ($status -ge 300 -and $status -lt 400) {
            throw [EitopApiError]::new(
                "HTTP ${status}: unexpected redirect refused (collector never follows redirects)", $status)
        }
        if ($status -lt 400) { return $result }

        if ($status -in $script:RetryableStatus -and $attempt -lt $MaxRetries) {
            $lastError = "HTTP $status"
            continue
        }
        $message = Get-EitopProblemMessage -Result $result
        throw [EitopApiError]::new($message, $status)
    }

    throw [EitopApiError]::new("Giving up after $($MaxRetries + 1) attempts: $lastError", 0)
}

function Get-EitopDefaultInvoker {
    param($Method, $Uri, $Headers, $Body, $TimeoutSec)
    try {
        $params = @{
            Method      = $Method
            Uri         = $Uri
            Headers     = $Headers
            TimeoutSec  = [int]$TimeoutSec
            ErrorAction = 'Stop'
            # Phase 6 audit W5: never follow redirects — a 3xx must come
            # back to Invoke-EitopApiRequest so it can be refused there,
            # instead of silently replaying the request (with our bearer
            # header) against whatever Location points at.
            MaximumRedirection = 0
            # PS 5.1: skip the IE-based HTML parser (PS 7 ignores this).
            UseBasicParsing    = $true
        }
        if ($null -ne $Body) {
            $params['Body'] = $Body
            $params['ContentType'] = 'application/json'
        }
        $response = Invoke-WebRequest @params
        # Report the REAL status code: the previous implementation
        # hardcoded 200, which could mask a 3xx/2xx difference.
        $status = [int]$response.StatusCode
        $content = [string]$response.Content
        $data = $null
        if ($content) {
            try { $data = $content | ConvertFrom-Json } catch { $data = $null }
        }
        [pscustomobject]@{ kind = 'response'; status = $status; data = $data; raw = $content }
    } catch {
        $statusCode = 0
        $parsed = $null
        $ex = $_.Exception
        if ($ex.PSObject.Properties['Response'] -and $ex.Response) {
            try { $statusCode = [int]$ex.Response.StatusCode } catch { $statusCode = 0 }
        }
        if (-not $statusCode -and $_.ErrorDetails -and $_.ErrorDetails.Message) {
            # PS7: status accessible via exception response too; try problem JSON
            try {
                $parsed = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($parsed.PSObject.Properties['status']) { $statusCode = [int]$parsed.status }
            } catch { }
        }
        if ($statusCode) {
            if (-not $parsed -and $_.ErrorDetails -and $_.ErrorDetails.Message) {
                try { $parsed = $_.ErrorDetails.Message | ConvertFrom-Json } catch { $parsed = $null }
            }
            [pscustomobject]@{ kind = 'response'; status = $statusCode; data = $parsed; raw = "$($_.ErrorDetails.Message)" }
        } else {
            # timeout / connection failure — never contains credentials
            [pscustomobject]@{ kind = 'error'; error = $ex.Message }
        }
    }
}

function Get-EitopJsonField {
    # Property read that works for both ConvertFrom-Json objects (PSCustomObject)
    # and hashtables (test seams), safe under Set-StrictMode.
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    $null
}

function Get-EitopProblemMessage {
    param([Parameter(Mandatory)][pscustomobject]$Result)
    $title = [string](Get-EitopJsonField -Object $Result.data -Name 'title')
    $detail = [string](Get-EitopJsonField -Object $Result.data -Name 'detail')
    if (-not $title -and $Result.PSObject.Properties['raw']) {
        try {
            $parsed = $Result.raw | ConvertFrom-Json
            $title = [string](Get-EitopJsonField -Object $parsed -Name 'title')
            $detail = [string](Get-EitopJsonField -Object $parsed -Name 'detail')
        } catch { }
    }
    # Server-supplied text lands in warnings and stderr: strip control
    # characters so a hostile/compromised response cannot forge log lines
    # (parity with Linux L7).
    $message = ("HTTP $($Result.status): $title $detail").Trim()
    ($message -replace '[\r\n\t\x00-\x1f\x7f]+', ' ').Trim()
}

# --- Agent endpoints (contract parity with collectors/linux api.py) ---------

function Invoke-EitopEnroll {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$SystemInfo,
        [scriptblock]$Invoker,
        [scriptblock]$Sleep
    )
    $body = @{ token = $Token }
    foreach ($key in $SystemInfo.Keys) { $body[$key] = $SystemInfo[$key] }
    $result = Invoke-EitopApiRequest -Config $Config -Method POST -Path '/api/v1/agent/enroll' `
        -Body $body -MaxRetries 0 -Invoker $Invoker -Sleep $Sleep   # a bad token is never retried
    if (-not (Get-EitopJsonField -Object $result.data -Name 'credential') -or
        -not (Get-EitopJsonField -Object $result.data -Name 'endpoint_id')) {
        throw [EitopApiError]::new('Enrollment response missing credential', [int]$result.status)
    }
    $result.data
}

function Invoke-EitopHeartbeat {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Credential,
        [Parameter(Mandatory)][string]$AgentVersion,
        [scriptblock]$Invoker,
        [scriptblock]$Sleep
    )
    $result = Invoke-EitopApiRequest -Config $Config -Method POST -Path '/api/v1/agent/heartbeat' `
        -Body @{ agent_version = $AgentVersion } -Credential $Credential -Invoker $Invoker -Sleep $Sleep
    $result.data
}

function Invoke-EitopInventory {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Credential,
        [Parameter(Mandatory)][hashtable]$Inventory,
        [scriptblock]$Invoker,
        [scriptblock]$Sleep
    )
    $result = Invoke-EitopApiRequest -Config $Config -Method POST -Path '/api/v1/agent/inventory' `
        -Body $Inventory -Credential $Credential -Invoker $Invoker -Sleep $Sleep
    $result.data
}

function Invoke-EitopRotateCredential {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][string]$Credential,
        [scriptblock]$Invoker,
        [scriptblock]$Sleep
    )
    $result = Invoke-EitopApiRequest -Config $Config -Method POST -Path '/api/v1/agent/rotate-credential' `
        -Credential $Credential -MaxRetries 1 -Invoker $Invoker -Sleep $Sleep
    $result.data
}

Export-ModuleMember -Function `
    Invoke-EitopApiRequest, Invoke-EitopEnroll, Invoke-EitopHeartbeat, `
    Invoke-EitopInventory, Invoke-EitopRotateCredential, Get-EitopBackoffDelay, `
    Get-EitopProblemMessage, Get-EitopJsonField, Enable-EitopTls12
