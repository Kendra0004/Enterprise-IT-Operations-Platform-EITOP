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
    # Windows PowerShell 5.1 may default to TLS 1.0 (dead on modern servers).
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }  # PS7 / non-Windows: platform default already fine
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
            $lastError = "network error: $($result.error)"
            Write-Warning "request_network_error path=$Path attempt=$attempt"
            continue
        }

        $status = [int]$result.status
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
        }
        if ($null -ne $Body) {
            $params['Body'] = $Body
            $params['ContentType'] = 'application/json'
        }
        $response = Invoke-RestMethod @params
        # Invoke-RestMethod already deserializes JSON on both 5.1 and 7.
        [pscustomobject]@{ kind = 'response'; status = 200; data = $response }
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
    ("HTTP $($Result.status): $title $detail").Trim()
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
