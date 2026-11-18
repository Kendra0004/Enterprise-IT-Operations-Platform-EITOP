<#
.SYNOPSIS
    EITOP Windows endpoint collector.

.DESCRIPTION
    Commands: collect | enroll | status | run | rotate

    The enrollment token is NEVER accepted as a command-line argument
    (argv is visible in process listings): use EITOP_ENROLL_TOKEN,
    -TokenStdin, or the interactive hidden prompt.
    Credentials are never printed, never passed as arguments, never logged.

.EXAMPLE
    .\eitop-collector.ps1 -Config .\config.json collect
    .\eitop-collector.ps1 -Config .\config.json enroll -TokenStdin
    .\eitop-collector.ps1 -Config .\config.json run
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('collect', 'enroll', 'status', 'run', 'rotate')]
    [string]$Command,

    [string]$Config,

    [switch]$TokenStdin,

    [switch]$IncludeDetails   # collect only: add software_details (local info)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleDir = Join-Path $PSScriptRoot 'modules'
foreach ($module in @(
        'Configuration', 'Credentials', 'ApiClient',
        'SystemInventory', 'HardwareInventory', 'NetworkInventory',
        'SoftwareInventory', 'Runner'
    )) {
    Import-Module (Join-Path $moduleDir "$module.psm1") -Force -DisableNameChecking
}

function Get-EitopEnrollmentToken {
    # Precedence: stdin → env → interactive hidden prompt. Never argv.
    if ($TokenStdin) {
        $token = [Console]::In.ReadLine()
        if ($token) { return $token.Trim() }
    }
    if ($env:EITOP_ENROLL_TOKEN) { return $env:EITOP_ENROLL_TOKEN }
    if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
        $secure = Read-Host -Prompt 'Enrollment token (hidden)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    throw 'No enrollment token. Set EITOP_ENROLL_TOKEN, pipe it with -TokenStdin, or run interactively.'
}

# --- Load configuration -------------------------------------------------------
try {
    $cfg = Read-EitopConfig -Path $Config
} catch {
    Write-Error "config error: $($_.Exception.Message)"
    exit 2
}

switch ($Command) {

    'collect' {
        $payload = Get-EitopInventoryPayload
        $output = [ordered]@{ payload = $payload }
        if ($IncludeDetails) {
            $software = Get-SoftwareInventory
            $output['software_details'] = @($software.details)
        }
        $output | ConvertTo-Json -Depth 8
        exit 0
    }

    'status' {
        try {
            $stored = Read-EitopCredential -Path $cfg.credential_file
        } catch {
            Write-Error "not enrolled: $($_.Exception.Message)"
            exit 1
        }
        Write-Output "endpoint_id: $($stored.endpoint_id)"
        Write-Output "credential_file: $($cfg.credential_file) (DPAPI + ACL)"
        Write-Output "server_url: $($cfg.server_url)"
        # NOTE: the credential value itself is never printed here.
        exit 0
    }

    'enroll' {
        try {
            $token = Get-EitopEnrollmentToken
            if (-not $token) { throw 'No enrollment token.' }
            $result = Invoke-EitopEnrollFlow -Config $cfg -Token $token
            Write-Output "enrolled endpoint_id=$($result.endpoint_id)"
            exit 0
        } catch {
            # Errors carry HTTP problem text only — the token never appears.
            Write-Error "enrollment failed: $($_.Exception.Message)"
            exit 1
        }
    }

    'rotate' {
        try {
            $stored = Read-EitopCredential -Path $cfg.credential_file
        } catch {
            Write-Error "credential error: $($_.Exception.Message)"
            exit 1
        }
        try {
            $result = Invoke-EitopRotateFlow -Config $cfg -Credential $stored.credential
            Write-Output "credential rotated endpoint_id=$($result.endpoint_id)"
            exit 0
        } catch {
            Write-Error "rotation failed: $($_.Exception.Message)"
            exit 1
        }
    }

    'run' {
        try {
            $stored = Read-EitopCredential -Path $cfg.credential_file
        } catch {
            Write-Error "credential error: $($_.Exception.Message)"
            exit 1
        }

        # Graceful stop on Ctrl+C: signal the loop instead of killing mid-write.
        try {
            [Console]::CancelKeyPress += {
                # Positional args from the .NET event; names must not shadow
                # PowerShell automatic variables ($Sender/$EventArgs).
                param($eventOrigin, $eventCancel)
                $eventCancel.Cancel = $true
                Set-EitopRunnerStop
            }
        } catch { }  # non-interactive host: default termination applies

        $credential = $stored.credential
        try {
            Start-EitopLoop -Config $cfg -Credential $credential `
                -HeartbeatAction { param($cred) Invoke-EitopHeartbeat -Config $cfg -Credential $cred -AgentVersion (Get-EitopAgentVersion) } `
                -InventoryAction { param($cred) Invoke-EitopInventoryFlow -Config $cfg -Credential $cred }
            exit 0
        } catch {
            # Problem+json text only — credential never included.
            Write-Error "server error: $($_.Exception.Message)"
            exit 1
        }
    }
}
