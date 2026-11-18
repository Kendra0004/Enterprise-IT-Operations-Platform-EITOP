# EITOP Windows Collector

PowerShell agent for EITOP endpoint inventory: enrolls with a one-time
token, then submits heartbeats and inventory (system, hardware, network,
volumes, installed software) to the EITOP backend — same API contract as the
Linux collector (`docs/endpoints/api.md`).

**Supported:** Windows 10, Windows 11, Windows Server 2019+.
**PowerShell:** Windows PowerShell 5.1 (built-in) and PowerShell 7 where
practical. No paid dependencies; no external modules required to run
(Pester only for tests).

> Development note: this collector was developed and unit-tested on a
> non-Windows host (all tests mocked/fixtures). Live-Windows validation is
> manual — see `docs/endpoints/windows-collector.md` § Manual validation.

## Layout

```
eitop-collector.ps1        entry point (collect|enroll|status|run|rotate)
config.example.json        configuration template (no secrets)
modules/
  Configuration.psm1       config load + validation (JSON)
  Credentials.psm1         DPAPI + ACL protected credential storage
  ApiClient.psm1           agent API client (timeout, backoff, problems)
  SystemInventory.psm1     OS edition/version/build/arch/uptime
  HardwareInventory.psm1   CPU/memory/chassis/disks/volumes
  NetworkInventory.psm1    interfaces, MAC, IPv4/IPv6, status
  SoftwareInventory.psm1   registry uninstall enumeration (no Win32_Product)
  Runner.psm1              payload assembly, flows, daemon loop
tests/                     Pester tests (fixtures + mocks, no Windows needed)
fixtures/                  CIM/registry fixture data
```

## Install

```powershell
# 1. Copy the collector (e.g. under C:\Program Files\EITOP\collector)
# 2. Configuration:
Copy-Item config.example.json C:\ProgramData\EITOP\collector.json
notepad C:\ProgramData\EITOP\collector.json   # set server_url (HTTPS in prod)

# 3. Restrict the config directory to the service account:
icacls C:\ProgramData\EITOP /inheritance:r /grant:r "<SID>:(OI)(CI)F"
```

Run under a dedicated service account (gMSA or local service account) —
DPAPI-bound credentials only decrypt under the account that wrote them.
See `docs/endpoints/windows-collector.md` § Permissions.

## Enroll

Admin mints a one-time token (`POST /api/v1/endpoints/enrollment-tokens`),
then on the endpoint host:

```powershell
# interactive hidden prompt (recommended)
.\eitop-collector.ps1 -Config C:\ProgramData\EITOP\collector.json enroll

# scripted: token via environment (NEVER a parameter — argv is visible)
$env:EITOP_ENROLL_TOKEN = '<raw token>'
.\eitop-collector.ps1 -Config C:\ProgramData\EITOP\collector.json enroll

# scripted: token via stdin
'<raw token>' | .\eitop-collector.ps1 -Config ... enroll -TokenStdin
```

The token works exactly once. The issued credential is stored encrypted
(DPAPI CurrentUser) at `credential_file` with an ACL limited to the current
SID. The raw credential is never printed again — only at issuance by the API.

## Run

```powershell
.\eitop-collector.ps1 -Config ... run        # heartbeat + inventory loop
.\eitop-collector.ps1 -Config ... collect    # print payload JSON (no upload)
.\eitop-collector.ps1 -Config ... collect -IncludeDetails   # + software_details
.\eitop-collector.ps1 -Config ... status     # endpoint id, never the secret
.\eitop-collector.ps1 -Config ... rotate     # rotate credential (new stored, old dead)
```

Scheduled task / service example (Task Scheduler, run as service account):

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\EITOP\collector\eitop-collector.ps1" -Config C:\ProgramData\EITOP\collector.json run'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId '<service-account>' -LogonType Password -RunLevel Limited
Register-ScheduledTask -TaskName 'EITOP Collector' -Action $action -Trigger $trigger -Principal $principal
```

`-RunLevel Limited`: inventory collection does **not** require permanent
administrator rights (DMI/serial-equivalents read via standard CIM;
registry uninstall keys are user-readable machine hives).

## Behavior

- Heartbeat every `heartbeat_interval_seconds` (default 60, min 10).
- Full inventory every `interval_seconds` (default 300, min 10).
- Request timeout `timeout_seconds`; retries with exponential backoff
  (1s→2s→… capped 60s) on network errors, timeouts, 429/5xx; other 4xx fail
  immediately. Sustained failure backs off up to 1 hour.
- Revoked/rotated-away credential → 401 → collector stops with a clear error
  (no infinite hammering of the server).
- The collector executes **nothing** received from the server: responses are
  parsed as data only (no Invoke-Expression anywhere — enforced by tests).
- Ctrl+C stops the loop gracefully between sleep slices.

## Tests

```powershell
# Pester 5.5+ (Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser)
Invoke-Pester -Path ./tests -CI

# Static analysis (by-design exclusions documented in the settings file)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.pse1 -Severity Warning,Error
```

Tests use fixtures/mocks only: no Windows machine, no network, no real
registry or CIM required. Cross-platform (verified with pwsh 7.4 on Linux).
All `.ps1`/`.psm1` sources are UTF-8 with BOM for Windows PowerShell 5.1
compatibility.
