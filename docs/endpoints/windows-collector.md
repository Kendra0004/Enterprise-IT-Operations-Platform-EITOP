# Windows Collector (Phase 2.4)

Location: `collectors/windows/` — PowerShell 5.1+ / 7, zero paid
dependencies, no external runtime modules. Reuses the Phase 2 enrollment and
endpoint-credential lifecycle unchanged (`docs/endpoints/api.md`).

## Supported versions

| Platform | Support |
|---|---|
| Windows 10 (21H2+) | target |
| Windows 11 | target |
| Windows Server 2019 / 2022 / 2025 | target |
| Windows PowerShell 5.1 | primary runtime (built-in) |
| PowerShell 7.2+ | supported where practical (tested under pwsh 7.4) |
| Windows Server 2016 / Windows 8.1 | untested, expected to work (same CIM classes) |

## Installation

1. Copy `collectors/windows/` to the host (e.g.
   `C:\Program Files\EITOP\collector\`).
2. `Copy-Item config.example.json C:\ProgramData\EITOP\collector.json`
3. Edit `server_url` — `https://` is **enforced** for non-loopback hosts
   (plaintext `http://` accepted only for `localhost`/`127.x`/`::1`).
4. Create a dedicated service account and restrict
   `C:\ProgramData\EITOP\` to it (`icacls ... /inheritance:r /grant:r
   "<SID>:(OI)(CI)F"`).
5. ExecutionPolicy: prefer `-ExecutionPolicy RemoteSigned` on the
   scheduled-task argument (local scripts run; downloads must be signed),
   or sign the scripts with your org's code-signing cert
   (`Set-AuthenticodeSignature`). Avoid `Bypass` unless the script is
   unsigned and network-sourced.

No admin rights needed for routine collection (see Permissions).

## Configuration

`config.example.json` keys (parity with the Linux collector's TOML):

| Key | Default | Meaning |
|---|---|---|
| `server_url` | — (required) | EITOP base URL; `https://` required except loopback (`http://` allowed only for localhost/127.x/::1) |
| `interval_seconds` | 300 | full inventory period (min 10) |
| `heartbeat_interval_seconds` | 60 | heartbeat period (min 10) |
| `timeout_seconds` | 30 | per-request timeout |
| `max_retries` | 5 | HTTP retries 1–10 (backoff 1s·2ⁿ cap 60s); enrollment is never retried (single-use token) |
| `credential_file` | `%ProgramData%\EITOP\credentials.json` | DPAPI-protected credential |

Env overrides: `EITOP_CONFIG` (config path), `EITOP_SERVER_URL` (URL).
The config file contains **no secrets** — validated by test.

## Enrollment

Same one-time-token flow as Linux (`docs/endpoints/enrollment.md`):

```powershell
# token sources, in precedence order: -TokenStdin → EITOP_ENROLL_TOKEN →
# interactive hidden prompt. NEVER a command-line parameter (argv is `ps`-visible).
.\eitop-collector.ps1 -Config C:\ProgramData\EITOP\collector.json enroll
'<token>' | .\eitop-collector.ps1 -Config ... enroll -TokenStdin
$env:EITOP_ENROLL_TOKEN='<token>'; .\eitop-collector.ps1 -Config ... enroll
```

- Token exchanged over `POST /api/v1/agent/enroll`; single-use, rate-limited
  server-side; failures return uniform 401 (no oracle).
- Issued credential is written straight to the protected credential file —
  it is never printed by the collector (only the API's one-time issuance
  response carries it, to whoever/whatever performs enrollment).

## Credential storage

Two layers, both local-machine protections (transport security comes from
HTTPS termination in production):

1. **DPAPI (CurrentUser scope)** — `ConvertFrom-SecureString` /
   `ConvertTo-SecureString`. On Windows this is the platform DPAPI: the
   ciphertext is bound to the **Windows identity** that created it. Another
   account (or an offline reader of the file) cannot decrypt it.
   **Windows-only by design**: on non-Windows hosts the protector throws
   (`DPAPI is Windows-only`) instead of silently storing reversible
   obfuscation that any same-host process could decode.
2. **ACL** — the credential file **and its parent directory** are locked to
   the service account's SID only (`icacls /inheritance:r /grant:r SID:F`,
   applied on every save, not only when the directory was newly created),
   and loading **refuses** either when the file's or the directory's ACL
   exposes other principals. ACL verification reads the structured ACL
   (`Get-Acl`) — every rule (allow/deny, named or numeric SID) must resolve
   to the current SID, and an unresolvable principal fails closed.

Consequences (by design):

- **Service account continuity**: the collector must run as the same Windows
  identity that enrolled. Account change ⇒ re-enroll (old file undecryptable
  → clear error, no silent credential loss).
- **Rotation**: `rotate` overwrites the file atomically (temp + rename),
  re-protected under the same identity; the old credential stops working on
  the server immediately.
- **Revocation**: a revoked credential yields HTTP 401 → the loop logs the
  problem status (never the secret) and stops.
- Never hardcoded, never printed, never in arguments, never logged —
  enforced by hygiene tests over code (comments excluded).

Documented test-platform caveat: unit tests run on Linux pwsh, where
`Protect/Unprotect-EitopSecret` correctly **refuse** to run (W2). The
Save/Read logic (atomicity, refusal paths, payload shape) is therefore
exercised against a mocked protector, and the platform guard itself is
tested unmocked — **Windows DPAPI itself is only verifiable on Windows**
(see Manual validation §6).

## Execution

| Command | Effect |
|---|---|
| `collect` | one inventory payload as JSON (no upload); `-IncludeDetails` adds `software_details` (publisher/install date/scope — local-only, see Limitations) |
| `enroll` | one-time-token enrollment → credential file |
| `status` | endpoint id, file path, server URL — **never** the credential |
| `run` | daemon: heartbeat + inventory loop, exponential failure backoff (cap 1h), graceful Ctrl+C stop |
| `rotate` | self-service credential rotation |

### Inventory fields (mapping to the backend contract)

| Backend field | Windows source |
|---|---|
| `system.hostname` | NetBIOS computer name (`$env:COMPUTERNAME`) |
| `system.fqdn` | `Win32_ComputerSystem.DNSHostName` / DNS lookup fallback / null |
| `system.os` | `"windows"` |
| `system.distribution` | `Caption` minus "Microsoft " (e.g. `Windows 11 Pro`) |
| `system.distribution_version` | `DisplayVersion` (e.g. `24H2`), `ReleaseId` fallback |
| `system.os_version` | full `Caption` (PRETTY_NAME equivalent) |
| `system.kernel` | `Version` (e.g. `10.0.26100`; contains the build) |
| `system.os_arch` | `OSArchitecture` |
| `system.uptime_seconds` | now − `LastBootUpTime` (clamped ≥0) |
| `hardware.cpu_model` | `Win32_Processor.Name` |
| `hardware.cpu_cores` | **sum of logical processors** (Linux parity); physical cores in facts `hardware.cpu_physical_cores` |
| `hardware.memory_bytes` | `Win32_ComputerSystem.TotalPhysicalMemory` |
| `hardware.manufacturer` / `model` | `Win32_ComputerSystem` |
| `hardware.serial_number` | `Win32_BIOS.SerialNumber` (placeholders → null) |
| `hardware.disk_bytes` | sum `Win32_DiskDrive.Size` (physical) |
| `filesystems[]` | fixed volumes (`DriveType=3`): `DeviceID` mount, `FileSystem`, size/free |
| `network.interfaces[]` | `IPEnabled` adapters: friendly name, MAC, IPv4/IPv6, `NetConnectionStatus==2` |
| interface descriptions | fact `network.interface_descriptions` (JSON map; contract has no description field) |
| `packages[]` | registry uninstall entries: name/version + `package_manager` = `registry-hklm64`/`registry-hklm32`/`registry-hkcu` (encodes scope) |
| `facts` | `collector.version`, `collector.runtime`, `software.count`, hardware/network extras |

Collected **but not sent** (contract has no fields for them): interface
description (sent via facts — OK), publisher, install date per package
(local `collect -IncludeDetails` only → Limitations).

Sensitive data explicitly **not** collected: Wi-Fi profiles/passwords,
stored credentials, credential managers, ARP/DNS caches, unrelated network
state (enforced by test on serialized output).

## API communication

Identical contract to the Linux agent: enroll / heartbeat / inventory /
rotate-credential, JSON via `ConvertTo-Json -Depth 8`, bearer credential
header only, RFC 9457 problem parsing, timeouts, exponential backoff with
capped retries (429/5xx/network retried; other 4xx fail fast; enrollment
never retried), TLS 1.2 pinned exactly for PS 5.1, and **redirects refused**
(`3xx` → error, the default invoker passes `-MaximumRedirection 0`) so a
response can never steer the bearer credential to another origin. Error and
warning text carries path/status/attempt plus a control-character-stripped,
length-capped cause — remote text cannot forge log lines. Server responses
are never interpreted as commands (static test: no
`Invoke-Expression`/`iex`/`Add-Type -TypeDefinition` in any code path).

## Permissions

- **Routine collection: standard user.** CIM reads
  (`Win32_OperatingSystem`, `Win32_Processor`, `Win32_ComputerSystem`,
  `Win32_LogicalDisk`, `Win32_NetworkAdapter*`) work without elevation;
  registry uninstall hives are user-readable. `Win32_BIOS.SerialNumber` and
  `Win32_DiskDrive` may return empty/restricted values for non-admins —
  degrades to null/0, never errors.
- **Enrollment/rotation: same standard identity** (only needs HTTPS egress).
- **Config/credential directories**: writable by service account only.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `config error: No config file found` | pass `-Config`, set `EITOP_CONFIG`, or create `%ProgramData%\EITOP\collector.json` |
| `credential file ... cannot be decrypted under the current identity` | collector runs as a different account than at enrollment → re-enroll as the service account |
| `credential file ... accessible to other principals` | ACL widened (restore: `icacls <file> /inheritance:r /grant:r "<SID>:F"`) |
| `Directory ... accessible to other principals` | parent directory ACL widened (restore: `icacls <dir> /inheritance:r /grant:r "<SID>:(OI)(CI)F"`) |
| `server_url must use https for non-loopback hosts` | plaintext remote URL rejected — use `https://` (http only allowed for localhost) |
| `DPAPI is Windows-only` | protector invoked off-Windows (expected in Linux test hosts; production runs on Windows) |
| `HTTP 401: Not authenticated` in loop, then stop | credential revoked/rotated server-side → re-enroll or restore correct credential file |
| `HTTP 401: Invalid enrollment token` | token already used / expired / hostname restriction mismatch → mint a new token |
| `HTTP 429` during enroll | server rate limit (per-IP/min) → wait a minute |
| `Giving up after N attempts` | server unreachable → check `server_url`, TLS, firewall; collector retries with backoff up to 1 h |
| empty `packages` | neither uninstall hive readable or enumerated 0 apps — verify `reg query HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` |
| `execution blocked by policy` | ExecutionPolicy → prefer `-ExecutionPolicy RemoteSigned` (or code signing); `Bypass` disables protection entirely |

## Testing

Pester (5.5+ / 6.x): `Invoke-Pester -Path ./tests -CI` — 133 tests over
parsing fixtures, registry-dedup cases, API retry behavior, redirect/TLS
policy, credential refusal paths (file + directory ACL, platform guard),
JSON contract shape, and static hygiene rules (no `Win32_Product`,
no `Invoke-Expression`, no secret printing, no token-as-parameter).
No Windows machine required (verified with `pwsh 7.4.11` on Linux,
Pester 6.2: 131 passed, 2 skipped — the skips are Windows-only
assertions: SID object handling and the real DPAPI roundtrip).

Static analysis: `Invoke-ScriptAnalyzer -Path . -Recurse -Settings
./PSScriptAnalyzerSettings.pse1 -Severity Warning,Error` → **clean**.
The settings file excludes only rules whose behavior is required by design
(string bearer credential, DI seams, intentional silent degradation), with
a written justification per rule; everything else stays enabled. All
sources are UTF-8 **with BOM** so Windows PowerShell 5.1 parses non-ASCII
correctly.

## Actual Windows validation status

**NOT VERIFIED ON WINDOWS.** Development host is Linux (CachyOS). What was
actually executed:

| Verified | How |
|---|---|
| All 133 unit tests | `pwsh 7.4.11` on Linux, Pester 6.2 (131 passed, 2 Windows-only skipped) |
| JSON payload shape vs backend Pydantic contract | tests + live Linux-agent E2E of the same contract |
| Retry/backoff, problem parsing, flows, loops | mocked-invoker tests |
| DPAPI platform guard (refuses off-Windows) | unmocked test on Linux |
| Protector round-trip (Save/Read logic) | mocked protector seam (`TESTENC:` prefix) |

**Unverified Windows-specific behavior (manual procedure below):**

1. `Get-CimInstance` responses on real Win10/11/Server (property names used
   are documented standard classes, but live values unconfirmed).
2. Windows DPAPI protect/decrypt under Windows PowerShell 5.1 and PS 7.
3. `icacls` ACL set/verify paths (`Set/ Test-EitopCredentialAcl` — skipped
   off-Windows).
4. Registry enumeration with real uninstall hives incl. 32-bit WOW6432Node.
5. Scheduled Task execution under a service account + profile-less context.
6. TLS negotiation to a real HTTPS endpoint under PS 5.1
   (`Enable-EitopTls12`).
7. Ctrl+C graceful stop behavior on Windows console host.

### Manual validation procedure (Windows 10/11 lab)

Prereqs: EITOP backend reachable over HTTPS from the VM; admin creates an
enrollment token.

1. **Install**: copy `collectors/windows` → `C:\Program Files\EITOP\collector`;
   create `C:\ProgramData\EITOP\collector.json` from example
   (`server_url` → backend).
2. **Identity**: create/use a dedicated standard account `eitop-svc`;
   restrict `C:\ProgramData\EITOP` to its SID only.
3. **Enroll** (as `eitop-svc`, interactive):
   `powershell -ExecutionPolicy RemoteSigned -File .\eitop-collector.ps1 -Config ... enroll`
   → expect `enrolled endpoint_id=<uuid>`; verify
   `icacls credentials.json` lists only `eitop-svc`; open the file → no
   plaintext secret (DPAPI blob only).
4. **Status**: `... status` → endpoint id + paths, no credential.
5. **Collect**: `... collect` → JSON with `system` (edition/build/uptime),
   `hardware` (CPU/RAM/serial), `network` (interfaces/MACs/IPs),
   `filesystems` (C:), `packages` (registry apps, non-empty on a used
   machine); `... collect -IncludeDetails` → publishers/install dates.
6. **DPAPI identity binding**: log in as a *different* account, run
   `... status` → expect *cannot be decrypted under the current identity*
   error; return to `eitop-svc` → works.
7. **Run loop**: `... run` → server logs show heartbeat + inventory;
   admin endpoint detail shows `last_heartbeat_at` advancing, facts/packages
   populated. Ctrl+C → clean `stopped`.
8. **Rotate**: `... rotate` → then heartbeat uses new credential (old dead):
   admin `POST /endpoints/{id}/rotate-credential` alternative; verify old
   credential 401s via manual curl.
9. **Revoke**: admin revokes endpoint → within one loop interval the
   collector logs `HTTP 401` problem and exits with *credential error*
   (no retry storm).
10. **Token reuse**: attempt enroll with the same token again → uniform 401.
11. **Task Scheduler**: register the run action as service account at
    startup; reboot; verify heartbeats resume.
12. **Hygiene**: `Get-WinEvent`/logs + collector console → no credential or
    token values anywhere.

## Known limitations

- No live-Windows verification yet (procedure above).
- Publisher / install date / scope are collected but **not transmitted**:
  the shared `PackageReport` contract has only name/version/package_manager
  (scope is encoded in `package_manager`; publisher/date would need a
  backward-compatible schema extension — deferred, no migration done).
- Interface descriptions ride in `facts.network.interface_descriptions`
  (8 KB fact-value cap); beyond ~30 interfaces the fact is dropped rather
  than truncated.
- `distribution_version` depends on `DisplayVersion`/`ReleaseId` presence;
  Windows Server builds may report null (documented behavior, not an error).
- No MSIX/Appx or Store app inventory (registry uninstall only — matches
  spec's registry requirement).
- Single credential file per machine; no multi-endpoint-on-one-host.
- PS 5.1-specific code paths (TLS pinning, `Invoke-RestMethod` error
  parsing) are written defensively but untested on real 5.1.
