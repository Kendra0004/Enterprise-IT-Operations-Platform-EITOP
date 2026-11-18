# Linux Collector (Phase 2.3)

Location: `collectors/linux/` — Python ≥ 3.11, dependencies `httpx`, `psutil`
only (no paid deps).

## Capabilities

| Module | Collects | Sources |
|---|---|---|
| `collect/system.py` | hostname, fqdn, distribution + version, arch, kernel, uptime | `/etc/os-release`, `platform`, `/proc/uptime` |
| `collect/hardware.py` | manufacturer, model, serial (when readable), CPU model/cores, memory, total disk, per-filesystem usage | `/proc/cpuinfo`, `/proc/meminfo`, `/sys/class/dmi/id`, psutil (statvfs fallback) |
| `collect/network.py` | interfaces (name, MAC, IPv4/IPv6, link state), aggregated IP/MAC lists | psutil (sysfs fallback) |
| `collect/packages.py` | installed packages with versions | `dpkg-query -W` (Debian/Ubuntu), `rpm -qa` (Fedora/RHEL) |

- **Distro support**: Ubuntu/Debian/Fedora/RHEL full (packages); other
  Linuxes degrade gracefully — package list empty with manager `"unknown"`,
  everything else still collected.
- Missing commands/files/permissions never crash the agent: each source
  degrades to `null`/empty with a warning log. DMI serial files are
  root-only → `null` when unreadable (spec: "when available").
- Output: JSON payloads matching the backend `AgentInventoryRequest` /
  `AgentEnrollRequest` contracts exactly (`extra="forbid"` server-side is
  the contract test).

## Commands

```bash
pip install -r requirements.txt && pip install -e .

# one-time enrollment (token via env/stdin/prompt — never argv)
EITOP_ENROLL_TOKEN='...' eitop-collector --config /etc/eitop/collector.toml enroll
printf '%s' "$TOKEN" | eitop-collector --config collector.toml enroll --token-stdin

eitop-collector --config collector.toml run       # heartbeat + inventory loop
eitop-collector --config collector.toml collect   # print payload JSON (no upload)
eitop-collector --config collector.toml status    # endpoint id, never the secret
eitop-collector --config collector.toml rotate    # rotate credential

python -m eitop_collector ...                     # equivalent entry point
```

Config: `config.example.toml` (`server_url`, intervals, timeout, retries,
`credential_file`); overrides via `EITOP_CONFIG`, `EITOP_SERVER_URL`.

## Networking & resilience

- Configurable server URL and intervals (heartbeat 60 s, inventory 300 s
  defaults; minimum 10 s enforced).
- Per-request timeout (default 30 s).
- Retry with exponential backoff `1s·2ⁿ` capped at 60 s on: network errors,
  timeouts, 429/500/502/503/504. Other 4xx fail immediately (retrying 401/422
  is pointless).
- Sustained server failure: loop-level backoff ×2 per failure up to 1 hour.
- Graceful shutdown on SIGINT/SIGTERM (signals stop the loop between
  1-second sleep slices).

## Security posture

- **No hardcoded credentials** — config file has no secrets; token comes
  from env/stdin/prompt; credential persisted at `credential_file` with mode
  `0600` in a `0700` directory (atomic write via tmp+rename). Loading
  **refuses** group/world-readable files (treated as compromised).
- **No `shell=True`** anywhere; package queries are fixed argv lists with
  `timeout=60`, `capture_output=True`, `check=False`; missing binary /
  timeout / non-zero exit → empty list + warning.
- **Minimal privileges**: works unprivileged; root only for default config
  and DMI serial. systemd unit example ships `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`.
- **No server-supplied execution**: server responses are parsed as JSON data
  only; nothing in the runner interprets response content as commands
  (regression test asserts this).
- **No secret logging**: the API client logs path/attempt/status only;
  enrollment token and credential never appear in log output.
- Enrollment token never accepted as a CLI argument (argv is world-visible
  via `ps`).

## Testing

`tests/` — 69 tests, no root, no network, no server (all HTTP via
`httpx.MockTransport`; psutil faked; sys paths injected as fixtures):

- `test_system.py`, `test_hardware.py`, `test_network.py`, `test_packages.py`
  — parsing, degradation, argv-list/no-shell assertion, truncation
- `test_api.py` — auth headers, retry/backoff order, 4xx no-retry, problem
  parsing, missing-credential response
- `test_credentials.py` — 0600/0700 perms, insecure-permission refusal,
  corrupt/missing files, clear
- `test_config.py` — TOML validation, env overrides, bounds
- `test_runner.py` — enroll/rotate/heartbeat flows, loop stop, backoff,
  server-response-is-inert guard

```bash
cd collectors/linux && python -m pytest
```
