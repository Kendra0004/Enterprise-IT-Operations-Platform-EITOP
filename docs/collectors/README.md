# Collectors

EITOP's endpoint agents push data inward: they enroll once with a
single-use token, then submit heartbeats and inventory over HTTPS using
a per-endpoint credential. No inbound ports are opened on endpoints.

| | Linux collector | Windows collector |
|---|---|---|
| Language | Python 3 | PowerShell 5.1 / 7 |
| Entry point | `eitop-collector` (CLI) | `eitop-collector.ps1` |
| Source | `collectors/linux/` | `collectors/windows/` |
| Tests | pytest (69) | Pester (113) |
| Credential storage | file, mode `0600` | DPAPI (CurrentUser) + ACL |
| Detail docs | [../endpoints/linux-collector.md](../endpoints/linux-collector.md) | [../endpoints/windows-collector.md](../endpoints/windows-collector.md) |

API contract: [../endpoints/api.md](../endpoints/api.md) (§ agent
routes) · enrollment internals: [../endpoints/enrollment.md](../endpoints/enrollment.md).

## Enrollment (both platforms)

1. Admin mints a single-use token
   ([runbook 4](../runbooks/endpoint-enrollment.md)):
   `POST /api/v1/endpoints/enrollment-tokens` (`endpoints:write`) —
   the raw token is returned exactly once.
2. Collector exchanges it for its own credential via
   `POST /api/v1/agent/enroll` — token consumed atomically, uniform
   error whether invalid/expired/used.
3. Credential persists locally (0600 / DPAPI); every later request
   uses `Authorization: Bearer eitop_ep_…`.

**Never pass the token as a CLI argument** (argv is visible in `ps`) —
both collectors accept it via environment or stdin.

## Linux installation

```bash
# 1. Install the package (from repo)
cd collectors/linux
pip install .                       # installs the `eitop-collector` command

# 2. Config
sudo install -d -m 0700 /etc/eitop /var/lib/eitop
sudo cp config.example.toml /etc/eitop/collector.toml
sudo chmod 0600 /etc/eitop/collector.toml
sudo $EDITOR /etc/eitop/collector.toml    # server_url = "https://<host>"

# 3. Enroll (token via env or stdin — never argv)
sudo -u eitop EITOP_ENROLL_TOKEN='<token>' \
  eitop-collector --config /etc/eitop/collector.toml enroll

# 4. Run
eitop-collector --config /etc/eitop/collector.toml run      # daemon loop
```

Configuration (`config.example.toml`):

| Key | Default | Notes |
|---|---|---|
| `server_url` | `http://localhost:8080` | HTTPS in production |
| `interval_seconds` | `300` | full inventory cadence (min 10) |
| `heartbeat_interval_seconds` | `60` | (min 10) |
| `timeout_seconds` | `30` | per request |
| `max_retries` | `5` | exponential backoff on 5xx/429/network |
| `credential_file` | `/var/lib/eitop/credentials.json` | mode 0600 |

Commands: `enroll`, `run`, `status` (endpoint id, never the secret),
`collect` (dry-run payload), `rotate`.

systemd (example unit — see `collectors/linux/README.md` for the full
snippet): run as user `eitop`, `Restart=on-failure`,
`NoNewPrivileges=true`, `ProtectSystem=strict`.

## Windows installation

```powershell
# 1. Copy collector, e.g. C:\Program Files\EITOP\collector
# 2. Config
Copy-Item config.example.json C:\ProgramData\EITOP\collector.json
notepad C:\ProgramData\EITOP\collector.json     # server_url
icacls C:\ProgramData\EITOP /inheritance:r /grant:r "<SID>:(OI)(CI)F"

# 3. Enroll (token via env or stdin — never a parameter)
$env:EITOP_ENROLL_TOKEN = '<token>'
.\eitop-collector.ps1 -Config C:\ProgramData\EITOP\collector.json enroll

# 4. Run (scheduled task example in collectors/windows/README.md)
.\eitop-collector.ps1 -Config C:\ProgramData\EITOP\collector.json run
```

- Credential: DPAPI CurrentUser, ACL-limited — decrypts only under the
  service account that wrote it. Run under a dedicated account
  (gMSA/local service).
- Supported: Windows 10/11, Server 2019+; no paid dependencies.
- Commands: `enroll`, `run`, `collect [-IncludeDetails]`, `status`,
  `rotate`.

## Operating

- Verify in the platform: endpoint appears `active` after first
  heartbeat; inventory after first submit
  ([runbook 5](../runbooks/endpoint-troubleshooting.md)).
- Rotate: agent-side (`rotate`) or admin-side
  (`POST /endpoints/{id}/rotate-credential`) —
  [runbook 4](../runbooks/endpoint-enrollment.md).
- Revoke: `POST /endpoints/{id}/revoke` — credential dies immediately;
  re-enrollment needs a fresh token.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `401` on heartbeat/inventory | credential rotated/revoked → re-enroll; verify credential file path/mode |
| `429` on enroll | per-IP enroll limit (10/min) → wait a minute |
| `413` on inventory | payload over 5 MB cap → check for absurd package lists; proxy `client_max_body_size` |
| endpoint stuck `pending` | collector not running / wrong `server_url` / TLS trust |
| retries then silence | collector backs off up to 1 h on sustained failure — check connectivity |
| Windows: DPAPI errors | credential written under another account → re-enroll under the service account |
| Linux: permission denied on credential file | wrong owner/mode → `chmod 600`, correct `credential_file` owner |

More: [../troubleshooting/README.md](../troubleshooting/README.md)
§ Collectors.

## Test suites

```bash
# Linux
cd collectors/linux && python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pytest -q

# Windows (containerized Pester, from repo root)
docker run --rm -v $PWD:/repo -w /repo/collectors/windows \
  mcr.microsoft.com/powershell:7.4-ubuntu-22.04 \
  pwsh -NoProfile -Command 'Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser; Invoke-Pester -Path ./tests -CI'
```

**Explicitly unverified:** live-Windows execution and native-domain
behavior remain outstanding (tests are mocked/fixtures on a
non-Windows host) — see
[../endpoints/windows-collector.md](../endpoints/windows-collector.md)
§ Manual validation.
