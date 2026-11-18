# EITOP Linux Collector

Agent for EITOP endpoint inventory: enrolls with a single-use token, then
submits heartbeats and inventory (system, hardware, network, filesystems,
packages) to the EITOP backend.

Supported: Ubuntu/Debian (dpkg), Fedora/RHEL (rpm), other distros (package
list empty, everything else works).

## Install

```bash
cd collectors/linux
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt        # httpx, psutil
.venv/bin/pip install -e .                       # optional: `eitop-collector` script
```

Requires Python ≥ 3.11. No root required for collection; root only needed
for default paths (`/etc/eitop/collector.toml`, `/var/lib/eitop/`).

## Configure

```bash
sudo mkdir -p /etc/eitop
sudo cp config.example.toml /etc/eitop/collector.toml
sudo chmod 600 /etc/eitop/collector.toml
# edit server_url, intervals
```

`EITOP_SERVER_URL` and `EITOP_CONFIG` override the file. The config file
contains **no secrets**.

## Enroll

Admin creates a token in the dashboard/API (`POST /api/v1/endpoints/enrollment-tokens`),
then on the endpoint host:

```bash
# interactive (hidden prompt, recommended)
sudo -u eitop eitop-collector --config /etc/eitop/collector.toml enroll

# scripted: token via env (never via argv — argv is visible in `ps`)
EITOP_ENROLL_TOKEN='et_xxx...' eitop-collector --config /etc/eitop/collector.toml enroll

# scripted: token via stdin
printf '%s' "$TOKEN" | eitop-collector --config /etc/eitop/collector.toml enroll --token-stdin
```

The raw token is shown to the admin exactly once and can only be used once.
The issued credential is written to `credential_file` with mode `0600`
(directory `0700`); loading refuses world/group-readable files.

## Run

```bash
eitop-collector --config /etc/eitop/collector.toml run     # daemon loop
eitop-collector --config /etc/eitop/collector.toml status  # endpoint id, no secret
eitop-collector --config /etc/eitop/collector.toml collect # dry-run inventory JSON
eitop-collector --config /etc/eitop/collector.toml rotate  # rotate credential
```

systemd example:

```ini
[Unit]
Description=EITOP endpoint collector
After=network-online.target

[Service]
User=eitop
ExecStart=/usr/local/bin/eitop-collector --config /etc/eitop/collector.toml run
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

## Behavior

- Heartbeat every `heartbeat_interval_seconds` (default 60s).
- Full inventory every `interval_seconds` (default 300s).
- Request timeout `timeout_seconds`; retries with exponential backoff
  (1s → 2s → … capped 60s) on network errors, timeouts, 429/5xx. 4xx other
  than 429 fail immediately.
- Server unavailable → loop backs off exponentially up to 1 hour.
- Revoked credential → server returns 401; agent stops with a clear error.
- The agent executes **nothing** received from the server — responses are
  data only. No `shell=True` anywhere; package queries run as fixed argv
  lists with timeouts.

## Tests

```bash
cd collectors/linux
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

Tests need no root, no network and no server (all HTTP mocked).
