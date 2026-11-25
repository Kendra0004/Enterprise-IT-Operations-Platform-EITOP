# Runbook 5 — Endpoint troubleshooting

**Purpose:** diagnose an endpoint that is offline, stale, or reporting
bad inventory.
**Prerequisites:** `endpoints:read` (or operator access on the host).

## Triage

```bash
# 1. What does the platform think?
curl -sS https://$HOST/api/v1/endpoints/$EP/health \
  -H "Authorization: Bearer $TOKEN"
```

Expected shape: last heartbeat/Inventory timestamps, status
(`active`/`offline`/`revoked`), health verdict derived from
`ENDPOINT_HEARTBEAT_INTERVAL_SECONDS` (300) and
`ENDPOINT_OFFLINE_THRESHOLD_SECONDS` (900).

```bash
# 2. Recent snapshots (is inventory arriving at all?)
curl -sS "https://$HOST/api/v1/endpoints/$EP/snapshots?page_size=5" \
  -H "Authorization: Bearer $TOKEN"
```

## Symptom → cause → fix

| Symptom | Check | Fix |
|---|---|---|
| Status `offline` | collector running? `systemctl status eitop-collector` / process list | restart collector; offline is only ever set by `eitop.scan_endpoint_offline` (beat) — recovery to `active` happens automatically on the next heartbeat |
| Status `revoked` | was the credential revoked? | expected — re-enroll with a fresh token ([runbook 4](endpoint-enrollment.md)) |
| 401s in collector logs | credential rotated/revoked or wrong `credential_file` | re-enroll; verify file mode 0600 and path in `collector.toml` |
| No snapshots, heartbeat ok | inventory submission failing (413/5xx) | check collector logs; inventory body cap is 5 MB — trim huge package lists or check proxy `client_max_body_size` |
| Snapshot exists but data looks wrong | collector config (categories, interval) | fix `collector.toml`, wait one interval (min 10 s) |
| Duplicate-looking snapshots | identical submissions are deduped by `content_hash` | if two rows differ, payloads genuinely differ — diff in the UI history view |
| Clock-skewed timestamps | host clock | fix NTP on the endpoint host |
| Endpoint stuck `pending` | never heartbeated | verify `server_url`, TLS trust, and network path to the proxy |

## Collector-side checks (Linux)

```bash
sudo journalctl -u eitop-collector -n 50 --no-pager   # if installed as unit
sudo tail -50 /var/log/eitop/collector.log            # if file logging
sudo stat -c '%a %U %n' /var/lib/eitop/credentials.json   # must be 600 root
curl -sS https://$HOST/health/ready                    # platform side
```

Collector retry semantics: network errors / 5xx / 429 are retried with
exponential backoff (`max_retries = 5` default) — brief outages
self-heal without operator action.

## Server-side checks

```bash
docker compose logs --tail 100 worker     # offline scan runs here
docker compose logs --tail 100 beat        # schedule ticks
docker compose exec backend alembic current
```

- Offline transitions are audited — filter audit events for
  `endpoint.` in [runbook 16](log-inspection-audit-review.md).
- If the whole fleet went offline at once, suspect the platform
  (beat/worker down, proxy down) before the agents.

## Recovery

No data repair should be necessary: inventory is append-only and
self-correcting (next submission upserts current state). After fixing
the collector, expect `active` within one heartbeat interval and a new
snapshot within one inventory interval.

**Security warning:** when troubleshooting a suspected compromise,
revoke first and investigate second ([runbook 15](incident-response.md)).
Never export `credential_file` contents into tickets.
