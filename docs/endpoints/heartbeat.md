# Endpoint Heartbeat & Health Monitoring (Phase 2.5)

How EITOP decides that a collector is alive, late, offline or revoked —
and what happens when it comes back.

## Status model

One `endpoints.status` column, three values (CHECK constraint):

| Status | Meaning | Terminal? |
|---|---|---|
| `active` | Enrolled and expected to heartbeat | no |
| `offline` | Last heartbeat (or enrollment) exceeded the threshold | no — transient |
| `revoked` | Administratively terminated | **yes** |

Key rules:

- **Missing heartbeat ≠ revoked.** An endpoint that stops heartbeating goes
  `offline`, never `revoked`. Revocation is an explicit administrator action
  (`POST /endpoints/{id}/revoke`, audited `endpoint.revoked`).
- **Offline is recoverable.** Offline endpoints keep valid credentials so the
  agent can heartbeat back to `active`. Revoked endpoints are rejected at
  authentication on **every** request (heartbeat, inventory, rotation).
- All timestamps are UTC; comparisons happen in the database/Python with
  timezone-aware datetimes.

## Configuration

| Setting (env) | Default | Meaning |
|---|---|---|
| `ENDPOINT_HEARTBEAT_INTERVAL_SECONDS` | `300` | Expected agent cadence — drives the `late` band and the UI hint |
| `ENDPOINT_OFFLINE_THRESHOLD_SECONDS` | `900` | Age after which an active endpoint is offline (validator: ≥ interval) |
| `ENDPOINT_HEALTH_SCAN_SECONDS` | `60` | Celery beat cadence for the offline scan |

Normal jitter never flips an endpoint: the threshold is enforced to be at
least the expected interval.

## Heartbeat flow (`POST /api/v1/agent/heartbeat`)

1. Agent authenticates with its endpoint credential (`eitop_ep_…`,
   SHA-256 at rest). `authenticate_agent` rejects **only** revoked
   endpoints — offline endpoints pass so they can recover.
2. `record_heartbeat` sets `last_heartbeat_at = now (UTC)` and refreshes
   `agent_version`.
3. If the endpoint was `offline`, a conditional `UPDATE … WHERE status =
   'offline'` flips it to `active`. Only when that update matched a row is
   the `endpoint.online` audit event written — so repeated heartbeats after
   recovery produce **no duplicate events**.
4. The response reports the current status.

**Routine heartbeats are never audited.** Audit covers lifecycle only:
`endpoint.enrolled`, `endpoint.offline`, `endpoint.online`,
`endpoint.revoked`, `endpoint.credential.rotated`.

## Offline detection (background only)

`POST` handlers never poll the database for health state. Detection runs in
a Celery periodic task:

```
beat (docker compose service)
  └─ every ENDPOINT_HEALTH_SCAN_SECONDS → task eitop.scan_endpoint_offline
       └─ endpoint_service.scan_offline_endpoints(db)
            UPDATE endpoints
               SET status = 'offline'
             WHERE status = 'active'
               AND (last_heartbeat_at < now - threshold
                    OR (last_heartbeat_at IS NULL AND enrolled_at < now - threshold))
            RETURNING id, hostname
            → one endpoint.offline audit row per returned id
```

- **No heartbeat yet**: age is measured from `enrolled_at`, so a fresh
  enrollment inside the grace window stays `active`; one that never
  reports goes `offline` (still not `revoked`).
- **Duplicate-event prevention** is structural: the `WHERE status='active'`
  guard means a second concurrent run (or a heartbeat that just recovered
  the row) matches zero rows → `rowcount = 0` → no audit.
- **Race with revocation**: the scanner only ever touches `active` rows, so
  a revoked endpoint can never be transitioned or audited by the scan.
- Recovery is **synchronous with the heartbeat**, not with the next scan —
  an endpoint is `active` again as soon as a valid heartbeat lands.

### Process layout

`docker-compose.yml` runs three backend processes from the same image:

| Service | Command | Role |
|---|---|---|
| `backend` | (no command → `entrypoint.sh` serves uvicorn) | API |
| `worker` | `celery worker` | executes tasks |
| `beat` | `celery beat --schedule /tmp/celerybeat-schedule` | fires periodic tasks |

`backend/entrypoint.sh` always migrates + seeds, then execs the given
command (or uvicorn when none is supplied). The beat schedule lives on
tmpfs because the container root filesystem is read-only.

## Read-time health derivation

Between scans, `GET /endpoints/{id}/health` derives `collector_status`
from UTC timestamps:

| `collector_status` | Condition |
|---|---|
| `revoked` | persisted status is `revoked` |
| `pending` | enrolled, never heartbeated, still inside the grace window |
| `offline` | persisted `offline`, or heartbeat older than the threshold |
| `late` | heartbeat older than the interval but within the threshold |
| `healthy` | heartbeat within the interval |

`status` (persisted) and `collector_status` (derived) are both returned so
the UI can show the lifecycle plus the freshness signal.

## API surface

| Route | Permission | Notes |
|---|---|---|
| `GET /endpoints/{id}/health` | `endpoints:read` | see above; 404 unknown id |
| `GET /endpoints?status=offline` | `endpoints:read` | status filter accepts `offline` |
| `GET /endpoints?heartbeat_from=&heartbeat_to=` | `endpoints:read` | heartbeat range filter |
| `GET /endpoints/overview` | `endpoints:read` | real aggregate counts (total/active/offline/revoked, OS split) |

List filters added in this phase: `os`, `agent_version`,
`heartbeat_from`/`heartbeat_to`. Sort allowlist gained `os` and
`agent_version`; unknown sort fields still return 400.

## Tests

`backend/tests/test_heartbeat_health.py` covers: heartbeat updates the
timestamp/version, routine heartbeats are not audited, the periodic scan
marks stale endpoints offline and audits once, repeat scans never
duplicate transitions, fresh enrollments stay active, never-heartbeated
endpoints past grace go offline (not revoked), recovery via heartbeat with
exactly one `endpoint.online`, the `late` band, revoked endpoints rejecting
heartbeat/inventory and never being resurrected, health endpoint shape +
UTC, list filters/sort, and overview counts.

End-to-end process verification (this environment): beat dispatched
`scan-endpoint_offline` every 60 s and the worker executed it — first run
returned `1` transition, subsequent runs `0` (idempotent).

## Security notes

- Agent authentication continues to enforce credential↔endpoint binding;
  offline status changes only the freshness gate, not identity checks.
- Revoked credentials are rejected before any handler runs — no heartbeat,
  inventory or rotation path can revive them.
- No remote execution, no per-heartbeat audit noise, no unbounded queries
  (page size capped at 100).
