# Runbook 14 — Service restart and recovery

**Purpose:** planned restarts, single-service recovery, full-stack
bounce without data loss.
**Prerequisites:** compose shell access.

## Planned restart (rolling)

Data survives on volumes — restarts are safe at any time:

```bash
docker compose restart postgres redis     # data services first (brief blip)
docker compose restart backend            # API reconnects
docker compose restart worker beat        # consumers last
```

Verify after:

```bash
docker compose ps                          # all healthy/Up
curl -s http://localhost:8000/health/ready # dev; use https://$HOST in prod
docker compose exec worker celery -A app.core.celery_app:celery_app inspect ping
docker compose logs --tail 20 beat         # scheduler ticks resume
```

Expected: `/health/ready` → `{"status":"ready","checks":{"database":"ok","redis":"ok"}}`;
worker `pong`; beat logs `Scheduler: Sending due task …` within one
interval. Users may see `401` only if you rotated secrets — plain
restarts keep tokens valid.

## Restart one service

```bash
docker compose up -d backend     # recreate (picks up new config/env)
docker compose restart worker    # in-place restart (same image)
```

Use `up -d <svc>` after any `.env` or compose change (env is baked at
container creation); `restart` is fine otherwise.

## Full-stack bounce

```bash
docker compose down              # stops containers, KEEPS volumes
docker compose up -d
```

**Never** add `-v` to `down` outside a deliberate wipe — it deletes the
database volume.

## Crash recovery expectations

| Failure | Auto-recovery | Manual action |
|---|---|---|
| backend crash | `restart: unless-stopped` + entrypoint re-runs `alembic upgrade head` (idempotent) | none unless crash-looping → read logs |
| worker crash | container restart; in-flight tasks redelivered (idempotent) | if loop: OOM? raise `mem_limit` ([runbook 13](redis-celery-troubleshooting.md)) |
| beat crash | restart resumes schedule | never run a second beat |
| postgres crash | restart with data intact (volume) | check disk; verify `/health/ready` |
| redis crash | restart; AOF preserves queues/counters | verify `{"redis":"ok"}`; watch for `503` login errors while down |
| host reboot | all `unless-stopped` services return | verify stack + time sync |

## When recovery is NOT automatic

- **Schema mid-migration failure:** see
  [runbook 11](upgrades-and-migrations.md) — restore backup if the DB
  is inconsistent.
- **Corrupted database volume:** [runbook 10](database-restoration.md).
- **Secrets lost (`.env` gone):** restore from secret store — the app
  fails fast by design until it is back.

## Expected state after recovery

- All services `healthy`/`Up`; `alembic current` == head.
- Existing logins still valid (no secret rotation occurred).
- Endpoint agents reconnect on their own (retry/backoff, then normal
  heartbeat cadence).
- AD syncs resume: overdue scheduled syncs enqueue on the next
  `directory_sync_tick`.

**Security warning:** during recovery, keep the stack unpublished
(production ports only via proxy); never "temporarily" expose
postgres/redis to debug — use `docker compose exec` instead.
