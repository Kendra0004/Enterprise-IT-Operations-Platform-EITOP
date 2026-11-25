# Runbook 13 — Redis and Celery troubleshooting

**Purpose:** diagnose dead workers, stalled beat, broker problems.
**Prerequisites:** compose shell access on the host.

## Health snapshot

```bash
docker compose ps worker beat redis backend
docker compose exec worker celery -A app.core.celery_app:celery_app inspect ping
docker compose logs --tail 100 worker
docker compose logs --tail 50 beat
curl -s https://$HOST/health/ready      # includes {"redis":"ok"}
```

Expected: worker container `healthy` (its healthcheck is a celery
`inspect ping` → `pong`); beat `Up` and logging scheduler ticks; redis
`healthy`; readiness `{"database":"ok","redis":"ok"}`.

## Tasks in the system

```bash
docker compose exec worker celery -A app.core.celery_app:celery_app inspect active
docker compose exec worker celery -A app.core.celery_app:celery_app inspect reserved
# queue depth (requires redis password from .env):
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" llen celery
```

Expected: `active` shows currently executing jobs (directory sync,
inventory processing); `reserved` near 0 when idle.

## Scheduled jobs (beat)

Tasks and cadence (`backend/app/core/celery_app.py`):

| Task | Default cadence | Purpose |
|---|---|---|
| `eitop.scan_endpoint_offline` | `ENDPOINT_HEALTH_SCAN_SECONDS` (60) | active→offline flips |
| `eitop.prune_endpoint_snapshots` | daily | retention (`SNAPSHOT_RETENTION_DAYS`) |
| `eitop.directory_sync_tick` | `DIRECTORY_SYNC_SCAN_SECONDS` (300) | enqueue due AD syncs |
| `eitop.directory_insights_tick` | `DIRECTORY_INSIGHT_SCAN_SECONDS` (600) | regenerate findings |

Beat must run **exactly once** — never `--scale beat=N`.

## Symptom → cause → fix

| Symptom | Cause | Fix |
|---|---|---|
| Worker healthcheck unhealthy / no `pong` | worker crashed or OOM | `docker compose logs worker`; raise `mem_limit` (prod overlay); `docker compose up -d worker` |
| Tasks pile up, nothing executes | worker down or wrong queue | restart worker; verify broker URL in `.env` matches redis password |
| No scheduler ticks in beat log | beat crashed / unwritable schedule | `docker compose logs beat`; beat keeps its schedule on tmpfs — restart beat |
| Sync runs stuck `running` | worker died mid-run | automatic: lease reaper finalizes after `DIRECTORY_STALE_RUN_MINUTES` (30); restart worker to expedite |
| `503 Rate limiter unavailable` on login | Redis down — **fail-closed by design** | restore redis: `docker compose up -d redis`; check `REDIS_PASSWORD` matches `.env` |
| `task_submission_failed` label on syncs | enqueue rejected (broker auth/capacity) | verify `REDIS_URL` password; check redis logs |
| Repeated `stale_run_reaped` | worker killed mid-sync (OOM, restart loops) | check `docker inspect` OOM kills; raise `mem_limit`; investigate host memory |
| Duplicate offline scans after restart | normal redelivery | idempotent — safe to ignore |

## Recovery after interruption

- **Worker killed mid-task:** tasks are redelivered or re-scheduled;
  inventory upserts and snapshot appends are idempotent (content-hash
  dedup). No data repair needed.
- **Redis restarted (AOF intact):** broker queues and counters survive.
- **Redis data lost:** queued tasks are gone (re-trigger manual syncs
  from the UI/API if needed) and rate-limit counters reset — the login
  brute-force window re-arms, which is safe-side.
- **Beat restart:** resumes schedule from scratch — a missed tick is
  picked up next interval (all jobs are periodic, none are one-shot).

**Do not** enable `maxmemory` eviction policies (`allkeys-*`) on this
Redis — evicting broker keys silently drops jobs and resets
brute-force protection. The compose file intentionally sets no
`maxmemory`.

**Security warning:** redis carries the broker and session-adjacent
counters; it has no host port in production and requires a password —
keep it that way (see [../architecture/security.md](../architecture/security.md)).
