# Runbook 7 — Active Directory synchronization troubleshooting

**Purpose:** diagnose failed, stale, or incomplete directory syncs.
**Prerequisites:** `directory:read`; worker/beat logs access.

## Triage

```bash
# Latest runs per connection
curl -sS "https://$HOST/api/v1/directory/sync-runs?page_size=10" \
  -H "Authorization: Bearer $TOKEN"

# Health per connection
curl -sS "https://$HOST/api/v1/directory/health" -H "Authorization: Bearer $TOKEN"

# Platform side
docker compose logs --tail 100 worker
docker compose logs --tail 50 beat
```

Expected healthy state: latest run `success`; `last_synced_at` fresher
than `sync_interval_minutes`; beat log shows `directory_sync_tick`
every `DIRECTORY_SYNC_SCAN_SECONDS` (300).

## Failure labels and fixes

Labels are sanitized — raw LDAP/OS error text is never returned or
logged. Map them as follows:

| Label | Meaning | Fix |
|---|---|---|
| `timeout` | connect/search exceeded timeout | DC reachable? raise `connect_timeout_seconds`/`search_timeout_seconds` on the connection |
| `connection_failed` | TCP/DNS failure | verify `host`/`port` from the worker container |
| `tls_error` | certificate problem | SAN match for `host`; `tls_ca_pem` = issuing CA; check DC cert expiry |
| `invalid_credentials` | bind rejected | verify DN/password/account status; re-enter password via PATCH |
| `search_base_not_found` | base DN wrong or invisible | correct `search_base` (`DC=example,DC=com`) |
| `protocol_error` / `search_failed` | server rejected an operation | check DC-side limits/permissions for the bind account |
| `credential_undecryptable` | `SECRET_KEY` rotated since password was stored | re-enter bind password ([runbook 12](secret-rotation.md)) |
| `stale_run_reaped` | worker died mid-run or run exceeded cap | automatic recovery — next scheduled sync proceeds; if it repeats, check worker stability/OOM |
| `task_submission_failed` | broker rejected enqueue | Redis down? [runbook 13](redis-celery-troubleshooting.md) |
| `unexpected` | unclassified — bug candidate | capture run id + worker logs, report with request ids |

## Stuck "running" run

Runs are bounded by leases: after `DIRECTORY_STALE_RUN_MINUTES` (30) an
orphaned run is reaped automatically; `DIRECTORY_MAX_SYNC_MINUTES` (60)
caps any run. **No manual SQL is needed** — wait for the reaper or
restart the worker ([runbook 14](service-restart-recovery.md)) to
expedite.

## Incomplete data / missing categories

Check `category_results` on the newest run:

- A category listed under `missing_scan` → the sync never collected it;
  usually server-side permission (bind account cannot read that
  subtree) or an aborted run.
- Findings "insufficient visibility" on endpoints → inventory, not AD:
  the endpoint never submitted that category
  ([runbook 5](endpoint-troubleshooting.md)); grace period
  `DIRECTORY_MISSING_GRACE_DAYS` (7 days) applies first.
- Computers present in AD but not matched to endpoints → check
  `GET /directory/reconciliations`; matching needs SID/category
  confirmation from both sides.

## Scheduled syncs not running

1. `GET /directory/connections` → `enabled` and `auto_sync` true?
2. Beat alive? `docker compose logs beat | tail -20` shows ticks?
3. Worker alive? `docker compose exec worker celery -A app.core.celery_app:celery_app inspect ping` → `pong`.
4. Connection's `sync_interval_minutes` elapsed?

Any "no" → [runbook 13](redis-celery-troubleshooting.md).

**Security warning:** when sharing diagnostics, the sanitized label +
exception class in logs are safe; raw LDAP dumps and `tls_ca_pem`
contents are fine (public certs), bind DN/passwords are not.
