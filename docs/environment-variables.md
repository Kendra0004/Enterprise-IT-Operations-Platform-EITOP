# Environment Variables

All configuration is environment-driven. Copy `.env.example` → `.env`.
`.env` is git-ignored — never commit it.

## Application

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `EITOP` | Display name (OpenAPI title) |
| `APP_ENV` | `development` | `development` \| `testing` \| `production` |
| `DEBUG` | `true` | Verbose error detail toggle |
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

## Security

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | **required** | JWT signing key. ≥16 chars enforced. Generate: `python -c "import secrets; print(secrets.token_urlsafe(64))"` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access JWT lifetime (1–60) |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime (1–90) |
| `CORS_ORIGINS` | `http://localhost:8080,...` | Comma-separated allowlist; `*` never used |
| `RATE_LIMIT_LOGIN_PER_MINUTE` | `10` | Login attempts per IP per minute |
| `RATE_LIMIT_REFRESH_PER_MINUTE` | `30` | Refresh calls per IP per minute |

## Data services

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://eitop:eitop@localhost:5432/eitop` | SQLAlchemy URL (psycopg v3 driver) |
| `REDIS_URL` | `redis://localhost:6379/0` | Rate limiter + Celery broker/backend |
| `TEST_DATABASE_URL` | `.../eitop_test` | Test suite target DB |
| `TEST_REDIS_URL` | `redis://localhost:6379/1` | Test suite target Redis DB |

## Endpoint monitoring & history (Phase 2.5–2.6)

| Variable | Default | Description |
|---|---|---|
| `ENDPOINT_HEARTBEAT_INTERVAL_SECONDS` | `300` | Expected agent heartbeat cadence (min 10) — drives the `late` health band |
| `ENDPOINT_OFFLINE_THRESHOLD_SECONDS` | `900` | Heartbeat age after which an active endpoint is marked offline; must be ≥ the interval (validator) |
| `ENDPOINT_HEALTH_SCAN_SECONDS` | `60` | Celery beat cadence for the offline-detection task |
| `SNAPSHOT_RETENTION_DAYS` | *(unset)* | Days to keep inventory snapshots. Unset = keep forever (prune task no-ops) |

See [endpoints/heartbeat.md](endpoints/heartbeat.md) and
[endpoints/inventory-history.md](endpoints/inventory-history.md).

## Active Directory integration (Phase 3.1)

Read-only AD mirror: LDAPS/StartTLS only (`ldap3`), no write operations
against the directory, sanitized error labels only (never raw exceptions
or credentials).

| Variable | Default | Description |
|---|---|---|
| `DIRECTORY_SYNC_SCAN_SECONDS` | `300` | Celery beat cadence scanning for due auto-sync connections (per-connection cadence is `sync_interval_minutes` on the connection row; min 30) |
| `DIRECTORY_CONNECT_TIMEOUT_SECONDS` | `10` | LDAP connect/bind budget per operation (1–120) |
| `DIRECTORY_SEARCH_TIMEOUT_SECONDS` | `30` | LDAP search/page-read budget per operation (1–600) |
| `DIRECTORY_PAGE_SIZE` | `500` | Paged-search page size (1–5000) |
| `DIRECTORY_MISSING_GRACE_DAYS` | `7` | Grace period before a never-seen-again object is marked missing (1–90) |
| `DIRECTORY_STALE_RUN_MINUTES` | `30` | Fallback reaper threshold for runs **never claimed** (lost broker delivery, pre-lease rows). Runs holding a live lease are never reaped by age alone (5–1440) |
| `DIRECTORY_MAX_SYNC_MINUTES` | `60` | Absolute wall-clock cap for ONE sync run, enforced by the reaper even while the lease is live; also sizes the Celery ladder below. Must be ≥ `DIRECTORY_STALE_RUN_MINUTES` (validator) |
| `DIRECTORY_SYNC_LEASE_SECONDS` | `300` | Ownership lease of the executing worker; renewed by a heartbeat thread every lease/3 and re-checked atomically before each mirror commit and before finalizing run status (30–3600) |

### Runtime limits ladder

One consistent ladder, sized from `DIRECTORY_MAX_SYNC_MINUTES` (see
`app/core/celery_app.py`):

| Bound | Value | Purpose |
|---|---|---|
| DB hard cap | `DIRECTORY_MAX_SYNC_MINUTES` | Reaper collects the run even if its lease is live |
| Celery `task_soft_time_limit` | `DIRECTORY_MAX_SYNC_MINUTES × 60` s (from task start) | Graceful failure → run finalized as failed |
| Celery `task_time_limit` | soft + 60 s | Hard worker kill |
| Broker `visibility_timeout` | `DIRECTORY_MAX_SYNC_MINUTES + 15` min | Redis unacked-redelivery window; must stay above `task_time_limit` so a live task is never delivered twice |

Duplicate deliveries are harmless regardless of the ladder: the second
worker loses the execution-token claim and returns `skipped` without
touching data or run status.

## Bootstrap (optional)

| Variable | Description |
|---|---|
| `BOOTSTRAP_ADMIN_EMAIL` | First admin email — used only when `users` table is empty |
| `BOOTSTRAP_ADMIN_PASSWORD` | Min 12 chars; ignored once any user exists. Prefer env/stdin — the seed CLI deliberately has **no password argument** (argv is visible in `ps`) |

## Data services (compose)

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `eitop` / dev default / `eitop` | Dev defaults — **override in production** |
| `REDIS_PASSWORD` | dev default | Enables Redis `--requirepass` inside the compose network |

## Frontend (Vite)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `/api/v1` | API prefix baked at build time |
| `VITE_BACKEND_URL` | `http://localhost:8000` | Dev-proxy target only |
