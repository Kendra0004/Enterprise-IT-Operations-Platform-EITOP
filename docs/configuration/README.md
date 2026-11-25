# Configuration reference

All environment variables EITOP reads, with defaults and constraints.
Sources of truth: `backend/app/core/config.py` (application settings),
`docker-compose.yml` (service wiring), `.env.example` (templated list).

Related: [../installation/README.md](../installation/README.md) (dev),
[../installation/production.md](../installation/production.md) (prod),
[../runbooks/secret-rotation.md](../runbooks/secret-rotation.md).

Variable names are the upper-case form of the Pydantic field (e.g.
`directory_page_size` → `DIRECTORY_PAGE_SIZE`), loaded from the
environment or the compose `.env` file.

## Application

| Variable | Default | Constraints / notes |
|---|---|---|
| `APP_NAME` | `EITOP` | display name |
| `APP_ENV` | `development` | `development` \| `testing` \| `production` — anything else rejected at startup |
| `DEBUG` | `false` | must be `false` in production (startup-enforced) |
| `LOG_LEVEL` | `INFO` | standard logging levels |
| `SECRET_KEY` | — (**required**, min 16 chars) | signs JWTs; derives the AD-credential encryption key. Production additionally requires ≥ 32 chars and rejects placeholder values. Rotation consequences: [runbook 12](../runbooks/secret-rotation.md) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | range 1–60 |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | range 1–90 |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | comma-separated allowlist; also the CSRF `Origin` allowlist; production requires https-only, no `*` |

## Database / Redis

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://eitop:eitop@localhost:5432/eitop` | used by app, workers and alembic; production rejects dev credentials |
| `REDIS_URL` | `redis://localhost:6379/0` | broker + rate limiter; production requires an authentication password |
| `TEST_DATABASE_URL` | — | test suite only (see [../testing.md](../testing.md)) |
| `TEST_REDIS_URL` | — | test suite only |

## Rate limiting (fail-closed)

| Variable | Default | Scope |
|---|---|---|
| `RATE_LIMIT_LOGIN_PER_MINUTE` | `10` (≥1) | `POST /auth/login` per bucket+IP |
| `RATE_LIMIT_REFRESH_PER_MINUTE` | `30` (≥1) | `POST /auth/refresh` |
| `RATE_LIMIT_ENROLL_PER_MINUTE` | `10` (≥1) | `POST /agent/enroll` |

Redis unavailable ⇒ these routes return `503` (never unprotected).

## Endpoint inventory

| Variable | Default | Constraints / notes |
|---|---|---|
| `ENDPOINT_HEARTBEAT_INTERVAL_SECONDS` | `300` (≥10) | expected agent heartbeat cadence |
| `ENDPOINT_OFFLINE_THRESHOLD_SECONDS` | `900` (≥10) | **must be ≥ heartbeat interval** (startup-enforced); no heartbeat for this long → offline |
| `ENDPOINT_HEALTH_SCAN_SECONDS` | `60` (≥10) | beat cadence of `eitop.scan_endpoint_offline` |
| `SNAPSHOT_RETENTION_DAYS` | unset (keep forever) | when set, beat prunes older snapshots daily |

## Active Directory

| Variable | Default | Constraints / notes |
|---|---|---|
| `DIRECTORY_CONNECT_TIMEOUT_SECONDS` | `10` | 1–120 |
| `DIRECTORY_SEARCH_TIMEOUT_SECONDS` | `30` | 1–600 |
| `DIRECTORY_PAGE_SIZE` | `500` | 1–5000 (LDAP paged search) |
| `DIRECTORY_MISSING_GRACE_DAYS` | `7` | 1–90 — grace before "insufficient visibility" findings |
| `DIRECTORY_STALE_RUN_MINUTES` | `30` | 5–1440 — lease reaper threshold for orphaned syncs |
| `DIRECTORY_MAX_SYNC_MINUTES` | `60` | 5–1440, **must be ≥ stale** (startup-enforced) — absolute run cap |
| `DIRECTORY_SYNC_LEASE_SECONDS` | `300` | 30–3600 — single-flight lease TTL |
| `DIRECTORY_SYNC_SCAN_SECONDS` | `300` | ≥30 — beat cadence of `eitop.directory_sync_tick` |
| `DIRECTORY_INSIGHT_SCAN_SECONDS` | `600` | ≥60 — beat cadence of `eitop.directory_insights_tick` |
| `DIRECTORY_INACTIVE_USER_DAYS` | `90` | 30–3650 — inactive-user insight threshold |
| `DIRECTORY_STALE_COMPUTER_DAYS` | `90` | 30–3650 — stale-computer insight threshold |
| `DIRECTORY_NESTED_GROUP_MAX_DEPTH` | `8` | 1–32 — nested-group traversal guard |

## Compose service variables

| Variable | Used by | Notes |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | postgres service + scripts | production: strong password, also used to build `DATABASE_URL` |
| `REDIS_PASSWORD` | redis `--requirepass`, healthcheck `REDISCLI_AUTH`, `REDIS_URL` | production: strong password |
| `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` | `python -m app.db.seed` | first admin; **password never via argv** — env/stdin only; seed runs only while `users` is empty |

## Backup scripts (`infrastructure/scripts/`)

| Variable | Default | Notes |
|---|---|---|
| `BACKUP_ENCRYPTION_KEY` | — (**required**) | AES-256-CBC key for `backup.sh`/`restore.sh`; env only, never argv |
| `BACKUP_RETENTION_DAYS` | `30` | prunes older backups after each run |
| `COMPOSE_FILE` | `docker-compose.yml` | set to `docker-compose.yml:docker-compose.prod.yml` in production |

`COMPOSE_PROJECT_NAME` targets a specific stack as usual.

## Frontend (Vite build-time)

| Variable | Default | Notes |
|---|---|---|
| `VITE_API_BASE_URL` | `/api/v1` | API prefix baked into the bundle |
| `VITE_BACKEND_URL` | `http://localhost:8000` | dev-proxy target only |

## Startup validation summary

- Always: `APP_ENV` enum; `SECRET_KEY` ≥ 16; cross-field rules
  (offline ≥ heartbeat, max-sync ≥ stale).
- **Production only**, every process (API/worker/beat/migrations):
  `DEBUG=false`; `SECRET_KEY` ≥ 32 and non-placeholder; DB not
  `eitop:eitop`; Redis URL carries a password (not a dev/placeholder
  value); `CORS_ORIGINS` https-only without `*`. All violations are
  reported in a single aggregated error at boot.
