# Production deployment

EITOP ships a development stack (`docker-compose.yml`) and a production
overlay (`docker-compose.prod.yml`). The overlay never breaks the dev
workflow: `docker compose up --build` alone keeps working exactly as
before.

## Topology

```
Internet ──HTTPS──► nginx (edge, :80/:443)      docker-compose.prod.yml
                      ├── /api, /health, /docs ─► backend :8000 (internal)
                      └── everything else ──────► frontend :8080 (internal)
backend/worker/beat ──► postgres + redis         (no host ports, ever)
```

* One proxy hop for API traffic — the edge proxy **overwrites**
  `X-Forwarded-For` with the real client address (never appends), so the
  rate limiter cannot be spoofed and keys on the true client IP.
* PostgreSQL and Redis publish **no host ports**; they are reachable only
  on the internal `eitop` network.
* `backend`/`worker`/`beat` run non-root (uid 10001 from the image) with
  a read-only root filesystem and `tmpfs /tmp`; `no-new-privileges` is set
  on every service.

## Prerequisites

* Docker Compose ≥ 2.24 (for `!override`/`!reset` and `!reset` support
  verified with Compose v5.x)
* Certificates for the domain (Let's Encrypt, corporate PKI, or a
  self-signed pair for internal use)
* A secrets source for the environment file (CI secret store, vault, or a
  root-owned `0600` file on the host)

## First deployment

```bash
# 1. Environment — copy and edit; every production value must change.
cp .env.example .env
chmod 600 .env
$EDITOR .env
```

Required production values (the app refuses to boot otherwise):

| Variable | Requirement |
|---|---|
| `APP_ENV` | `production` |
| `DEBUG` | `false` |
| `SECRET_KEY` | ≥32 chars, not a placeholder (`python -c "import secrets; print(secrets.token_urlsafe(64))"`) |
| `POSTGRES_PASSWORD` | strong, not `change-me-db-password` / `eitop` |
| `REDIS_PASSWORD` | strong, not `change-me-redis-password` / `eitop-dev-redis` |
| `CORS_ORIGINS` | `https://…` origins only, no wildcard |

Validation runs at startup of **every** process (API, worker, beat,
migrations) in `app/core/config.py` — a misconfigured deploy fails fast
with a single aggregated error instead of running insecurely.

```bash
# 2. TLS material (gitignored)
mkdir -p certs
# fullchain.pem + privkey.pem for your domain

# 3. Start
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# 4. Bootstrap the first administrator (only while the users table is empty)
printf '%s' "$BOOTSTRAP_ADMIN_PASSWORD" | \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T backend \
  python -m app.db.seed --admin-email admin@your-domain.com --admin-password-stdin
```

Migrations run automatically on container start (`backend/entrypoint.sh`:
`alembic upgrade head` → RBAC seed → app). `alembic upgrade head` is
idempotent and safe to re-run.

## Secrets management

| Secret | Source | Notes |
|---|---|---|
| `SECRET_KEY` | env file (0600) / secret store | Signs JWTs; rotating it invalidates all access tokens (users re-login; refresh cookies are opaque and unaffected) |
| `POSTGRES_PASSWORD` | env file | Used by postgres *and* to build `DATABASE_URL` |
| `REDIS_PASSWORD` | env file | Used by redis `--requirepass`, healthcheck, `REDIS_URL` |
| `BOOTSTRAP_ADMIN_PASSWORD` | env/stdin **only** | Seed CLI has no password argv (`ps` would expose it); bootstrap runs only while `users` is empty |
| AD bind password | database column | Fernet-encrypted with a key derived from `SECRET_KEY` (`app/services/directory/secrets.py`); never returned by the API, never logged |
| Backup encryption key | env `BACKUP_ENCRYPTION_KEY` | AES-256-CBC + PBKDF2; keep separate from `SECRET_KEY` |

Rules:

* Never commit `.env`, `.env.*` (except `.env.example`), or `certs/` —
  all are gitignored.
* No secrets appear on command lines (argv is visible in `ps`), in container
  logs (structured logger never attaches secrets), or in API responses.
* Treat `.env` as a secret: `chmod 600`, restrict host access, rotate on
  staff change.

## HTTPS and headers

* Edge proxy (`infrastructure/nginx/eitop.conf`): TLSv1.2/1.3 only,
  modern cipher suite, HTTP→HTTPS redirect, HSTS, `client_max_body_size 10m`.
* Secure cookies: with `APP_ENV=production` the refresh cookie is issued
  `Secure` (plus `HttpOnly`, `SameSite=Lax`, `Path=/api/v1/auth`).
* CSRF: state-changing requests are rejected unless `Origin` is in
  `CORS_ORIGINS` (https only in production).
* The frontend container adds nosniff/frame-deny/referrer/CSP headers on
  every response; the edge adds HSTS.

## Operations

* **Logs**: JSON lines on stdout (docker json-file, rotated 5×10 MB by the
  overlay). No passwords/tokens/bind credentials are ever logged.
* **Health**: `GET /health` (liveness), `GET /health/ready` (db+redis).
  Worker health via `celery … inspect ping` (prod overlay healthcheck).
* **Restart**: all services `restart: unless-stopped`; worker/beat/broker
  recover automatically — see [../architecture.md](../architecture.md)
  ADRs for fail-closed rate limiting and sync-ownership leases.
* **Scaling**: `docker compose up -d --scale worker=2` (workers coordinate
  through DB leases; never scale `beat` — one scheduler only).

## Backups and recovery

See [backup-restore.md](backup-restore.md). Summary:

```bash
BACKUP_ENCRYPTION_KEY=… ./infrastructure/scripts/backup.sh ./backups
# restore into a disposable database and verify:
BACKUP_ENCRYPTION_KEY=… ./infrastructure/scripts/restore.sh backups/eitop-….sql.gz.enc eitop_restore
```

A backup is only complete once a restore has been demonstrated.

## Validation checklist (fresh environment)

1. `docker compose … up -d --build` → all services healthy
2. `alembic current` → head revision
3. Bootstrap admin → login → `/api/v1/auth/me` → 200
4. Endpoint API (`/api/v1/endpoints`) and directory API
   (`/api/v1/directory/connections`) → 200
5. `celery inspect ping` → pong; beat log shows schedule ticks
6. Restart the stack → data intact (endpoints/connections persist)
7. `backup.sh` → `restore.sh` into scratch DB → sanity counts match
8. `curl -I http://host/` → 301 to https; `curl -k https://host/api/v1/auth/me`
   → 401 problem (not blocked); refresh cookie carries `Secure`

## Troubleshooting

See [../troubleshooting/README.md](../troubleshooting/README.md).