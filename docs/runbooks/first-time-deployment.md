# Runbook 1 — First-time deployment

**Purpose:** stand up a fresh EITOP instance and verify it end to end.
**Prerequisites:** Docker Compose ≥ 2.24, host with ≥ 4 GB free RAM,
TLS certificates for production, a secrets source for `.env`.

## Development

```bash
git clone <repo> && cd EITOP
cp .env.example .env            # dev defaults are fine
docker compose up -d --build
```

Expected: all services reach `healthy` (backend healthcheck runs
`/health`), frontend serves on `http://localhost:8080`, API on
loopback `http://localhost:8000`.

```bash
docker compose ps
curl -s http://localhost:8000/health          # {"status":"ok"}
curl -s http://localhost:8000/health/ready    # db + redis "ok"
```

Migrations and RBAC seed run automatically on first backend start
(`backend/entrypoint.sh`: `alembic upgrade head` → seed → app).

## Production

Full detail: [../installation/production.md](../installation/production.md).

```bash
cp .env.example .env && chmod 600 .env
$EDITOR .env        # APP_ENV=production, DEBUG=false, strong SECRET_KEY,
                    # strong POSTGRES_PASSWORD/REDIS_PASSWORD, https CORS_ORIGINS
mkdir -p certs      # fullchain.pem + privkey.pem for your domain

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Expected: `proxy` publishes 80/443 only; `docker compose … ps` shows
backend/worker/postgres/redis `healthy`, beat `Up`, proxy `Up`.

**Failure — backend exits with
`Insecure production configuration: …`:** the fail-fast validator
rejected the listed values. Fix each named item in `.env`, re-run
`up -d`. Nothing is half-started: the container simply exits.

**Failure — worker/beat restart-loop:** same validator; check
`docker compose logs worker | tail -50`.

## Post-deploy verification checklist

1. `alembic current` == `alembic heads` (see runbook 11).
2. Bootstrap an admin ([runbook 2](administrator-bootstrap.md)).
3. Login over HTTPS; refresh cookie must show `Secure`.
4. `GET /api/v1/endpoints` → 200 (empty list is fine).
5. `GET /api/v1/directory/connections` → 200.
6. Worker: `docker compose exec worker celery -A app.core.celery_app:celery_app inspect ping` → `pong`.
7. Beat log shows a tick: `docker compose logs beat | tail -5`.
8. Restart the stack (`docker compose restart backend worker beat`) and
   confirm login still works — data persists on volumes.
9. Take a backup and restore it into a scratch DB
   ([runbook 9](backup-scheduling.md), [runbook 10](database-restoration.md)).

**Security warning:** never commit `.env` or `certs/` — both are
gitignored for this reason. Treat `.env` as a secret (`chmod 600`).
