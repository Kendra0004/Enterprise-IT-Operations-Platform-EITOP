# Installation — production

Step-by-step production deployment. Operational detail (secrets
management, HTTPS internals, scaling, logs) lives in
[../deployment/README.md](../deployment/README.md); recovery procedures
in [../deployment/backup-restore.md](../deployment/backup-restore.md).

## Prerequisites

- Docker Compose ≥ **2.24** (production overlay uses `!override`)
- DNS name + certificate chain for the serving domain (Let's Encrypt,
  corporate PKI, or a trusted internal CA) — **the repo ships no
  certificates**
- A secrets store for `.env` and the backup key (separate locations)
- Host with ≥ 4 GB RAM, persistent disk for Docker volumes

## 1. Environment file

```bash
git clone <repo-url> && cd EITOP
cp .env.example .env
chmod 600 .env
$EDITOR .env
```

The application **refuses to start** in production unless all of these
hold (fail-fast validation in `backend/app/core/config.py`, enforced in
API, worker, beat and migrations):

| Variable | Requirement |
|---|---|
| `APP_ENV` | `production` |
| `DEBUG` | `false` |
| `SECRET_KEY` | ≥ 32 chars, not a placeholder — `python3 -c "import secrets; print(secrets.token_urlsafe(64))"` |
| `POSTGRES_PASSWORD` | strong, ≠ dev defaults |
| `REDIS_PASSWORD` | strong, ≠ dev defaults |
| `CORS_ORIGINS` | `https://…` origins, comma separated, no `*` |
| `DATABASE_URL` / `REDIS_URL` | built from the strong passwords |

All violations are reported together in one startup error.

## 2. TLS material

```bash
mkdir -p certs   # gitignored
# place your chain here:
#   certs/fullchain.pem   (server cert + intermediates)
#   certs/privkey.pem     (private key, mode 0600)
chmod 600 certs/privkey.pem
```

## 3. Start the stack

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Expected: `postgres`/`redis`/`backend` **healthy**, `worker` healthy,
`beat` up, `frontend` up, `proxy` up. Only ports **80/443** are
published; backend/frontend/postgres/redis expose nothing.

## 4. Migrations + RBAC seed

Automatic on backend start (`backend/entrypoint.sh`). Verify:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  exec backend alembic current    # must print the head revision
```

## 5. Bootstrap the first administrator

Only works while the `users` table is empty
([../runbooks/administrator-bootstrap.md](../runbooks/administrator-bootstrap.md)):

```bash
printf '%s' "$BOOTSTRAP_ADMIN_PASSWORD" | \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T backend \
    python -m app.db.seed --admin-email admin@your-domain.com --admin-password-stdin
```

Expected: `Admin bootstrap: created.`

## 6. Verify

```bash
# HTTP redirects to HTTPS (301), HSTS present
curl -sI http://$HOST/ | head -1
curl -sI https://$HOST/ | grep -i strict-transport

# login + Secure cookie
curl -sk -D - -o /dev/null -X POST https://$HOST/api/v1/auth/login \
  -H 'Content-Type: application/json' -H "Origin: https://$HOST" \
  -d "{\"email\":\"admin@your-domain.com\",\"password\":\"$BOOTSTRAP_ADMIN_PASSWORD\"}" \
  | grep -i set-cookie        # must contain: HttpOnly; ... SameSite=lax; ... Secure

# readiness + APIs
curl -sk https://$HOST/health/ready
# (with TOKEN from the login response)
curl -sk https://$HOST/api/v1/endpoints -H "Authorization: Bearer $TOKEN"
curl -sk https://$HOST/api/v1/directory/connections -H "Authorization: Bearer $TOKEN"

# worker + beat
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  exec worker celery -A app.core.celery_app:celery_app inspect ping   # pong
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  logs --tail 5 beat    # scheduler ticks
```

Full checklist (incl. restart persistence and a backup→restore
round-trip): [../deployment/README.md](../deployment/README.md#validation-checklist-fresh-environment).

## 7. Schedule backups

Daily cron + verification: [../runbooks/backup-scheduling.md](../runbooks/backup-scheduling.md).

## Upgrades

[../runbooks/upgrades-and-migrations.md](../runbooks/upgrades-and-migrations.md).

## Troubleshooting

[../troubleshooting/README.md](../troubleshooting/README.md) — most
first-boot failures are the fail-fast validator naming exact `.env`
fixes.

**Security warnings**

- `.env` and `certs/` are gitignored — never force-add them.
- No default admin password exists anywhere in the product; the
  bootstrap password you generate is yours to store securely.
