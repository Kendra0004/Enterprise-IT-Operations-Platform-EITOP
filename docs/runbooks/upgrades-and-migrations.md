# Runbook 11 — Application upgrades and migrations

**Purpose:** upgrade EITOP to a newer version safely.
**Prerequisites:** recent backup ([runbook 9](backup-scheduling.md)),
`admin` shell access.

## Standard upgrade

```bash
cd /opt/eitop
git fetch && git checkout <tag-or-commit>     # or pull main
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  up -d --build
```

Expected:

1. Images rebuild.
2. Backend entrypoint runs `alembic upgrade head` → RBAC seed (idempotent,
   additive) → app.
3. All services healthy; `/health/ready` → `ok`.
4. Worker/beat restart with the new code; beat resumes its schedule.

Verify:

```bash
docker compose exec backend alembic current    # == alembic heads
curl -s https://$HOST/health/ready
docker compose exec worker celery -A app.core.celery_app:celery_app inspect ping
```

## Migration procedure (what actually happens)

- Migrations live in `backend/alembic/versions/`; **forward-only in
  production**. `alembic downgrade` exists for development only.
- Every upgrade is: `backup.sh` → deploy → automatic `upgrade head` →
  verify `alembic current == alembic heads`.
- The seed is additive: new permissions/roles from the new version are
  granted to existing roles; nothing is revoked.

Manual equivalent (to preview before restarting):

```bash
docker compose exec backend alembic history     # what would apply
docker compose exec backend alembic upgrade head # apply (idempotent)
```

## Rollback

1. `git checkout <previous-tag>` and `up -d --build` (code rollback).
2. **Do not** run `alembic downgrade` against production data unless the
   migration explicitly documents data-safety — prefer restoring the
   pre-upgrade backup ([runbook 10](database-restoration.md)) when a
   schema rollback is unavoidable.
3. Verify login, `/health/ready`, worker ping, and one endpoint page.

## Failure symptoms

| Symptom | Cause | Recovery |
|---|---|---|
| Backend exits during `alembic upgrade head` | migration error | read `docker compose logs backend`; fix forward with a corrective migration — never edit tables by hand; restore backup if the DB is mid-broken |
| `alembic current` behind head after "successful" start | entrypoint interrupted | `docker compose exec backend alembic upgrade head` |
| RBAC seed errors | DB manually altered | restore role/permission tables from backup; seed is idempotent otherwise |
| Worker crash-loop after upgrade | new code + old env | compare `.env` against the new `.env.example` — new required variables fail fast by name |
| Frontend shows old assets | browser cache / CDN | hard refresh; assets are content-hashed |

**Security warnings**

- Upgrades can add fail-fast configuration checks — a bad `.env` now
  stops the container on purpose; read the named error, do not disable
  validation.
- Keep `SECRET_KEY` stable across upgrades (rotation has consequences:
  [runbook 12](secret-rotation.md)).
