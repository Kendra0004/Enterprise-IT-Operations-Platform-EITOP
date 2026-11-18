# Database Migrations

Alembic manages schema changes. **Never** modify an applied migration —
create a new one.

## Commands

```bash
cd backend
alembic current               # which revision is applied
alembic heads                 # latest available revision
alembic upgrade head          # apply all pending
alembic downgrade -1          # roll back one step
alembic revision --autogenerate -m "add endpoints table"
```

In Docker:

```bash
docker compose exec backend alembic current
docker compose exec backend alembic upgrade head
```

Migrations run automatically on container start (`backend/entrypoint.sh`).

## Conventions

- Revision IDs: sequential, readable (`0001_initial`, `0002_endpoints`).
- Additive-only in normal PRs. Dropping/renaming a column requires an ADR
  and a documented rollback plan.
- Every migration defines both `upgrade()` and `downgrade()`.
- Data seeds (RBAC roles/permissions) live in `app/db/seed.py`, not in
  migrations — they are idempotent and run separately.

## Testing migrations

```bash
# Round-trip test: full upgrade, then downgrade back to base
docker compose exec backend sh -c "alembic upgrade head && alembic downgrade base && alembic upgrade head"
```

The pytest suite runs `alembic upgrade head` against `eitop_test` at session
start, so schema drift fails CI immediately.
