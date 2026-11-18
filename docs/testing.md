# Running Tests

## Backend (pytest)

Requires PostgreSQL + Redis. With the compose stack running:

```bash
docker compose up -d postgres redis
cd backend && source .venv/bin/activate   # or use the backend container

export TEST_DATABASE_URL="postgresql+psycopg://eitop:eitop@localhost:5432/eitop_test"
export TEST_REDIS_URL="redis://localhost:6379/1"
export SECRET_KEY="test-secret-key-not-for-production-use"
pytest
```

In Docker (matches CI exactly):

```bash
docker compose run --rm --no-deps --entrypoint "" backend sh -c \
  "TEST_DATABASE_URL=postgresql+psycopg://eitop:eitop@postgres:5432/eitop_test \
   TEST_REDIS_URL=redis://redis:6379/1 \
   SECRET_KEY=test-secret-key-not-for-production-use \
   python -m pytest tests -v"
```

> The test database is migrated with `alembic upgrade head` at session start
> and re-seeded idempotently. Tests that need Postgres/Redis are skipped
> **with an explicit reason** when the service is unreachable — the suite
> never silently substitutes a fake database.

### What is covered

| Area | File |
|---|---|
| Startup, OpenAPI, health, problem+json | `tests/test_health.py` |
| Argon2 hashing, JWT roundtrip/rejection, refresh digest | `tests/test_security.py` |
| Login, refresh rotation + reuse detection, logout, `/me` | `tests/test_auth.py` |
| Role × endpoint permission matrix, 401/403 paths | `tests/test_rbac.py` |
| User CRUD, audit entries, no password leakage in logs | `tests/test_users_and_audit.py` |
| DB config, session rollback, token hash uniqueness | `tests/test_database.py` |
| Rate limiter windows, identifier isolation, X-Forwarded-For | `tests/test_rate_limit.py` |

## Frontend (vitest)

```bash
cd frontend
npm test           # unit + component tests (jsdom)
npx tsc --noEmit   # strict typecheck
npm run build      # production build gate
```

Covers: API client problem parsing / bearer attach / network failure /
token storage, route protection redirect, login form render.

## Static analysis

```bash
cd backend && ruff check app tests && mypy app
```

CI runs all of the above plus Trivy image scanning — see
`.github/workflows/ci.yml`.

## Coverage

```bash
pytest --cov=app --cov-report=term-missing
```

Target: ≥70% overall, ≥80% for `app/core` + auth paths (enforced as the
suite grows; current Phase-1 core paths are fully exercised).
