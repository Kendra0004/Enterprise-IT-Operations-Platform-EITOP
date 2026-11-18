# Running Tests

## Backend (pytest)

Requires PostgreSQL + Redis. With the compose stack running:

```bash
docker compose up -d postgres redis
cd backend && source .venv/bin/activate   # or use the tester container

export TEST_DATABASE_URL="postgresql+psycopg://eitop:eitop@localhost:5432/eitop_test"
export TEST_REDIS_URL="redis://:your-redis-password@localhost:6379/1"
export SECRET_KEY="test-secret-key-not-for-production-use"
pip install -r requirements-dev.txt
pytest
```

In Docker (matches CI exactly — uses the `tester` service, which is built
from the `dev` stage of the backend Dockerfile with the test toolchain):

```bash
docker compose run --rm --entrypoint "" tester \
  python -m pytest tests -v
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
| Login, refresh rotation + reuse detection, logout, `/me`, cookie transport | `tests/test_auth.py` |
| Role × endpoint permission matrix, 401/403 paths, escalation attempts | `tests/test_rbac.py` |
| User CRUD, audit entries, no password leakage in logs | `tests/test_users_and_audit.py` |
| DB config, session rollback, token hash uniqueness | `tests/test_database.py` |
| Rate limiter windows, identifier isolation, X-Forwarded-For | `tests/test_rate_limit.py` |
| CSRF origin check, security headers, audit DB immutability, production doc gating, timing-equalized login, bootstrap safety | `tests/test_security_hardening.py` |

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
docker compose run --rm --entrypoint "" tester sh -c \
  "ruff check --no-cache app tests && MYPY_CACHE_DIR=/tmp/mypy mypy app"
```

CI runs all of the above plus Trivy image scanning — see
`.github/workflows/ci.yml`.

## Dependency vulnerability scans

```bash
# Backend (Python) — runs in a throwaway container
docker run --rm -v "$PWD/backend/requirements.txt":/r.txt:ro python:3.12-slim \
  sh -c "pip install -q pip-audit && python -m pip_audit -r /r.txt"

# Frontend (npm)
cd frontend && npm audit
```

Production runtime dependencies are isolated in `requirements.txt` (the
production image contains no test/lint tooling); dev tools live in
`requirements-dev.txt`.

## Coverage

```bash
pytest --cov=app --cov-report=term-missing
```

Target: ≥70% overall, ≥80% for `app/core` + auth paths (enforced as the
suite grows; current Phase-1 core paths are fully exercised).
