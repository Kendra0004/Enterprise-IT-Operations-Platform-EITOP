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
>
> `tests/test_directory_migration.py` is the exception that proves the rule:
> it creates its own scratch database (`eitop_mig_*`), runs
> `alembic upgrade head` → `downgrade 0004` → `upgrade head` against it in a
> subprocess with an overridden `DATABASE_URL`, and drops it afterwards — so
> the shared test schema is never downgraded. It skips with an explicit
> reason if `CREATE DATABASE` is denied.

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
| Endpoint enrollment, inventory/heartbeat, snapshots/diff, groups admin API | `tests/test_enrollment.py`, `tests/test_agent_api.py`, `tests/test_heartbeat_health.py`, `tests/test_snapshots.py`, `tests/test_groups_api.py`, `tests/test_endpoints_admin_api.py`, `tests/test_endpoint_models.py` |
| AD client: TLS handshake (trusted/untrusted/expired/hostname mismatch), StartTLS, no plaintext/bypass, paged search, filter escaping, error classification, connect-failure unbind cleanup | `tests/test_directory_client.py` |
| AD sync engine: category fail-fast, missing-marking grace, upsert idempotency, reconciliation rules, run lifecycle, enqueue failure, lease-aware stale-reap/concurrency, execution-token ownership (duplicate delivery, lease gates, stale-worker finalization), membership-rebuild rollback | `tests/test_directory_sync.py` |
| AD API: RBAC matrix, write-only bind password tracing, connection scoping, sanitized test/sync errors, 409/503/400 contracts | `tests/test_directory_api.py` |
| AD migration round-trip (downgrade/upgrade) on an **isolated scratch database** | `tests/test_directory_migration.py` |
| AD real-protocol (optional): TLS handshake → bind → paged search → wrong-password classification over a real TLS socket — **OpenLDAP, not real AD**; 3 explicit skips unless `EITOP_OPENLDAP_URL` is set | `tests/test_directory_openldap.py` |

## Frontend (vitest)

```bash
cd frontend
npm test           # unit + component tests (jsdom)
npx tsc --noEmit   # strict typecheck
npm run build      # production build gate
```

Covers: API client problem parsing / bearer attach / network failure /
token storage, route protection redirect, login form, endpoint
list/detail/history/groups pages, theme switching, dashboard KPI
links (Phase 2.8), and the Active Directory page — tab navigation,
connection-scoped queries, RBAC denial/affordance behavior, write-only
bind-password field, sanitized test/sync results (Phase 3.1).

## Browser verification + screenshots (Playwright)

With the stack running (`docker compose up -d`, UI at
`http://localhost:8080`):

```bash
cd frontend
npm i -D @playwright/test        # once
npx playwright install chromium  # once (add --with-deps where sudo allows)
node scripts/screenshots.mjs     # login + every page × dark/light × 4 viewports
```

Output: 57 PNGs in `docs/screenshots/` (see
`docs/frontend/design-system.md` for the matrix and limitations).

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
