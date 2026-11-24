# EITOP — Enterprise IT Operations Platform

EITOP is an open-source, modular enterprise IT operations platform for endpoint
inventory, security compliance, vulnerability management, network operations,
and IT automation.

> **Status:** Phase 3.2.3 — foundation, endpoint operations, and the
> read-only Active Directory module (sync, inventory, security findings,
> insights) are implemented with real backend data. Administration remains
> marked "Soon" in the UI until implemented.

## Features

### Platform core (Phase 1)

- FastAPI backend with versioned REST API (`/api/v1`)
- Argon2id password hashing, JWT access tokens, rotating refresh tokens
  with reuse detection; refresh token in an **HttpOnly cookie** (never in
  JSON bodies or localStorage) with CSRF Origin checks
- Role-based access control (admin, security_auditor, operator, readonly, agent)
- Audit logging of authentication and privileged actions — append-only at
  the application *and* database level (PostgreSQL trigger)
- Structured JSON logging, RFC 9457 problem responses, health/readiness probes
- Security headers (nosniff, frame deny, referrer policy, CSP on the SPA)
- Redis-backed rate limiting on auth endpoints (fails closed; proxy
  overwrites `X-Forwarded-For` so the key cannot be spoofed)

### Endpoint operations (Phase 2)

- Linux agent and Windows collector: inventory, heartbeat, enrollment,
  secure communication with the platform
- Endpoint inventory with detail views, history, OS/process/agent data
- Endpoint groups and a management dashboard with monitoring views
- React + TypeScript + Vite + Tailwind CSS + TanStack Query frontend with
  an enterprise design system (light/dark themes)

### Active Directory — read-only (Phase 3)

- LDAP/LDAPS connections (secrets Fernet-encrypted, never exposed by the API)
- Synchronization engine with lifecycle hardening: category tracking,
  freshness/overdue evaluation, never writing back to the directory
- Directory objects: users, groups, computers, OUs, memberships
- Security findings engine (privileged membership, stale/disabled subjects,
  sync freshness) with severity, acknowledge/suppress/reopen lifecycle
- Insights UI: findings table with server-side sort/filter/pagination,
  summary metrics, detail drawer with structured evidence
- Health tab: newest-run verdict, category completeness, visibility, freshness
- Correlation Gaps tab: never_reconciled / unmatched / ambiguous only,
  with unconfirmed candidates clearly labelled

### Operations

- Docker Compose stack (backend, worker, frontend, PostgreSQL, Redis with
  requirepass; data services unpublished, backend loopback-only)
- Alembic migrations, CI (ruff, mypy, pytest, frontend tests, Trivy scan),
  full test suites for backend, frontend, Linux collector, and Windows
  collector (Pester)

## Quick start (Docker)

```bash
cp .env.example .env          # then set SECRET_KEY!
docker compose up --build
```

- Frontend: http://localhost:8080
- Backend API + OpenAPI docs: http://localhost:8000/docs

## Quick start (local development)

Requires Python 3.12, Node 20+, PostgreSQL, Redis. See
[docs/local-development.md](docs/local-development.md).

```bash
# Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head
python -m app.db.seed          # seed roles + permissions
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev                    # http://localhost:5173 (proxies /api to :8000)
```

## Tests

```bash
cd backend && pytest           # needs Postgres + Redis, see docs/testing.md
cd frontend && npm test
cd collectors/linux && .venv/bin/pytest
cd collectors/windows && Invoke-Pester -Path ./tests
```

## Documentation

| Document | Path |
|---|---|
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Installation | [docs/installation.md](docs/installation.md) |
| Local development | [docs/local-development.md](docs/local-development.md) |
| Environment variables | [docs/environment-variables.md](docs/environment-variables.md) |
| Database migrations | [docs/database-migrations.md](docs/database-migrations.md) |
| Authentication flow | [docs/authentication.md](docs/authentication.md) |
| RBAC model | [docs/rbac.md](docs/rbac.md) |
| API documentation | [docs/api.md](docs/api.md) |
| Running tests | [docs/testing.md](docs/testing.md) |
| Endpoint & agent docs | [docs/endpoints/](docs/endpoints/) |
| Frontend design system | [docs/frontend/design-system.md](docs/frontend/design-system.md) |
| Deployment | [docs/deployment/](docs/deployment/) |
| Troubleshooting | [docs/troubleshooting/](docs/troubleshooting/) |
| User guides | [docs/user-guides/](docs/user-guides/) |
| Phase 1 security review | [docs/security/PHASE1_SECURITY_REVIEW.md](docs/security/PHASE1_SECURITY_REVIEW.md) |
| UI screenshots | [docs/screenshots/](docs/screenshots/) |

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md). Never commit secrets;
all configuration is via environment variables (see `.env.example`).

## License

MIT — see [LICENSE](LICENSE).
