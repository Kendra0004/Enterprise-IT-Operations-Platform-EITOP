# EITOP — Enterprise IT Operations Platform

EITOP is an open-source, modular enterprise IT operations platform for endpoint
inventory, security compliance, vulnerability management, network operations,
and IT automation.

> **Status:** Phase 1 — foundation (auth, RBAC, audit, API, frontend shell).
> Feature modules are clearly marked "Under development" in the UI until
> implemented with real backend data.

## Features (Phase 1)

- FastAPI backend with versioned REST API (`/api/v1`)
- Argon2id password hashing, JWT access tokens, rotating refresh tokens
  with reuse detection
- Role-based access control (admin, security_auditor, operator, readonly, agent)
- Audit logging of authentication and privileged actions
- Structured JSON logging, RFC 9457 problem responses, health/readiness probes
- Redis-backed rate limiting on auth endpoints (fails closed)
- React + TypeScript + Vite + Tailwind CSS + TanStack Query frontend
- Docker Compose stack (backend, worker, frontend, PostgreSQL, Redis)
- GitHub Actions CI (ruff, mypy, pytest, frontend tests)

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
pip install -r requirements.txt
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

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md). Never commit secrets;
all configuration is via environment variables (see `.env.example`).

## License

MIT — see [LICENSE](LICENSE).
