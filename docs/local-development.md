# Local Development

## Day-to-day loop

```bash
# One-time
cp .env.example .env   # set SECRET_KEY
docker compose up -d postgres redis   # only the data services

# Backend (host venv)
cd backend && source .venv/bin/activate
pip install -r requirements-dev.txt   # runtime + test/lint toolchain
uvicorn app.main:app --reload

# Frontend (host)
cd frontend && npm run dev
```

The Vite dev server proxies `/api` and `/health` to `localhost:8000`
(override with `VITE_BACKEND_URL`).

## Full stack in Docker

```bash
docker compose up --build -d
docker compose logs -f backend     # structured JSON logs
```

## Project layout

```
backend/app/
  api/           # routers + dependencies (HTTP layer)
  core/          # config, db, redis, security, logging, exceptions, rate limit
  models/        # SQLAlchemy ORM models
  schemas/       # Pydantic request/response contracts
  services/      # business logic + audit writes
  db/            # seed script
  tasks/         # Celery tasks
backend/tests/   # pytest suites
frontend/src/    # React SPA (auth, layout, pages, api client)
frontend/tests/  # vitest suites
docs/            # this documentation
```

## Conventions

- Type-annotate everything; `ruff` + `mypy` must pass before pushing.
- New endpoint → new test. No exceptions.
- Errors: raise `AppError(status, title, detail)` — handlers render RFC 9457.
- Mutating operations that matter security-wise → `_record_audit(...)`.
- Never log passwords, tokens, or `SECRET_KEY`.
- Never pass passwords via command-line arguments (use env/stdin/getpass).
- State-changing endpoints must keep working with the `Origin` check and
  cookie-based refresh transport (see docs/authentication.md).

## Git workflow

Branch from `main`, conventional-ish commit subjects (`auth: …`, `api: …`),
open a PR with the template filled in.
