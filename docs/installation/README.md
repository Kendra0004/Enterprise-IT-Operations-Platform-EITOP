# Installation — development

Get an EITOP development stack running locally. For production see
[production.md](production.md); for the deeper dev-loop conventions see
[../local-development.md](../local-development.md).

## Prerequisites

- Docker + Docker Compose ≥ 2.24 (base stack also works with older
  v2; the production overlay needs `!override` support)
- Git
- Node.js ≥ 20 and Python ≥ 3.12 **only** for running frontend/backend
  tools directly on the host (optional — everything runs in containers
  otherwise)

## Quick start

```bash
git clone <repo-url>
cd EITOP
cp .env.example .env            # dev defaults are intentionally usable as-is
docker compose up -d --build
```

Expected state:

```bash
docker compose ps               # backend/postgres/redis healthy, others Up
curl -s localhost:8000/health   # {"status":"ok"}
curl -s localhost:8000/health/ready   # {"status":"ready","checks":{"database":"ok","redis":"ok"}}
open http://localhost:8080      # SPA (login page)
```

On first start the backend entrypoint automatically runs
`alembic upgrade head` (schema) and seeds RBAC roles/permissions.

Create the first admin (only ever works while the `users` table is
empty — see [../runbooks/administrator-bootstrap.md](../runbooks/administrator-bootstrap.md)):

```bash
printf '%s' '<password ≥12 chars>' | \
  docker compose exec -T backend python -m app.db.seed \
    --admin-email admin@example.com --admin-password-stdin
```

Then log in at `http://localhost:8080`.

## Repository layout

```
EITOP/
├── backend/            FastAPI app, Celery tasks, alembic migrations, tests
├── frontend/           React SPA (Vite, TypeScript)
├── collectors/
│   ├── linux/          Python collector (pytest suite)
│   └── windows/        PowerShell collector (Pester suite)
├── docs/               all documentation (start at README.md)
├── infrastructure/
│   ├── nginx/          production edge-proxy config
│   └── scripts/        backup.sh / restore.sh
├── docker-compose.yml          dev stack
├── docker-compose.prod.yml     production overlay
└── .env.example                all supported variables
```

## Common development commands

| Task | Command |
|---|---|
| Backend tests | `docker compose run --rm --entrypoint "" tester sh -c "python -m pytest -q -p no:warnings -o addopts=''"` |
| Lint + types | `docker run --rm -v $PWD:/work -w /work/backend --entrypoint "" eitop-tester sh -c "ruff check --no-cache app tests && MYPY_CACHE_DIR=/tmp/mypy_cache mypy app"` |
| Frontend tests | `cd frontend && npx vitest run` |
| Type-check / build | `cd frontend && npx tsc --noEmit && npm run build` |
| Linux collector tests | `cd collectors/linux && .venv/bin/pytest -p no:warnings -q` |
| Windows collector tests | see [../testing.md](../testing.md) (Pester in container) |
| Rebuild after backend changes | `docker compose build backend && docker compose up -d backend` (the tester image bakes app code — rebuild it too: `docker compose build tester`) |
| Logs | `docker compose logs -f backend worker` |

Full gate list: [../testing.md](../testing.md).

## Service ports (dev)

| Service | Address | Notes |
|---|---|---|
| Frontend (SPA + API proxy) | `http://localhost:8080` | primary entry |
| Backend API direct | `http://127.0.0.1:8000` | loopback only, bypasses proxy — never expose |
| PostgreSQL | internal only | `docker compose exec postgres psql -U eitop -d eitop` |
| Redis | internal only | `docker compose exec redis redis-cli` |

## Uninstall / reset

```bash
docker compose down         # keep data volumes
docker compose down -v      # DESTROY all data (dev only!)
```

## Next steps

- [Testing guide](../testing.md) · [Local development conventions](../local-development.md)
- [Configuration reference](../configuration/README.md)
- [Runbooks](../runbooks/README.md)
