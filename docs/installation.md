# Installation

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Docker + Compose | 24+ / 2.x | Run the full stack (recommended) |
| Python | 3.12 | Backend (only if running without Docker) |
| Node.js | 20+ (22 LTS recommended) | Frontend (only if running without Docker) |
| PostgreSQL | 16 | Database (bundled in compose) |
| Redis | 7 | Rate limiting / broker (bundled in compose) |

No paid services, APIs, or subscriptions are required.

## Install with Docker (recommended)

```bash
git clone <repo-url> eitop && cd eitop
cp .env.example .env
# Edit .env: set SECRET_KEY to a long random value:
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
docker compose up --build -d
```

Verify:

```bash
curl -s http://localhost:8000/health          # {"status":"ok"}
curl -s http://localhost:8000/health/ready    # db + redis checks
open http://localhost:8080                    # SPA
```

Create the first admin user (only runs when the user table is empty).
**Never pass the password as a CLI argument** — use the hidden prompt, the
environment, or stdin:

```bash
# Interactive (hidden prompt, TTY)
docker compose exec backend python -m app.db.seed --admin-email admin@example.com

# Scripted: environment (recommended)
docker compose exec \
  -e BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
  -e BOOTSTRAP_ADMIN_PASSWORD='Your#Str0ngPass!' \
  backend python -m app.db.seed

# Scripted: stdin
printf '%s\n' 'Your#Str0ngPass!' | docker compose exec -T -i backend \
  python -m app.db.seed --admin-email admin@example.com --admin-password-stdin
```

> Password must be ≥12 characters. `.local`, `.test` and other special-use
> domains are rejected by email validation — use a real-looking domain.

## Install without Docker

```bash
# Database
createdb eitop && createdb eitop_test

# Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
export DATABASE_URL="postgresql+psycopg://eitop:eitop@localhost:5432/eitop"
alembic upgrade head
python -m app.db.seed --admin-email admin@example.com --admin-password '...'
uvicorn app.main:app --reload                 # :8000

# Frontend (second terminal)
cd frontend
npm install
npm run dev                                   # :5173, proxies /api → :8000
```

## Uninstall / reset

```bash
docker compose down          # stop containers
docker compose down -v       # ALSO delete database volumes
```
