# Environment Variables

All configuration is environment-driven. Copy `.env.example` → `.env`.
`.env` is git-ignored — never commit it.

## Application

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `EITOP` | Display name (OpenAPI title) |
| `APP_ENV` | `development` | `development` \| `testing` \| `production` |
| `DEBUG` | `true` | Verbose error detail toggle |
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

## Security

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | **required** | JWT signing key. ≥16 chars enforced. Generate: `python -c "import secrets; print(secrets.token_urlsafe(64))"` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access JWT lifetime (1–60) |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime (1–90) |
| `CORS_ORIGINS` | `http://localhost:8080,...` | Comma-separated allowlist; `*` never used |
| `RATE_LIMIT_LOGIN_PER_MINUTE` | `10` | Login attempts per IP per minute |
| `RATE_LIMIT_REFRESH_PER_MINUTE` | `30` | Refresh calls per IP per minute |

## Data services

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://eitop:eitop@localhost:5432/eitop` | SQLAlchemy URL (psycopg v3 driver) |
| `REDIS_URL` | `redis://localhost:6379/0` | Rate limiter + Celery broker/backend |
| `TEST_DATABASE_URL` | `.../eitop_test` | Test suite target DB |
| `TEST_REDIS_URL` | `redis://localhost:6379/1` | Test suite target Redis DB |

## Bootstrap (optional)

| Variable | Description |
|---|---|
| `BOOTSTRAP_ADMIN_EMAIL` | First admin email — used only when `users` table is empty |
| `BOOTSTRAP_ADMIN_PASSWORD` | Min 12 chars; ignored once any user exists. Prefer env/stdin — the seed CLI deliberately has **no password argument** (argv is visible in `ps`) |

## Data services (compose)

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `eitop` / dev default / `eitop` | Dev defaults — **override in production** |
| `REDIS_PASSWORD` | dev default | Enables Redis `--requirepass` inside the compose network |

## Frontend (Vite)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `/api/v1` | API prefix baked at build time |
| `VITE_BACKEND_URL` | `http://localhost:8000` | Dev-proxy target only |
