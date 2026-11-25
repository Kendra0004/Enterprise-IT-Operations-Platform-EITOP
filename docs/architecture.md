# EITOP Architecture

## Overview

EITOP is a **modular monolith**: one FastAPI application serving a versioned
REST API, one Celery worker for background jobs, one React SPA, PostgreSQL as
the system of record, Redis for rate limiting / caching / job broker.

Modules are isolated Python packages under `backend/app/` with defined
boundaries. Microservices are explicitly **not** used at this stage — the
monolith keeps transactions, migrations, and deployment simple while module
packages preserve a path to later extraction.

```
                 ┌────────────────────────────┐
                 │  React SPA (nginx) :8080   │
                 └─────────────┬──────────────┘
                               │ /api/* proxy
                 ┌─────────────▼──────────────┐
                 │  FastAPI  :8000            │
                 │  ├─ /api/v1/* routers      │
                 │  ├─ auth + RBAC deps       │
                 │  ├─ audit middleware/svc   │
                 │  ├─ RFC 9457 handlers      │
                 │  └─ structured JSON logs   │
                 └──────┬──────────────┬──────┘
                        │              │
              ┌─────────▼───┐    ┌─────▼─────┐
              │ PostgreSQL  │    │   Redis    │
              │ (system of  │    │ rate-limit │
              │  record)    │    │ + celery   │
              └─────────▲───┘    └─────▲─────┘
                        │              │
                 ┌──────┴──────────────┴──────┐
                 │  Celery worker (app.tasks) │
                 └────────────────────────────┘
```

## Layers

| Layer | Location | Responsibility |
|---|---|---|
| API | `backend/app/api/` | HTTP routing, request/response schemas, status codes |
| Auth | `backend/app/core/security.py`, `api/deps.py` | Argon2, JWT, RBAC guards |
| Business logic | `backend/app/services/` | Transactions, audit writes, rotation rules |
| Data access | `backend/app/models/`, `core/database.py` | SQLAlchemy 2 ORM, session scoping |
| Config | `backend/app/core/config.py` | pydantic-settings, env-only secrets |
| Background jobs | `backend/app/core/celery_app.py`, `app/tasks/` | Celery (phase 2+ jobs) |
| Frontend | `frontend/src/` | SPA, API client, auth state, layout |

## Key decisions (ADR-lite)

1. **Sync SQLAlchemy + FastAPI `def` endpoints** — request handlers run in
   the threadpool; Celery workers share the same session code. Async would
   force two session styles for no Phase-1 benefit.
2. **Refresh tokens are opaque**, stored as SHA-256 digests, rotated on every
   use, grouped in *families* — reuse of a revoked token revokes the family
   (theft detection).
3. **Audit log is append-only** — no update/delete API surface exists.
4. **Rate limiting fails closed** — Redis outage rejects logins (503) rather
   than silently disabling brute-force protection.
5. **Errors are RFC 9457 `application/problem+json`** everywhere, including
   validation errors.
6. **Directory syncs are single-flight per connection** — a database lease
   guarantees one sync at a time; leases expire
   (`DIRECTORY_STALE_RUN_MINUTES`) so a dead worker cannot wedge a
   connection, and `DIRECTORY_MAX_SYNC_MINUTES` caps any run.
7. **Collectors push; the platform never dials endpoints** — enrollment
   issues a per-endpoint credential, agents submit heartbeat/inventory
   over HTTPS, and inventory ingestion is idempotent (current-state
   upsert + content-hash-deduplicated immutable snapshots).

## Data model

```
users ──< user_roles >── roles ──< role_permissions >── permissions
users ──< refresh_tokens (token_hash, family_id, revoked_at)
users ──< audit_logs (event_type, outcome, ip, detail)
```

Built on top of that auth core (migrations `0002`–`0007`):

- **Endpoints:** `endpoints`, `enrollment_tokens`, `endpoint_credentials`,
  `endpoint_groups`, inventory tables (`endpoint_metadata`,
  `endpoint_facts`, `endpoint_software`), snapshots
  (`endpoint_snapshots`, `endpoint_snapshot_software`).
- **Directory:** `directory_connections`, domains/OUs/users/groups/
  computers, `directory_sync_runs`, `directory_reconciliations`,
  `directory_findings`.

Planned-but-unbuilt modules (vulnerabilities, network devices, DNS
checks, automation jobs) will follow the same table-group pattern
without altering the auth core. See
[architecture/README.md](architecture/README.md) for the component
overview and [architecture/data-flow.md](architecture/data-flow.md) for
flows.

## Scalability path

- API is stateless (JWT) → horizontal scaling behind a load balancer.
- Celery workers scale independently (`docker compose up --scale worker=N`).
- Read replicas / partitioning for `audit_logs` when volume requires it.
- Module packages can be extracted into services only when a real scaling or
  team-ownership need appears — not before.
