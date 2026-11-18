# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

### Added

- Phase 1 foundation:
  - FastAPI application factory, `/api/v1` versioned API
  - Structured JSON logging, RFC 9457 problem responses, exception handlers
  - Health (`/health`) and readiness (`/health/ready`) endpoints
  - PostgreSQL via SQLAlchemy 2 + Alembic migrations; Redis configuration
  - Argon2id password hashing, JWT access tokens, rotating refresh tokens
    with reuse detection
  - User/Role/Permission models, RBAC authorization dependencies
  - Audit logging for auth events and user management
  - Login/refresh rate limiting (Redis, fail-closed)
  - React + TypeScript + Vite + Tailwind + TanStack Query frontend shell:
    login, protected routes, sidebar/header layout, dashboard
  - Docker Compose stack (backend, worker, frontend, PostgreSQL, Redis)
  - GitHub Actions CI (ruff, mypy, pytest, frontend tests)
  - Project documentation (architecture, auth, RBAC, API, testing, ops)
