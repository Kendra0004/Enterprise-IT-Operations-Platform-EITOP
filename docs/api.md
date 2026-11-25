# API Documentation

**Canonical reference: [api/README.md](api/README.md)** — conventions,
authentication, CSRF, pagination, error format, the complete 61-route
inventory with required permissions, and the role × permission matrix.

Module-specific detail lives with each module:

- Endpoint & agent routes: [endpoints/api.md](endpoints/api.md)
- Authentication flow: [authentication.md](authentication.md)
- Interactive docs (development only): `GET /docs`, `GET /redoc`,
  `GET /openapi.json` — disabled in production.

This file previously held condensed route tables; they were removed
when the complete reference (including the Phase 3 directory routes)
became [api/README.md](api/README.md) — keeping two inventories caused
them to drift.
