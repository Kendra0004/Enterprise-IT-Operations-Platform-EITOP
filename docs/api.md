# API Documentation

Base URL: `/api/v1`. Interactive docs: `GET /docs` (Swagger UI), `GET /redoc`,
spec: `GET /openapi.json`.

## Conventions

- **Auth**: `Authorization: Bearer <access_token>`.
- **Errors**: always RFC 9457 `application/problem+json`:

  ```json
  {
    "type": "about:blank",
    "title": "Invalid credentials",
    "status": 401,
    "detail": "Email or password is incorrect.",
    "errors": [{"field": "email", "message": "..."}]
  }
  ```

  `errors[]` present on 422 validation failures (field paths without the
  `body`/`query` prefix).
- **Pagination**: `?page=1&page_size=20` →
  `{items: [...], total, page, page_size}` (max `page_size` 100–200 by endpoint).
- **Filtering**: `?event_type=…&outcome=…` on audit logs.
- **Status codes**: 200/201 success, 401 unauthenticated, 403 forbidden,
  404 missing resource, 409 conflict, 422 validation, 429 rate limited,
  503 dependency down.

## Endpoints (Phase 1)

### Health (unauthenticated)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness — process up |
| GET | `/health/ready` | Readiness — DB + Redis; 503 when degraded |

### Auth (`/api/v1/auth`)

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/login` | — | Credentials → token pair (rate-limited) |
| POST | `/refresh` | — | Rotate refresh token (rate-limited) |
| POST | `/logout` | Bearer | Revoke refresh family → 204 |
| GET | `/me` | Bearer | Current user + roles + permissions |

### Administration (`/api/v1`)

| Method | Path | Permission |
|---|---|---|
| GET | `/users?page=&page_size=` | `admin:read` |
| POST | `/users` | `admin:write` |
| GET | `/roles` | `admin:read` |
| GET | `/audit-logs?page=&event_type=&outcome=` | `audit:read` |

### Example

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"..."}' | jq -r .access_token)

curl -s localhost:8000/api/v1/audit-logs \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Versioning

Breaking changes require `/api/v2` alongside `/api/v1` — existing routes are
never redefined in place within a major version.
