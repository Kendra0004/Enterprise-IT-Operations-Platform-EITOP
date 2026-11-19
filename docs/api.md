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
| POST | `/login` | — | Credentials → access token + HttpOnly refresh cookie (rate-limited) |
| POST | `/refresh` | cookie | Rotate refresh cookie (rate-limited, no body) |
| POST | `/logout` | Bearer + cookie | Revoke refresh family, clear cookie → 204 |
| GET | `/me` | Bearer | Current user + roles + permissions |

> The refresh token is **never** present in a response body — it travels
> only in the `eitop_refresh` HttpOnly cookie (see
> [authentication.md](authentication.md)). State-changing requests carry an
> `Origin` header that must match `CORS_ORIGINS` or they are rejected 403.

### Endpoint management (Phase 2)

Full reference: [endpoints/api.md](endpoints/api.md).

| Method | Path | Permission |
|---|---|---|
| GET | `/endpoints?page=&page_size=&status=&group_id=&q=&os=&agent_version=&heartbeat_from=&heartbeat_to=&sort=&order=` | `endpoints:read` |
| GET | `/endpoints/overview` | `endpoints:read` |
| GET | `/endpoints/{id}` · `/health` · `/snapshots` · `/snapshots/{sid}` · `/software` · `/network` | `endpoints:read` |
| POST | `/endpoints/{id}/revoke` · `/rotate-credential` | `endpoints:write` |
| GET/POST | `/endpoints/groups` · GET `/endpoints/groups/{gid}` | read / write |
| POST/DELETE | `/endpoints/{id}/groups/{gid}` (assign/remove) | `endpoints:write` |
| POST | `/agent/enroll` · `/agent/heartbeat` · `/agent/inventory` · `/agent/rotate-credential` | endpoint credential |

`status` accepts `active` \| `offline` \| `revoked`; history routes accept
`from`/`to` bounded to 366 days; `page_size` ≤ 100.

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
  -H 'Origin: http://localhost:8080' \
  -d '{"email":"admin@example.com","password":"..."}' | jq -r .access_token)

curl -s localhost:8000/api/v1/audit-logs \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Versioning

Breaking changes require `/api/v2` alongside `/api/v1` — existing routes are
never redefined in place within a major version.
