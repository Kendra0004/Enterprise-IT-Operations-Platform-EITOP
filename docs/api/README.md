# API reference

EITOP's REST API — conventions, authentication, permissions, and the
complete route inventory. Generated from and verified against the
FastAPI route definitions (`backend/app/api/v1/`, 61 operations) and
the live OpenAPI document.

- Base path: `/api/v1` (health endpoints are mounted at root).
- All request/response bodies are JSON (`application/json`); errors are
  `application/problem+json` (RFC 9457-style).
- In production the API is reachable only through the TLS edge proxy;
  `Origin` must be in `CORS_ORIGINS` for state-changing requests.

## Authentication

### User sessions (browser)

| Step | Route | Notes |
|---|---|---|
| Login | `POST /api/v1/auth/login` `{email,password}` | `200` → `{access_token, token_type:"bearer", …}` **and** `Set-Cookie: eitop_refresh` (`HttpOnly`, `SameSite=Lax`, `Path=/api/v1/auth`, `Secure` in production) |
| Authenticated calls | any route below | `Authorization: Bearer <access_token>` (JWT, TTL `ACCESS_TOKEN_EXPIRE_MINUTES`, default 15 min) |
| Refresh | `POST /api/v1/auth/refresh` | sends the cookie only; returns a **new** access token and **rotates** the refresh cookie (old value invalidated) |
| Current user | `GET /api/v1/auth/me` | `200` → profile + roles |
| Logout | `POST /api/v1/auth/logout` | requires Bearer **and** cookie; revokes the refresh-token family, clears the cookie, `204` |

Token lifecycle guarantees:

- **Rotation:** every refresh issues a fresh opaque token and retires
  the previous one.
- **Reuse detection:** presenting an already-rotated token →
  `auth.refresh.reuse` audit event and revocation of the whole token
  family (all sessions of that login lineage die).
- **Rate limits:** login `RATE_LIMIT_LOGIN_PER_MINUTE` (10/min),
  refresh `RATE_LIMIT_REFRESH_PER_MINUTE` (30/min), per client IP +
  bucket. **Fail-closed:** Redis unavailable ⇒ `503`, never open.
- Unknown e-mails still perform a dummy password verification (timing
  equalization).

### CSRF

Any `POST/PUT/PATCH/DELETE` under `/api/v1` that carries an `Origin`
header not in `CORS_ORIGINS` is rejected `403`
(`Cross-origin request rejected`). Safe methods are exempt;
non-browser clients (no `Origin`) are unaffected.

### Agent (collector) authentication

Separate credential space, **no JWTs**:

| Route | Credential |
|---|---|
| `POST /api/v1/agent/enroll` | single-use enrollment token (rate-limited, 16 KB cap) |
| `POST /api/v1/agent/heartbeat`, `/inventory`, `/rotate-credential` | `Authorization: Bearer eitop_ep_…` bound to one endpoint |

User JWTs are rejected on `/agent/*` and agent credentials on user
routes. A user `agent` role exists in RBAC but is not a login path.

## Error responses

Every error body:

```json
{
  "type": "about:blank",
  "title": "Not authenticated",
  "status": 401,
  "detail": "Missing bearer access token."
}
```

`Content-Type: application/problem+json`. Validation failures add an
`errors` array of `{field, message}`. Common statuses:

| Status | Meaning |
|---|---|
| `400` | malformed request (e.g. unknown role, bad `Content-Length`) |
| `401` | missing/invalid/expired token, deactivated user, bad agent credential |
| `403` | insufficient permission **or** disallowed `Origin` |
| `404` | not found (also used for cross-connection ids — no existence leak) |
| `409` | conflict (duplicate e-mail, sync already running) |
| `413` | body over path limit (see below) |
| `422` | schema validation failure (`errors[]`) |
| `429` | rate limit (login/refresh/enroll) |
| `503` | dependency unavailable (fail-closed rate limiter; `/health/ready`) |

Body-size limits (from `Content-Length`, checked before parsing):

| Path prefix | Limit |
|---|---|
| `/api/v1/agent/inventory` | 5 MB |
| `/api/v1/agent/enroll` | 16 KB |
| `/api/v1/agent/` | 8 KB |
| `/api/v1/endpoints/` | 256 KB |
| `/api/v1/` | 64 KB |

## Pagination, filtering, sorting

List endpoints return a `Page`:

```json
{"items":[…],"total":123,"page":1,"page_size":20}
```

- `page` ≥ 1 (default 1); `page_size` default 20, max 100 — except
  `GET /api/v1/audit-logs` (default 50, max 200).
- Filtering: `q` (substring, ≤ 255) on searchable lists;
  `GET /endpoints` also supports `status` (`active|offline|revoked`),
  `group_id`, `os`, `agent_version`, `heartbeat_from`/`heartbeat_to`.
- Sorting: `sort=<field>&order=asc|desc`. Endpoint list `sort` ∈
  `hostname, status, os, agent_version, enrolled_at, last_heartbeat_at`
  (default `enrolled_at`); invalid fields → `400 Invalid sort field`.
- `GET /directory/findings` requires `connection_id` (query) and
  supports `subject_type`, `access`, `status` filters.

## Permission matrix

Permission catalog and seeded roles (source of truth:
`backend/app/db/seed.py`):

| Permission | admin | security_auditor | operator | readonly | agent |
|---|:--:|:--:|:--:|:--:|:--:|
| `admin:read` | ✅ | | | | |
| `admin:write` | ✅ | | | | |
| `audit:read` | ✅ | ✅ | | | |
| `endpoints:read` | ✅ | ✅ | ✅ | ✅ | |
| `endpoints:write` | ✅ | | ✅ | | ✅ |
| `directory:read` | ✅ | ✅ | ✅ | ✅ | |
| `directory:write` | ✅ | | | | |
| `directory:sync` | ✅ | | | | |
| `security:read` | | ✅ | | ✅ | |
| `vulns:read` | | ✅ | | ✅ | |
| `vulns:write` | | | | | |
| `network:read` | | ✅ | ✅ | ✅ | |
| `network:write` | | | | | |
| `automation:read` | | | ✅ | | |
| `automation:execute` | | | ✅ | | |
| `assets:read` | | ✅ | ✅ | ✅ | |
| `assets:write` | | | ✅ | | |
| `reports:read` | | ✅ | ✅ | ✅ | |

(Catalog entries without a ✅ above exist for future modules — no route
uses them yet.)

Checks run per request against the DB (roles are not baked into
tokens).

## Routes

Legend: **U** = any authenticated user · **R/W/S** = `directory:read` /
`directory:write` / `directory:sync` · **ER/EW** = `endpoints:read` /
`endpoints:write` · **AR/AW** = `admin:read` / `admin:write` ·
**AU** = `audit:read` · **agent** = endpoint credential.

### Health (no auth)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness — `{"status":"ok"}` |
| GET | `/health/ready` | readiness — db + redis checks, `503` if either unavailable |

### Authentication — `/api/v1/auth`

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/login` | — | rate-limited; sets refresh cookie |
| POST | `/refresh` | cookie | rotates refresh token |
| POST | `/logout` | U + cookie | `204`, family revoked |
| GET | `/me` | U | profile + roles |

### Admin — `/api/v1/users`, `/roles`, `/audit-logs`

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/users` | AR | paginated |
| POST | `/users` | AW | `{email,password≥12,full_name,roles[]}` → `201`; `409` duplicate, `400` unknown role |
| GET | `/roles` | AR | role → permissions |
| GET | `/audit-logs` | AU | filters: `event_type`, `outcome`; `page_size` ≤ 200 |

### Endpoints — `/api/v1/endpoints`

| Method | Path | Permission |
|---|---|---|
| GET | `/endpoints` | ER |
| GET | `/endpoints/overview` | ER |
| GET | `/endpoints/{id}` | ER |
| GET | `/endpoints/{id}/health` | ER |
| GET | `/endpoints/{id}/snapshots` · `/snapshots/{sid}` | ER |
| GET | `/endpoints/{id}/software` · `/network` | ER |
| GET | `/endpoints/groups` · `/groups/{gid}` | ER |
| GET | `/endpoints/enrollment-tokens` | ER |
| POST | `/endpoints/groups` | EW |
| POST | `/endpoints/{id}/groups/{gid}` · `DELETE` same | EW |
| POST | `/endpoints/enrollment-tokens` | EW → raw token **once** |
| POST | `/endpoints/{id}/rotate-credential` | EW → new secret once |
| POST | `/endpoints/{id}/revoke` | EW |

### Agent — `/api/v1/agent`

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/enroll` | enrollment token | single-use, uniform `401` on any failure |
| POST | `/heartbeat` | `eitop_ep_…` | |
| POST | `/inventory` | `eitop_ep_…` | ≤ 5 MB; idempotent snapshot append |
| POST | `/rotate-credential` | `eitop_ep_…` | agent-initiated rotation |

### Directory — `/api/v1/directory`

| Method | Path | Permission |
|---|---|---|
| GET | `/overview` · `/health` · `/correlation/gaps` | R |
| GET | `/connections` · `/connections/{id}` | R |
| POST | `/connections` | W |
| PATCH | `/connections/{id}` | W (`bind_password` write-only, re-encrypts) |
| DELETE | `/connections/{id}` | W |
| POST | `/connections/{id}/test` | S |
| POST | `/connections/{id}/sync` | S → `202`; `409` if running |
| GET | `/domains` · `/ous` · `/ous/{id}` · `/users` · `/users/{id}` · `/groups` · `/groups/{id}` · `/groups/{id}/members` · `/computers` · `/computers/{id}` | R |
| POST | `/computers/{id}/match` | W |
| GET | `/reconciliations` · `/sync-runs` · `/sync-runs/{run_id}` | R |
| GET | `/findings` (needs `connection_id`) · `/findings/summary` · `/findings/{id}` | R |
| POST | `/findings/{id}/ack` · `/suppress` · `/reopen` | W |

## OpenAPI

`GET /openapi.json` and interactive `/docs` are available in
development and **disabled in production** (`docs_url=None` when
`APP_ENV=production`).

## Related

- [Authentication deep-dive](../authentication.md)
- [Endpoints module reference](../endpoints/api.md)
- [RBAC model](../rbac.md)
- [Runbooks](../runbooks/README.md)
