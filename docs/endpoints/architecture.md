# Endpoint Management — Architecture (Phase 2.1–2.3)

Scope: milestones 2.1 (data model + admin/agent API), 2.2 (enrollment
lifecycle), 2.3 (Linux collector). Phase 1 auth/RBAC/audit is unchanged and
extended, never replaced.

## Components

```
┌────────────────────┐   HTTPS (prod)    ┌──────────────────────────┐
│ collectors/linux    │ ────────────────► │ FastAPI backend          │
│  - collect/*        │  enroll          │  /api/v1/agent/*          │
│  - api.py (retry)   │  heartbeat       │  /api/v1/endpoints/*      │
│  - credentials 0600 │  inventory       │  deps: get_current_       │
└────────────────────┘  rotate           │          endpoint         │
                                          │  endpoint_service         │
┌────────────────────┐   JWT (admin)     │  (token claim, upserts)   │
│ dashboard / API     │ ────────────────► │  audit via _record_audit  │
└────────────────────┘                   └──────────┬───────────────┘
                                                    │
                                     PostgreSQL (alembic 0003) + Redis
```

## Data model (migration `0003_endpoints`)

| Table | Purpose |
|---|---|
| `endpoint_groups` | Named groups; unique name |
| `endpoints` | Core identity: hostname/fqdn/os/kernel/status (`active\|revoked` CHECK), enrollment & heartbeat timestamps |
| `endpoint_group_members` | M2M endpoint↔group |
| `endpoint_metadata` | 1:1 hardware/network summary (manufacturer, serial, cpu, memory, IPs, MACs) |
| `endpoint_facts` | Key/value facts, unique `(endpoint_id, key)` — upserted |
| `endpoint_software` | Package rows, unique `(endpoint_id, name, package_manager)` |
| `enrollment_tokens` | Hash-only single-use tokens, expiry, optional group + restrictions |
| `endpoint_credentials` | Hash-only agent credentials, revocation/rotation lineage |

All keys UUID, timestamps UTC. **Secrets exist only as digests**
(`token_hash`, SHA-256) — no raw token/credential columns anywhere.

### Extension path to 2.4–2.7

- Hardware/software inventory → already modeled (`endpoint_metadata`,
  `endpoint_software`); 2.4 adds queries/UI over existing rows.
- Heartbeat dashboard → reads `last_heartbeat_at` + new fact keys; no schema
  change required.
- Snapshots → new table keyed by `endpoint_id` (same FK pattern as
  `endpoint_facts`); groups/status machinery reusable for scoping.
- Facts JSON blobs (`network.interfaces`, `filesystem.usage`) keep
  high-cardinality detail out of relational tables while summary columns in
  `endpoint_metadata` stay queryable.

## API surface (`/api/v1`)

Admin (JWT + `endpoints:read` / `endpoints:write`):

- `GET  /endpoints` — pagination, `q`/`status`/`group_id` filters, allowlisted
  `sort`+`order` (400 on unknown field), `page`/`page_size`
- `GET  /endpoints/{id}` — detail incl. metadata, facts, groups, counts;
  **never** credential/token material
- `POST /endpoints/{id}/revoke` — 409 if already revoked; kills credentials
- `POST /endpoints/{id}/rotate-credential` — returns new raw credential
  exactly once (see `security.md`)
- `GET/POST /endpoints/groups` — list/create (declared before `/{endpoint_id}`
  routes to avoid path capture)
- `POST/GET /endpoints/enrollment-tokens` — mint (raw shown once) / list
  (hashes only, `include_used` flag)

Agent (endpoint credential in `Authorization: Bearer`):

- `POST /agent/enroll` — rate-limited, 16 KB limit
- `POST /agent/heartbeat` — updates `last_heartbeat_at`, `agent_version`
- `POST /agent/inventory` — 5 MB limit, idempotent upserts
- `POST /agent/rotate-credential` — self-service rotation

Errors: RFC 9457 `application/problem+json` with stable `title`
(`Invalid enrollment token`, `Payload too large`, `Invalid sort field`, …).

## Request flow: inventory

1. Middleware enforces body-size cap for the path prefix (413 before parsing).
2. `get_current_endpoint` authenticates credential (hash lookup,
   `compare_digest`, status/revocation checks), rejects user JWTs.
3. Pydantic validates with `extra="forbid"` (a smuggled `endpoint_id` is 422,
   never an authorization input).
4. `apply_inventory` upserts facts/metadata/packages keyed by the *authenticated*
   endpoint id; packages absent from the new report are deleted by
   `(name, manager)` — repeat submissions converge to identical state.
5. Audit events recorded for sensitive transitions only (not routine
   heartbeats, to keep the log meaningful).

## Key files

- `backend/app/models/endpoints.py` — ORM
- `backend/alembic/versions/0003_endpoints.py` — migration
- `backend/app/schemas/endpoints.py` — contracts
- `backend/app/services/endpoint_service.py` — enrollment/credential/inventory logic
- `backend/app/api/v1/endpoints.py`, `backend/app/api/v1/agent.py` — routers
- `backend/app/api/deps.py` — `get_current_endpoint`
- `collectors/linux/` — agent
