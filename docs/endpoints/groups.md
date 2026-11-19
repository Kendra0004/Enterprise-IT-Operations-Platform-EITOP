# Endpoint Groups (Phase 2.7)

Groups are lightweight logical buckets for endpoints (e.g. `production`,
`lab`). They exist for filtering and as the scoping primitive for future
policy work — they are **not** a security boundary today (RBAC is
permission-based; every route still checks permissions server-side).

## Model

`endpoint_groups` (from Phase 2.1) with a many-to-many
`endpoint_group_members` table:

- group: `id`, `name` (unique), `description`, timestamps;
- membership is an association row — an endpoint may belong to several
  groups;
- endpoint list rows expose `groups: [name]`, and `GET /endpoints?group_id=`
  filters by membership.

## API

| Method | Path | Permission | Behavior |
|---|---|---|---|
| GET | `/endpoints/groups` | `endpoints:read` | list with `endpoint_count` |
| POST | `/endpoints/groups` | `endpoints:write` | create `{name, description}` → 201; duplicate → 409; empty name → 422 |
| GET | `/endpoints/groups/{group_id}` | `endpoints:read` | detail **with `members[]`** (endpoint rows, no credential material) → 404 unknown |
| POST | `/endpoints/{endpoint_id}/groups/{group_id}` | `endpoints:write` | assign → 200 with updated group detail; idempotent; unknown id → 404 |
| DELETE | `/endpoints/{endpoint_id}/groups/{group_id}` | `endpoints:write` | remove → 200 with updated group detail; idempotent; unknown id → 404 |

Membership routes were added in Phase 2.7 (Phase 2.1 shipped only
create/list plus assignment through enrollment tokens).

### Auditing

Membership changes write audit events — **only when membership actually
changes**, so idempotent repeats stay silent:

- `endpoint.group.member.added` — target = endpoint id,
  detail `{group_id, group_name}`
- `endpoint.group.member.removed` — same shape

Group creation is covered by the existing audit flow for group writes.

### Assignment paths

1. **At enrollment** — `POST /endpoints/enrollment-tokens` accepts
   `group_id`; the token's group is applied when the agent enrolls.
2. **After enrollment** — the membership routes above (UI or API).

Both are normal `endpoints:write` operations; neither affects the
endpoint's identity or credentials.

## UI (`/groups`)

- **All groups** — list with live `endpoint_count`; selecting one opens
  the detail panel (deep-linkable via `?group=<id>`).
- **Create group** — form rendered only with `endpoints:write`; validates
  non-empty name client-side (server enforces again).
- **Detail** — description, created (UTC), member rows with hostname link,
  status badge and OS.
  - *Add endpoint*: dropdown of active endpoints not already in the group →
    `POST` membership.
  - *Remove*: per-row button behind a confirmation dialog → `DELETE`
    membership. The dialog states that the endpoint itself is unaffected.
- Read-only users (`endpoints:read`) can browse groups and members; all
  mutation controls are hidden. The backend still returns 403 independently
  if such a request is made.

## Security notes

- No group can grant permissions: authorization is decided per route from
  the user's roles (`endpoints:read`/`write`), enforced in the API layer
  and hidden in the UI as a convenience.
- Membership responses contain endpoint rows only — never credentials,
  tokens or hashes.
- Path ids are UUIDs validated by FastAPI (non-UUID → 422); unknown
  endpoint/group → 404 (no existence oracle beyond an authorized read).
- All queries are parameterized; membership changes go through the ORM
  association (no raw SQL).

## Tests

`backend/tests/test_groups_api.py`: add/remove membership with audit
events (exactly one per change), idempotent repeats, group detail listing
members without credential material, 404s for unknown endpoint/group,
`group_id` list filter, read-only 403 on mutations (reads allowed),
anonymous 401 on all membership routes.

`frontend/tests/groups.test.tsx`: list with real counts, create → POST
body, member rendering + deep link, removal only after confirmation
(DELETE asserted), assignment POST, and control hiding for read-only users.
