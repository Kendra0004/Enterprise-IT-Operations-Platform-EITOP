# Endpoint API Reference (Phase 2.1–2.7)

Base: `/api/v1`. Two auth domains:

- **Admin routes** — user JWT (login flow from Phase 1) + RBAC permissions.
- **Agent routes** — endpoint credential (`eitop_ep_…`) in
  `Authorization: Bearer`. User JWTs are rejected here (401) and agent
  credentials on user routes.

All errors are RFC 9457 `application/problem+json`. Timestamps are UTC ISO-8601.

## Admin: endpoints

### `GET /endpoints` — `endpoints:read`

Query params:

| Param | Type | Notes |
|---|---|---|
| `page`, `page_size` | int | `page_size` max 100 |
| `q` | string | substring match on hostname |
| `status` | `active` \| `offline` \| `revoked` | else 422 |
| `group_id` | uuid | membership filter |
| `os` | string | exact OS match (`windows`, `linux`, …) |
| `agent_version` | string | exact agent version match |
| `heartbeat_from`, `heartbeat_to` | ISO-8601 | `last_heartbeat_at` range (UTC) |
| `sort` | allowlist | `hostname`, `status`, `os`, `agent_version`, `created_at`, `enrolled_at`, `last_heartbeat_at` — anything else → **400 `Invalid sort field`** |
| `order` | `asc` \| `desc` | else 422 |

Rows include `ip_addresses: []` (last reported; empty when never reported).

Response: `{"items": [...], "page": 1, "page_size": 25, "total": N}`.

Items contain hostname/status/heartbeat/group info — never credential or
token material.

### `GET /endpoints/overview` — `endpoints:read`

Aggregate counters computed from rows: `total`, `active`, `offline`,
`revoked`, `windows`, `linux`, `other_os` plus the five most recent
`latest_enrollments`. `total == active + offline + revoked` and
`total == windows + linux + other_os`.

### `GET /endpoints/{endpoint_id}` — `endpoints:read`

Detail: core fields + `metadata` (hardware/network summary), `facts`
(key/value), `groups`, `software_count`. 404 `Endpoint not found`; non-UUID
path param → 422. **No** credential/token fields.

### `GET /endpoints/{endpoint_id}/health` — `endpoints:read`

```json
{"endpoint_id": "…", "status": "active", "collector_status": "healthy",
 "last_heartbeat_at": "…", "last_inventory_at": "…",
 "seconds_since_heartbeat": 42, "agent_version": "0.2.0",
 "heartbeat_interval_seconds": 300, "offline_threshold_seconds": 900,
 "server_time": "…"}
```

`status` is the persisted lifecycle (`active|offline|revoked`);
`collector_status` is derived **at read time** from UTC timestamps
(`healthy|late|offline|pending|revoked`) so health stays accurate between
background scans. Missing heartbeat is never reported as `revoked`.
See `heartbeat.md`.

### `POST /endpoints/{endpoint_id}/revoke` — `endpoints:write`

→ `200 {"status": "revoked", "revoked_credentials": n}`. Already revoked →
409. Effect immediate for all agent requests. Audited `endpoint.revoked`.

### `POST /endpoints/{endpoint_id}/rotate-credential` — `endpoints:write`

→ `200 {"endpoint_id", "credential"}` — the **only** response ever containing
the raw credential (single issuance moment; see `security.md`). Old
credential invalid immediately. Revoked endpoint → 409. Audited
`endpoint.credential.rotated` without the secret.

## Admin: groups

### `GET /endpoints/groups` — `endpoints:read`

List with `endpoint_count`.

### `POST /endpoints/groups` — `endpoints:write`

`{"name": "...", "description": "..."}` → 201. Duplicate name → 409; empty
name → 422.

### `GET /endpoints/groups/{group_id}` — `endpoints:read`

Group detail: fields above + `members: [endpoint rows]` (no credential
material). Unknown id → 404.

### `POST /endpoints/{endpoint_id}/groups/{group_id}` — `endpoints:write`

Assign an endpoint to a group (idempotent → 200 with the updated group
detail). Unknown endpoint/group → 404. Audited
`endpoint.group.member.added` **only when membership changes**.

### `DELETE /endpoints/{endpoint_id}/groups/{group_id}` — `endpoints:write`

Remove membership (idempotent → 200). Audited
`endpoint.group.member.removed` only on change.

## Admin: inventory history (Phase 2.6)

### `GET /endpoints/{endpoint_id}/snapshots` — `endpoints:read`

Paginated snapshot list (newest first). Query: `page`, `page_size` (≤100),
`from`, `to` (ISO on `received_at`). Range rules: `to` without `from` →
400; spans > 366 days → 400; inverted range → 400. 404 for an unknown
endpoint. Always scoped to the path endpoint (cross-endpoint reads → 404).

### `GET /endpoints/{endpoint_id}/snapshots/{snapshot_id}` — `endpoints:read`

Full payload: `system`, `hardware`, `network`, `filesystems`, `facts`,
`packages[]`, plus `changes` when `?compare_to=<snapshot_id>` (same
endpoint; otherwise 404). `changes` = `{added_packages, removed_packages,
changed_packages (with previous_version), hardware_changes}`.

### `GET /endpoints/{endpoint_id}/software` — `endpoints:read`

`view=current` (default) → live package table (`name`, `version`,
`package_manager`, `collected_at`); `view=history` → package rows across
snapshots (`snapshot_id`, `collected_at`, …). Extra: `name` substring
filter, `from`/`to` (history only, same bounds as snapshots).

### `GET /endpoints/{endpoint_id}/network` — `endpoints:read`

Network sections per snapshot (`snapshot_id`, `collected_at`, `network`),
newest first, paginated with the same `from`/`to` bounds. Snapshots without
a network section are excluded.

## Admin: enrollment tokens

### `POST /endpoints/enrollment-tokens` — `endpoints:write`

```json
{"expires_in_minutes": 60, "group_id": null, "note": "...",
 "restrictions": {"allowed_hostname_patterns": ["web*.example.com"]}}
```

→ 201 with `{"id", "token", "expires_at", ...}` — `token` raw shown **once**.
Unknown `group_id` → 400 `Unknown group`. Rate-limited like other POSTs.

### `GET /endpoints/enrollment-tokens` — `endpoints:read`

Default: unused tokens only; `?include_used=true` adds consumed/expired.
Rows carry id/created/expiry/used_at/note/group — **never** `token`.

## Agent: enrollment

### `POST /agent/enroll` — no prior auth; rate-limited

```json
{"token": "…", "hostname": "web01", "fqdn": "web01.example.com",
 "os": "linux", "os_version": "…", "os_arch": "x86_64",
 "kernel_version": "…", "agent_version": "0.1.0"}
```

- 201 → `{"endpoint_id", "credential", "status", "enrolled_at"}` (credential
  raw, once).
- 401 `Invalid enrollment token` — uniform for unknown/used/expired/
  restriction-mismatch.
- 413 payload > 16 KB; 422 unknown fields (`extra=forbid`) or invalid types.
- 429 rate limit exceeded.

## Agent: authenticated routes

### `POST /agent/heartbeat`

`{"agent_version": "0.1.0"}` → 200 `{"endpoint_id", "status",
"last_heartbeat_at"}`. Updates agent version + heartbeat timestamp.

### `POST /agent/inventory`

```json
{
  "system": { "hostname", "fqdn", "os", "distribution",
              "distribution_version", "os_arch", "kernel", "uptime_seconds" },
  "hardware": { "manufacturer", "model", "serial_number", "cpu_model",
                "cpu_cores", "memory_bytes", "disk_bytes" },
  "network": { "interfaces": [{"name","mac","ipv4","ipv6","is_up"}],
               "ip_addresses": [], "mac_addresses": [] },
  "filesystems": [{"mount","fstype","total_bytes","used_bytes"}],
  "packages": [{"name","version","package_manager"}],
  "facts": {"key": "value"}
}
```

- 200 `{"endpoint_id", "accepted": true, "counts": {...}}` — `counts`
  includes `snapshots` (1 when a new immutable snapshot was appended, 0 for
  an identical resubmission).
- Optional additive fields: `schema_version` (default 1) and `collected_at`
  (agent-side UTC). Existing collectors omit both — unchanged behavior.
- Idempotent: resubmitting identical data yields identical state/counts.
- 413 if body > 5 MB; 422 for empty package names, oversized fact values
  (>8 KB), or unknown fields; 401/403 with credential problems.

### `POST /agent/rotate-credential`

No body. → 200 `{"endpoint_id", "credential"}` — new raw credential (only
issuance). Old credential dead immediately.

## Permission matrix

| Permission | Routes |
|---|---|
| `endpoints:read` | GET endpoints, overview, health, snapshots, software, network, groups, tokens |
| `endpoints:write` | revoke, rotate, create groups/tokens, group assign/remove (admin **and** operator roles) |
| endpoint credential | agent routes for **its own endpoint only** |
| none (anonymous) | 401 everywhere |
