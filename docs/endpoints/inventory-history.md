# Inventory History & Snapshots (Phase 2.6)

Every valid `POST /agent/inventory` leaves an immutable record of what the
endpoint looked like at that moment — without duplicating the live tables
the API already serves.

## Data model

```
endpoint_snapshots                 immutable, one row per distinct submission
  id                uuid PK
  endpoint_id       uuid FK → endpoints (index: (endpoint_id, received_at))
  collected_at      agent-side UTC (falls back to server receipt)
  received_at       server receipt, UTC (index)
  agent_version     text
  schema_version    int          (default 1)
  content_hash      sha256 of the canonical payload JSON
  system / hardware / network / filesystems / facts   JSONB sections
  UNIQUE (endpoint_id, content_hash)

endpoint_snapshot_software         normalized package rows for ONE snapshot
  (snapshot_id, name, package_manager)  composite PK
  version, name index
```

### Why three representations (and which one wins where)

| Layer | Table(s) | Mutability | Used for |
|---|---|---|---|
| **Current state** | `endpoint_facts`, `endpoint_software`, `endpoint_metadata` | upserted on each submission (stale packages removed) | detail page, `?view=current`, filters — always the *latest* truth, cheap to query |
| **Immutable snapshots** | `endpoint_snapshots` (JSONB sections) | append-only, never updated | history timeline, network/hardware history, diffs, audit-grade fidelity |
| **Normalized detail** | `endpoint_snapshot_software` | written once per new snapshot | package history queries, install/remove/upgrade diffs, index-friendly joins |

Decision: **history lives in immutable snapshots + a normalized package
table; live state stays in the existing upserted tables.**

- Packages are deliberately **not** stored inside the snapshot JSONB —
  they live only in `endpoint_snapshot_software`. Storing them twice would
  double storage for the largest section (tens of thousands of rows per
  endpoint) and force a JSONB scan for every package query.
- The other sections are stored verbatim as JSONB because they are read as
  a whole (detail rendering) and change shape rarely; a relational mirror
  would add migrations for no query win.
- Current-state tables are kept upserted (not rebuilt from snapshots) so
  Phase 2.1/2.3 read paths and their indexes are untouched — history is
  purely additive.

## Submission semantics

1. `AgentInventoryRequest` validates the payload (`extra="forbid"`,
   ≤5 MB body, ≤20 000 packages, ≤512 facts) and takes two **optional,
   additive** fields: `schema_version` (1…1000, default 1) and
   `collected_at` (agent UTC). Existing Linux/Windows collectors omit both
   and behave exactly as before — no collector change was required.
2. Current-state upsert runs first (unchanged Phase 2.3 behavior) and
   `endpoints.last_inventory_at` is set.
3. `_append_snapshot` computes `content_hash = sha256(canonical JSON)` of
   the whole submission and inserts with
   `ON CONFLICT (endpoint_id, content_hash) DO NOTHING`:
   - **first time** → snapshot row + bulk package rows; `counts.snapshots = 1`
   - **identical resubmission** (network retry, duplicate POST) → nothing;
     `counts.snapshots = 0`, history unchanged
   - **any difference** (uptime, package set, facts…) → new snapshot
4. `collected_at` from the agent is normalized to UTC (naive values are
   treated as UTC); otherwise it falls back to server `received_at`.
   Partial inventory is legal: `hardware`, `network`, `filesystems`,
   `packages` may be absent — stored as SQL `NULL`/empty and skipped in
   comparisons.

## Retention

`SNAPSHOT_RETENTION_DAYS` (default **unset**):

- unset → `prune_endpoint_snapshots` (daily Celery task) deletes **nothing**
  — history is preserved indefinitely unless an operator opts in;
- set to *N* → snapshots with `received_at < now − N days` are deleted
  (software rows removed first, then the snapshot; the FK also cascades).

## API

| Route | Permission | Notes |
|---|---|---|
| `GET /endpoints/{id}/snapshots` | `endpoints:read` | page/page_size (≤100), `from`/`to` on `received_at` |
| `GET /endpoints/{id}/snapshots/{sid}` | `endpoints:read` | full payload; `?compare_to=<sid>` adds `changes` |
| `GET /endpoints/{id}/software?view=current\|history` | `endpoints:read` | live table vs per-snapshot package rows; `name` filter; `from`/`to` for history |
| `GET /endpoints/{id}/network` | `endpoints:read` | network sections per snapshot (snapshots without one are excluded) |

Comparison (`changes`) reports:

- `added_packages` / `removed_packages` — key `(name, package_manager)`
- `changed_packages` — same key, different `version`, includes
  `previous_version`
- `hardware_changes` — field-level `before`/`after` from the JSONB section
  (skipped entirely when either side has no hardware)

### Query bounds (unbounded-query prevention)

- `page_size` capped at 100 by validation.
- History queries accept at most **366 days** per request → 400
  `Date range too large`; `to` without `from` → 400 `Missing 'from'`;
  inverted ranges → 400.
- All filters are bound parameters (SQLAlchemy `where()`), never string
  concatenation; sorting is not exposed on history routes (fixed
  newest-first order).

## Isolation & RBAC

- Every history query carries `endpoint_id = <path endpoint>` in its
  `WHERE`; loading a snapshot or a `compare_to` snapshot from another
  endpoint returns **404**, not 403 (no existence oracle).
- Agent credentials are rejected (401) on all user routes — agents can
  submit inventory but can never read history, health or software lists.
- Reads require `endpoints:read`; there are no mutation routes for
  snapshots (they are immutable by construction).

## Tests

`backend/tests/test_snapshots.py` covers: snapshot creation with the
expected summary fields, deduplication of identical submissions, new
snapshot on change, `last_inventory_at`, list rows carrying reported IPs,
pagination + `page_size` cap, date filtering, query bounds (366-day /
missing-`from` / inverted), package + hardware comparison, partial-inventory
comparison, cross-endpoint isolation (detail, list, software history,
`compare_to`), agents blocked from history routes, 404s, current vs history
software views, network history (excluding snapshots without a section),
`schema_version`/`collected_at` recording, invalid schema version → 422,
migration 0004 column/index/uniqueness assertions, and the keep-forever
retention default.

`backend/tests/test_agent_api.py::test_inventory_is_idempotent` was updated
for the intentional new `counts.snapshots` counter (1 then 0) while keeping
the original equality assertion for every other counter.
