# Endpoint Management Dashboard (Phase 2.7)

React + TypeScript + Vite + Tailwind + TanStack Query UI for endpoint
health, inventory, history and groups. Built on the existing auth/RBAC
context and the shared API client — no second state or routing framework.

## Routes

| Route | Page | Required permission |
|---|---|---|
| `/endpoints` | Overview stats + inventory table | `endpoints:read` |
| `/endpoints/:id` | Endpoint detail + actions | `endpoints:read` (actions need `endpoints:write`) |
| `/endpoints/:id/history` | Snapshot history + comparison | `endpoints:read` |
| `/groups` | Group list/detail/membership | `endpoints:read` (mutations `endpoints:write`) |

Nav: `Endpoints` and `Groups` appear only with `endpoints:read`.

## Pages

### Overview + inventory table (`EndpointListPage`)

- Six stat cards (total / active / offline / revoked / windows / linux)
  from `GET /endpoints/overview` — real aggregates, never client-side
  arithmetic on a partial page.
- Table columns: hostname (+ groups), OS + version, status badge, IP
  addresses, agent version, last heartbeat, enrollment date — all UTC.
- Filters: status (active/offline/revoked), OS, agent version, hostname
  search, group — all server-side query params.
- Sorting: clickable headers limited to allowlisted fields
  (`hostname`, `status`, `os`, `agent_version`, `enrolled_at`,
  `last_heartbeat_at`); server rejects anything else with 400.
- Pagination: server-side (`page`, `page_size` ≤ 100) with a page-size
  selector; `Refresh` refetches table + stats.

### Detail (`EndpointDetailPage`)

- Identity (hostname/FQDN/id/groups), OS (version/arch/kernel), hardware
  (manufacturer/model/serial/CPU cores + model, memory, storage formatted
  from bytes), network (IPs + MACs), software list with name filter,
  agent version, enrollment, last heartbeat, last inventory.
- Health strip: persisted status + derived `collector_status`, age of the
  heartbeat, and the configured interval/threshold/server time from
  `GET /endpoints/{id}/health`.
- Actions:
  - **Inventory history** — link (read permission).
  - **Revoke** — `endpoints:write`, confirmation dialog (destructive,
    focus starts on Cancel), then `POST /revoke`; backend failures render
    as an inline alert.
  - **Rotate credential** — `endpoints:write`, confirmation dialog; the new
    raw credential is displayed **exactly once** in a dismissible panel
    (it comes from the API's single issuance response and is never stored).
  - **Group assignment** — add/remove membership (see `groups.md`).

### History (`EndpointHistoryPage`)

- Snapshot table (received + collected UTC, package/fact counts, section
  flags, schema version) with optional `from`/`to` date filters.
- Selecting a snapshot loads it and automatically compares it against the
  previous snapshot in the list: installed / removed / version-changed
  packages (`8.5.0 → 8.6.0`) and field-level hardware changes.
- Network history section (latest reported network snapshots with IPs).

### Groups (`GroupsPage`)

See `groups.md`.

## Cross-cutting behavior

- **Data**: every value comes from the API via typed hooks in
  `src/api/endpoints.ts`; there is no mocked/seeded content in the UI.
- **RBAC**: buttons/forms for mutations render only when
  `hasPermission("endpoints:write")`. The backend enforces the same rules
  independently (403), so hiding is UX, not the security boundary.
- **States**: explicit loading (`role="status"`), empty (`empty-state`)
  and error (`role="alert"` with the RFC 9457 title/detail + Retry)
  components on every query.
- **UTC**: all timestamps render as `YYYY-MM-DD HH:MM:SS UTC`
  (`src/utils/datetime.ts`), never in the viewer's local zone.
- **Accessibility**: labeled form controls, `aria-label`s on sort buttons
  and checkboxes, `alertdialog` semantics with focus management for
  confirmations, table headers with `scope="col"`, live regions for
  pagination totals.
- **Responsive**: sidebar collapses on small screens; tables scroll
  horizontally; grids reflow (`sm:`/`lg:` breakpoints).
- **Requests**: all traffic goes through `src/api/client.ts` (bearer
  header, single transparent refresh retry, problem+json → `ApiError`).

## Tests

`frontend/tests/` (Vitest + Testing Library, fetch mocked per URL):

| File | Coverage |
|---|---|
| `endpoints.test.tsx` | stats + row rendering, status filter → API param, server-side pagination, allowlisted sort, loading state, error state + retry, empty state, read-only nav visibility |
| `endpoint-detail.test.tsx` | identity/OS/hardware/network/software/health rendering, revoke+rotate hidden without `endpoints:write`, revoke confirmation (no mutation before confirm, POST after), cancel without API call, backend 403 surfaced as an error |
| `history.test.tsx` | snapshot list with UTC timestamps, comparison request (`compare_to`) and diff rendering, date-range params, empty state |
| `groups.test.tsx` | group list with counts, create → POST, member list, remove with confirmation (DELETE only after confirm), assign endpoint, read-only control hiding |

Plus the pre-existing `api-client.test.ts` and `routing.test.tsx`.

No browser screenshots are included: this environment has no browser
automation available, and the UI is verified through the DOM-level tests
above and a production build (`npm run build`).
