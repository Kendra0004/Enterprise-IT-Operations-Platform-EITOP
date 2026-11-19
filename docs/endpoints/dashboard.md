# Endpoint Management Dashboard (Phases 2.7–2.8)

React + TypeScript + Vite + Tailwind + TanStack Query UI for endpoint
health, inventory, history and groups. Built on the existing auth/RBAC
context and the shared API client — no second state or routing framework.
Phase 2.8 added the enterprise visual layer (design tokens, dark/light
themes, app shell, shared components) — see
`docs/frontend/design-system.md`.

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
  arithmetic on a partial page. Each card links to the corresponding
  filtered view (`/endpoints?status=…`, `?os=…`).
- Distribution section: status bar, OS bar (CSS-only, from the same
  overview payload) and inventory coverage
  (`inventory_reported / total` — new additive overview field).
- Operational sections, each with its own loading/empty/error state:
  recently enrolled (`latest_enrollments`), recently active
  (`GET /endpoints?sort=last_heartbeat_at&page_size=5`), offline alerts
  (rendered only when `overview.offline > 0`), and recent lifecycle
  activity (`GET /audit-logs?page_size=100` narrowed client-side to
  `endpoint.*` event types — the audit API filters exact types only;
  requires `audit:read`).
- Table columns: hostname (+ groups), OS + version, status badge, IP
  addresses, agent version, last heartbeat, **last inventory**
  (`last_inventory_at`, new additive list field), enrollment date — all
  UTC.
- Filters: status (active/offline/revoked), OS, agent version, hostname
  search (debounced), group — all server-side query params.
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
| `theme.test.tsx` | theme default dark, toggle → light with persistence, stored light preference restored; dashboard KPI links to filtered views, UTC audit timestamps, no stale Phase-1 copy |

Plus the pre-existing `api-client.test.ts` and `routing.test.tsx`.

Browser verification: Playwright (chromium headless) drives the real UI
against the live stack — login flow plus every page × {dark, light} ×
{1440×900, 1280×800, 768×1024, 390×844}, 57 screenshots stored in
`docs/screenshots/`. Reproduce with `node frontend/scripts/screenshots.mjs`
(details in `docs/frontend/design-system.md`).
