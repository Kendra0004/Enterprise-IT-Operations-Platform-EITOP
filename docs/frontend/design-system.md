# EITOP Design System (Phase 2.8)

Enterprise visual design for the React dashboard: a token-driven theme
system, a persistent app shell, and shared components. All data shown in
the UI comes from real backend APIs — the design layer only renders.

## Stack

- Tailwind CSS v4 (CSS-first config in `frontend/src/index.css`)
- `lucide-react` ^1.75.0 — the only new dependency of Phase 2.8 (OSS,
  MIT). Icon set used for nav, stat cards, section glyphs, and OS
  metaphors (`Monitor` for Windows/macOS, `Terminal` for Linux —
  lucide ships no vendor logos, and OS state is always paired with its
  text label, never color/icon alone).
- No charting library: distributions render as pure CSS/SVG bars
  (`ChartCard`, `ProgressBar`). Count data does not justify a chart
  dependency; bars are decorative (`aria-hidden`) with an accessible
  legend underneath.

## Design tokens

Defined once in `frontend/src/index.css`:

- Light palette on `:root`, dark palette on `.dark` (`.dark` class on
  `<html>`).
- `@custom-variant dark` maps Tailwind's `dark:` to the class.
- `@theme inline` maps semantic tokens to Tailwind utilities, so
  components use `bg-surface`, `text-ink`, `border-line`, etc. and never
  raw colors.

| Token | Purpose |
|---|---|
| `--canvas` / `bg-canvas` | Page background |
| `--surface` / `bg-surface` | Cards, panels, sidebar |
| `--raised` / `bg-raised` | Hover states, table head, chips |
| `--overlay` / `bg-overlay` | Popovers, menus, dialogs |
| `--line` / `border-line` | Default borders/dividers |
| `--line-strong` | Input borders, stronger dividers |
| `--ink` / `text-ink` | Primary text |
| `--muted` | Secondary text |
| `--faint` | Tertiary/label text |
| `--accent` / `bg-accent` | Brand/primary actions, links |
| `--accent-soft` | Selected/soft accent backgrounds |
| `--accent-contrast` | Text on accent fills |
| `--ok`, `--warn`, `--danger` | Semantic states (also `bg-*`, `ring-*`) |
| `--shadow-card`, `--shadow-pop` (CSS vars `--elev-card`, `--elev-pop`) | Elevation |

Status colors are always paired with a text label (`StatusBadge`,
outcome chips), satisfying "status not color alone".

## Theme implementation

- `frontend/src/theme/ThemeProvider.tsx` — React context exposing
  `theme` (`dark` | `light`), `setTheme`, `toggleTheme`.
- Persistence: `localStorage["eitop.theme"]`; the `.dark` class and
  `color-scheme` live on `<html>`.
- No-flash: inline script in `frontend/index.html` applies the stored
  preference before first paint (default **dark** — the palette EITOP
  has always shipped with).
- `ThemeProvider` is mounted inside `App` so every render path
  (including tests) has theme state.
- `ThemeToggle` (header and login page) announces the *next* action
  (`aria-label="Switch to light theme"`).

## App shell

- `layout/AppLayout.tsx` — fixed sidebar + compact header + scrollable
  `<main id="main-content">`.
- `layout/Sidebar.tsx` — persistent nav: Platform section (Dashboard,
  Endpoints, Endpoint Groups) plus a muted **Preview** section listing
  future modules with `soon` chips (honest — those routes render
  `UnderDevelopment`, no fabricated data). Collapses to an icon rail
  (desktop, tooltips via `title` + sr-only labels); below `lg` it is an
  overlay drawer opened from the header menu button.
- `layout/Header.tsx` — sidebar collapse toggle (desktop), page title,
  `Breadcrumbs` (endpoint pages resolve the hostname from the same
  query cache the page uses — no extra request), `ThemeToggle`, account
  menu (email, roles, sign out). Focus/Escape close the menu.
- `layout/pageMeta.ts` — maps routes to titles/crumbs.
- Skip target: `<main id="main-content">`; focus-visible outlines are
  tokenized in the base layer.

## Components (`frontend/src/components/`)

| Component | Role |
|---|---|
| `PageHeader` | Page title + description + actions |
| `StatCard` | KPI card; becomes a link when `href` is set (metric → filtered view) |
| `ChartCard` / `ProgressBar` | CSS distribution bars + single-value coverage bar |
| `DataTable` | Generic semantic table: sortable header buttons with stable accessible names (`sortLabel`), horizontal scroll wrapper |
| `SearchInput` | Debounced (350 ms) search; Enter/submit flushes immediately |
| `FilterBar` / `FilterSelect` | List-page filter toolbar |
| `SectionNav` | Anchor-style section nav (detail page keeps all sections mounted) |
| `StatusBadge` | Lifecycle/collector badge with `status-*` test ids |
| `ActivityList` | Real audit lifecycle events with UTC times |
| `OsIcon` | Neutral OS glyph paired with OS text |
| `Pagination` | Server-side paging + page-size selector |
| `Breadcrumbs`, `ThemeToggle` | Header pieces |
| `ConfirmDialog` | `role="alertdialog"`, focus starts on Cancel, Escape closes |
| `states` (`Loading`/`Empty`/`ErrorState`) | Shared async states; `ErrorState` has an `inline` variant without the `error-state` test id so page sections never collide with main query states |

## Pages

- **Dashboard** — platform readiness (`/health/ready`), endpoint KPI
  preview (gated on `endpoints:read`), permission chips, recent audit
  events (gated on `audit:read`). All timestamps UTC.
- **Endpoints** — six KPI stat cards linking to filtered views, status/
  OS distribution bars + inventory coverage (from
  `GET /endpoints/overview`, including the new `inventory_reported`
  field), operational sections (recently enrolled, recently active,
  offline alerts — rendered only when `offline > 0` — recent lifecycle
  activity from `GET /audit-logs` filtered client-side by
  `endpoint.*`), then filters + enterprise table (search, status/OS/
  group/agent-version filters, allowlisted sorting, server-side
  pagination, page size, row actions, `Last inventory` column from the
  new `last_inventory_at` list field).
- **Detail** — section nav (Overview/Hardware/Software/Network/
  Activity & health) with all sections mounted, health strip,
  RBAC-gated revoke/rotate with confirmation dialogs and the one-time
  credential display, group assignment.
- **History** — collected vs received timestamps, date range filter,
  snapshot comparison with explicit missing-section messaging.
- **Groups** — search, create, member assign/remove with confirmations.

## Backend additions (backward-compatible)

1. `OverviewStatsOut.inventory_reported: int = 0` — count of endpoints
   with `last_inventory_at IS NOT NULL`. Additive optional field;
   covered by `test_overview_counts_are_real`.
2. `EndpointOut.last_inventory_at: datetime | None = None` — already
   loaded on the row; exposed so the table can show collection recency
   without N+1 detail requests. Covered by
   `test_list_rows_include_last_inventory_at`.

No other API changes; no auth/RBAC/collector behavior touched.

## Browser testing / screenshots

Prereqs: stack running (`docker compose up -d`), frontend at
`http://localhost:8080`.

```bash
cd frontend
npm i -D @playwright/test        # once
npx playwright install chromium  # once (add --with-deps where sudo is available)
node scripts/screenshots.mjs     # writes ../docs/screenshots/*.png
```

The script logs in through the real UI and captures every page ×
{dark, light} × {1440×900, 1280×800, 768×1024, 390×844} plus an open
mobile drawer (63 PNGs). Credentials default to the bootstrap admin and
can be overridden with `EITOP_URL`, `EITOP_EMAIL`, `EITOP_PASSWORD`.

## Limitations (honest)

- Browser verification in Phase 2.8 was performed with Playwright
  screenshots against the live stack (chromium headless shell);
  `--with-deps` system-library install failed without sudo, so the
  browser ran on preinstalled host libraries — if a fresh machine
  fails to launch, run `npx playwright install chromium --with-deps`.
- No automated visual-regression baselines (screenshots are manual
  evidence, not asserted in CI).
- Charts are aggregate bars only — the API exposes counts, not time
  series, so no trend lines are shown (fabricated series are forbidden).
- Windows/macOS glyphs are neutral metaphors, not vendor logos.
