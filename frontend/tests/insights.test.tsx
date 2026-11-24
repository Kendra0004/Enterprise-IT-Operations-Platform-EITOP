/**
 * Directory Insights tests (Phase 3.2.3): findings list/pagination,
 * server-side filtering and sorting, detail drawer, lifecycle actions,
 * invalid transitions, five-role RBAC, API error handling (401/403/404/
 * 400/5xx), summary metrics, health states, correlation gap classes,
 * light/dark themes and loading/empty/error states.
 */

import { afterEach, describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import {
  ADMIN_PERMISSIONS,
  getFetchMock,
  jsonResponse,
  makeUser,
  renderApp,
  type FetchCall,
} from "./helpers";

const CONNECTION_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const FINDING_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const FINDING_ID_2 = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const RUN_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

const DIRECTORY_ADMIN = [
  ...ADMIN_PERMISSIONS,
  "directory:read",
  "directory:write",
  "directory:sync",
];
const DIRECTORY_READONLY = ["endpoints:read", "directory:read"];
const DIRECTORY_AUDITOR = ["directory:read", "audit:read"];
const DIRECTORY_OPERATOR = ["directory:read", "directory:sync"];
const AGENT_ROLE = ["endpoints:read"];

const connection = {
  id: CONNECTION_ID,
  name: "hq-ad",
  domain_dns: "eitop.test",
  host: "dc01.eitop.test",
  port: 636,
  tls_mode: "ldaps",
  search_base: "OU=HQ,DC=eitop,DC=test",
  bind_username: "CN=svc-eitop,DC=eitop,DC=test",
  connect_timeout_seconds: 10,
  search_timeout_seconds: 30,
  page_size: 500,
  enabled: true,
  auto_sync: true,
  sync_interval_minutes: 60,
  has_custom_ca: true,
  last_run_status: "success",
  last_run_started_at: "2026-11-20T02:00:00+00:00",
  last_success_at: "2026-11-20T02:00:12+00:00",
  created_at: "2026-11-01T10:00:00+00:00",
  updated_at: "2026-11-20T02:00:12+00:00",
  tls_ca_pem: null,
};

const openFinding = {
  id: FINDING_ID,
  connection_id: CONNECTION_ID,
  fingerprint: "fp-1",
  rule_key: "privileged.direct_member",
  severity: "critical",
  status: "open",
  subject_type: "user",
  access: "direct",
  subject_guid: "3f1e2d4c-0000-0000-0000-000000000001",
  subject_dn: "CN=alice,OU=HQ,DC=eitop,DC=test",
  subject_name: "alice",
  title: "Direct member of privileged group Domain Admins",
  detail: {
    hops: 1,
    path: ["Domain Admins"],
    privileged_group: {
      name: "Domain Admins",
      dn: "CN=Domain Admins,CN=Users,DC=eitop,DC=test",
      rid: 512,
      detection: "sid",
    },
    confirmed_security: true,
    privilege_visibility: "full",
    visibility_reasons: [],
  },
  first_seen_at: "2026-11-19T02:00:00+00:00",
  last_seen_at: "2026-11-20T02:00:00+00:00",
  resolved_at: null,
  reopen_count: 0,
  acknowledged_at: null,
  acknowledged_by: null,
  suppressed_at: null,
  created_at: "2026-11-19T02:00:00+00:00",
  updated_at: "2026-11-20T02:00:00+00:00",
};

const resolvedFinding = {
  ...openFinding,
  id: FINDING_ID_2,
  rule_key: "user.inactive",
  severity: "medium",
  status: "resolved",
  subject_name: "bob",
  subject_dn: "CN=bob,OU=HQ,DC=eitop,DC=test",
  title: "User inactive for 30+ days: bob",
  detail: { last_logon_at: null, threshold_days: 30 },
  resolved_at: "2026-11-21T03:00:00+00:00",
  reopen_count: 2,
};

const summary = {
  total: 41,
  open: 12,
  acknowledged: 5,
  suppressed: 3,
  resolved: 21,
  by_severity: { critical: 4, high: 7, medium: 20, low: 6, info: 4 },
  by_rule: { "user.inactive": 12, "privileged.direct_member": 9 },
  by_subject_type: { user: 25, computer: 10, group: 6 },
  privilege_visibility: "partial",
  visibility_reasons: ["untyped_intermediate_group"],
  inventory_complete: true,
};

const completeCategories = {
  connect: { status: "success" },
  domains: { status: "success" },
  ous: { status: "success" },
  users: { status: "success" },
  groups: { status: "success" },
  computers: { status: "success" },
  memberships: { status: "success" },
  missing_scan: { status: "skipped" },
  reconcile: { status: "success" },
};

const healthyHealth = {
  connection_id: CONNECTION_ID,
  inventory_complete: true,
  missing_categories: [],
  newest_run: {
    id: RUN_ID,
    status: "success",
    trigger: "manual",
    started_at: "2026-11-20T02:00:00+00:00",
    finished_at: "2026-11-20T02:00:12+00:00",
    duration_ms: 12000,
    category_results: completeCategories,
  },
  privilege_visibility: "full",
  visibility_reasons: [],
  findings: summary,
  sync_freshness: {
    last_success_at: "2026-11-20T02:00:12+00:00",
    newest_run_started_at: "2026-11-20T02:00:00+00:00",
    sync_interval_minutes: 60,
    sync_overdue: false,
  },
};

const gap = (
  id: string,
  name: string,
  gapType: string,
  extra: Record<string, unknown> = {},
) => ({
  computer_id: id,
  computer_name: name,
  dns_hostname: `${name.toLowerCase()}.eitop.test`,
  distinguished_name: `CN=${name},OU=HQ,DC=eitop,DC=test`,
  object_guid: null,
  gap_type: gapType,
  recon_status: null,
  recon_method: null,
  recon_confidence: null,
  candidates: [],
  reviewed_at: null,
  ...extra,
});

const gapsPage = {
  items: [
    gap("11111111-1111-1111-1111-111111111111", "WS-01", "never_reconciled"),
    gap("22222222-2222-2222-2222-222222222222", "WS-02", "unmatched", {
      recon_status: "unmatched",
      recon_method: "hostname",
      recon_confidence: "high",
      reviewed_at: "2026-11-19T04:00:00+00:00",
    }),
    gap("33333333-3333-3333-3333-333333333333", "WS-03", "ambiguous", {
      recon_status: "needs_review",
      recon_method: "sid",
      recon_confidence: "medium",
      candidates: ["44444444-4444-4444-4444-444444444444"],
    }),
  ],
  total: 3,
  page: 1,
  page_size: 20,
};

function problem(status: number, title: string, detail?: string): Response {
  return jsonResponse({ type: "about:blank", title, status, detail }, status);
}

function pageOf(items: unknown[], total = items.length, pageSize = 20) {
  return { items, total, page: 1, page_size: pageSize };
}

interface Routes {
  permissions?: string[];
  findings?: Response | (() => Response);
  summary?: Response;
  health?: Response;
  gaps?: Response;
  detail?: Response;
  transition?: (url: URL) => Response;
  /** When set, detail transitions mutate this object (stateful detail). */
  mutableDetail?: { value: Record<string, unknown> };
}

/** Response bodies are single-use — factories hand out fresh ones. */
function fresh(response: Response | (() => Response) | undefined) {
  return typeof response === "function" ? response() : response;
}

function insightsHandler(routes: Routes = {}) {
  return ({ url, init }: FetchCall): Response | undefined => {
    const path = url.pathname;
    const method = init?.method ?? "GET";

    if (path.endsWith("/api/v1/auth/me")) {
      return jsonResponse(makeUser(routes.permissions ?? DIRECTORY_ADMIN));
    }
    if (path.endsWith("/api/v1/directory/connections")) {
      return jsonResponse(pageOf([connection], 1, 100));
    }

    const transition = path.match(
      /\/directory\/findings\/[^/]+\/(ack|suppress|reopen)$/,
    );
    if (transition && method === "POST") {
      if (routes.transition) return routes.transition(url);
      if (routes.mutableDetail) {
        routes.mutableDetail.value = {
          ...routes.mutableDetail.value,
          status: "acknowledged",
          acknowledged_at: "2026-11-22T10:00:00+00:00",
          acknowledged_by: "u-1",
        };
        return jsonResponse(routes.mutableDetail.value);
      }
      return jsonResponse(openFinding);
    }
    if (path.endsWith("/directory/findings/summary")) {
      return routes.summary ?? jsonResponse(summary);
    }
    if (/\/directory\/findings\/[0-9a-f-]{36}$/.test(path)) {
      if (routes.detail) return routes.detail;
      if (routes.mutableDetail) return jsonResponse(routes.mutableDetail.value);
      return jsonResponse(openFinding);
    }
    if (path.endsWith("/directory/findings")) {
      return (
        fresh(routes.findings) ??
        jsonResponse(pageOf([openFinding, resolvedFinding], 41))
      );
    }
    if (path.endsWith("/directory/health")) {
      return routes.health ?? jsonResponse(healthyHealth);
    }
    if (path.endsWith("/directory/correlation/gaps")) {
      return routes.gaps ?? jsonResponse(gapsPage);
    }
    return undefined;
  };
}

/** Response whose body arrives after `ms` — lets us catch the loading state. */
function delayedJson(data: unknown, ms: number): Response {
  const stream = new ReadableStream({
    start(controller) {
      setTimeout(() => {
        controller.enqueue(new TextEncoder().encode(JSON.stringify(data)));
        controller.close();
      }, ms);
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function findCall(fragment: string, method = "GET") {
  const matches = getFetchMock().mock.calls.filter(
    ([input, init]) =>
      String(input).includes(fragment) &&
      (init?.method ?? "GET") === method,
  );
  return matches[matches.length - 1];
}

afterEach(() => {
  localStorage.clear();
});

// --- Findings list -----------------------------------------------------------

describe("Insights — findings list", () => {
  it("lists findings for the selected connection, server-scoped", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());

    expect(
      await screen.findByText("Direct member of privileged group Domain Admins"),
    ).toBeInTheDocument();
    expect(screen.getByText("User inactive for 30+ days: bob")).toBeInTheDocument();

    const call = findCall("/directory/findings?");
    expect(call).toBeDefined();
    expect(String(call![0])).toContain(`connection_id=${CONNECTION_ID}`);
    expect(String(call![0])).toContain("page_size=20");
  });

  it("filters server-side — the request carries the enum value", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());
    await screen.findByText("Direct member of privileged group Domain Admins");

    fireEvent.change(screen.getByLabelText("Severity"), {
      target: { value: "high" },
    });
    await waitFor(() => {
      const call = findCall("/directory/findings?");
      expect(String(call![0])).toContain("severity=high");
    });
  });

  it("sorts server-side via the allowlisted sort and order params", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());
    await screen.findByText("Direct member of privileged group Domain Admins");

    fireEvent.click(screen.getByRole("button", { name: "Sort by severity" }));
    await waitFor(() => {
      const call = findCall("/directory/findings?");
      expect(String(call![0])).toContain("sort=severity");
      expect(String(call![0])).toContain("order=asc");
    });

    // The params change starts a fresh query — wait for the table again
    // before interacting (the previous page is replaced while it loads).
    fireEvent.click(await screen.findByRole("button", { name: "Sort by severity" }));
    await waitFor(() => {
      const call = findCall("/directory/findings?");
      expect(String(call![0])).toContain("order=desc");
    });
  });

  it("paginates server-side", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());
    await screen.findByText("Direct member of privileged group Domain Admins");

    expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => {
      const call = findCall("/directory/findings?");
      expect(String(call![0])).toContain("page=2");
    });
  });

  it("shows the empty state when the API returns no findings", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ findings: jsonResponse(pageOf([], 0)) }),
    );

    expect(
      await screen.findByText("No findings recorded for this connection yet."),
    ).toBeInTheDocument();
    expect(screen.getByTestId("empty-state")).toBeInTheDocument();
  });

  it("shows a distinct message when filters exclude everything", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ findings: () => jsonResponse(pageOf([], 0)) }),
    );
    await screen.findByTestId("empty-state");

    fireEvent.change(screen.getByLabelText("Status"), {
      target: { value: "suppressed" },
    });
    expect(
      await screen.findByText("No findings match the current filters."),
    ).toBeInTheDocument();
  });

  it("surfaces server errors with retry", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ findings: problem(500, "Internal Server Error", "boom") }),
    );

    const alert = await screen.findByTestId("error-state");
    expect(alert).toHaveTextContent("Internal Server Error");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows the loading state before the first page arrives", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({
        findings: () => delayedJson(pageOf([openFinding], 1), 600),
      }),
    );

    expect(await screen.findByTestId("findings-summary")).toBeInTheDocument();
    // role=status carries no content-derived accessible name (ARIA), so the
    // loading region is located by its text and verified for the role.
    const loading = await screen.findByText("Loading findings…");
    expect(loading).toHaveAttribute("role", "status");
    expect(
      await screen.findByText("Direct member of privileged group Domain Admins"),
    ).toBeInTheDocument();
  });

  it("shows a 401 from the API as an auth error", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ findings: problem(401, "Not Authenticated", "Missing credentials") }),
    );

    const alert = await screen.findByTestId("error-state");
    expect(alert).toHaveTextContent("Not Authenticated");
  });
});

// --- Summary -----------------------------------------------------------------

describe("Insights — summary", () => {
  it("renders status counts, distributions and the visibility verdict", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());

    const panel = await screen.findByTestId("findings-summary");
    expect(panel).toHaveTextContent("12"); // open
    expect(panel).toHaveTextContent("21"); // resolved
    expect(panel).toHaveTextContent("41 finding(s) total");

    // Distributions come straight from the API payload.
    expect(await screen.findByText("Privilege visibility")).toBeInTheDocument();
    expect(screen.getByTestId("visibility-partial")).toHaveTextContent(
      "Partial visibility",
    );
    expect(screen.getByText("Untyped Intermediate Group")).toBeInTheDocument();
    expect(screen.getByText("Inventory complete")).toBeInTheDocument();

    // Rule distribution shows the raw rule identifiers.
    expect(screen.getAllByText("user.inactive").length).toBeGreaterThan(0);
  });

  it("reports a summary failure inline without breaking the list", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ summary: problem(500, "Internal Server Error", "x") }),
    );

    expect(
      await screen.findByText("Direct member of privileged group Domain Admins"),
    ).toBeInTheDocument();
    expect(await screen.findByText("Could not load data")).toBeInTheDocument();
  });
});

// --- Detail drawer ------------------------------------------------------------

describe("Insights — finding details", () => {
  it("opens the drawer with lifecycle metadata and structured evidence", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());
    await screen.findByText("Direct member of privileged group Domain Admins");

    const detailButtons = await screen.findAllByRole("button", {
      name: "Details",
    });
    detailButtons[0].click();

    const drawer = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(drawer).toHaveTextContent(
        "Direct member of privileged group Domain Admins",
      ),
    );
    expect(drawer).toHaveTextContent("privileged.direct_member");

    // Lifecycle facts from the API (UTC rendering, reopen count).
    expect(drawer).toHaveTextContent("First seen: 2026-11-19 02:00:00 UTC");
    expect(drawer).toHaveTextContent("Reopen count: 0");

    // Evidence renders as structured key/value groups — no invented fields.
    expect(drawer).toHaveTextContent("Privileged Group");
    expect(drawer).toHaveTextContent("Domain Admins");
    expect(drawer).toHaveTextContent("Confirmed Security: Yes");
    expect(drawer).toHaveTextContent("Hops: 1");
  });

  it("closes on Escape", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();
    await screen.findByRole("dialog");

    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows a 404 when the finding is gone from this connection", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ detail: problem(404, "Not Found", "Finding not found") }),
    );
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    expect(await screen.findByText("Could not load data")).toBeInTheDocument();
    expect(await screen.findByText(/Not Found/)).toHaveTextContent(
      "Finding not found",
    );
  });
});

// --- Lifecycle ----------------------------------------------------------------

describe("Insights — lifecycle actions", () => {
  it("acknowledges only after the API confirms, then refreshes the UI", async () => {
    const mutable = { value: { ...openFinding } as Record<string, unknown> };
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ mutableDetail: mutable }),
    );
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    const ack = await screen.findByRole("button", { name: "Acknowledge" });
    ack.click();

    // Success appears only after the POST resolves; the connection scope rides
    // in the query string exactly as the backend route declares it.
    expect(await screen.findByText("Finding acknowledged.")).toBeInTheDocument();
    const call = findCall("/ack", "POST");
    expect(call).toBeDefined();
    expect(String(call![0])).toContain(`connection_id=${CONNECTION_ID}`);

    // The refreshed detail now reports acknowledged — the acknowledge button
    // is gone (no duplicate submission path) and the status badge updated.
    await waitFor(() => {
      expect(
        screen.queryByRole("button", { name: "Acknowledge" }),
      ).not.toBeInTheDocument();
    });
    expect(screen.getByTestId("finding-status-acknowledged")).toBeInTheDocument();
  });

  it("confirms suppression before any request is sent", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    (await screen.findByRole("button", { name: "Suppress…" })).click();

    // Confirmation first — no POST yet.
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("Suppress this finding?");
    expect(findCall("/suppress", "POST")).toBeUndefined();

    fireEvent.click(screen.getByRole("button", { name: "Suppress" }));
    expect(await screen.findByText("Finding suppressed.")).toBeInTheDocument();
    expect(findCall("/suppress", "POST")).toBeDefined();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("reopens a resolved finding", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ detail: jsonResponse(resolvedFinding) }),
    );
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    const reopen = await screen.findByRole("button", { name: "Reopen" });
    reopen.click();

    expect(await screen.findByText("Finding reopened.")).toBeInTheDocument();
    const call = findCall("/reopen", "POST");
    expect(String(call![0])).toContain(`connection_id=${CONNECTION_ID}`);
  });

  it("shows the backend's validation detail for an invalid transition (400)", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({
        transition: () =>
          problem(400, "Invalid transition", "finding is suppressed"),
      }),
    );
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    (await screen.findByRole("button", { name: "Acknowledge" })).click();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Invalid transition — finding is suppressed",
    );
    expect(screen.queryByText("Finding acknowledged.")).not.toBeInTheDocument();
  });

  it("explains a 403 instead of pretending the action worked", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({
        transition: () => problem(403, "Forbidden", "directory:write required"),
      }),
    );
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    (await screen.findByRole("button", { name: "Acknowledge" })).click();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "directory:write required",
    );
    expect(screen.queryByText("Finding acknowledged.")).not.toBeInTheDocument();
  });

  it("hides lifecycle controls from read-only roles", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ permissions: DIRECTORY_READONLY }),
    );
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    expect(
      screen.queryByRole("button", { name: "Acknowledge" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Suppress…" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reopen" })).not.toBeInTheDocument();
    expect(
      await screen.findByText(
        "Lifecycle actions require the directory:write permission.",
      ),
    ).toBeInTheDocument();
  });
});

// --- RBAC matrix --------------------------------------------------------------

describe("Insights — RBAC visibility", () => {
  it("admin: read + lifecycle actions", async () => {
    renderApp("/active-directory?tab=insights", insightsHandler());
    await screen.findByText("Direct member of privileged group Domain Admins");
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();

    expect(await screen.findByRole("button", { name: "Acknowledge" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Suppress…" })).toBeInTheDocument();
  });

  it("security auditor: read only", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ permissions: DIRECTORY_AUDITOR }),
    );
    expect(
      await screen.findByText("Direct member of privileged group Domain Admins"),
    ).toBeInTheDocument();
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();
    expect(
      screen.queryByRole("button", { name: "Acknowledge" }),
    ).not.toBeInTheDocument();
  });

  it("operator: read only", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ permissions: DIRECTORY_OPERATOR }),
    );
    expect(
      await screen.findByText("Direct member of privileged group Domain Admins"),
    ).toBeInTheDocument();
    (await screen.findAllByRole("button", { name: "Details" }))[0].click();
    expect(
      screen.queryByRole("button", { name: "Suppress…" }),
    ).not.toBeInTheDocument();
  });

  it("readonly: read only", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ permissions: DIRECTORY_READONLY }),
    );
    expect(
      await screen.findByText("Direct member of privileged group Domain Admins"),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Details" }).length).toBeGreaterThan(0);
  });

  it("agent: no Directory Insights access at all", async () => {
    renderApp(
      "/active-directory?tab=insights",
      insightsHandler({ permissions: AGENT_ROLE }),
    );

    expect(
      await screen.findByText(/Missing permission\(s\): directory:read/),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("findings-summary")).not.toBeInTheDocument();
    expect(findCall("/directory/findings?")).toBeUndefined();
  });
});

// --- Directory health ---------------------------------------------------------

describe("Health tab", () => {
  it("healthy inventory: newest run success, complete, fresh", async () => {
    renderApp("/active-directory?tab=health", insightsHandler());

    expect(await screen.findByTestId("health-verdict")).toHaveTextContent(
      "Healthy inventory",
    );
    expect(screen.getByTestId("run-status-success")).toBeInTheDocument();
    expect(screen.getByText("All required categories reported success.")).toBeInTheDocument();
    expect(screen.getByTestId("freshness-state")).toHaveTextContent("Fresh");
  });

  it("failed synchronization: newest failed run is what counts", async () => {
    renderApp(
      "/active-directory?tab=health",
      insightsHandler({
        health: jsonResponse({
          ...healthyHealth,
          inventory_complete: false,
          missing_categories: ["domains", "ous", "users", "groups", "computers", "memberships", "reconcile"],
          newest_run: {
            id: RUN_ID,
            status: "failed",
            trigger: "scheduled",
            started_at: "2026-11-20T03:00:00+00:00",
            finished_at: "2026-11-20T03:00:02+00:00",
            duration_ms: 2000,
            category_results: {
              connect: { status: "failed", label: "invalid_credentials" },
              domains: { status: "skipped" },
              ous: { status: "skipped" },
              users: { status: "skipped" },
              groups: { status: "skipped" },
              computers: { status: "skipped" },
              memberships: { status: "skipped" },
              missing_scan: { status: "skipped" },
              reconcile: { status: "skipped" },
            },
          },
          sync_freshness: {
            ...healthyHealth.sync_freshness,
            last_success_at: "2026-11-19T02:00:12+00:00",
            sync_overdue: true,
          },
        }),
      }),
    );

    expect(await screen.findByTestId("health-verdict")).toHaveTextContent(
      "Failed synchronization",
    );
    // The failed run itself is displayed — not any older success.
    expect(screen.getByTestId("run-status-failed")).toBeInTheDocument();
    expect(screen.getByTestId("category-connect")).toHaveTextContent(
      "invalid_credentials",
    );
    expect(
      screen.getByText(/older successful run is never presented as current/),
    ).toBeInTheDocument();
  });

  it("partial inventory: success run missing required categories", async () => {
    renderApp(
      "/active-directory?tab=health",
      insightsHandler({
        health: jsonResponse({
          ...healthyHealth,
          inventory_complete: false,
          missing_categories: ["reconcile"],
          newest_run: {
            ...healthyHealth.newest_run!,
            // reconcile never reported success — it is genuinely absent.
            category_results: (() => {
              const { reconcile: _omit, ...rest } = completeCategories;
              return rest;
            })(),
          },
        }),
      }),
    );

    expect(await screen.findByTestId("health-verdict")).toHaveTextContent(
      "Partial inventory",
    );
    expect(screen.getByText(/Missing or unsuccessful:/)).toHaveTextContent(
      "Reconcile",
    );
    expect(screen.getByTestId("category-reconcile")).toHaveTextContent("missing");
  });

  it("stale synchronization: complete but overdue against the cadence", async () => {
    renderApp(
      "/active-directory?tab=health",
      insightsHandler({
        health: jsonResponse({
          ...healthyHealth,
          sync_freshness: {
            ...healthyHealth.sync_freshness,
            sync_overdue: true,
          },
        }),
      }),
    );

    expect(await screen.findByTestId("health-verdict")).toHaveTextContent(
      "Stale synchronization",
    );
    expect(screen.getByTestId("freshness-state")).toHaveTextContent("Overdue");
  });

  it("unknown: no run ever — all nine categories listed as missing", async () => {    renderApp(
      "/active-directory?tab=health",
      insightsHandler({
        health: jsonResponse({
          ...healthyHealth,
          inventory_complete: false,
          missing_categories: [
            "connect", "domains", "ous", "users", "groups",
            "computers", "memberships", "missing_scan", "reconcile",
          ],
          newest_run: null,
          privilege_visibility: "insufficient",
          visibility_reasons: ["inventory_incomplete"],
          sync_freshness: {
            last_success_at: null,
            newest_run_started_at: null,
            sync_interval_minutes: 60,
            sync_overdue: true,
          },
        }),
      }),
    );

    expect(await screen.findByTestId("health-verdict")).toHaveTextContent(
      "Unknown — no synchronization run yet",
    );
    expect(screen.getByText(/Required categories \(9\/9\)/)).toBeInTheDocument();
    expect(screen.getByText("No synchronization run recorded yet.")).toBeInTheDocument();
    expect(screen.getByTestId("visibility-insufficient")).toBeInTheDocument();
    expect(screen.getByText("Last successful sync:")).toBeInTheDocument();
    expect(screen.getAllByText("never").length).toBeGreaterThan(0);
  });
});

// --- Correlation gaps ---------------------------------------------------------

describe("Correlation gaps tab", () => {
  it("classifies only the three gap states, with honest explanations", async () => {
    renderApp("/active-directory?tab=gaps", insightsHandler());

    expect(await screen.findByTestId("gap-never_reconciled")).toBeInTheDocument();
    expect(screen.getByTestId("gap-unmatched")).toBeInTheDocument();
    expect(screen.getByTestId("gap-ambiguous")).toBeInTheDocument();
    expect(screen.getByText("WS-01")).toBeInTheDocument();
    expect(screen.getByText("1 (unconfirmed)")).toBeInTheDocument();
    expect(
      screen.getByText(/Candidates are leads for review, not matches/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/deliberate decisions and never appear/),
    ).toBeInTheDocument();

    // Matched/rejected are not gap types the API can return.
    expect(screen.queryByTestId("gap-matched")).not.toBeInTheDocument();
    expect(screen.queryByTestId("gap-rejected")).not.toBeInTheDocument();

    const rows = screen.getAllByRole("row").length; // header + 3 bodies
    expect(rows).toBe(4);
  });

  it("filters by gap type server-side", async () => {
    renderApp("/active-directory?tab=gaps", insightsHandler());
    await screen.findByTestId("gap-never_reconciled");

    fireEvent.change(screen.getByLabelText("Gap type"), {
      target: { value: "ambiguous" },
    });
    await waitFor(() => {
      const call = findCall("/directory/correlation/gaps?");
      expect(String(call![0])).toContain("gap_type=ambiguous");
    });
  });

  it("paginates server-side", async () => {
    renderApp(
      "/active-directory?tab=gaps",
      insightsHandler({
        gaps: jsonResponse({
          items: gapsPage.items,
          total: 45,
          page: 1,
          page_size: 20,
        }),
      }),
    );
    await screen.findByTestId("gap-never_reconciled");

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => {
      const call = findCall("/directory/correlation/gaps?");
      expect(String(call![0])).toContain("page=2");
    });
  });

  it("shows the empty state when every computer correlates", async () => {
    renderApp(
      "/active-directory?tab=gaps",
      insightsHandler({ gaps: jsonResponse(pageOf([], 0)) }),
    );

    expect(
      await screen.findByText(
        "No correlation gaps of this type — every computer is matched or deliberately rejected.",
      ),
    ).toBeInTheDocument();
  });

  it("shows a fetch error with retry", async () => {
    renderApp(
      "/active-directory?tab=gaps",
      insightsHandler({ gaps: problem(500, "Internal Server Error", "x") }),
    );

    expect(await screen.findByTestId("error-state")).toBeInTheDocument();
  });
});

// --- Themes -------------------------------------------------------------------

describe("Insights — themes", () => {
  it("renders the insights tab in the light theme", async () => {
    localStorage.setItem("eitop.theme", "light");
    renderApp("/active-directory?tab=insights", insightsHandler());

    expect(await screen.findByTestId("findings-summary")).toBeInTheDocument();
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(
      screen.getByText("Direct member of privileged group Domain Admins"),
    ).toBeInTheDocument();
  });

  it("renders the insights tab in the dark theme", async () => {
    localStorage.setItem("eitop.theme", "dark");
    renderApp("/active-directory?tab=insights", insightsHandler());

    expect(await screen.findByTestId("findings-summary")).toBeInTheDocument();
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("renders health and gaps under the active theme too", async () => {
    localStorage.setItem("eitop.theme", "light");
    const { unmount } = renderApp("/active-directory?tab=health", insightsHandler());
    expect(await screen.findByTestId("health-verdict")).toBeInTheDocument();
    unmount();

    localStorage.setItem("eitop.theme", "dark");
    renderApp("/active-directory?tab=gaps", insightsHandler());
    expect(await screen.findByTestId("gap-ambiguous")).toBeInTheDocument();
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
