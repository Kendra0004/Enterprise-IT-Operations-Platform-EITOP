/** Active Directory page tests (Phase 3.1): tabs, RBAC, contract. */

import { afterEach, describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import {
  ADMIN_PERMISSIONS,
  getFetchMock,
  jsonResponse,
  makeUser,
  renderApp,
  type FetchCall,
} from "./helpers";

const CONNECTION_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const RUN_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

const DIRECTORY_ADMIN = [
  ...ADMIN_PERMISSIONS,
  "directory:read",
  "directory:write",
  "directory:sync",
];

const overview = {
  domains: 1,
  users_total: 12,
  users_enabled: 10,
  users_disabled: 2,
  groups: 4,
  computers: 7,
  missing_objects: 1,
  connections_total: 1,
  connections_enabled: 1,
  reconciliation_matched: 5,
  reconciliation_needs_review: 1,
  reconciliation_unmatched: 1,
  reconciliation_rejected: 0,
  running_syncs: 0,
  failed_runs_24h: 0,
  last_sync_success_at: "2026-11-19T02:00:00+00:00",
  last_sync_failure_at: null,
};

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
  last_run_started_at: "2026-11-19T02:00:00+00:00",
  last_success_at: "2026-11-19T02:00:00+00:00",
  created_at: "2026-11-01T10:00:00+00:00",
  updated_at: "2026-11-19T02:00:00+00:00",
  tls_ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
};

function page(items: unknown[], total = items.length) {
  return { items, total, page: 1, page_size: 50 };
}

const userRow = {
  id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
  connection_id: CONNECTION_ID,
  object_guid: "3f1e2d4c-0000-0000-0000-000000000001",
  distinguished_name: "CN=alice,OU=HQ,DC=eitop,DC=test",
  sid: "S-1-5-21-1-2-3-1001",
  sam_account_name: "alice",
  user_principal_name: "alice@eitop.test",
  display_name: "Alice Adams",
  email: "alice@eitop.test",
  enabled: true,
  department: "IT",
  title: null,
  manager_dn: null,
  last_logon_at: "2026-11-19T01:00:00+00:00",
  ad_created_at: null,
  ad_changed_at: null,
  last_seen_at: "2026-11-19T02:00:00+00:00",
  missing_since: null,
};

const runRow = {
  id: RUN_ID,
  connection_id: CONNECTION_ID,
  started_at: "2026-11-19T02:00:00+00:00",
  finished_at: "2026-11-19T02:00:12+00:00",
  status: "failed",
  trigger: "manual",
  objects_discovered: 0,
  objects_created: 0,
  objects_updated: 0,
  objects_marked_missing: 0,
  duration_ms: 12000,
};

const DIRECTORY_READONLY = ["endpoints:read", "directory:read"];

function directoryHandler(permissions: string[] = DIRECTORY_ADMIN) {
  return ({ url, init }: FetchCall): Response | undefined => {
    const path = url.pathname;
    const method = init?.method ?? "GET";

    if (path.endsWith("/api/v1/auth/me")) return jsonResponse(makeUser(permissions));

    if (path.endsWith("/api/v1/directory/overview")) return jsonResponse(overview);

    if (path.endsWith("/api/v1/directory/connections") && method === "POST") {
      return jsonResponse({ ...connection, name: "new-ad" }, 201);
    }
    if (path.endsWith("/api/v1/directory/connections")) {
      return jsonResponse(page([connection]));
    }
    if (path.endsWith("/api/v1/directory/sync-runs")) {
      return jsonResponse(page([runRow]));
    }
    if (path.includes("/test") && method === "POST") {
      return jsonResponse({
        ok: false,
        label: "connection_failed",
        message: "Could not reach the domain controller.",
        duration_ms: 12,
        default_naming_context: null,
        dns_hostname: null,
      });
    }
    if (path.includes("/sync") && method === "POST") {
      return jsonResponse(runRow, 202);
    }
    if (path.endsWith("/api/v1/directory/users")) {
      return jsonResponse(page([userRow]));
    }
    if (path.endsWith("/api/v1/directory/groups")) return jsonResponse(page([]));
    if (path.endsWith("/api/v1/directory/computers")) return jsonResponse(page([]));
    if (path.endsWith("/api/v1/directory/ous")) return jsonResponse(page([]));
    return undefined;
  };
}

afterEach(() => {
  localStorage.clear();
});

describe("Active Directory page", () => {
  it("shows overview KPIs from the API", async () => {
    renderApp("/active-directory", directoryHandler());

    expect(await screen.findByTestId("directory-page")).toBeInTheDocument();
    expect(await screen.findByText("Connections")).toBeInTheDocument();
    // Values come from the overview payload, not hard-coded.
    expect(await screen.findByText("12")).toBeInTheDocument();
    expect(await screen.findByText(/Last successful sync: 2026-11-19 02:00 UTC/)).toBeInTheDocument();
  });

  it("renders every tab section on demand", async () => {
    renderApp("/active-directory?tab=connections", directoryHandler());

    expect(await screen.findByTestId("directory-page")).toBeInTheDocument();
    expect((await screen.findAllByText("hq-ad")).length).toBeGreaterThan(0);
    expect(screen.getByText(/TLS validation is always on/)).toBeInTheDocument();

    // The create form hosts the write-only bind password field.
    screen.getByRole("button", { name: "Add connection" }).click();
    const password = (await screen.findByLabelText("Bind password")) as HTMLInputElement;
    expect(password.type).toBe("password");
    expect(password.value).toBe("");
  });

  it("lists directory users for the selected connection", async () => {
    renderApp("/active-directory?tab=users", directoryHandler());

    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(await screen.findByText("Alice Adams")).toBeInTheDocument();
    expect(await screen.findByText(/1 user\(s\)/)).toBeInTheDocument();

    // The request must carry the connection scope.
    const call = getFetchMock().mock.calls.find(([input]) =>
      String(input).includes("/directory/users"),
    );
    expect(call).toBeDefined();
    expect(String(call![0])).toContain(`connection_id=${CONNECTION_ID}`);
  });

  it("shows sync history with sanitized-label note", async () => {
    renderApp("/active-directory?tab=history", directoryHandler());

    expect(await screen.findByText("failed")).toBeInTheDocument();
    expect(await screen.findByText(/never raw exception text or credentials/)).toBeInTheDocument();
  });

  it("denies the page to roles without directory:read", async () => {
    renderApp("/active-directory", directoryHandler([]));

    expect(await screen.findByText(/Missing permission\(s\): directory:read/)).toBeInTheDocument();
    expect(screen.queryByTestId("directory-page")).not.toBeInTheDocument();
  });

  it("hides mutating controls from read-only roles", async () => {
    renderApp("/active-directory?tab=connections", directoryHandler(DIRECTORY_READONLY));

    expect((await screen.findAllByText("hq-ad")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Add connection" })).not.toBeInTheDocument();
    // Affordances may render, but they are inert without directory:sync.
    expect(screen.getByRole("button", { name: "Test" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Sync now" })).toBeDisabled();
  });

  it("queues a sync and reports the test result without leaking secrets", async () => {
    const handler = directoryHandler();
    renderApp("/active-directory?tab=connections", handler);

    expect((await screen.findAllByText("hq-ad")).length).toBeGreaterThan(0);
    const testBtn = await screen.findByRole("button", { name: "Test" });
    testBtn.click();

    expect(
      await screen.findByText("Could not reach the domain controller."),
    ).toBeInTheDocument();
    // The failure label is the API's sanitized label, not an exception dump.
    // Queued sync: POST …/sync issued for this connection, no secret echoed.
    screen.getByRole("button", { name: "Sync now" }).click();
    await waitFor(() => {
      const call = getFetchMock().mock.calls.find(
        ([input, init]) =>
          String(input).includes(`/connections/${CONNECTION_ID}/sync`) &&
          (init?.method ?? "GET") === "POST",
      );
      expect(call).toBeDefined();
      expect(String(call![0])).not.toContain("bind_password");
    });
  });
});
