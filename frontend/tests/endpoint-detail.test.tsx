/** Endpoint detail page tests: rendering, RBAC visibility, revoke flow. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  ADMIN_PERMISSIONS,
  endpointRow,
  getFetchMock,
  jsonResponse,
  makeUser,
  renderApp,
  type FetchCall,
} from "./helpers";

const ID = "11111111-1111-1111-1111-111111111111";

const detail = endpointRow({
  metadata: {
    manufacturer: "QEMU",
    model: "Standard PC",
    serial_number: "SN-123",
    cpu_model: "Common KVM processor",
    cpu_cores: 4,
    memory_bytes: 8 * 1024 ** 3,
    disk_bytes: 100 * 1024 ** 3,
    ip_addresses: ["192.0.2.10"],
    mac_addresses: ["52:54:00:12:34:56"],
    updated_at: "2026-11-19T02:00:00+00:00",
  },
  facts: [
    {
      key: "collector.version",
      value: "0.2.0",
      source: "agent",
      collected_at: "2026-11-19T02:00:00+00:00",
    },
  ],
  software_count: 2,
  last_inventory_at: "2026-11-19T02:05:00+00:00",
});

const health = {
  endpoint_id: ID,
  status: "active",
  collector_status: "healthy",
  last_heartbeat_at: "2026-11-19T02:00:00+00:00",
  last_inventory_at: "2026-11-19T02:05:00+00:00",
  seconds_since_heartbeat: 30,
  agent_version: "0.2.0",
  heartbeat_interval_seconds: 300,
  offline_threshold_seconds: 900,
  server_time: "2026-11-19T02:00:30+00:00",
};

function detailHandler(
  permissions: string[] = ADMIN_PERMISSIONS,
  overrides: { revokeStatus?: number } = {},
) {
  return ({ url, init }: FetchCall): Response | undefined => {
    const path = url.pathname;
    if (path.endsWith("/api/v1/auth/me")) return jsonResponse(makeUser(permissions));
    if (path.endsWith(`/api/v1/endpoints/${ID}/health`)) return jsonResponse(health);
    if (path.endsWith("/api/v1/audit-logs")) {
      // lifecycle activity for this endpoint (empty in the base fixture)
      return jsonResponse({ items: [], total: 0, page: 1, page_size: 100 });
    }
    if (path.endsWith(`/api/v1/endpoints/${ID}/software`)) {
      return jsonResponse({
        items: [
          { name: "curl", version: "8.5.0", package_manager: "dpkg" },
          { name: "openssl", version: "3.0.13", package_manager: "dpkg" },
        ],
        total: 2,
        page: 1,
        page_size: 50,
      });
    }
    if (path.endsWith(`/api/v1/endpoints/${ID}/revoke`) && init?.method === "POST") {
      if (overrides.revokeStatus && overrides.revokeStatus >= 400) {
        return jsonResponse(
          { type: "about:blank", title: "Forbidden", status: overrides.revokeStatus },
          overrides.revokeStatus,
        );
      }
      return jsonResponse({ id: ID, status: "revoked", revoked_credentials: 1 });
    }
    if (path.endsWith(`/api/v1/endpoints/${ID}`)) return jsonResponse(detail);
    if (path.endsWith("/api/v1/endpoints/groups")) return jsonResponse([]);
    return undefined;
  };
}

describe("endpoint detail page", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("renders identity, hardware, network, software and health", async () => {
    renderApp(`/endpoints/${ID}`, detailHandler());

    expect(await screen.findByRole("heading", { name: /web-01/ })).toBeInTheDocument();

    // identity + OS
    expect(screen.getByText("web-01.example.com")).toBeInTheDocument();
    expect(screen.getByText("24.04")).toBeInTheDocument();
    expect(screen.getByText("6.8.0")).toBeInTheDocument();

    // hardware (CPU / memory / storage formatted from bytes)
    expect(screen.getByText(/Common KVM processor/)).toBeInTheDocument();
    expect(screen.getByText(/8 GiB/)).toBeInTheDocument();
    expect(screen.getByText(/100 GiB/)).toBeInTheDocument();

    // network
    expect(screen.getByText(/52:54:00:12:34:56/)).toBeInTheDocument();
    expect(screen.getByText(/192\.0\.2\.10/)).toBeInTheDocument();

    // software
    expect(await screen.findByText("curl")).toBeInTheDocument();
    expect(screen.getByText("8.5.0 · dpkg")).toBeInTheDocument();

    // heartbeat + enrollment rendered in UTC
    expect(screen.getByText(/2026-11-19 02:00:00 UTC/)).toBeInTheDocument();
    expect(screen.getByText(/2026-11-01 10:00:00 UTC/)).toBeInTheDocument();

    // health configuration surfaced
    expect(screen.getByText(/Expected heartbeat every 300s/)).toBeInTheDocument();
  });

  it("shows revoke/rotate actions only with endpoints:write", async () => {
    renderApp(`/endpoints/${ID}`, detailHandler(ADMIN_PERMISSIONS));
    expect(await screen.findByRole("button", { name: "Revoke endpoint" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rotate credential" })).toBeInTheDocument();
    cleanup();
    vi.unstubAllGlobals();

    localStorage.clear();
    renderApp(`/endpoints/${ID}`, detailHandler(["endpoints:read"]));
    expect(await screen.findByRole("heading", { name: /web-01/ })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Revoke endpoint" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Rotate credential" }),
    ).not.toBeInTheDocument();
    // read-only users still get navigation to history
    expect(
      screen.getByRole("link", { name: "Inventory history" }),
    ).toBeInTheDocument();
  });

  it("requires confirmation before revoking and then posts to the API", async () => {
    renderApp(`/endpoints/${ID}`, detailHandler());
    const user = userEvent.setup();

    await screen.findByRole("button", { name: "Revoke endpoint" });
    await user.click(screen.getByRole("button", { name: "Revoke endpoint" }));

    // confirmation dialog appears — no mutation yet
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent(/cannot be undone/i);
    expect(
      getFetchMock().mock.calls.some((c) => String(c[0]).endsWith("/revoke")),
    ).toBe(false);

    await user.click(within(dialog).getByRole("button", { name: "Revoke" }));

    await waitFor(() => {
      const revokeCall = getFetchMock()
        .mock.calls.map((c) => new URL(String(c[0])))
        .find(
          (u) => u.pathname.endsWith(`/api/v1/endpoints/${ID}/revoke`) && u.searchParams.size === 0,
        );
      expect(revokeCall).toBeDefined();
    });
    expect(
      getFetchMock().mock.calls.some((c) => String(c[0]).endsWith(`/api/v1/endpoints/${ID}/revoke`)),
    ).toBe(true);
  });

  it("cancel closes the dialog without calling the API", async () => {
    renderApp(`/endpoints/${ID}`, detailHandler());
    const user = userEvent.setup();

    await screen.findByRole("button", { name: "Revoke endpoint" });
    await user.click(screen.getByRole("button", { name: "Revoke endpoint" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(
      getFetchMock().mock.calls.some((c) => String(c[0]).endsWith("/revoke")),
    ).toBe(false);
  });

  it("surfaces backend failures as an error message", async () => {
    renderApp(`/endpoints/${ID}`, detailHandler(ADMIN_PERMISSIONS, { revokeStatus: 403 }));
    const user = userEvent.setup();

    await screen.findByRole("button", { name: "Revoke endpoint" });
    await user.click(screen.getByRole("button", { name: "Revoke endpoint" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Revoke" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/Forbidden/);
  });
});
