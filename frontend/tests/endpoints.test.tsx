/** Endpoint overview + inventory table tests (Phase 2.7). */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
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

const overview = {
  total: 2,
  active: 1,
  offline: 1,
  revoked: 0,
  windows: 1,
  linux: 1,
  other_os: 0,
  inventory_reported: 1,
  latest_enrollments: [],
};

function listHandler(options: { items?: unknown[]; total?: number; fail?: boolean } = {}) {
  return ({ url }: FetchCall): Response | undefined => {
    const path = url.pathname;
    if (path.endsWith("/api/v1/auth/me")) return jsonResponse(makeUser(ADMIN_PERMISSIONS));
    if (path.endsWith("/api/v1/endpoints/overview")) return jsonResponse(overview);
    if (path.endsWith("/api/v1/endpoints/groups")) return jsonResponse([]);
    if (path.endsWith("/api/v1/endpoints")) {
      if (options.fail) {
        return jsonResponse(
          { type: "about:blank", title: "Server Error", status: 500 },
          500,
        );
      }
      // Section queries (page_size=5) get their own realistic rows so the
      // page never shows the same hostname twice under one render.
      const pageSize = Number(url.searchParams.get("page_size") ?? 20);
      if (pageSize === 5 && url.searchParams.get("status") === "offline") {
        return jsonResponse({
          items: [endpointRow({ id: "33333333-3333-3333-3333-333333333333", hostname: "edge-02", status: "offline" })],
          total: 1,
          page: 1,
          page_size: 5,
        });
      }
      if (pageSize === 5 && url.searchParams.get("sort") === "last_heartbeat_at") {
        return jsonResponse({
          items: [endpointRow({ id: "44444444-4444-4444-4444-444444444444", hostname: "db-01" })],
          total: 1,
          page: 1,
          page_size: 5,
        });
      }
      return jsonResponse({
        items: options.items ?? [endpointRow()],
        total: options.total ?? 1,
        page: Number(url.searchParams.get("page") ?? 1),
        page_size: pageSize,
      });
    }
    return undefined;
  };
}

function pendingListHandler(): (call: FetchCall) => Response | undefined {
  return ({ url }: FetchCall): Response | undefined => {
    if (url.pathname.endsWith("/api/v1/auth/me")) return jsonResponse(makeUser(ADMIN_PERMISSIONS));
    if (url.pathname.endsWith("/api/v1/endpoints/overview")) return jsonResponse(overview);
    if (url.pathname.endsWith("/api/v1/endpoints/groups")) return jsonResponse([]);
    if (url.pathname.endsWith("/api/v1/endpoints")) {
      // never settles → the UI must show its loading state
      return new Promise<Response>(() => {}) as unknown as Response;
    }
    return undefined;
  };
}

describe("endpoint list page", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("renders real overview stats and endpoint rows", async () => {
    renderApp("/endpoints", listHandler());

    expect(await screen.findByText("web-01")).toBeInTheDocument();
    // stats come from the API payload — no hardcoded numbers
    const stats = screen.getByRole("region", { name: "Endpoint statistics" });
    expect(within(stats).getByText("Total").parentElement).toHaveTextContent("2");
    expect(within(stats).getByText("Offline").parentElement).toHaveTextContent("1");
    // row shows status, IPs, agent version and UTC timestamps
    expect(screen.getByTestId("status-active")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
    expect(screen.getByText("0.2.0")).toBeInTheDocument();
    expect(screen.getByText(/2026-11-19 02:00 UTC/)).toBeInTheDocument();
    expect(screen.getByText(/2026-11-01 10:00 UTC/)).toBeInTheDocument();
  });

  it("filters by status through the API", async () => {
    renderApp("/endpoints", listHandler());
    const user = userEvent.setup();

    await screen.findByText("web-01");
    await user.selectOptions(screen.getByLabelText("Status"), "offline");

    await waitFor(() => {
      const listCall = getFetchMock()
        .mock.calls.map((c) => new URL(String(c[0])))
        .find(
          (u) =>
            u.pathname.endsWith("/api/v1/endpoints") &&
            u.searchParams.get("status") === "offline",
        );
      expect(listCall).toBeDefined();
    });
    expect(await screen.findByText("web-01")).toBeInTheDocument();
  });

  it("paginates server-side", async () => {
    renderApp("/endpoints", listHandler({ total: 40 }));
    const user = userEvent.setup();

    await screen.findByText("web-01");
    await user.click(screen.getByRole("button", { name: "Next" }));

    await waitFor(() => {
      const pageCall = getFetchMock()
        .mock.calls.map((c) => new URL(String(c[0])))
        .find(
          (u) =>
            u.pathname.endsWith("/api/v1/endpoints") &&
            u.searchParams.get("page") === "2",
        );
      expect(pageCall).toBeDefined();
    });
  });

  it("sorts only through allowlisted fields", async () => {
    renderApp("/endpoints", listHandler());
    const user = userEvent.setup();

    await screen.findByText("web-01");
    await user.click(screen.getByRole("button", { name: "Sort by hostname" }));

    await waitFor(() => {
      const sortCall = getFetchMock()
        .mock.calls.map((c) => new URL(String(c[0])))
        .find(
          (u) =>
            u.pathname.endsWith("/api/v1/endpoints") &&
            u.searchParams.get("sort") === "hostname",
        );
      expect(sortCall).toBeDefined();
    });
  });

  it("shows the loading state while the list request is pending", async () => {
    renderApp("/endpoints", pendingListHandler());

    expect(await screen.findByText(/Loading endpoints/i)).toBeInTheDocument();
  });

  it("shows an error state when the list request fails", async () => {
    renderApp("/endpoints", listHandler({ fail: true }));

    const alert = await screen.findByTestId("error-state");
    expect(alert).toHaveTextContent(/Server Error/);
    // main + section error states each offer a retry action
    expect(screen.getAllByRole("button", { name: "Retry" }).length).toBeGreaterThan(0);
  });

  it("shows an empty state when no endpoints match", async () => {
    renderApp("/endpoints", listHandler({ items: [], total: 0 }));

    expect(await screen.findByTestId("empty-state")).toHaveTextContent(
      /No endpoints match/i,
    );
  });

  it("keeps nav links available to read-only users", async () => {
    renderApp("/endpoints", ({ url }: FetchCall) => {
      if (url.pathname.endsWith("/api/v1/auth/me")) {
        return jsonResponse(makeUser(["endpoints:read"]));
      }
      return listHandler()({ url });
    });

    expect(await screen.findByText("web-01")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Endpoint Groups" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Endpoints" })).toBeInTheDocument();
  });
});
