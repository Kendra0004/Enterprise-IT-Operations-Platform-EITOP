/** Phase 2.8: theme switching + dashboard design/behavior tests. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  ADMIN_PERMISSIONS,
  jsonResponse,
  makeUser,
  renderApp,
  type FetchCall,
} from "./helpers";

const overview = {
  total: 3,
  active: 2,
  offline: 1,
  revoked: 0,
  windows: 1,
  linux: 2,
  other_os: 0,
  inventory_reported: 2,
  latest_enrollments: [],
};

function dashboardHandler() {
  return ({ url }: FetchCall): Response | undefined => {
    const path = url.pathname;
    if (path.endsWith("/api/v1/auth/me")) return jsonResponse(makeUser(ADMIN_PERMISSIONS));
    if (path.endsWith("/api/v1/endpoints/overview")) return jsonResponse(overview);
    if (path.endsWith("/api/v1/audit-logs")) {
      return jsonResponse({
        items: [
          {
            id: "a-1",
            event_type: "endpoint.enrolled",
            actor_email: "admin@example.com",
            target: "11111111-1111-1111-1111-111111111111",
            outcome: "success",
            created_at: "2026-11-19T02:00:00+00:00",
          },
        ],
        total: 1,
        page: 1,
        page_size: 8,
      });
    }
    if (path.endsWith("/health/ready")) {
      return jsonResponse({ status: "ok", checks: { database: "ok", redis: "ok" } });
    }
    return undefined;
  };
}

describe("theme switching", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.classList.remove("dark");
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("defaults to dark and toggles to light with persistence", async () => {
    const user = userEvent.setup();
    renderApp("/login", dashboardHandler());

    // Default theme is dark (html class applied by ThemeProvider).
    await waitFor(() =>
      expect(document.documentElement.classList.contains("dark")).toBe(true),
    );

    const toggle = await screen.findByRole("button", {
      name: "Switch to light theme",
    });
    await user.click(toggle);

    await waitFor(() => {
      expect(localStorage.getItem("eitop.theme")).toBe("light");
      expect(document.documentElement.classList.contains("dark")).toBe(false);
    });

    // Accessible name now advertises the opposite action.
    expect(
      screen.getByRole("button", { name: "Switch to dark theme" }),
    ).toBeInTheDocument();
  });

  it("restores a stored light preference on mount", async () => {
    localStorage.setItem("eitop.theme", "light");
    renderApp("/login", dashboardHandler());

    await waitFor(() =>
      expect(document.documentElement.classList.contains("dark")).toBe(false),
    );
    expect(
      await screen.findByRole("button", { name: "Switch to dark theme" }),
    ).toBeInTheDocument();
  });
});

describe("dashboard (Phase 2.8)", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("links endpoint KPI cards to the filtered endpoint views", async () => {
    renderApp("/", dashboardHandler());

    const total = await screen.findByRole("link", { name: /3 endpoints/ });
    expect(total).toHaveAttribute("href", "/endpoints");

    expect(
      screen.getByRole("link", { name: /2 active endpoints/ }),
    ).toHaveAttribute("href", "/endpoints?status=active");
    expect(
      screen.getByRole("link", { name: /1 offline endpoints/ }),
    ).toHaveAttribute("href", "/endpoints?status=offline");
    expect(
      screen.getByRole("link", { name: /0 revoked endpoints/ }),
    ).toHaveAttribute("href", "/endpoints?status=revoked");
  });

  it("renders audit timestamps in UTC and keeps real event types", async () => {
    renderApp("/", dashboardHandler());

    expect(await screen.findByText("endpoint.enrolled")).toBeInTheDocument();
    expect(screen.getAllByText("2026-11-19 02:00 UTC").length).toBeGreaterThan(0);
    // No local-zone rendering of the same instant.
    expect(screen.queryByText(/2026-11-19T02:00/)).not.toBeInTheDocument();
  });

  it("does not show stale Phase-1 copy", async () => {
    renderApp("/", dashboardHandler());
    // Header title + page heading both say "Dashboard".
    expect((await screen.findAllByText("Dashboard")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Phase 1/i)).not.toBeInTheDocument();
  });
});
