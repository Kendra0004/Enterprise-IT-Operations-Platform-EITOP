/** Inventory history tests: snapshot list, date filter, comparison diff. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  ADMIN_PERMISSIONS,
  getFetchMock,
  jsonResponse,
  makeUser,
  renderApp,
  type FetchCall,
} from "./helpers";

const ID = "11111111-1111-1111-1111-111111111111";
const SNAP_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"; // older
const SNAP_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"; // newer

const snapshotA = {
  id: SNAP_A,
  endpoint_id: ID,
  collected_at: "2026-11-10T08:00:00+00:00",
  received_at: "2026-11-10T08:00:05+00:00",
  agent_version: "0.2.0",
  schema_version: 1,
  package_count: 3,
  fact_count: 1,
  has_hardware: true,
  has_network: true,
};

const snapshotB = {
  ...snapshotA,
  id: SNAP_B,
  collected_at: "2026-11-19T08:00:00+00:00",
  received_at: "2026-11-19T08:00:04+00:00",
  package_count: 3,
};

const diff = {
  base_snapshot_id: SNAP_A,
  target_snapshot_id: SNAP_B,
  added_packages: [{ name: "newapp", version: "2.0", package_manager: "dpkg" }],
  removed_packages: [{ name: "legacy", version: "1.0", package_manager: "dpkg" }],
  changed_packages: [
    {
      name: "curl",
      version: "8.6.0",
      package_manager: "dpkg",
      previous_version: "8.5.0",
    },
  ],
  hardware_changes: [{ field: "cpu_cores", before: 4, after: 8 }],
};

function historyHandler(options: { empty?: boolean } = {}) {
  return ({ url }: FetchCall): Response | undefined => {
    const path = url.pathname;
    if (path.endsWith("/api/v1/auth/me")) return jsonResponse(makeUser(ADMIN_PERMISSIONS));
    if (path.includes("/snapshots/") && path.endsWith(SNAP_B)) {
      return jsonResponse({
        ...snapshotB,
        system: { hostname: "web-01", os: "linux" },
        hardware: { cpu_cores: 8 },
        network: { ip_addresses: ["192.0.2.10"] },
        filesystems: [],
        facts: { "collector.version": "0.2.0" },
        packages: [{ name: "curl", version: "8.6.0", package_manager: "dpkg" }],
        changes: diff,
      });
    }
    if (path.includes("/snapshots/") && path.endsWith(SNAP_A)) {
      return jsonResponse({
        ...snapshotA,
        system: { hostname: "web-01", os: "linux" },
        hardware: { cpu_cores: 4 },
        network: null,
        filesystems: [],
        facts: {},
        packages: [],
        changes: null,
      });
    }
    if (path.endsWith(`/api/v1/endpoints/${ID}/snapshots`)) {
      return jsonResponse({
        items: options.empty ? [] : [snapshotB, snapshotA],
        total: options.empty ? 0 : 2,
        page: 1,
        page_size: 20,
      });
    }
    if (path.endsWith(`/api/v1/endpoints/${ID}/network`)) {
      return jsonResponse({
        items: [
          {
            snapshot_id: SNAP_B,
            collected_at: "2026-11-19T08:00:00+00:00",
            network: { ip_addresses: ["192.0.2.10", "198.51.100.5"] },
          },
        ],
        total: 1,
        page: 1,
        page_size: 20,
      });
    }
    if (path.endsWith(`/api/v1/endpoints/${ID}`)) {
      return jsonResponse({
        id: ID,
        hostname: "web-01",
        fqdn: null,
        os: "linux",
        os_version: "24.04",
        os_arch: "x86_64",
        kernel_version: "6.8.0",
        status: "active",
        agent_version: "0.2.0",
        enrolled_at: "2026-11-01T10:00:00+00:00",
        last_heartbeat_at: "2026-11-19T07:59:00+00:00",
        created_at: "2026-11-01T10:00:00+00:00",
        updated_at: "2026-11-19T07:59:00+00:00",
        groups: [],
        ip_addresses: ["192.0.2.10"],
        metadata: null,
        facts: [],
        software_count: 3,
        last_inventory_at: "2026-11-19T08:00:04+00:00",
      });
    }
    return undefined;
  };
}

describe("inventory history page", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("lists snapshots with UTC timestamps", async () => {
    renderApp(`/endpoints/${ID}/history`, historyHandler());

    expect(await screen.findByText("2026-11-19 08:00:04 UTC")).toBeInTheDocument();
    expect(screen.getByText("2026-11-10 08:00:05 UTC")).toBeInTheDocument();
    expect(screen.getByText("2026-11-10 08:00:00 UTC")).toBeInTheDocument(); // collected
    // network history section shows reported IPs
    expect(screen.getByText(/192\.0\.2\.10, 198\.51\.100\.5/)).toBeInTheDocument();
  });

  it("compares the selected snapshot with the previous one", async () => {
    renderApp(`/endpoints/${ID}/history`, historyHandler());
    const user = userEvent.setup();

    await screen.findByText("2026-11-19 08:00:04 UTC");
    const checkbox = screen.getByLabelText(/Select snapshot 2026-11-19/);
    await user.click(checkbox);

    await waitFor(() => {
      const call = getFetchMock()
        .mock.calls.map((c) => new URL(String(c[0])))
        .find((u) => u.pathname.includes(`/snapshots/${SNAP_B}`));
      expect(call?.searchParams.get("compare_to")).toBe(SNAP_A);
    });

    // diff panel shows installs, removals, version change and hardware change
    expect(await screen.findByText(/Installed since base/)).toBeInTheDocument();
    expect(screen.getByText("newapp")).toBeInTheDocument();
    expect(screen.getByText("legacy")).toBeInTheDocument();
    expect(screen.getByText(/8\.5\.0 → 8\.6\.0/)).toBeInTheDocument();
    expect(
      screen.getByText(
        (_, node) =>
          node?.tagName === "LI" &&
          (node.textContent ?? "").includes("cpu_cores") &&
          (node.textContent ?? "").includes("4") &&
          (node.textContent ?? "").includes("8"),
      ),
    ).toBeInTheDocument();
  });

  it("sends the selected date range to the API", async () => {
    renderApp(`/endpoints/${ID}/history`, historyHandler());
    const user = userEvent.setup();

    await screen.findByText("2026-11-19 08:00:04 UTC");
    const from = screen.getByLabelText("From");
    await user.type(from, "2026-11-01");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() => {
      const call = getFetchMock()
        .mock.calls.map((c) => new URL(String(c[0])))
        .find(
          (u) =>
            u.pathname.endsWith(`/api/v1/endpoints/${ID}/snapshots`) &&
            u.searchParams.get("from") === "2026-11-01T00:00:00Z",
        );
      expect(call).toBeDefined();
    });
  });

  it("shows an empty state when no snapshots exist", async () => {
    renderApp(`/endpoints/${ID}/history`, historyHandler({ empty: true }));
    expect(await screen.findByTestId("empty-state")).toHaveTextContent(
      /No snapshots/i,
    );
    expect(screen.getByText(/Select a snapshot to compare/)).toBeInTheDocument();
  });
});
