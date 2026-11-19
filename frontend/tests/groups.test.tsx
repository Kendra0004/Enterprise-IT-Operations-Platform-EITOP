/** Group management tests: list, create, members, assign/remove, RBAC. */

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

const GROUP_ID = "22222222-2222-2222-2222-222222222222";
const ENDPOINT_ID = "11111111-1111-1111-1111-111111111111";

const CANDIDATE_ID = "44444444-4444-4444-4444-444444444444";

const groupRow = {
  id: GROUP_ID,
  name: "production",
  description: "Production servers",
  created_at: "2026-11-01T10:00:00+00:00",
  updated_at: "2026-11-01T10:00:00+00:00",
  endpoint_count: 1,
};

function groupHandler(permissions: string[] = ADMIN_PERMISSIONS) {
  return ({ url, init }: FetchCall): Response | undefined => {
    const path = url.pathname;
    const method = init?.method ?? "GET";

    if (path.endsWith("/api/v1/auth/me")) return jsonResponse(makeUser(permissions));

    if (path.endsWith("/api/v1/endpoints/groups") && method === "POST") {
      return jsonResponse({ ...groupRow, name: "staging", endpoint_count: 0 }, 201);
    }
    if (path.endsWith(`/api/v1/endpoints/groups/${GROUP_ID}`)) {
      return jsonResponse({
        ...groupRow,
        members: [endpointRow()],
      });
    }
    if (path.endsWith("/api/v1/endpoints/groups")) {
      return jsonResponse([groupRow]);
    }
    if (path.includes(`/groups/${GROUP_ID}`) && method === "DELETE") {
      return jsonResponse({ ...groupRow, endpoint_count: 0, members: [] });
    }
    if (path.includes(`/groups/${GROUP_ID}`) && method === "POST") {
      return jsonResponse(groupRow);
    }
    if (path.endsWith("/api/v1/endpoints")) {
      // active endpoints available for assignment (the member is excluded
      // client-side, so return a different endpoint here)
      return jsonResponse({
        items: [endpointRow({ id: CANDIDATE_ID, hostname: "batch-02" })],
        total: 1,
        page: 1,
        page_size: 100,
      });
    }
    return undefined;
  };
}

describe("groups page", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("lists groups with real endpoint counts", async () => {
    renderApp("/groups", groupHandler());

    const groupBtn = await screen.findByRole("button", { name: /production/ });
    expect(groupBtn).toHaveTextContent("1 endpoint(s)");
  });

  it("creates a group through the API", async () => {
    renderApp("/groups", groupHandler());
    const user = userEvent.setup();

    const nameInput = await screen.findByLabelText("Name");
    await user.type(nameInput, "staging");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => {
      const call = getFetchMock().mock.calls.find(
        (c) =>
          String(c[0]).endsWith("/api/v1/endpoints/groups") &&
          c[1]?.method === "POST",
      );
      expect(call).toBeDefined();
      expect(String(call![1]?.body)).toContain("staging");
    });
  });

  it("shows group members after selecting a group", async () => {
    renderApp(`/groups?group=${GROUP_ID}`, groupHandler());

    expect(await screen.findByText("web-01")).toBeInTheDocument();
    expect(screen.getByText(/Created 2026-11-01 10:00 UTC/)).toBeInTheDocument();
    expect(screen.getByTestId("status-active")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web-01" })).toHaveAttribute(
      "href",
      `/endpoints/${ENDPOINT_ID}`,
    );
  });

  it("removes a member only after confirmation", async () => {
    renderApp(`/groups?group=${GROUP_ID}`, groupHandler());
    const user = userEvent.setup();

    const removeBtn = await screen.findByRole("button", { name: "Remove" });
    await user.click(removeBtn);

    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent(/web-01/);
    expect(
      getFetchMock().mock.calls.some(
        (c) => String(c[0]).includes("/groups/") && c[1]?.method === "DELETE",
      ),
    ).toBe(false);

    await user.click(within(dialog).getByRole("button", { name: "Remove" }));

    await waitFor(() => {
      const call = getFetchMock()
        .mock.calls.map((c) => ({ url: new URL(String(c[0])), init: c[1] }))
        .find(
          (c) =>
            c.url.pathname.includes(`/api/v1/endpoints/${ENDPOINT_ID}/groups/${GROUP_ID}`) &&
            c.init?.method === "DELETE",
        );
      expect(call).toBeDefined();
    });
  });

  it("assigns an endpoint to a group", async () => {
    renderApp(`/groups?group=${GROUP_ID}`, groupHandler());
    const user = userEvent.setup();

    const select = await screen.findByLabelText("Add endpoint");
    await user.selectOptions(select, CANDIDATE_ID);
    await user.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() => {
      const call = getFetchMock()
        .mock.calls.map((c) => ({ url: new URL(String(c[0])), init: c[1] }))
        .find(
          (c) =>
            c.url.pathname.endsWith(
              `/api/v1/endpoints/${CANDIDATE_ID}/groups/${GROUP_ID}`,
            ) && c.init?.method === "POST",
        );
      expect(call).toBeDefined();
    });
  });

  it("hides create/remove controls from read-only users", async () => {
    renderApp(`/groups?group=${GROUP_ID}`, groupHandler(["endpoints:read"]));

    expect(await screen.findByText("web-01")).toBeInTheDocument();
    expect(screen.queryByLabelText("Name")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Add endpoint")).not.toBeInTheDocument();
    // read-only users can still inspect the group
    expect(
      await screen.findByRole("button", { name: /production/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "production" })).toBeInTheDocument();
  });
});
