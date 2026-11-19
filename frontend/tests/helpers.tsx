/** Shared render/fetch helpers for frontend feature tests. */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { App } from "../src/App";
import { AuthProvider } from "../src/auth/AuthContext";
import type { UserInfo } from "../src/auth/AuthContext";

export const ADMIN_PERMISSIONS = [
  "endpoints:read",
  "endpoints:write",
  "admin:read",
  "audit:read",
];

export const READONLY_PERMISSIONS = ["endpoints:read"];

export function makeUser(permissions: string[]): UserInfo {
  return {
    id: "u-1",
    email: "admin@example.com",
    full_name: "Admin",
    is_active: true,
    roles: ["admin"],
    permissions,
    created_at: "2026-01-01T00:00:00+00:00",
  };
}

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export interface FetchCall {
  url: URL;
  init?: RequestInit;
}

/**
 * Install a URL-routed fetch mock. The handler receives the parsed URL and
 * request init; returning undefined yields a 404 problem+json (so missing
 * routes fail loudly in assertions instead of silently succeeding).
 */
let lastMock: ReturnType<typeof vi.fn> | null = null;

/** The most recently installed fetch mock (for asserting request URLs). */
export function getFetchMock(): ReturnType<typeof vi.fn> {
  if (!lastMock) throw new Error("fetch mock not installed");
  return lastMock;
}

export function installFetch(
  handler: (call: FetchCall) => Response | undefined,
): ReturnType<typeof vi.fn> {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost:3000");
    const response = handler({ url, init });
    if (response) return response;
    return jsonResponse(
      { type: "about:blank", title: "Not Found", status: 404, detail: url.pathname },
      404,
    );
  });
  vi.stubGlobal("fetch", mock);
  lastMock = mock;
  return mock;
}

/** Standard handler: /auth/me returns the given user. */
export function authHandler(user: UserInfo) {
  return ({ url }: FetchCall): Response | undefined => {
    if (url.pathname.endsWith("/api/v1/auth/me")) return jsonResponse(user);
    return undefined;
  };
}

export function renderApp(
  initialPath: string,
  handler: (call: FetchCall) => Response | undefined,
) {
  // Presence hint so AuthProvider restores the session via /auth/me.
  localStorage.setItem("eitop.session", "1");
  installFetch(handler);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Endpoint row fixture matching the backend's EndpointOut. */
export function endpointRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    hostname: "web-01",
    fqdn: "web-01.example.com",
    os: "linux",
    os_version: "24.04",
    os_arch: "x86_64",
    kernel_version: "6.8.0",
    status: "active",
    agent_version: "0.2.0",
    enrolled_at: "2026-11-01T10:00:00+00:00",
    last_heartbeat_at: "2026-11-19T02:00:00+00:00",
    created_at: "2026-11-01T10:00:00+00:00",
    updated_at: "2026-11-19T02:00:00+00:00",
    groups: ["production"],
    ip_addresses: ["192.0.2.10"],
    last_inventory_at: "2026-11-19T02:05:00+00:00",
    ...overrides,
  };
}
