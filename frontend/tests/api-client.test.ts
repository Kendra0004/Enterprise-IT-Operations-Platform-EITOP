import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  apiFetch,
  ApiError,
  setAccessToken,
  clearTokens,
  hasSessionHint,
  setSessionHint,
} from "../src/api/client";

describe("api client", () => {
  beforeEach(() => {
    clearTokens();
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("parses RFC 9457 problem+json into ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            type: "about:blank",
            title: "Invalid credentials",
            status: 401,
            detail: "Email or password is incorrect.",
          }),
          { status: 401, headers: { "Content-Type": "application/problem+json" } },
        ),
      ),
    );

    await expect(apiFetch("/auth/login", { auth: false })).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      problem: { title: "Invalid credentials" },
    });
  });

  it("attaches the bearer token when set", async () => {
    setAccessToken("access-abc");
    const mock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", mock);

    await apiFetch("/auth/me");
    const headers = mock.mock.calls[0][1].headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer access-abc");
  });

  it("maps network failure to a problem object", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("Failed to fetch")),
    );
    await expect(apiFetch("/health")).rejects.toBeInstanceOf(ApiError);
  });

  it("never stores token material in localStorage (cookie-only refresh)", async () => {
    setAccessToken("access-secret");
    setSessionHint(true);

    // Only the non-secret presence hint may exist — no tokens, ever.
    expect(localStorage.getItem("eitop.session")).toBe("1");
    expect(localStorage.length).toBe(1);
    expect(localStorage.getItem("eitop.refresh_token")).toBeNull();
    expect(localStorage.getItem("eitop.access_token")).toBeNull();

    clearTokens();
    expect(localStorage.getItem("eitop.session")).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it("session hint drives whether a restore is attempted", () => {
    expect(hasSessionHint()).toBe(false);
    setSessionHint(true);
    expect(hasSessionHint()).toBe(true);
  });

  it("cookie refresh sends no token in the request body", async () => {
    setSessionHint(true);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ title: "Invalid token", status: 401 }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              access_token: "new",
              token_type: "bearer",
              expires_in: 900,
              refresh_expires_in: 604800,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );

    await apiFetch("/auth/me");

    const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
    const refreshCall = calls.find((c) => String(c[0]).endsWith("/auth/refresh"));
    expect(refreshCall).toBeDefined();
    // Cookie-based: no JSON body carrying a refresh token.
    expect(refreshCall![1]?.body).toBeUndefined();
    // Same-origin credentials so the HttpOnly cookie is sent.
    expect(refreshCall![1]?.credentials).toBe("same-origin");
  });
});
