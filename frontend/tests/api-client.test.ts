import { describe, expect, it, vi, beforeEach } from "vitest";
import { apiFetch, ApiError, setTokens, clearTokens } from "../src/api/client";

describe("api client", () => {
  beforeEach(() => {
    clearTokens();
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
    setTokens("access-abc", "refresh-xyz");
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

  it("stores refresh token in localStorage and clears it", () => {
    setTokens("a", "r1");
    expect(localStorage.getItem("eitop.refresh_token")).toBe("r1");
    clearTokens();
    expect(localStorage.getItem("eitop.refresh_token")).toBeNull();
  });
});
