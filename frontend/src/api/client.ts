/**
 * Typed API client for the EITOP backend.
 *
 * - Sends `Authorization: Bearer` when an access token is present.
 * - Parses RFC 9457 problem+json errors into `ApiError`.
 * - On 401, attempts a single refresh-token rotation and retries once.
 */

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  errors?: { field: string; message: string }[];
}

export class ApiError extends Error {
  readonly status: number;
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(problem.detail ?? problem.title);
    this.name = "ApiError";
    this.status = problem.status;
    this.problem = problem;
  }
}

export interface TokenPair {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  refresh_expires_in: number;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

let accessToken: string | null = null;
let refreshToken: string | null = null;

export function setTokens(access: string | null, refresh: string | null): void {
  accessToken = access;
  refreshToken = refresh;
  if (access && refresh) {
    localStorage.setItem("eitop.refresh_token", refresh);
  } else {
    localStorage.removeItem("eitop.refresh_token");
  }
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function getStoredRefreshToken(): string | null {
  return refreshToken ?? localStorage.getItem("eitop.refresh_token");
}

export function clearTokens(): void {
  setTokens(null, null);
}

async function parseProblem(res: Response): Promise<ApiError> {
  try {
    const body = (await res.json()) as ProblemDetails;
    if (body && typeof body.status === "number") {
      return new ApiError(body);
    }
  } catch {
    // non-JSON body — fall through
  }
  return new ApiError({
    type: "about:blank",
    title: `HTTP ${res.status}`,
    status: res.status,
    detail: res.statusText,
  });
}

/** Rotate the refresh token; returns new pair or null when it fails. */
async function tryRefresh(): Promise<TokenPair | null> {
  const stored = getStoredRefreshToken();
  if (!stored) return null;
  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: stored }),
    });
    if (!res.ok) {
      clearTokens();
      return null;
    }
    const pair = (await res.json()) as TokenPair;
    setTokens(pair.access_token, pair.refresh_token);
    return pair;
  } catch {
    return null;
  }
}

export interface RequestOptions extends Omit<RequestInit, "headers"> {
  headers?: Record<string, string>;
  auth?: boolean;
  query?: Record<string, string | number | undefined>;
  retry?: boolean;
}

export async function apiFetch<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { auth = true, query, retry = true, ...init } = options;

  const url = new URL(API_BASE + path, window.location.origin);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }

  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (auth && accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  let res: Response;
  try {
    res = await fetch(url.toString(), { ...init, headers });
  } catch {
    throw new ApiError({
      type: "about:blank",
      title: "Network error",
      status: 0,
      detail: "Could not reach the API server.",
    });
  }

  // One transparent refresh attempt on 401.
  if (res.status === 401 && auth && retry && (accessToken || getStoredRefreshToken())) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      return apiFetch<T>(path, { ...options, retry: false });
    }
    clearTokens();
  }

  if (!res.ok) throw await parseProblem(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(path: string, opts?: RequestOptions) =>
    apiFetch<T>(path, { ...opts, method: "GET" }),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) =>
    apiFetch<T>(path, { ...opts, method: "POST", body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown, opts?: RequestOptions) =>
    apiFetch<T>(path, { ...opts, method: "PUT", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown, opts?: RequestOptions) =>
    apiFetch<T>(path, { ...opts, method: "PATCH", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string, opts?: RequestOptions) =>
    apiFetch<T>(path, { ...opts, method: "DELETE" }),
};
