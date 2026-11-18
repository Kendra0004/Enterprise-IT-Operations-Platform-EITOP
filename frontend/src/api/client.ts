/**
 * Typed API client for the EITOP backend.
 *
 * - Sends `Authorization: Bearer` with the in-memory access token.
 * - The refresh token lives ONLY in an HttpOnly cookie set by the backend;
 *   JavaScript never reads or writes it (XSS cannot exfiltrate it).
 * - Parses RFC 9457 problem+json errors into `ApiError`.
 * - On 401, attempts a single cookie-based refresh and retries once.
 * - A non-secret `eitop.session` localStorage flag is only a presence hint
 *   (no token) so the app can avoid probing /auth/me on every cold load.
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
  refresh_expires_in: number;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";
const SESSION_HINT_KEY = "eitop.session";

// Access token: memory only — never persisted.
let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

/** True when a session *might* exist (hint flag only — no token material). */
export function hasSessionHint(): boolean {
  return localStorage.getItem(SESSION_HINT_KEY) === "1";
}

export function setSessionHint(present: boolean): void {
  if (present) {
    localStorage.setItem(SESSION_HINT_KEY, "1");
  } else {
    localStorage.removeItem(SESSION_HINT_KEY);
  }
}

export function clearTokens(): void {
  accessToken = null;
  setSessionHint(false);
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

/**
 * Rotate the refresh token held in the HttpOnly cookie; returns the new
 * access token or null when rotation fails (session is gone).
 */
async function tryRefresh(): Promise<string | null> {
  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
    if (!res.ok) {
      clearTokens();
      return null;
    }
    const pair = (await res.json()) as TokenPair;
    accessToken = pair.access_token;
    setSessionHint(true);
    return pair.access_token;
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
    res = await fetch(url.toString(), {
      ...init,
      headers,
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError({
      type: "about:blank",
      title: "Network error",
      status: 0,
      detail: "Could not reach the API server.",
    });
  }

  // One transparent cookie-refresh attempt on 401.
  if (res.status === 401 && auth && retry && (accessToken || hasSessionHint())) {
    const newAccess = await tryRefresh();
    if (newAccess) {
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
