# Authentication Flow

## Components

- **Argon2id** password hashing (argon2-cffi: t=2, 19 MiB, p=1).
- **Access token**: JWT (HS256), 15 min default, claims:
  `sub` (user id), `email`, `type=access`, `iss=eitop`, `iat`, `exp`, `jti`.
  Held **in memory only** on the client.
- **Refresh token**: opaque 48-byte random string, 7 days default.
  Only its **SHA-256 digest** is stored (`refresh_tokens.token_hash`).
  Transported **exclusively in an HttpOnly cookie** — never in a JSON body,
  never in `localStorage`.

### Refresh cookie attributes

| Attribute | Value | Why |
|---|---|---|
| `HttpOnly` | set | JavaScript (XSS) cannot read the token |
| `SameSite` | `Lax` | browser withholds it from cross-site POSTs (CSRF) |
| `Secure` | production only | dev/demo runs over plain HTTP on localhost |
| `Path` | `/api/v1/auth` | cookie only ever sent to auth endpoints |

## Login

```
POST /api/v1/auth/login {email, password}
  → Origin check (CSRF: cross-site Origin → 403)
  → rate limit check (Redis, per-IP, fails closed → 503)
  → verify Argon2 hash — including a dummy verify for unknown/inactive
    accounts so response timing cannot enumerate users
  → issue access JWT + refresh token (family_id = new UUID)
  → audit: auth.login.success | auth.login.failure
  ← {access_token, expires_in, refresh_expires_in}
    Set-Cookie: eitop_refresh=...; HttpOnly; SameSite=lax; Path=/api/v1/auth
```

Failure responses are a single 401 `Invalid credentials` for both unknown
email and wrong password (no user enumeration, no cookie issued).

## Refresh (rotation)

```
POST /api/v1/auth/refresh        (cookie, no body)
  → Origin check
  ├─ cookie missing              → 401  (audited: auth.refresh.failure)
  ├─ token unknown               → 401  (audited)
  ├─ token already revoked       → REUSE: revoke entire family → 401 (theft detection)
  ├─ token expired               → revoke → 401
  ├─ account disabled/deleted    → revoke family → 401 (audited)
  └─ valid → revoke old token (replaced_by = new id), issue new pair
             Set-Cookie with rotated token; audit: auth.refresh.success
```

Rotation means a refresh token is **single-use**. If it is presented twice,
both legitimate user and attacker lose the session — the safe failure mode.

A raw refresh token placed in a JSON body is **ignored**: the endpoint reads
only the cookie.

## Logout

```
POST /api/v1/auth/logout         (Bearer access + cookie)
  → revoke every non-revoked token in the family
  → audit: auth.logout
  ← 204 + Set-Cookie: eitop_refresh=...; Max-Age=0
```

## CSRF protection

1. **SameSite=Lax** cookie — browsers do not attach it to cross-site POSTs.
2. **Origin check middleware** (`app/main.py`) — any state-changing request
   under `/api/v1` whose `Origin` header is present but not in
   `CORS_ORIGINS` is rejected with 403 before it reaches a handler.
   Requests without an `Origin` header (curl, service-to-service) pass;
   browsers always send `Origin` on cross-site POSTs, so this blocks CSRF
   while remaining compatible with API clients.

## Client behavior (frontend)

1. Access token in memory only; the refresh cookie is HttpOnly and never
   touched by JavaScript. A non-secret `eitop.session` flag in
   `localStorage` is a *presence hint only* (no token material) used to
   avoid probing `/auth/me` on every cold load.
2. On 401 the API client attempts **one** transparent cookie refresh, then
   retries the original request once; failure clears the session → `/login`.
3. Logout POSTs to `/auth/logout`; the server revokes the family from the
   cookie and expires it.

## Security properties

| Property | Mechanism |
|---|---|
| No plaintext passwords at rest | Argon2id |
| Token theft detection | Refresh family revocation on reuse |
| Refresh token not readable by JS | HttpOnly cookie; absent from all bodies |
| CSRF on auth endpoints | SameSite=Lax + Origin allowlist check |
| Brute-force protection | Redis rate limit, fail-closed, IP unspoofable (proxy overwrites XFF) |
| Account enumeration (content) | Uniform 401 on login failure |
| Account enumeration (timing) | Dummy Argon2 verify for unknown/inactive accounts |
| Algorithm confusion | Fixed `HS256`, issuer checked, type claim checked |
| Weak key | `SECRET_KEY` min length enforced; no default value |
| Disabled accounts | Rejected at login, refresh (family revoked) and every authenticated route |
