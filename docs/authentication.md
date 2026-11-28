# Authentication Flow

## Components

- **Argon2id** password hashing (argon2-cffi: t=2, 19 MiB, p=1).
- **Access token**: JWT (HS256), 15 min default, claims:
  `sub` (user id), `email`, `type=access`, `iss=eitop`, `iat`, `exp`, `jti`.
  Held **in memory only** on the client. The `email` claim is readable by
  the token holder — an accepted tradeoff of stateless claims-based auth
  (JWTs are integrity-protected, not encrypted; see
  [architecture/security.md](architecture/security.md) § Explicit
  limitations).
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
  → per-account rate limit (key = SHA-256(email), same fail-closed limiter)
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

**Absolute session cap**: a family is revoked once it is older than
`REFRESH_TOKEN_EXPIRE_DAYS` (default 7) regardless of rotation — a stolen
refresh token can no longer mint an indefinite session by rotating.

**Known limitation**: replaying a refresh token *after logout* also hits
the reuse/theft-detection branch (the family was already revoked by
logout), so `auth.refresh.reuse` can fire without an actual attacker.
The outcome is identical (401, family stays dead); distinguishing the two
cases would require a schema migration and is not implemented.

A raw refresh token placed in a JSON body is **ignored**: the endpoint reads
only the cookie.

## Logout

```
POST /api/v1/auth/logout         (Bearer access + cookie; either may be
                                  absent/expired — cookie is authoritative)
  → revoke every non-revoked token in the family (atomic UPDATE)
  → audit: auth.logout
  ← 204 + Set-Cookie: eitop_refresh=...; Max-Age=0
```

**Stateless access-token contract**: logout revokes the refresh family
immediately — a subsequent refresh with the same cookie answers `401`.
The already-issued *access* JWT stays valid until its `exp` (≤ 15 min)
because access tokens are stateless (no denylist). This is the intended
contract, covered by the regression test
`test_access_jwt_stays_valid_until_expiry_after_logout`.

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
| Token theft detection | Refresh family revocation on reuse (single atomic UPDATE) |
| Unlimited session via token rotation | Absolute family lifetime = `REFRESH_TOKEN_EXPIRE_DAYS` |
| Refresh token not readable by JS | HttpOnly cookie; absent from all bodies |
| CSRF on auth endpoints | SameSite=Lax + Origin allowlist check + `Sec-Fetch-Site: cross-site` rejection |
| Brute-force protection | Redis rate limit, fail-closed: per-IP **and** per-account (SHA-256 of email), IP unspoofable (proxy overwrites XFF; rightmost hop wins) |
| Account enumeration (content) | Uniform 401 on login failure |
| Account enumeration (timing) | Dummy Argon2 verify for unknown/inactive accounts |
| Algorithm confusion | Fixed `HS256`, issuer checked, type claim checked |
| Weak key | `SECRET_KEY` min length enforced (≥ 32 chars); no default value |
| Disabled accounts | Rejected at login, refresh (family revoked) and every authenticated route |
| Request correlation | Server-synthesized `X-Request-ID` on every response, attached to JSON log records |
