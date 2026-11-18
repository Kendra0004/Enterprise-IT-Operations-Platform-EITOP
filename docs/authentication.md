# Authentication Flow

## Components

- **Argon2id** password hashing (argon2-cffi: t=2, 19 MiB, p=1).
- **Access token**: JWT (HS256), 15 min default, claims:
  `sub` (user id), `email`, `type=access`, `iss=eitop`, `iat`, `exp`, `jti`.
- **Refresh token**: opaque 48-byte random string, 7 days default.
  Only its **SHA-256 digest** is stored (`refresh_tokens.token_hash`).

## Login

```
POST /api/v1/auth/login {email, password}
  → rate limit check (Redis, per-IP, fails closed → 503)
  → verify Argon2 hash (constant-time on mismatch path)
  → issue access JWT + refresh token (family_id = new UUID)
  → audit: auth.login.success | auth.login.failure
  ← {access_token, refresh_token, expires_in, refresh_expires_in}
```

Failure responses are a single 401 `Invalid credentials` for both unknown
email and wrong password (no user enumeration).

## Refresh (rotation)

```
POST /api/v1/auth/refresh {refresh_token}
  ├─ token unknown          → 401
  ├─ token already revoked  → REUSE: revoke entire family → 401  (theft detection)
  ├─ token expired          → revoke → 401
  └─ valid → revoke old token (replaced_by = new id), issue new pair
             audit: auth.refresh.success
```

Rotation means a refresh token is **single-use**. If it is presented twice,
both legitimate user and attacker lose the session — the safe failure mode.

## Logout

```
POST /api/v1/auth/logout {refresh_token}   (Bearer access required)
  → revoke every non-revoked token in the family
  → audit: auth.logout
  ← 204
```

## Client behavior (frontend)

1. Access token kept in memory; refresh token in `localStorage`
   (documented tradeoff: XSS-resilient access, XSS-exposed refresh —
   moving to `HttpOnly` cookie is a Phase-2 hardening item).
2. On 401 the API client attempts **one** transparent refresh, then retries
   the original request once; failure clears the session → `/login`.
3. On app load, a stored refresh token restores the session via `/auth/me`.

## Security properties

| Property | Mechanism |
|---|---|
| No plaintext passwords at rest | Argon2id |
| Token theft detection | Refresh family revocation on reuse |
| Brute-force protection | Redis rate limit, fail-closed |
| Algorithm confusion | Fixed `HS256`, issuer checked, type claim checked |
| Weak key | `SECRET_KEY` min length enforced; no default value |
| User enumeration | Uniform 401 on login failure |
