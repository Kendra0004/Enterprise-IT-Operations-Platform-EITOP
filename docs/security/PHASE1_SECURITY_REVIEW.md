# EITOP Phase 1 — Security & Quality Review

**Date:** 2026-11-18 · **Scope:** Phase 1 foundation only (auth, RBAC, audit,
token storage, API/infrastructure, tests). No Phase 2 modules were touched.
**Method:** source inspection of `backend/app/**`, `frontend/src/**`,
`docker-compose.yml`, `frontend/nginx.conf`, CI, plus dynamic verification
against the running stack. Every fix below is implemented **and tested**;
nothing is claimed fixed without a passing test.

---

## 1. Findings by severity

### HIGH

#### H-1 — Refresh token readable by JavaScript (localStorage)
**Evidence (before fix):** `frontend/src/api/client.ts` stored the raw
refresh token under `localStorage["eitop.refresh_token"]`; `AuthContext`
restored sessions from it. Any XSS could exfiltrate a 7-day credential and
persist access after password change until expiry.
**Fix:** refresh token is now delivered **only** in an `HttpOnly; SameSite=Lax;
Path=/api/v1/auth` cookie set by the backend. JS never reads or writes it.
A non-secret `eitop.session` *hint flag* (boolean, no token material) remains
in localStorage solely to avoid a cold-start `/auth/me` probe.
**Tests:** `test_login_success_returns_access_token_and_httponly_cookie`
(cookie flags asserted, `refresh_token` absent from body);
`frontend/tests/api-client.test.ts::never stores token material in localStorage`.

#### H-2 — Refresh token returned in JSON response bodies
**Evidence (before fix):** `TokenResponse.refresh_token`
(`backend/app/schemas/auth.py`) returned the raw token in every login/refresh
body — equivalent exposure to H-1 (XSS reads `fetch` responses).
**Fix:** `TokenResponse` no longer contains `refresh_token`; rotation
(`POST /auth/refresh`) reads only the cookie. Legacy clients sending a token
in the body are rejected 401 (cookie-only transport).
**Tests:** `test_refresh_with_legacy_body_token_rejected`,
`test_refresh_rotates_cookie_and_body_has_no_token`.

### MEDIUM

#### M-1 — Bootstrap admin password accepted as a CLI argument
**Evidence (before fix):** `python -m app.db.seed --admin-password ...`
(`backend/app/db/seed.py`) placed the password in `argv` — visible via `ps`,
shell history, and CI logs.
**Fix:** the flag is removed. Password now comes from
`BOOTSTRAP_ADMIN_PASSWORD` (env), an interactive `getpass` prompt, or
`--admin-password-stdin`. Minimum length 12 enforced.
**Tests:** `test_seed_cli_has_no_password_argument` (asserts only the stdin
flag exists in `--help`), `test_bootstrap_admin_creation_refusal_and_no_password_leak`
(password absent from stdout/stderr and from captured logs).

#### M-2 — Rate limiter keyed on a spoofable `X-Forwarded-For`
**Evidence (before fix):** `backend/app/core/rate_limit.py::client_ip` used
the **first** XFF value; `frontend/nginx.conf` used `$proxy_add_x_forwarded_for`
(appends attacker-supplied header). An attacker could send a fresh
`X-Forwarded-For` per attempt and bypass login/refresh brute-force limits;
audit `ip_address` could be forged too.
**Fix:** nginx now **overwrites** `X-Forwarded-For` with `$remote_addr`
(+ `X-Real-IP`), and the backend port is published on `127.0.0.1` only so
direct access cannot bypass the proxy.
**Verified:** spoofed `X-Forwarded-For: 9.9.9.9` through `:8080` recorded
`ip_address = 172.18.0.1` (the proxy's address), not `9.9.9.9`.
**Test:** `test_client_ip_prefers_forwarded_header` (unit) + E2E above.

#### M-3 — Audit log immutable only at the application layer
**Evidence (before fix):** no update/delete API exists, but the application's
PostgreSQL role could `UPDATE`/`DELETE` `audit_logs` directly (e.g. via a
compromised process or `psql`).
**Fix:** migration `0002_audit_append_only` installs a `BEFORE UPDATE OR
DELETE` trigger that raises `restrict_violation`. Inserts remain allowed;
`TRUNCATE` (test fixtures) and a documented owner-only
`ALTER TABLE ... DISABLE TRIGGER` escape hatch remain for retention ops.
**Tests:** `test_audit_logs_reject_update_and_delete_at_db_level`,
`test_audit_logs_still_accept_inserts`.

#### M-4 — No CSRF defense for cookie-borne credentials (and login CSRF)
**Evidence:** cookie refresh transport (H-1 fix) makes classic CSRF relevant;
no origin validation existed on state-changing routes.
**Fix:** HTTP middleware in `backend/app/main.py` rejects any non-safe
request under `/api/v1` whose `Origin` header is present but not in
`CORS_ORIGINS` (403 problem+json) — browsers always attach `Origin` to
cross-site POSTs; curl/clients send none and are unaffected. Combined with
`SameSite=Lax` (cookie not sent cross-site at all).
**Tests:** `test_cross_origin_login_rejected`, `test_null_origin_state_change_rejected`,
`test_cross_origin_state_change_rejected_with_valid_token`,
`test_allowed_origin_state_change_accepted`, `test_safe_methods_not_blocked_by_origin`.

#### M-5 — Timing side channel for account enumeration
**Evidence (before fix):** `authenticate_user` returned early for unknown
emails — skipping the ~50 ms Argon2 verification and leaking account
existence via response time (responses were otherwise uniform 401).
**Fix:** unknown/inactive accounts now verify against a lazily generated
`dummy_password_hash()` (real Argon2 hash of an ephemeral secret), equalizing
work on all paths.
**Tests:** `test_unknown_email_still_performs_password_verification`
(dummy hash is a verifiable `$argon2…` hash; unknown-account path takes
> 5 ms, i.e. performs real work).

#### M-6 — Redis without authentication
**Evidence (before fix):** compose ran `redis-server` with no
`--requirepass` (internal network only, no published ports).
**Fix:** `--requirepass ${REDIS_PASSWORD:-eitop-dev-redis}`; healthcheck
authenticates via `REDISCLI_AUTH`; backend/worker/tester `REDIS_URL`
embed the credential.
**Verified:** `redis-cli ping` without credentials → `NOAUTH Authentication
required.`; backend `PING` with `REDIS_URL` → `True`; full suite green.

#### M-7 — Test/lint tooling shipped in the production image
**Evidence (before fix):** `backend/Dockerfile` installed the single
`requirements.txt` containing `pytest`, `ruff`, `mypy`, `httpx`; `pip-audit`
reported `PYSEC-2026-1845` in `pytest 8.4.2` (fix: 9.0.3) **inside the
production image**.
**Fix:** requirements split — `requirements.txt` (runtime only) vs
`requirements-dev.txt` (pytest ≥ 9.0.3, the patched version); Dockerfile is
now multi-stage (`runtime` / `dev`); compose `backend`/`worker` build
`target: runtime`, a `tester` service (profile `tools`) builds `target: dev`.
CI installs `requirements-dev.txt`.
**Verified:** production container → `ModuleNotFoundError: No module named 'pytest'`;
`pip-audit` clean for both files.

### LOW

| ID | Finding | Evidence | Fix | Test |
|---|---|---|---|---|
| L-1 | No security headers on API responses | `app/main.py` | Middleware sets `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`; `Strict-Transport-Security` when `APP_ENV=production` | `test_security_headers_present_on_responses`, `…_on_error_responses`, E2E |
| L-2 | No CSP / permissions policy on the SPA | `frontend/nginx.conf` | Server-level CSP (`default-src 'self'`, `frame-ancestors 'none'`, …) + headers on all responses incl. proxied API | E2E `curl -I :8080/health` shows full header set |
| L-3 | Swagger/`openapi.json` publicly reachable (also via nginx `/docs` proxy) | `app/main.py` | `docs_url/redoc_url/openapi_url = None` when `APP_ENV=production` | `test_docs_disabled_in_production` (404 on `/openapi.json`, HSTS present) |
| L-4 | Backend published on `0.0.0.0:8000` | `docker-compose.yml` | Bound to `127.0.0.1:8000` (loopback) | compose config + E2E via localhost |
| L-5 | Fragile `algorithms=[JWT_ISSUER and JWT_ALGORITHM]` expression | `core/security.py` | `algorithms=[JWT_ALGORITHM]` (identical value, explicit) | existing JWT tests in `test_security.py` |
| L-6 | Disabled-account refresh returned 401 with **no audit record** | `services/auth_service.py` | Family revoked + `auth.refresh.failure` audited (`account_unavailable`) before raising | `test_disabled_user_cannot_refresh_and_is_audited` |
| L-7 | Unknown refresh token audited under misleading `auth.refresh.reuse` | `services/auth_service.py` | `auth.refresh.failure` for missing/unknown/expired/inactive; `reuse` reserved for actual revoked-token reuse | covered by refresh/audit tests |

### Informational / accepted (no fix available or out of Phase 1 scope)

| Item | Status |
|---|---|
| `npm audit`: `picomatch` ReDoS (GHSA-fc5q-39xc-vjpf) | **Accepted.** Dev/build toolchain only (vite/vitest → not present in `dist/`); advisory affects **all** picomatch versions — no upstream fix exists. Reduced from 9 vulns (2 critical, 4 high, 3 moderate) to 5 high by upgrading vitest 2 → 5. CI reports but does not fail on it. |
| No password-reset / self-service change flow | Not implemented in Phase 1 (no fake behavior). Admins can create users. See §4. |
| Refresh cookie lacks `Secure` outside production | Intentional: dev/demo runs over plain HTTP on localhost; `Secure` is set when `APP_ENV=production`. |
| Rate-limit key granularity behind compose | All external clients share the proxy's address (`172.18.0.1`) as the rate-limit identifier — unspoofable but coarse (availability trade-off, unchanged from before the fix). Production deployments must terminate TLS at a real proxy that preserves client IPs. Per-account login throttling recommended (Phase 2). |
| Rate limiting only on `/auth/*` | Documented; general API throttling belongs at the edge in production. |
| Postgres/Redis default credentials | Dev defaults, **no host ports published**, internal bridge network only; `POSTGRES_PASSWORD`/`REDIS_PASSWORD` env-overridable. Override both in production. |
| `DEBUG` defaults to `true` in compose | Dev/demo convenience; unhandled errors never leak tracebacks to clients (fixed 500 body, `exceptions.py`). Set `DEBUG=false`, `APP_ENV=production` in production. |
| Audit IP records proxy address (compose) | Consequence of M-2 fix; correct client IPs require a proxy that overwrites XFF — verified for the shipped nginx config. |

---

## 2. What was verified as already sound (no change needed)

- **JWT:** HS256 fixed algorithm list, `iss` + `type` claims validated,
  `exp` enforced, `SECRET_KEY` required (≥ 16 chars, no default).
- **Refresh rotation & reuse detection:** single-use tokens, family
  revocation on reuse, SHA-256-at-rest, unique constraint on `token_hash`.
  Reuse, rotation, logout-revocation all E2E-tested (§3).
- **Disabled users:** rejected at login, at refresh (family killed), and on
  every authenticated route (`get_current_user` checks `is_active`).
- **Account enumeration (content):** uniform 401 for unknown email vs wrong
  password; no user existence in error bodies.
- **RBAC:** every admin/audit endpoint guarded server-side by
  `require_permissions`; permission checks use the union across all roles.
  Read-only and agent roles cannot list/create users or read audit logs;
  vertical escalation attempt (agent minting an admin) tested 403.
- **Password storage:** Argon2id (OWASP baseline 19 MiB / t=2 / p=1);
  plaintext never logged (structured JSON logger, audit `detail` contains
  reasons only).
- **Audit of failed auth:** committed **before** the exception propagates
  (`get_db` rolls back on error) — proven by `test_failed_login_writes_audit_log`.
- **Secrets in Git:** `.env` ignored (`git check-ignore` ✓), no `.env`
  tracked, secret-pattern scan of the tree clean; `.env.example` carries
  placeholders only.
- **CORS:** explicit allowlist, never `*` with credentials.
- **Containers:** non-root (`USER eitop`, uid 10001), `no-new-privileges`,
  read-only rootfs + tmpfs for backend/worker/tester, healthchecks on all
  data services, frontend `nginx-unprivileged`.
- **Bootstrap:** creates the first admin only while `users` is empty.

## 3. Tests performed and results

| Check | Command / target | Result |
|---|---|---|
| Backend suite (pytest 9.0.3, real PG+Redis) | `docker compose run --rm --entrypoint "" tester python -m pytest tests` | **68 passed** (was 46; +22 security tests) |
| Ruff | `ruff check --no-cache app tests` | **All checks passed** |
| Mypy (28 files) | `mypy app` | **No issues found** |
| Frontend unit (vitest 5) | `npm test` | **8 passed** |
| TypeScript strict | `npx tsc --noEmit` | **No errors** |
| Frontend production build | `npm run build` | **Clean** (316 KB / 100 KB gzip) |
| pip-audit (runtime + dev reqs) | throwaway `python:3.12-slim` container | **No known vulnerabilities found** (both files) |
| npm audit | `npm audit` | 5 high — all `picomatch`, dev-only, **no upstream fix** (was 9: 2 critical/4 high/3 moderate) |
| E2E login → me → rotate → reuse → 401 | curl + cookie jar via `:8080` | **Pass** — body has no `refresh_token`; cookie `HttpOnly; SameSite=lax; Path=/api/v1/auth`; reuse → `Token reuse detected` |
| E2E logout | curl | **204** + `Max-Age=0` cookie; subsequent refresh → 401 |
| E2E CSRF | curl with `Origin: https://evil.example` / `Origin: null` | **403** `Cross-origin request rejected`; allowed origin → 200 |
| E2E security headers | `curl -I` via nginx and direct | Full set present on both paths; CSP on SPA responses |
| E2E XFF spoof | login attempt with `X-Forwarded-For: 9.9.9.9` | Recorded IP `172.18.0.1` (spoof ignored) |
| Redis auth | `redis-cli ping` w/o creds / backend `PING` with URL | `NOAUTH Authentication required.` / `True` |
| Prod image tooling | `python -c 'import pytest'` in backend container | `ModuleNotFoundError` (tooling absent) |
| Migration round-trip | `alembic upgrade head` on `eitop` + `eitop_test` (auto on start/test session) | `0002_audit_append_only` applied |
| Stack health | `docker compose ps` + `/health`, `/health/ready`, SPA 200 | All services healthy |

**Not tested / out of scope:** GitHub Actions CI execution (repo not
pushed), real-browser Playwright E2E, production TLS termination, password
reset (not implemented), Phase 2 modules.

## 4. Remaining risks & production deployment recommendations

1. **Terminate TLS at a real reverse proxy** and keep the loopback binding;
   ensure the proxy **overwrites** `X-Forwarded-For` (as the shipped nginx
   does) so rate-limit keys and audit IPs stay trustworthy. HSTS is emitted
   only with `APP_ENV=production`.
2. **Set `APP_ENV=production`, `DEBUG=false`** — disables `/docs`,
   `/openapi.json`, `/redoc` and enables HSTS.
3. **Rotate all default credentials:** generate a strong `SECRET_KEY`
   (invalidates all JWTs — do at a maintenance boundary), set unique
   `POSTGRES_PASSWORD` and `REDIS_PASSWORD` (requires `ALTER USER` on the
   existing volume / `redis-cli CONFIG SET requirepass`), and change the
   bootstrap admin password. Prefer orchestrator secrets over `.env` files.
4. **Session invalidation on credential change:** rotating `SECRET_KEY`
   instantly invalidates access tokens; to force full logout, `UPDATE
   refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL` (or drop
   the session rows) — document this runbook for operators.
5. **Password reset flow** (Phase 2): single-use, short-TTL, audited tokens;
   until then, admin-driven provisioning is the only path — gate it behind
   `admin:write` as today.
6. **Per-account login throttling** in addition to per-IP (Phase 2), since
   the compose network collapses clients onto one rate-limit identifier.
7. **Keep dev tooling out of production images** (now enforced by the
   Dockerfile stages) and re-run `pip-audit` / `npm audit` in CI on a
   schedule; the `picomatch` advisory should be re-checked for a fixed
   release.
8. **Audit retention:** the append-only trigger blocks `DELETE`; implement
   partitioned archival (with a deliberate trigger-suspension procedure)
   before audit volume becomes a problem.

## 5. Fixes — file map

| Fix | Files |
|---|---|
| HttpOnly cookie transport | `backend/app/core/security.py` (`set_refresh_cookie`/`clear_refresh_cookie`), `backend/app/api/v1/auth.py`, `backend/app/schemas/auth.py`, `backend/app/services/auth_service.py`, `frontend/src/api/client.ts`, `frontend/src/auth/AuthContext.tsx` |
| CSRF origin check + security headers | `backend/app/main.py`, `frontend/nginx.conf` |
| XFF overwrite + loopback port | `frontend/nginx.conf`, `docker-compose.yml` |
| Audit immutability trigger | `backend/alembic/versions/0002_audit_append_only.py` |
| Timing-equalized login | `backend/app/core/security.py` (`dummy_password_hash`), `backend/app/services/auth_service.py` |
| Bootstrap password hygiene | `backend/app/db/seed.py` |
| Redis auth | `docker-compose.yml`, `.env.example` |
| Prod image hardening | `backend/Dockerfile` (stages), `backend/requirements.txt`, `backend/requirements-dev.txt`, `.github/workflows/ci.yml`, `docker-compose.yml` (`tester`) |
| Audit/refresh semantics | `backend/app/services/auth_service.py` |
| New tests | `backend/tests/test_security_hardening.py` (new), `backend/tests/test_auth.py`, `backend/tests/test_rbac.py`, `backend/tests/conftest.py`, `frontend/tests/api-client.test.ts` |
| Docs | `docs/authentication.md`, `docs/api.md`, `docs/installation.md`, `docs/testing.md`, `docs/environment-variables.md`, `docs/local-development.md`, `README.md`, this file |
