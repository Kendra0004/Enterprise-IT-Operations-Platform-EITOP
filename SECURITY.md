# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

- Use GitHub's private vulnerability reporting on this repository, or
- Email the maintainers privately.

Include: description, affected component, reproduction steps, impact.
Acknowledgment within 72 hours; assessment within 14 days.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| < 0.1 | no (pre-release) |

## Security design (summary)

- Passwords hashed with **Argon2id** (argon2-cffi) — never stored in plaintext.
- Short-lived **JWT access tokens** (default 15 min) + **rotating refresh
  tokens** stored server-side as SHA-256 digests; reuse of a revoked refresh
  token revokes the whole session family (theft detection).
- **RBAC** on every privileged endpoint (permission-checked dependencies).
- **Audit log** for authentication events and privileged mutations
  (append-only, no delete API).
- **Rate limiting** on authentication endpoints (Redis, fails closed).
- Secrets come from environment variables only; `.env` is git-ignored.
- Parameterized SQL throughout (SQLAlchemy ORM) — no string-built queries.
- Strict CORS allowlist (never `*` with credentials).
- CI runs ruff, mypy, pytest, frontend tests, `npm audit` and Trivy image scans.

## Explicit non-goals (Phase 1)

- No arbitrary remote command execution surface exists (automation module not
  yet implemented; when it lands it will require authz + approval + audit).
- Active Directory integration will be read-only when implemented.
