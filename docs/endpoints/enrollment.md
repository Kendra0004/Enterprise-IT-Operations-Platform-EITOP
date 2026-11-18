# Enrollment & Credential Lifecycle (Phase 2.2)

## Token issuance (admin)

`POST /api/v1/endpoints/enrollment-tokens` (requires `endpoints:write`):

```json
{
  "expires_in_minutes": 60,          // configurable per token
  "group_id": "uuid-or-null",        // optional group assignment
  "note": "new web tier",            // optional label
  "restrictions": {
    "allowed_hostname_patterns": ["web*.example.com"]  // optional globs
  }
}
```

Response contains the **raw token exactly once**. Storage keeps only
`token_hash = SHA-256(raw)`. The raw value is never logged, never returned by
any GET, never written to audit details.

## Consumption (agent)

`POST /api/v1/agent/enroll`:

1. **Rate limited** per client IP (`rate_limit_enroll_per_minute`, default 10)
   → token guessing is throttled. Body capped at 16 KB → 413.
2. Token looked up **by hash** (constant-time-comparable digest; no raw-token
   index). Unknown hash → generic failure.
3. Checks in order: exists → not used → not expired → optional hostname
   glob restrictions match (compared against hostname and fqdn with
   `fnmatch`, case-insensitive).
4. **Atomic claim**: conditional
   `UPDATE enrollment_tokens SET used_at=now(), consumed_by=:endpoint_id
   WHERE id=:id AND used_at IS NULL RETURNING ...` — exactly one concurrent
   transaction can win; losers get 401. Endpoint row is created in the same
   transaction, so a crash cannot leave a consumed token without an endpoint
   or vice versa.
5. On success: endpoint credential generated (`eitop_ep_` +
   `secrets.token_urlsafe(32)`), stored as SHA-256 digest, returned raw in the
   201 response. Group membership applied if the token carried `group_id`.
6. Every outcome is audited (`endpoint.enrollment_token.created`,
   `endpoint.enrolled`, `endpoint.enrollment.rejected` with **reason but never
   the raw token**) — audit rows commit *before* the error is raised (the
   request-scoped `get_db` would otherwise roll them back).

### Anti-abuse properties

| Threat | Counter-measure |
|---|---|
| Token reuse | Single-use claim, `used_at IS NULL` guard |
| Concurrent double-enroll | Atomic `UPDATE … RETURNING`; one winner, loser 401 |
| Token guessing | Rate limit + uniform timing-independent 401 |
| Oracle (used vs expired vs unknown) | Identical 401 body/title for all failures; reason only in server-side audit |
| Restriction bypass | Restrictions checked *before* claim — a rejected attempt does **not** burn the token |
| Hostname spoofing for auth | Hostname/MAC/serial never grant access; only the issued credential does |
| Impersonating another endpoint | Agent schemas `extra="forbid"`; endpoint id comes only from the credential |
| Replay of raw token after use | Digest lookup + `used_at` check |

## Agent credentials

- Format: `eitop_ep_` + 43-char URL-safe random (256 bits entropy).
- Stored: SHA-256 digest in `endpoint_credentials`; one active row per
  endpoint (rotations supersede via `rotated_from`).
- Presented: `Authorization: Bearer <credential>` on `/api/v1/agent/*` only.
- Authentication: digest lookup + `secrets.compare_digest` (constant time),
  then checks: endpoint status `active`, credential not `revoked_at`,
  not expired. Failures audited (`auth.agent.failure`) without the secret.
- **Separation**: the shared bearer scheme discriminates by `eitop_ep_`
  prefix. User JWTs are rejected on agent routes; agent credentials are
  rejected on user routes (no user identity, no roles, no admin access).

### Rotation

- Admin: `POST /endpoints/{id}/rotate-credential` (`endpoints:write`).
- Agent: `POST /agent/rotate-credential` (self-service).
- Both mark the old credential revoked and issue a new one; **the new raw
  credential appears only in the rotation response** (single issuance
  moment), audited without the secret. Old credential stops working on the
  very next request — no caching, no grace period.

### Revocation

- Admin: `POST /endpoints/{id}/revoke` → endpoint `status=revoked`, all
  credentials `revoked_at=now()`. Effective immediately (checked per
  request). Re-revoke → 409. Revoked endpoints cannot rotate (409).
- Audited: `endpoint.revoked` (success path) and rejection attempts.

## Expiry

`expires_at = created_at + expires_in_minutes`. Checked at claim time; an
expired token yields the same uniform 401 plus an audit reason. Tokens left
unused simply age out — nothing to clean up (rows are retained for audit).

## What is never done

- Admin JWTs are never accepted for agent authentication (and vice versa).
- No secrets in logs, audit details, or non-issuance responses.
- No agent-supplied authorization data (endpoint id, roles, status).
- No server-directed command execution.
