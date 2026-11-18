# Endpoint Security Design (Phase 2.1–2.3)

Threat-driven summary of how enrollment and agent authentication are
implemented. Tests referenced live in `backend/tests/test_enrollment.py`,
`test_agent_api.py`, `test_endpoint_models.py`, `test_endpoints_admin_api.py`.

## Identity separation

- **Agent identity ≠ user identity.** Endpoint credentials (`eitop_ep_` prefix)
  authenticate only `/api/v1/agent/*` and grant access to exactly one
  endpoint's own data. They carry no roles, no user id, no admin rights.
- Shared `HTTPBearer` scheme discriminates by prefix: user JWTs on agent
  routes → 401 `Not authenticated`; agent credentials on user routes → 401.
  *(test: `test_user_jwt_rejected_on_agent_routes`,
  `test_agent_credential_rejected_on_user_routes`)*
- **Admin JWTs are never used for agent auth** (and never provisioned to
  endpoints).

## Trusted vs untrusted inputs

| Input | Trusted for identity/authz? |
|---|---|
| endpoint credential digest match | ✅ sole authorization source |
| hostname / FQDN / MAC / serial | ❌ never (display + filtering only) |
| `endpoint_id` in request body | ❌ rejected (`extra="forbid"` → 422) |
| token restrictions (hostname globs) | ❌ only *restricts*, never *grants* |
| anything sent by the server to agent | ❌ parsed as data, never executed |

*(tests: `test_endpoint_id_in_payload_is_rejected`,
`test_hostname_claim_does_not_grant_access`,
`test_cross_endpoint_isolation`)*

## Secret handling

- Enrollment tokens and credentials stored **only as SHA-256 digests**;
  schema has no secret columns *(test: `test_secrets_only_stored_hashed`)*.
- Raw enrollment token returned once at creation; raw credential returned
  once at issuance (enroll or rotate) — **by design**, because the secret
  must be handed to the operator/agent at issuance and can never be shown
  again. All other responses (list/detail/audit) exclude it
  *(tests: `test_token_listing_never_exposes_values`,
  `test_admin_rotation_flow` asserts credential absent from GETs and audit)*.
- Comparison uses `secrets.compare_digest` (constant time).
- No secret ever appears in logs, audit `detail`, or problem responses
  *(tests: audit detail scanned for token/credential substrings)*.
- Collector persists credentials 0600 in 0700 dir; refuses to load
  group/world-readable files; token never accepted via argv (`ps`-visible).

## Enrollment abuse resistance

- **Reuse**: atomic conditional `UPDATE … WHERE used_at IS NULL RETURNING`;
  single winner *(test: `test_enrollment_token_single_use`)*.
- **Race**: barrier-synchronized concurrent claim → exactly one 201, one 401,
  one endpoint row *(test: `test_concurrent_enrollment_has_exactly_one_winner`)*.
- **Guessing**: per-IP rate limit on `/agent/enroll`
  (`rate_limit_enroll_per_minute`, default 10) + uniform 401 with fixed
  title/detail → no oracle between unknown/used/expired/restricted
  *(tests: `test_unknown_and_used_tokens_get_identical_responses`,
  `test_enroll_rate_limit_kicks_in`)*.
- **Expiry**: checked at claim; failure reason recorded in audit only
  *(tests: `test_expired_token_rejected`,
  `test_expired_token_is_audited_with_reason`)*.
- **Restriction bypass**: restrictions evaluated *before* claim, so a failed
  attempt does not burn the token *(test:
  `test_hostname_restriction_rejects_non_matching`)*.
- **Impersonation**: only the credential's endpoint can receive data; payload
  endpoint ids are validation errors *(tests: `test_cross_endpoint_isolation`,
  `test_endpoint_id_in_payload_is_rejected`)*.
- Audit rows for rejected attempts are committed **before** raising the 401
  (request-scoped transaction would roll them back otherwise).

## Revocation & rotation

- Revocation sets endpoint `status=revoked` + `revoked_at` on every
  credential; checked on **every request** → immediate effect, no cache
  *(tests: `test_revoke_endpoint_kills_credentials_immediately`)*.
- Rotation supersedes the old credential atomically; old value fails on the
  next request *(tests: `test_agent_self_rotation_invalidates_old_credential`,
  `test_admin_rotation_flow`)*.
- Revoked endpoints cannot rotate (409); double revoke → 409.

## Input hardening

- Body-size middleware: enroll 16 KB, inventory 5 MB, other agent 8 KB,
  `/endpoints/` 256 KB, `/api/v1/` 64 KB → 413 before parsing
  *(tests: `test_oversized_enroll_payload_rejected`,
  `test_oversized_inventory_payload_rejected`)*.
- Pydantic `extra="forbid"` on all agent + admin endpoint schemas; field
  bounds (fact value ≤ 8 KB, package name non-empty, interval minimums).
- Sort field **allowlist** → 400 on anything else (no column-name injection
  through ORM `text()` or error-surfacing) *(test:
  `test_sort_allowlist_and_order`)*.
- RBAC: `endpoints:read` / `endpoints:write` (seeded, additively synced);
  admin and operator hold them; readonly/auditor/anonymous denied
  *(tests: RBAC section in both admin test files)*.

## Transport & deployment

- Production deployments must use HTTPS/TLS termination in front of the
  backend; collector config accepts `https://` and plain HTTP only for local
  dev (documented in `config.example.toml` and README).
- Dev compose credentials and npm dev-only advisories: known items carried
  over from Phase 1.5 (`docs/security/PHASE1_SECURITY_REVIEW.md`), unchanged.

## Out of scope (per Phase 2 boundaries)

Windows collectors, AD integration, remote automation/patching, vulnerability
scanning, network/DNS monitoring — none implemented; server has **no command
execution endpoint** at all, so adding one later is a deliberate design
decision, not an existing surface.
