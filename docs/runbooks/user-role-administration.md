# Runbook 3 — User and role administration

**Purpose:** create users and assign roles.
**Prerequisites:** an `admin` user (permission `admin:write`), see
[runbook 2](administrator-bootstrap.md).

> **Scope note:** user administration is **API-only** today. There is
> no update/deactivate/password-reset endpoint and no Administration UI
> page (it is marked "Under development" in the UI). Plan accordingly —
> see [Limitations](#limitations-by-design-of-the-current-api).

Roles and their permissions: [../rbac.md](../rbac.md) and the
[permission matrix](../api/README.md#permission-matrix).

## List roles

```bash
curl -sS https://$HOST/api/v1/roles -H "Authorization: Bearer $TOKEN"
```

Expected: `admin`, `security_auditor`, `operator`, `readonly`, `agent`
with their permission arrays.

## List users

```bash
curl -sS "https://$HOST/api/v1/users?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

Expected: `{"items":[{id,email,full_name,roles,is_active,created_at}…],
"total":N,…}`. Needs `admin:read`.

## Create a user

```bash
curl -sS -X POST https://$HOST/api/v1/users \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H "Origin: https://$HOST" \
  -d '{"email":"jdoe@your-domain.com","password":"<min 12 chars>",
       "full_name":"Jane Doe","roles":["operator"]}'
```

Expected: `201` with the user object including assigned `roles`.

| Status | Meaning |
|---|---|
| `201` | created (active immediately) |
| `409 User already exists` | email taken (lowercased before compare) |
| `400 Unknown role` | role name not found — check `GET /roles` |
| `422` | invalid email or password < 12 / > 128 chars |

Permissions apply on the user's next token issuance; permission checks
read role→permission mappings from the database on every request, so a
user only ever acts within their current roles.

## Limitations (by design of the current API)

- **No user update, deactivation, or password reset endpoint.** An
  account cannot be disabled through the API. Mitigations that exist
  today:
  - password rotation is unavailable → protect the account (strong
    password, no sharing);
  - if an account must be neutralized, rotate `SECRET_KEY`
    ([runbook 12](secret-rotation.md)) — this invalidates every session
    — and restore a backup modified to remove the user
    ([runbook 10](database-restoration.md)) if the account itself must
    be gone;
  - refresh tokens can be mass-revoked only via `SECRET_KEY` rotation
    (no per-user revocation API).
- Password self-service reset is **not implemented** (flagged in the
  [Phase 1 security review](../security/PHASE1_SECURITY_REVIEW.md)).
- The `agent` role is reserved for the collector identity — collectors
  authenticate with endpoint credentials (`eitop_ep_…`), never with user
  logins; do not assign `agent` to humans.

## Audit

Every user creation and role assignment is appended to the audit log —
review via [runbook 16](log-inspection-audit-review.md).
