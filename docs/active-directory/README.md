# Active Directory integration

EITOP mirrors Active Directory **read-only**: it never creates, modifies
or deletes AD objects. The mirror powers the Directory views, the
endpoint↔computer reconciliation, and the findings/insights engine.

Related: [data flows](../architecture/data-flow.md#active-directory-synchronization),
[security model](../architecture/security.md),
[runbooks](../runbooks/README.md).

## What is synchronized

Per connection: domains, organizational units, users, groups (incl.
membership), computers — plus reconciliation rows comparing directory
computers against enrolled endpoint inventory.

Inventory categories reported per sync run (`category_results`):
`connect`, `domains`, `ous`, `users`, `groups`, `computers`,
`memberships`, `missing_scan`.

## Prerequisites

- **LDAPS (port 636) or StartTLS (port 389)** — the only supported
  transports (`ldap3`). Plaintext LDAP is rejected.
- A dedicated read-only bind account, e.g.
  `CN=EITOP Reader,OU=Service Accounts,DC=example,DC=com`, with read
  permission on the search base (no elevation required).
- Network reachability from the **worker** container to the DC
  (syncs run in the worker, not the API process).
- Trust for the DC certificate:
  - public CA → nothing to configure;
  - private/enterprise CA → paste the CA certificate (public part only)
    into `tls_ca_pem`.

## Connection setup

UI: **Directory → Connections → New**. API:

```bash
curl -sS -X POST https://$HOST/api/v1/directory/connections \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" -H "Origin: https://$HOST" \
  -d '{
    "name": "corp.example.com",
    "domain_dns": "example.com",
    "host": "dc01.example.com",
    "port": 636,
    "tls_mode": "ldaps",
    "search_base": "DC=example,DC=com",
    "bind_username": "CN=EITOP Reader,OU=Service Accounts,DC=example,DC=com",
    "bind_password": "<write-only, encrypted at rest>",
    "auto_sync": true,
    "sync_interval_minutes": 60
  }'
```

Permission: `directory:write` (roles `admin` only — see the
[permission matrix](../api/README.md#permission-matrix)).

Field notes:

| Field | Default | Notes |
|---|---|---|
| `tls_mode` | `ldaps` | `ldaps` (636) or `starttls` (389) |
| `tls_ca_pem` | — | PEM of the CA that issued the DC cert; never a secret |
| `page_size` | 500 | LDAP paged-search page size (≤ 5000) |
| `auto_sync` / `sync_interval_minutes` | `true` / 60 | beat-driven scheduled sync |
| `enabled` | `true` | disabled connections are never scheduled |

`bind_password` is **write-only**: accepted on create/update, Fernet-
encrypted with a key derived from `SECRET_KEY`, and absent from every
response schema.

## Testing a connection

```bash
curl -sS -X POST https://$HOST/api/v1/directory/connections/$ID/test \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Origin: https://$HOST"
```

Permission: `directory:sync`. Expected success:

```json
{"ok":true,"label":null,"duration_ms":84,
 "default_naming_context":"DC=example,DC=com","dns_hostname":"dc01.example.com"}
```

Failures return `ok:false` with a **sanitized label** (below) — raw
LDAP/OS error text is never sent to clients.

## Synchronization

- **Manual**: `POST /api/v1/directory/connections/$ID/sync`
  (`directory:sync`) → `202` with a `sync_runs` row; `409` if one is
  already running for that connection.
- **Scheduled**: beat task `eitop.directory_sync_tick` enqueues
  connections whose `sync_interval_minutes` elapsed (`enabled` +
  `auto_sync` required).
- **Concurrency**: one run per connection — enforced by a DB lease.
  Stale leases are reaped after `DIRECTORY_STALE_RUN_MINUTES` (30);
  a run can never outlive `DIRECTORY_MAX_SYNC_MINUTES` (60).
- Progress/results: `GET /api/v1/directory/sync-runs[/{run_id}]`
  (`directory:read`).

## Insights and findings

Beat task `eitop.directory_insights_tick` (every
`DIRECTORY_INSIGHT_SCAN_SECONDS`, default 600) regenerates findings:

- inventory visibility gaps (a category never collected on an endpoint
  is reported as `missing_scan` / "insufficient visibility" after
  `DIRECTORY_MISSING_GRACE_DAYS`, default 7);
- directory staleness (inactive users, stale computers — thresholds
  `DIRECTORY_INACTIVE_USER_DAYS`, `DIRECTORY_STALE_COMPUTER_DAYS`);
- group-membership correlation gaps.

Lifecycle: open → acknowledged/suppressed → reopen
(`POST /directory/findings/{id}/ack|suppress|reopen`, `directory:write`;
reads need `directory:read`). See
[data-flow: findings lifecycle](../architecture/data-flow.md#findings-lifecycle).

## Health and status

- `GET /api/v1/directory/health` — per-connection reachability status.
- `GET /api/v1/directory/overview` — sync freshness, gap counts.
- `GET /api/v1/directory/reconciliations` — endpoint↔computer matching.

## Permissions

| Action | Permission |
|---|---|
| View directory data, findings, sync history | `directory:read` |
| Create/update/delete connections; findings ack/suppress/reopen; decide computer matches | `directory:write` |
| Test connection, trigger sync | `directory:sync` |

Seeded roles: `admin` has all three; `security_auditor`, `operator`,
`readonly` have `directory:read` only. Full matrix:
[../api/README.md](../api/README.md#permission-matrix).

## Troubleshooting

| Symptom (API/label) | Likely cause | Fix |
|---|---|---|
| `timeout` | DC unreachable / firewall | check network from the worker container: `docker compose exec worker python -c "import socket; s=socket.create_connection(('dc01.example.com',636),10); s.close()"` |
| `connection_failed` | DNS or TCP refused | verify `host`/`port`, DNS from worker |
| `tls_error` | hostname mismatch, untrusted CA, expired cert | match `host` to cert SAN; set `tls_ca_pem` to the issuing CA |
| `invalid_credentials` | wrong bind DN/password, expired account | verify bind DN in AD; re-enter password via `PATCH` (write-only field) |
| `search_base_not_found` | `search_base` wrong or invisible to bind DN | correct DN, e.g. `DC=example,DC=com` |
| `credential_undecryptable` | `SECRET_KEY` was rotated | re-enter the bind password (old ciphertext is unrecoverable by design) |
| `stale_run_reaped` | worker died mid-run | automatic — next scheduled sync proceeds; check worker logs |
| Sync returns `409` | another run active | wait for it or inspect `GET /sync-runs` |
| Findings stuck "insufficient visibility" | inventory categories never collected | ensure collectors run full inventory; check endpoint health |

Backend logs (JSON) carry the same sanitized label plus the exception
*class name* — enough for diagnosis, never raw directory content.

## Limitations

- **No write operations against AD** — remediation happens in AD
  tooling, then the next sync reflects it.
- **Configuring a connection implies an SSRF-shaped surface (accepted)**:
  `directory:write` (admin-equivalent) can aim the TLS probe and the bind
  at an arbitrary `host:port`. This is inherent to "point EITOP at an
  LDAP server"; it is gated by role and audit-logged — there is no
  unauthenticated or read-only path to it.
- **`search_base` DN syntax is validated at runtime, not at save time**:
  a malformed DN surfaces as a classified sync-error label on the first
  run rather than a 422 on create/update. This is *not* an injection
  surface — the DN is never interpolated into an LDAP filter (constant
  `(objectClass=*)`), and `bind_username` is transmitted only as the bind
  name.
- **Changing `host` or `tls_ca_pem` requires re-entering
  `bind_password`** (422 otherwise): the stored password must never be
  silently sent to a newly pointed target — credential and target are
  bound together (Phase 6 AD-1).
- **Microsoft AD real-environment validation is outstanding**: behavior
  is verified against test doubles/containers; a trial against a real
  Microsoft AD domain remains on the backlog (Phase reports).
- Bind-password recovery requires re-entry (no key escrow).
