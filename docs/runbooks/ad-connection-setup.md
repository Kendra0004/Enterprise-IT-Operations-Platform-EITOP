# Runbook 6 — Active Directory connection setup

**Purpose:** connect EITOP to an AD domain over LDAPS and run the first
sync.
**Prerequisites:** `directory:write` (+ `directory:sync` to test/sync),
a read-only bind account, DC certificate chain reachable from the
**worker** container.

Reference: [../active-directory/README.md](../active-directory/README.md).

## 1. Verify network + TLS from the worker

```bash
docker compose exec worker python - <<'PY'
import socket, ssl
ctx = ssl.create_default_context()
with socket.create_connection(("dc01.example.com", 636), 10) as s:
    with ctx.wrap_socket(s, server_hostname="dc01.example.com") as t:
        print(t.version(), t.getpeercert()["subject"])
PY
```

Expected: `TLSv1.3` (or `TLSv1.2`) and the DC subject. Failure here =
fix DNS/firewall/CA trust **before** creating the connection.

## 2. Create the connection

```bash
curl -sS -X POST https://$HOST/api/v1/directory/connections \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H "Origin: https://$HOST" \
  -d '{
    "name": "corp.example.com",
    "domain_dns": "example.com",
    "host": "dc01.example.com",
    "port": 636,
    "tls_mode": "ldaps",
    "search_base": "DC=example,DC=com",
    "bind_username": "CN=EITOP Reader,OU=Service Accounts,DC=example,DC=com",
    "bind_password": "<read-only bind password>",
    "auto_sync": true,
    "sync_interval_minutes": 60
  }'
```

Expected `201`. For a private CA add `"tls_ca_pem": "-----BEGIN
CERTIFICATE-----…"` (the CA certificate — public material, not a secret).

`403` = missing `directory:write`; `422` = field validation (extra
fields are rejected — `extra="forbid"`).

## 3. Test the connection

```bash
curl -sS -X POST https://$HOST/api/v1/directory/connections/$ID/test \
  -H "Authorization: Bearer $TOKEN" -H "Origin: https://$HOST"
```

Expected:

```json
{"ok":true,"label":null,"duration_ms":84,
 "default_naming_context":"DC=example,DC=com","dns_hostname":"dc01.example.com"}
```

`ok:false` returns a sanitized `label` (`timeout`, `tls_error`,
`invalid_credentials`, `search_base_not_found`, …) — map it in
[runbook 7](ad-sync-troubleshooting.md).

## 4. Run the first sync

```bash
curl -sS -X POST https://$HOST/api/v1/directory/connections/$ID/sync \
  -H "Authorization: Bearer $TOKEN" -H "Origin: https://$HOST"
```

Expected `202` with a `sync_runs` row (`queued`/`running`). Watch it:

```bash
curl -sS "https://$HOST/api/v1/directory/sync-runs?connection_id=$ID" \
  -H "Authorization: Bearer $TOKEN"
```

Expected final state: `success` with populated `category_results`
(`connect`, `domains`, `ous`, `users`, `groups`, `computers`,
`memberships` all ok). `409` on trigger = a run is already active.

First sync duration scales with directory size (paged search,
`page_size` 500); cap `DIRECTORY_MAX_SYNC_MINUTES` (60) aborts
overlong runs safely — they are reaped as `stale_run_reaped` and can be
re-triggered.

## 5. Confirm data

```bash
curl -sS "https://$HOST/api/v1/directory/overview" -H "Authorization: Bearer $TOKEN"
curl -sS "https://$HOST/api/v1/directory/computers?page_size=5" -H "Authorization: Bearer $TOKEN"
```

Expected: overview shows fresh `last_synced_at`; computers list
populates. Endpoint↔computer matches appear under
`GET /directory/reconciliations`.

## Failure symptoms

| Symptom | Fix |
|---|---|
| test `ok:false, label:"tls_error"` | SAN mismatch → fix `host`; untrusted CA → set `tls_ca_pem` |
| test `label:"invalid_credentials"` | verify bind DN/password in AD; password is write-only — re-enter via PATCH |
| sync `409` | wait for the running sync or inspect `sync-runs` |
| sync `failed` + `search_base_not_found` | correct `search_base` |
| worker crash-loop after adding connection | check worker logs; a bad connection must not crash the worker — report if reproducible |

**Security warnings**

- Bind password is write-only: it is encrypted (Fernet over
  `SECRET_KEY`) and never returned. Store it in your secrets vault —
  EITOP cannot show it back.
- Read-only bind only — EITOP never writes to AD; do not grant
  write permissions to the bind account.
