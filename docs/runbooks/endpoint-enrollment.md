# Runbook 4 — Endpoint enrollment and credential rotation

**Purpose:** onboard a collector to an endpoint, rotate or revoke its
credential.
**Prerequisites:** stack running, a user with `endpoints:write`
(`admin`, `operator`); HTTPS URL of the deployment.

Deep-dive reference: [../endpoints/enrollment.md](../endpoints/enrollment.md),
collector install: [../collectors/README.md](../collectors/README.md).

## 1. Mint an enrollment token

```bash
curl -sS -X POST https://$HOST/api/v1/endpoints/enrollment-tokens \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H "Origin: https://$HOST" \
  -d '{"expires_in_minutes": 60}'
```

Expected `201` — **the raw token appears exactly once** in this
response (list endpoints never return it; only its SHA-256 is stored):

```json
{"id":"…","token":"<raw>","expires_at":"…","used_at":null,"group_id":null,…}
```

Optionally pass `"group_id":"<uuid>"` to auto-add the endpoint to a
group, or `restrictions` for token-scoped limits.

Rate limit: `RATE_LIMIT_ENROLL_PER_MINUTE` (default 10/min) applies to
enroll attempts — minting is not limited, enrolling is.

## 2. Enroll the collector

**Linux** (see [../collectors/README.md](../collectors/README.md)):

```bash
sudo install -d -m 0700 /etc/eitop /var/lib/eitop
sudo cp collectors/linux/config.example.toml /etc/eitop/collector.toml
sudo chmod 0600 /etc/eitop/collector.toml
sudo $EDITOR /etc/eitop/collector.toml     # server_url = "https://$HOST"

# token via env or stdin — never as a CLI argument (argv shows in ps)
sudo -u eitop EITOP_ENROLL_TOKEN='<raw token>' \
  eitop-collector --config /etc/eitop/collector.toml enroll
# or: printf '%s' '<raw token>' | sudo -u eitop \
#   eitop-collector --config /etc/eitop/collector.toml enroll --token-stdin
```

**Windows**:

```powershell
$env:EITOP_ENROLL_TOKEN = '<raw token>'   # never a parameter — argv is visible
.\eitop-collector.ps1 -Config C:\ProgramData\EITOP\collector.json enroll
# or: '<raw token>' | .\eitop-collector.ps1 -Config ... enroll -TokenStdin
```

Expected: enrollment returns `201` with `endpoint_id` and the raw
`eitop_ep_…` credential, persisted to
`[collector].credential_file` (mode 0600). The raw enrollment token is
then dead.

**API-level equivalent** (what the collector calls):

```bash
curl -sS -X POST https://$HOST/api/v1/agent/enroll \
  -H 'Content-Type: application/json' \
  -d '{"token":"<raw>","hostname":"web01","fqdn":"web01.example.com",
       "os":"linux","os_version":"Ubuntu 24.04","agent_version":"1.0.0"}'
```

Failure is always one uniform error — `Invalid enrollment token` —
whether the token was wrong, expired or already used (no guessing
oracle). `429` means the per-IP enroll limit tripped; wait a minute.

## 3. Verify the endpoint

```bash
curl -sS "https://$HOST/api/v1/endpoints?search=web01" \
  -H "Authorization: Bearer $TOKEN"
```

Expected: the endpoint listed with status `active` after its first
heartbeat; inventory appears after the first inventory submission
(default every 300 s).

## 4. Rotate a credential

- **Admin-initiated** (compromised host, scheduled hygiene):

  ```bash
  curl -sS -X POST https://$HOST/api/v1/endpoints/$EP/rotate-credential \
    -H "Authorization: Bearer $TOKEN" -H "Origin: https://$HOST"
  ```

  Expected `200` with a **new raw credential**. The old credential
  stops working immediately; update the agent's `credential_file` (or
  re-run enrollment) before the next submission or the agent will get
  `401`.

- **Agent-initiated**: `POST /api/v1/agent/rotate-credential` with the
  current credential — same one-time raw response semantics.

## 5. Revoke an endpoint

```bash
curl -sS -X POST https://$HOST/api/v1/endpoints/$EP/revoke \
  -H "Authorization: Bearer $TOKEN" -H "Origin: https://$HOST"
```

Expected: endpoint status `revoked`; every subsequent agent request
with its credential returns `401`. Re-enrollment requires a **new**
enrollment token — revocation is permanent for that credential.

## Failure symptoms

| Symptom | Cause | Recovery |
|---|---|---|
| `401 Invalid enrollment token` | expired (> `expires_in_minutes`) or already consumed | mint a new token |
| `429` on enroll | per-IP enroll rate limit | wait 1 min |
| `413` on enroll | body > 16 KB | trim payload (defaults are fine) |
| Agent 401 after rotate | agent still has old credential | re-enroll or write the new credential to `credential_file`, restart collector |
| Endpoint never leaves `pending` | no heartbeat yet | check collector logs + `server_url` reachability |

**Security warnings**

- Raw tokens/credentials exist only in the issuance response — copy
  them straight to the target host; never paste into tickets or chat.
- Deliver enrollment tokens out of band (one-time secret channel), and
  mint short expiry (`expires_in_minutes: 15`) when possible.
- Every rotation/revocation is audited (`endpoint.*` events) — see
  [runbook 16](log-inspection-audit-review.md).
