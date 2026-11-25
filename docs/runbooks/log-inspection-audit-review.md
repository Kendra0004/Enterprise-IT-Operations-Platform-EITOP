# Runbook 16 — Log inspection and audit review

**Purpose:** read operational logs and the audit trail for routine
reviews and incident forensics.
**Prerequisites:** host shell; `audit:read` for the API (roles:
`admin`, `security_auditor`).

## Container logs (operational)

```bash
docker compose logs --tail 200 backend
docker compose logs --tail 200 worker beat
docker compose logs --since 1h frontend proxy
docker compose logs -f backend            # follow
```

Format: **one JSON object per line** (stdout → docker json-file;
production overlay rotates 5 × 10 MB). Useful keys:

| Key | Meaning |
|---|---|
| `timestamp` | ISO-8601 UTC |
| `level` | `INFO` / `WARNING` / `ERROR` |
| `logger` | emitting module |
| `message` | human-readable event |
| `event_type` | structured event name (matches audit families) |
| `exception` | class + stack for errors |

Any additional `extra=` fields the caller attached ride along (the
formatter attaches everything except Python's reserved LogRecord
attributes).

Filter with jq:

```bash
docker compose logs --since 24h backend | \
  jq -r 'select(.level=="ERROR") | "\(.timestamp) \(.message)"' | tail -50
```

**Secrets are never logged** — the JSON formatter attaches a fixed
field set (no passwords/tokens/bind credentials). If you find one,
treat it as a defect and rotate the exposed value.

## Audit trail (security)

The audit log is append-only in PostgreSQL; the API only reads it.

```bash
# recent activity across the platform (newest first)
curl -sS "https://$HOST/api/v1/audit-logs?page=1&page_size=50" \
  -H "Authorization: Bearer $TOKEN"

# filtered — exact event_type / outcome
curl -sS "https://$HOST/api/v1/audit-logs?event_type=auth.login.failure&page_size=100" \
  -H "Authorization: Bearer $TOKEN"
curl -sS "https://$HOST/api/v1/audit-logs?outcome=failure" \
  -H "Authorization: Bearer $TOKEN"
```

`page_size` ≤ 200. Fields returned: `event_type`, `actor_email`,
`target`, `outcome`, `ip_address`, `created_at`.

### Event catalog (complete)

| Family | Event types |
|---|---|
| Authentication | `auth.login.success`, `auth.login.failure`, `auth.logout`, `auth.refresh.success`, `auth.refresh.failure`, `auth.refresh.reuse`, `auth.agent.failure` |
| Endpoints | `endpoint.enrollment_token.created`, `endpoint.enrolled`, `endpoint.enrollment.rejected`, `endpoint.credential.rotated`, `endpoint.revoked`, `endpoint.online`, `endpoint.offline`, `endpoint.group.created`, `endpoint.group.member.added`, `endpoint.group.member.removed` |
| Directory | `directory.connection.created/updated/deleted/tested`, `directory.sync.triggered`, `directory.sync.failed`, `directory.finding.acknowledged/suppressed/reopened`, `directory.reconciliation.decided` |
| Admin | `user.created` |

## Routine review (weekly)

1. `auth.login.failure` bursts → brute-force attempt? Rate limiting
   should cap it (10/min per bucket); a sustained global spike means
   many IPs → consider raising `RATE_LIMIT_LOGIN_PER_MINUTE` or
   checking the proxy XFF handling.
2. `auth.refresh.reuse` → **token theft detected and neutralized**;
   identify the affected user and verify their subsequent activity.
3. `endpoint.enrollment.rejected` spikes → someone probing tokens.
4. `endpoint.revoked` / `credential.rotated` without a change ticket →
   investigate.
5. `directory.sync.failed` → [runbook 7](ad-sync-troubleshooting.md).
6. `ERROR`-level container logs → correlate by timestamp + `event_type`.

## Correlating events

There is no request-id header in the API today — correlate by
`timestamp` (second precision in practice) plus `event_type`/`message`:

```bash
docker compose logs --since 1h backend | \
  grep -E '"timestamp":"2026-11-25T14:0[3-5]' | head -50
```

When a user reports an error, note the exact time and path; the
matching uvicorn access line and application lines sit in the same
window.

## Retention

- Audit rows are append-only and **not pruned by the application** —
  size the DB and plan DBA-level archival if needed.
- Container logs rotate via docker (`max-size`/`max-file` in the prod
  overlay); dev keeps default docker rotation.
- No log shipping/SIEM integration exists (out of scope) — export via
  your own agent if required.

**Security warning:** logs may contain e-mail addresses and client IPs
(personal data): restrict host access, and redact before sharing
outside the ops team.
