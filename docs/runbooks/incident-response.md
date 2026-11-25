# Runbook 15 — Incident response and security investigation

**Purpose:** structured response to a suspected compromise (stolen
admin session, malicious collector, data exposure).
**Prerequisites:** `admin` access, host shell, audit-log access
(`audit:read`).

Order matters: **contain first, investigate second, recover last.**

## 1. Triage (minutes)

```bash
curl -s https://$HOST/health/ready
docker compose ps
curl -sS "https://$HOST/api/v1/audit-logs?page_size=50" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -100
```

Decide the scope: single user? single endpoint? whole platform?

## 2. Containment

| Scenario | Action |
|---|---|
| Stolen/leaked user session | rotate `SECRET_KEY` ([runbook 12](secret-rotation.md)) — kills every JWT immediately; then audit who did what |
| Rogue/compromised endpoint | `POST /api/v1/endpoints/{id}/revoke` ([runbook 4](endpoint-enrollment.md)) — credential dies at once |
| Compromised enrollment token (unused) | wait out its expiry (max 14 days) or revoke the consuming path by rotating `SECRET_KEY`… tokens are SHA-256-stored; short expiry means patience is usually enough — verify `used_at` in the token list |
| AD bind password exposed | change it in AD first, then `PATCH /directory/connections/{id}` with the new password; test connection |
| Host-level breach | isolate host; assume `.env` (DB/Redis passwords, `SECRET_KEY`) is burned → rotate per runbook 12 after containment |
| Backup key exposed | re-key backups per runbook 12; treat old dumps as readable by attacker |

After containment, verify the platform still works
([runbook 1](first-time-deployment.md) checklist).

## 3. Investigation — audit forensics

The audit log is append-only and API-untouched (no write/delete
routes). Query windows of interest:

```bash
# auth events (login failures = brute force signal)
curl -sS "https://$HOST/api/v1/audit-logs?event_type=auth.login.failure&page_size=100" \
  -H "Authorization: Bearer $TOKEN"
# token-replay signal
curl -sS "https://$HOST/api/v1/audit-logs?event_type=auth.refresh.reuse" \
  -H "Authorization: Bearer $TOKEN"
# who touched endpoints/directory
curl -sS "https://$HOST/api/v1/audit-logs?event_type=endpoint.revoked" \
  -H "Authorization: Bearer $TOKEN"
```

Complement with container logs ([runbook 16](log-inspection-audit-review.md)):
timestamps, `event_type`/`message` correlation, source IPs (from the
trusted `X-Forwarded-For` — only meaningful behind the edge proxy).

Questions to answer: first bad event, actor ids, targets, whether
`auth.refresh.reuse` fired (means a token was stolen *and* detected),
whether any AD connection changed, whether enrollment tokens were
minted unexpectedly.

## 4. Recovery

1. Rotate every secret touched by the scenario (runbook 12).
2. Re-issue endpoint credentials for affected endpoints (runbook 4).
3. Re-supply AD bind passwords if `SECRET_KEY` changed (runbook 12).
4. Restore from backup **only** for data-integrity attacks — restoring
   to "before the incident" also resurrects whatever the attacker
   changed for the worse; prefer forward-fixing via API where possible
   (runbook 10 if a restore is truly needed).
5. Verify: login, `/health/ready`, endpoint heartbeat flow, one AD sync
   test, backup+restore round-trip (runbooks 9–10).

## 5. Post-incident

- Record timeline with audit `event_type`s and log excerpts.
- Decide: any control failed? (e.g. rate limit bypassed → check proxy
  XFF handling; audit gap → report as a defect, do not patch tables.)
- Rotate credentials that were shared during the incident.

**Security warnings**

- Never export raw audit rows containing e-mails/IPs into public
  tickets — summarize.
- The audit log is your evidence chain: preserve a copy (SQL dump of
  `audit_logs`) before major remediation steps.
- If `SECRET_KEY` rotation is used for containment, AD bind passwords
  must be re-supplied before the next sync or directory integration
  silently degrades (runbook 12).
