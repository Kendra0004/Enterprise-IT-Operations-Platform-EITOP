# Runbook 12 — Secret rotation and its consequences

**Purpose:** rotate credentials/secrets without surprise outages.
**Prerequisites:** shell access to the host, `.env` edit rights, (for
backup key) access to `backup.key`.

## Decision table

| Secret | How to rotate | Immediate consequence | Downtime |
|---|---|---|---|
| `SECRET_KEY` | new value in `.env`, restart all services | **all JWTs invalid** (users re-login) **and stored AD bind passwords become undecryptable** | seconds (restart) |
| `POSTGRES_PASSWORD` | alter role, update `.env` (`POSTGRES_PASSWORD` **and** `DATABASE_URL`), restart | brief DB auth blip | restart backend/worker/beat after DB |
| `REDIS_PASSWORD` | `CONFIG SET requirepass`, update `.env` (`REDIS_PASSWORD` **and** `REDIS_URL`), restart redis + consumers | queued tasks survive if Redis restarts with AOF; counters reset if flushed | seconds |
| `BACKUP_ENCRYPTION_KEY` | new key; re-encrypt strategy below | **old backups unreadable with the new key alone** | none |
| Admin/user password | not rotatable via API today ([runbook 3](user-role-administration.md)) | — | — |
| Enrollment tokens | mint new; old expire naturally | none | none |
| Endpoint credentials | [runbook 4](endpoint-enrollment.md) | agent re-auth on next submit | none |

## Rotating `SECRET_KEY`

```bash
NEW=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
# 1. BACK UP FIRST (JWTs and AD passwords depend on it):
./infrastructure/scripts/backup.sh ./backups
# 2. edit .env → SECRET_KEY=$NEW (chmod 600, never commit)
# 3. restart everything:
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart \
  backend worker beat
```

Expected after restart: healthy services; **every user must log in
again** (`401` on old tokens is expected, not an outage).

**Mandatory follow-up — AD bind passwords:** ciphertext encrypted under
the old key cannot be decrypted (`credential_undecryptable` label on
next test/sync). Re-enter each connection's bind password:

```bash
curl -sS -X PATCH https://$HOST/api/v1/directory/connections/$ID \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H "Origin: https://$HOST" \
  -d '{"bind_password":"<same password, re-supplied>"}'
# then verify:
curl -sS -X POST https://$HOST/api/v1/directory/connections/$ID/test \
  -H "Authorization: Bearer $TOKEN" -H "Origin: https://$HOST"
```

Expected: `{"ok":true,…}`. Repeat per connection. Skip this and the
next scheduled sync fails with `credential_undecryptable`.

Also verify the fresh login flow end to end
([runbook 1](first-time-deployment.md) checklist items 2–4).

## Rotating `POSTGRES_PASSWORD`

```bash
docker compose exec -T postgres psql -U eitop -d postgres \
  -c "ALTER ROLE eitop WITH PASSWORD '<new-strong>'"
# .env: POSTGRES_PASSWORD=<new-strong>
#       DATABASE_URL=postgresql+psycopg://eitop:<new-strong>@postgres:5432/eitop
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d \
  backend worker beat
```

Expected: `/health/ready` → `{"database":"ok"}`. Note: the password
above is a **dev-stack** command; on production the same `ALTER ROLE`
runs as the superuser configured in `POSTGRES_USER`.

## Rotating `REDIS_PASSWORD`

```bash
docker compose exec -T redis redis-cli CONFIG SET requirepass '<new>'
# .env: REDIS_PASSWORD=<new>
#       REDIS_URL=redis://:<new>@redis:6379/0
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d \
  backend worker beat redis
```

Expected: `docker compose exec redis redis-cli -a '<new>' ping` →
`PONG`; `/health/ready` → `{"redis":"ok"}`. Keep `--requirepass` in the
redis command line in sync (compose interpolates it from `REDIS_PASSWORD`).

## Rotating `BACKUP_ENCRYPTION_KEY`

There is no re-encrypt command. Safe procedure:

1. Keep the **old key** stored (old backups need it forever).
2. Take a fresh backup under the **new** key.
3. Immediately restore-verify it into a scratch DB with the new key
   ([runbook 10](database-restoration.md)).
4. Record: `backup.key v2 since <date>`; tag old files
   (`mv backups/… backups/…` under an `old-key/` folder helps).

**Never lose either key**: losing a key loses every backup encrypted
under it — there is no escrow.

**Security warnings**

- Rotation commands take secrets from env/files, never argv.
- After any rotation, review audit logs for unexpected failures
  ([runbook 16](log-inspection-audit-review.md)) — a wave of `401`s
  right after a `SECRET_KEY` change is expected; a wave of
  `auth.login.failure` is not.
