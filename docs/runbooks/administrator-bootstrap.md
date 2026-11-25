# Runbook 2 — Administrator bootstrap

**Purpose:** create the first administrator on a fresh instance.
**Prerequisites:** stack running, `users` table empty (fresh database —
the seed refuses to run once any user exists).

The bootstrap runs **only while the users table is empty**. There is no
default password anywhere in the product.

## Create the first admin

Password goes in via environment/stdin — **never as a command
argument** (argv is visible in `ps`):

```bash
export BOOTSTRAP_ADMIN_PASSWORD='<generate: openssl rand -base64 24>'
printf '%s' "$BOOTSTRAP_ADMIN_PASSWORD" | \
  docker compose exec -T backend python -m app.db.seed \
    --admin-email admin@your-domain.com --admin-password-stdin
```

Expected output:

```
INFO:__main__:rbac_seeded
INFO:__main__:bootstrap_admin_created
Admin bootstrap: created.
```

Alternative: run the command with no piped password and it prompts
invisibly via getpass.

## Verify

```bash
curl -sS -X POST https://$HOST/api/v1/auth/login \
  -H 'Content-Type: application/json' -H "Origin: https://$HOST" \
  -d "{\"email\":\"admin@your-domain.com\",\"password\":\"$BOOTSTRAP_ADMIN_PASSWORD\"}"
```

Expected: `200` with `access_token` and a `Set-Cookie: eitop_refresh`
carrying `HttpOnly; SameSite=lax; Secure` (production).

## Failure symptoms

| Symptom | Cause | Fix |
|---|---|---|
| `users table not empty — refusing` (seed exits without creating) | instance already bootstrapped | use existing admin; reset via runbook 3 if all admins are lost |
| `password must be at least 12 characters` | weak password | generate one: `openssl rand -base64 24` |
| Login 429 after retries | rate limit (`RATE_LIMIT_LOGIN_PER_MINUTE`, default 10/min per IP+bucket) | wait one minute; the limit recovers automatically |
| Email rejected with 422 "not a valid email address" | validator requires a real domain part | use `admin@your-domain.com`, not `admin@localhost` |

## Recovery — all admins lost

1. Stop the stack: `docker compose stop backend worker beat`.
2. On a **development** instance, delete users and re-bootstrap:
   `docker compose exec postgres psql -U eitop -d eitop -c "DELETE FROM user_roles; DELETE FROM users;"`,
   then re-run the bootstrap command above.
3. On **production**, prefer restoring a backup that contains an admin
   ([runbook 10](database-restoration.md)) over deleting rows — audit
   history stays intact.

**Security warning:** unset `BOOTSTRAP_ADMIN_PASSWORD` from your shell
history source after use (`unset`), and never put it in `.env` on a
shared host longer than needed.
