# Troubleshooting

Operational playbook for a running EITOP deployment. General diagnosis
starts at the health endpoints and the JSON logs.

## Where to look

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail 100 backend
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail 100 worker beat
curl -s https://your-domain/health        # {"status":"ok"}
curl -s https://your-domain/health/ready  # db + redis checks
```

Logs are one JSON object per line; useful keys: `level`, `logger`,
`message`, `event_type` (audit), `exception`. Secrets are never logged —
if you find one, treat it as a bug and rotate it.

## Startup failures

| Symptom | Cause | Fix |
|---|---|---|
| Backend exits: `Insecure production configuration: …` | Fail-fast validation (Phase 4) rejected dev credentials/placeholder key/CORS | Fix the listed values in `.env`; the error names every problem at once |
| `SECRET_KEY must be set in .env` | compose `${SECRET_KEY:?…}` expansion with no `.env` | `cp .env.example .env`, set a real key |
| Backend restart-loop with `address already in use` | Port conflict on host | Change the published port or stop the conflicting service |
| `depends_on … service_healthy` wait forever | postgres/redis healthcheck failing | `docker compose logs postgres` — usually bad `POSTGRES_PASSWORD`/`REDIS_PASSWORD` in `.env` |

## Authentication / rate limiting

| Symptom | Cause | Fix |
|---|---|---|
| Everyone gets 429 | `X-Forwarded-For` spoofing attempt or shared client IP; limit = `RATE_LIMIT_LOGIN_PER_MINUTE` | Verify the edge proxy overwrites XFF (it must, see `infrastructure/nginx/eitop.conf`); adjust the limit if traffic legitimately exceeds it |
| 503 `Rate limiter unavailable` | Redis down — **fail-closed by design** (ADR) | `docker compose ps redis`; check `REDIS_PASSWORD` matches; restore Redis |
| Users suddenly logged out | `SECRET_KEY` rotated | Expected — access JWTs are signed; users re-login (refresh cookies keep working) |
| 401 `Token reuse detected` | Stolen/refresh-replayed token, or a browser replaying an old cookie | Expected protective behavior; family revoked; user logs in again |
| 403 `Cross-origin request rejected` | `CORS_ORIGINS` missing the real origin | Add the https origin to `.env` and restart |

## Celery worker / beat

| Symptom | Cause | Fix |
|---|---|---|
| Worker healthcheck unhealthy (`inspect ping` no pong) | worker crashed / OOM | `docker compose logs worker`; raise `mem_limit` in the prod overlay |
| Periodic jobs not running (offline scan, sync, retention) | beat down or its schedule file unwritable | `docker compose logs beat`; the prod overlay keeps the schedule on `tmpfs /tmp` |
| Sync run stuck `running` | worker died mid-run | Lease reaper finalizes stale/expired leases automatically (`DIRECTORY_STALE_RUN_MINUTES`, `DIRECTORY_MAX_SYNC_MINUTES`); no manual SQL needed |
| Tasks piling up in Redis | worker saturated | `docker compose up -d --scale worker=2`; check worker logs for exceptions |

## Database

| Symptom | Cause | Fix |
|---|---|---|
| `alembic current` ≠ `alembic heads` | entrypoint migration failed | `docker compose exec backend alembic upgrade head` — read the error; never hand-edit rows |
| Disk growth | snapshots/audit log | `SNAPSHOT_RETENTION_DAYS` enables pruning (default keeps forever); audit log is append-only by design — plan archival at the DBA layer |
| Backup restore fails checksum | corrupted/truncated file | Restore from the previous backup; verify the key matches the one used at backup time |

## TLS / proxy

| Symptom | Cause | Fix |
|---|---|---|
| `502 Bad Gateway` from nginx | backend/frontend not running or unhealthy | `docker compose ps`; check `depends_on` health |
| nginx: `open() … cert failed` | missing `certs/fullchain.pem` / `privkey.pem` | Mount valid certificate pair (see deployment README) |
| Cookie not sent over HTTPS | `APP_ENV` not `production` | Secure cookies are only issued in production mode — fix `.env` |
| Rate limiter keys everyone as one IP | a proxy inside the chain *appends* instead of overwrites | Keep exactly one trusted edge proxy that overwrites `X-Forwarded-For` |

## AD sync / LDAP

| Symptom | Cause | Fix |
|---|---|---|
| Test connection shows sanitized label only | by design — raw LDAP errors never reach clients | Backend logs carry the sanitized label; verify DNS/TLS/credentials out-of-band |
| Sync fails: TLS hostname mismatch | LDAP host not in cert SAN | Use the hostname that matches the certificate |
| Sync fails: untrusted CA | enterprise CA not trusted | Set the connection's `tls_ca_pem` (public cert only — never a secret) |
| Findings say "Insufficient visibility" | inventory incomplete (`missing_scan` category) | Run a full sync; the Health tab shows which categories are missing |

## Collectors (agents)

* Linux agent: check `config.toml` and the credential file permissions
  (must be `0600`); agent logs to stdout/journald — rotate like any unit.
* Windows collector: verify the enrolled credential still exists
  (rotation/revocation invalidates old secrets immediately by design);
  endpoint status in the UI shows `revoked` after admin revocation.

## Still stuck

1. Capture: `docker compose ps`, the failing request's timestamp +
   `event_type` from logs, `alembic current`, and `/health/ready` output.
2. Reproduce against a disposable stack (backup → restore → test) — never
   debug directly on production data.
3. See [../architecture.md](../architecture.md) for ADRs that explain
   intentional behavior (fail-closed rate limiting, append-only audit,
   stateless JWTs, sync leases).