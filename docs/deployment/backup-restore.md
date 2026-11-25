# Backup and recovery runbook

PostgreSQL is the system of record. Redis is **not** backed up: it holds
the Celery broker (tasks are re-delivered or simply re-queued after
restart) and rate-limit counters (resetting them only re-arms the
brute-force window). Everything durable lives in Postgres.

## What a backup contains

One compressed, encrypted dump of the entire database: users/RBAC,
audit log, endpoints, snapshots, directory connections/findings/sync
runs, reconciliations. Alembic's `alembic_version` row travels with it,
so a restore always lands on a known schema revision.

## Creating a backup

```bash
export BACKUP_ENCRYPTION_KEY='…'   # separate key, NOT SECRET_KEY
./infrastructure/scripts/backup.sh ./backups
```

Produces:

```
backups/eitop-20261125T031500Z.sql.gz.enc          # AES-256-CBC (PBKDF2, 100k iter)
backups/eitop-20261125T031500Z.sql.gz.enc.sha256   # integrity sidecar
```

The script fails loudly if the freshly written backup cannot be
decrypted and `gzip -t`-verified.

### Retention

`BACKUP_RETENTION_DAYS` (default **30**) prunes older backups by mtime
after each run. Schedule via cron/systemd:

```cron
15 3 * * * cd /opt/eitop && BACKUP_ENCRYPTION_KEY=… BACKUP_RETENTION_DAYS=30 \
  ./infrastructure/scripts/backup.sh ./backups >> /var/log/eitop-backup.log 2>&1
```

### Key management

* The encryption key is read **only** from the environment — scripts
  refuse to run without it and never accept it as argv.
* Store it in a different place than the `.env` (host keyfile, secret
  manager, sealed envelope). A backup is useless to attackers without
  the key, but a leaked `.env` + leaked key = full data exposure.
* Losing the key = losing the backups. Verify restores after any key
  rotation.

## Restoring

```bash
export BACKUP_ENCRYPTION_KEY='…'
./infrastructure/scripts/restore.sh backups/eitop-20261125T031500Z.sql.gz.enc eitop_restore
```

The script:

1. Verifies the sha256 sidecar (detects truncated/corrupted files).
2. Decrypts and `gzip -t`s the archive.
3. Creates the target database and loads it with `psql -v ON_ERROR_STOP=1`
   — the first SQL error aborts, no partial silent success.
4. Prints sanity counts: `alembic=`, `users=`, `endpoints=`.

### Disaster recovery (fresh host)

```bash
# 1. Restore the environment + certificates (from your secret store)
# 2. Start the data services and load the dump:
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d postgres redis
BACKUP_ENCRYPTION_KEY=… ./infrastructure/scripts/restore.sh backups/eitop-….sql.gz.enc eitop
# 3. Bring up the rest (entrypoint runs alembic upgrade head — a dump
#    restored at an older revision is migrated forward automatically):
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
# 4. Verify login + /health/ready
```

### Point-in-time note

This procedure recovers the last successful backup (RPO = backup
interval, e.g. 24 h with daily cron). Continuous PITR (WAL archiving) is
deliberately out of scope — see "Explicit limitations" in
[../architecture/security.md](../architecture/security.md).

## Backup integrity verification

* Per run: decrypt + `gzip -t` inside `backup.sh`; sha256 sidecar written.
* Per restore: sidecar check + `ON_ERROR_STOP` load + sanity counts.
* Recommended cadence: monthly full restore into a scratch database on
  disposable infrastructure, comparing `users`, `endpoints`,
  `directory_findings`, `alembic_version` counts against the source.

## Migration procedure

1. Back up first (`backup.sh`) — every schema migration starts here.
2. `docker compose … exec backend alembic upgrade head` (automatic on
   container start; run manually to see the plan first with
   `alembic history`).
3. Migrations are forward-only in production; `alembic downgrade` exists
   for development only — never run it against a restored/live dataset
   without a fresh backup.
4. Verify `alembic current` equals `alembic heads` after the upgrade.

## Redis recovery expectations

| Loss | Effect | Mitigation |
|---|---|---|
| Redis restart (AOF intact) | no effect | `appendonly yes` already configured |
| Redis data loss | queued Celery tasks lost; rate-limit counters reset | tasks are idempotent; beat re-schedules periodic jobs; re-trigger manual syncs from the UI if needed |
| Long worker outage | scheduled runs miss their window | sync engine marks runs failed/stale and re-queues (lease reaper) — see ADR in architecture docs |