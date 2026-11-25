# Runbook 10 — Database restoration

**Purpose:** restore a backup into a scratch database (verification) or
recover production data.
**Prerequisites:** backup file + its `.sha256` sidecar, correct
`BACKUP_ENCRYPTION_KEY` (the one used **at backup time**), stack
running at least `postgres`.

Full reference: [../deployment/backup-restore.md](../deployment/backup-restore.md).

## Restore into a scratch database (verification)

```bash
export BACKUP_ENCRYPTION_KEY='…'
BK=$(ls -t backups/*.sql.gz.enc | head -1)
./infrastructure/scripts/restore.sh "$BK" eitop_restore
```

Expected output:

```
[1/4] Verifying checksum...
checksum OK (<sha256>)
[2/4] Decrypting and testing archive...
archive OK
[3/4] Restoring into database 'eitop_restore'...
CREATE DATABASE
[4/4] Post-restore sanity checks...
alembic=0007_directory_findings
users=<n>
endpoints=<n>
Restore complete: eitop_restore
```

Compare the sanity counts with the source:

```bash
docker compose exec -T postgres psql -U eitop -d eitop -tAc \
  "SELECT 'users='||count(*) FROM users; SELECT 'alembic='||version_num FROM alembic_version;"
```

Expected: counts match. Drop the scratch DB afterwards:

```bash
docker compose exec -T postgres psql -U eitop -d postgres \
  -c 'DROP DATABASE IF EXISTS eitop_restore'
```

## Disaster recovery (fresh host)

```bash
# 1. Restore .env (from secret store), certificates, and the backups/ directory.
# 2. Start data services:
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d postgres redis
# 3. Load the dump into the real database name:
BACKUP_ENCRYPTION_KEY='…' \
  COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml \
  ./infrastructure/scripts/restore.sh backups/eitop-<ts>.sql.gz.enc eitop
# 4. Start everything else — entrypoint runs `alembic upgrade head`, which
#    migrates a restored older schema forward automatically:
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
# 5. Verify:
curl -s https://$HOST/health/ready     # {"status":"ready",...}
#    then log in as an existing admin and spot-check endpoints/directory.
```

## In-place restore over a live database

Prefer stop-and-swap over dropping the live DB:

```bash
docker compose stop backend worker beat
docker compose exec -T postgres psql -U eitop -d postgres -c \
  'CREATE DATABASE eitop_old' 
docker compose exec -T postgres pg_dump -U eitop -d eitop --clean \
  | docker compose exec -T postgres psql -U eitop -d eitop_old -q   # safety copy
docker compose exec -T postgres psql -U eitop -d postgres -c \
  'DROP DATABASE eitop; CREATE DATABASE eitop'
./infrastructure/scripts/restore.sh "$BK" eitop
docker compose start backend worker beat
```

Expected: services return healthy; login works; sanity counts match the
backup. Keep `eitop_old` until the recovery is signed off.

## Failure symptoms

| Exit / message | Cause | Recovery |
|---|---|---|
| `CHECKSUM MISMATCH` (exit 1) | truncated/corrupted file | use previous backup; check storage |
| `gzip: stdin: not in gzip format` | wrong `BACKUP_ENCRYPTION_KEY` | retrieve correct key — there is no recovery without it |
| psql errors during load (exit 1, `ON_ERROR_STOP`) | dump incompatible with server | restore aborted mid-load: recreate the target DB and retry with a matching-version backup; never hand-patch |
| `alembic current` ≠ head after restore | dump predates a migration | start backend — entrypoint runs `alembic upgrade head`; if it fails, read the migration error, do not edit rows |
| `401` for all users after restore | dump from before those users existed | expected; use accounts present in the dump |

**Security warnings**

- Never restore production data into a shared/non-production system
  without encryption at rest — the dump contains directory data and
  user e-mails.
- Audit trail: the restored DB's audit log ends at backup time; record
  the restore event (who/when/which backup) in your incident log.
