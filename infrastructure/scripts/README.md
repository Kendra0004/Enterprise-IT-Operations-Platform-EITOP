# Infrastructure scripts

| Script | Purpose |
|---|---|
| `backup.sh [dir]` | Encrypted, checksummed PostgreSQL dump with retention pruning. Requires `BACKUP_ENCRYPTION_KEY` in the environment (never argv). |
| `restore.sh <backup.sql.gz.enc> <target-db>` | Verifies sha256 sidecar, decrypts, restores with `ON_ERROR_STOP=1`, prints sanity counts. |

Full runbook: [../../docs/deployment/backup-restore.md](../../docs/deployment/backup-restore.md)

```bash
export BACKUP_ENCRYPTION_KEY='…'
./infrastructure/scripts/backup.sh ./backups
./infrastructure/scripts/restore.sh backups/eitop-<ts>.sql.gz.enc eitop_restore
```

In production set `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml`
(and/or `COMPOSE_PROJECT_NAME`) so the scripts target the right stack.
