# Runbook 9 — Backup scheduling and verification

**Purpose:** schedule automated PostgreSQL backups, verify them, manage
retention.
**Prerequisites:** `BACKUP_ENCRYPTION_KEY` set (separate from
`SECRET_KEY`), scripts in `infrastructure/scripts/` (executable).

Full reference: [../deployment/backup-restore.md](../deployment/backup-restore.md).

## One manual backup

```bash
export BACKUP_ENCRYPTION_KEY='…'          # env only — never argv
./infrastructure/scripts/backup.sh ./backups
```

Expected output:

```
Dumping PostgreSQL...
Backup written: backups/eitop-20261125T205845Z.sql.gz.enc
Checksum:       backups/eitop-20261125T205845Z.sql.gz.enc.sha256
Retention: pruned backups older than 30 days.
```

The script **fails loudly** (non-zero exit) if the fresh dump cannot be
decrypted and `gzip -t`-verified — a zero exit means a readable,
checksummed backup exists.

In production, target the production compose files:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml \
  BACKUP_ENCRYPTION_KEY='…' ./infrastructure/scripts/backup.sh ./backups
```

## Schedule (cron, daily 03:15)

```cron
15 3 * * * cd /opt/eitop && \
  BACKUP_ENCRYPTION_KEY="$(cat /opt/eitop/backup.key)" \
  COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml \
  ./infrastructure/scripts/backup.sh ./backups >> /var/log/eitop-backup.log 2>&1
```

(Do not `source .env` in cron — values may contain shell metacharacters.
Compose itself reads `.env` for interpolation; the script defaults
`POSTGRES_USER`/`POSTGRES_DB` correctly.)

Expected: one `eitop-<UTC>.sql.gz.enc` + `.sha256` per day; files older
than `BACKUP_RETENTION_DAYS` (default 30) pruned automatically.

## Verify (weekly, cheap)

```bash
BK=$(ls -t backups/*.sql.gz.enc | head -1)
export BACKUP_ENCRYPTION_KEY='…'
# 1. sidecar
cut -d' ' -f1 "$BK.sha256"
openssl dgst -sha256 -r "$BK" | cut -d' ' -f1      # must match
# 2. decrypt + gzip integrity
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
  -pass env:BACKUP_ENCRYPTION_KEY -in "$BK" | gzip -t && echo OK
```

Expected: hashes equal, then `OK`.

**Verification is not optional**: a backup is only complete once a
restore has been demonstrated — schedule a real restore into a scratch
database at least monthly ([runbook 10](database-restoration.md)).

## Monitor

- Alert if `/var/log/eitop-backup.log` shows a non-zero exit or no new
  file for 25 h.
- Alert on `gzip: stdin: not in gzip format` / `CHECKSUM MISMATCH` —
  wrong key or corrupted storage respectively.

## Failure symptoms

| Symptom | Cause | Fix |
|---|---|---|
| `BACKUP_ENCRYPTION_KEY must be set…` (exit 2) | env not exported | fix cron line / shell |
| `could not connect to postgres` | stack down or wrong `COMPOSE_FILE`/`COMPOSE_PROJECT_NAME` | check `docker compose ps`; export the right project |
| disk fills | retention too long / backups too frequent | lower `BACKUP_RETENTION_DAYS`, move `backups/` to bigger volume |
| restore-time `CHECKSUM MISMATCH` | file corrupted after creation | use the previous backup; investigate storage |

**Security warnings**

- Keep `backup.key` in a **different** secret store than `.env`
  (compromise of one must not unlock the other).
- Losing the key loses the backups — no recovery exists; test restores
  after any key change.
- Backups contain user e-mails, hashes, directory data: treat the
  `backups/` directory as confidential (0700, encrypted at rest by the
  dump itself).
