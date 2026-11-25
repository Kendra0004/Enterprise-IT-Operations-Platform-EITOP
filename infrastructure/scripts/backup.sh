#!/bin/sh
# EITOP PostgreSQL backup — encrypted, checksummed, retention-pruned.
#
# Usage:
#   BACKUP_ENCRYPTION_KEY='...' ./infrastructure/scripts/backup.sh [dir]
#
# Output (in [dir], default ./backups):
#   eitop-<UTC-timestamp>.sql.gz.enc        encrypted dump
#   eitop-<UTC-timestamp>.sql.gz.enc.sha256 integrity checksum
#
# Retention: BACKUP_RETENTION_DAYS (default 30) — older backups pruned.
# The encryption key is read from the environment ONLY (never argv).
# Redis is intentionally NOT dumped: it holds the Celery broker and
# rate-limit counters; losing them is recoverable (see docs/deployment/
# backup-restore.md). PostgreSQL is the system of record.

set -eu

DIR="${1:-./backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
: "${COMPOSE_FILE:=docker-compose.yml}"
export COMPOSE_FILE
TS="$(date -u +%Y%m%dT%H%M%SZ)"

if [ -z "${BACKUP_ENCRYPTION_KEY:-}" ]; then
    echo "BACKUP_ENCRYPTION_KEY must be set in the environment (never argv)." >&2
    exit 2
fi

mkdir -p "$DIR"
OUT="$DIR/eitop-$TS.sql.gz.enc"

echo "Dumping PostgreSQL..."
docker compose exec -T postgres \
    pg_dump -U "${POSTGRES_USER:-eitop}" -d "${POSTGRES_DB:-eitop}" \
    --no-owner --no-privileges \
    | gzip -9 \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt \
        -pass env:BACKUP_ENCRYPTION_KEY \
        -out "$OUT"

# Checksum AFTER encryption so the sidecar detects storage corruption
# without exposing plaintext digests.
openssl dgst -sha256 -r "$OUT" > "$OUT.sha256"

# Verify what we just wrote (fail the run if unreadable/corrupt).
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass env:BACKUP_ENCRYPTION_KEY \
    -in "$OUT" | gzip -t

echo "Backup written: $OUT"
echo "Checksum:       $OUT.sha256"

# Retention prune (by mtime).
find "$DIR" -maxdepth 1 -name 'eitop-*.sql.gz.enc' -mtime +"$RETENTION_DAYS" -print -delete
find "$DIR" -maxdepth 1 -name 'eitop-*.sql.gz.enc.sha256' -mtime +"$RETENTION_DAYS" -delete
echo "Retention: pruned backups older than ${RETENTION_DAYS} days."