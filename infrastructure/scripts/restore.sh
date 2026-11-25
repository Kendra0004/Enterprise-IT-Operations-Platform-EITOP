#!/bin/sh
# EITOP PostgreSQL restore — verify, decrypt, load into a TARGET database.
#
# Usage:
#   BACKUP_ENCRYPTION_KEY='...' ./infrastructure/scripts/restore.sh \
#       <backup.sql.gz.enc> <target-db>
#
# The target database is created if missing. Restoring into the LIVE
# database requires dropping it first — prefer a disposable target and
# switch over. Steps performed:
#   1. sha256 sidecar verification
#   2. decrypt + gunzip integrity test
#   3. restore with ON_ERROR_STOP=1 (any SQL error aborts)
#   4. post-restore sanity: alembic_version present + row counts
#
# NEVER pass the key as an argv — environment only.

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <backup.sql.gz.enc> <target-db>" >&2
    exit 2
fi

BACKUP="$1"
TARGET_DB="$2"
: "${COMPOSE_FILE:=docker-compose.yml}"
export COMPOSE_FILE
PGUSER="${POSTGRES_USER:-eitop}"

if [ -z "${BACKUP_ENCRYPTION_KEY:-}" ]; then
    echo "BACKUP_ENCRYPTION_KEY must be set in the environment (never argv)." >&2
    exit 2
fi

echo "[1/4] Verifying checksum..."
if [ -f "$BACKUP.sha256" ]; then
    EXPECTED="$(cut -d' ' -f1 "$BACKUP.sha256")"
    ACTUAL="$(openssl dgst -sha256 -r "$BACKUP" | cut -d' ' -f1)"
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "CHECKSUM MISMATCH for $BACKUP" >&2
        echo "  expected: $EXPECTED" >&2
        echo "  actual:   $ACTUAL" >&2
        exit 1
    fi
    echo "checksum OK ($ACTUAL)"
else
    echo "WARNING: no $BACKUP.sha256 sidecar; integrity unverified." >&2
fi

echo "[2/4] Decrypting and testing archive..."
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
    -pass env:BACKUP_ENCRYPTION_KEY -in "$BACKUP" | gzip -t
echo "archive OK"

echo "[3/4] Restoring into database '$TARGET_DB'..."
docker compose exec -T postgres \
    psql -U "$PGUSER" -d postgres -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE \"$TARGET_DB\"" 2>/dev/null || true

openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
    -pass env:BACKUP_ENCRYPTION_KEY -in "$BACKUP" \
    | gunzip \
    | docker compose exec -T postgres \
        psql -U "$PGUSER" -d "$TARGET_DB" -v ON_ERROR_STOP=1 -q

echo "[4/4] Post-restore sanity checks..."
docker compose exec -T postgres \
    psql -U "$PGUSER" -d "$TARGET_DB" -tAc "
        SELECT 'alembic=' || version_num FROM alembic_version;
        SELECT 'users=' || count(*) FROM users;
        SELECT 'endpoints=' || count(*) FROM endpoints;
    "

echo "Restore complete: $TARGET_DB"