#!/bin/sh
# Container entrypoint: migrate, seed, serve.
set -e

echo "Running database migrations..."
alembic upgrade head

echo "Seeding RBAC (idempotent)..."
python -m app.db.seed

echo "Starting API server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
