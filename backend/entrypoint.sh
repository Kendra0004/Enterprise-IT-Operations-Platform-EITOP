#!/bin/sh
# Container entrypoint: migrate, seed, then run the given command.
# - No command (API service): serve the FastAPI app.
# - Command given (worker/beat): run it instead — periodic tasks only
#   execute if the Celery process actually starts.
set -e

echo "Running database migrations..."
alembic upgrade head

echo "Seeding RBAC (idempotent)..."
python -m app.db.seed

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

echo "Starting API server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
