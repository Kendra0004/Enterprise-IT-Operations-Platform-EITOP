"""directory sync run ownership — execution token + lease (Phase 3.1.1)

Revision ID: 0006_directory_sync_ownership
Revises: 0005_directory_integration
Create Date: 2026-11-21

Changes:
- directory_sync_runs.execution_token — opaque per-run claim token set
  atomically by the executing worker; exactly one live owner per run
  (duplicate Celery deliveries lose the claim and skip).
- directory_sync_runs.lease_expires_at — renewable ownership lease. The
  stale reaper only collects runs whose lease expired, that were never
  claimed and aged past the fallback threshold, or that exceeded the
  absolute maximum sync duration; a live lease spares an active worker.
"""
import sqlalchemy as sa
from alembic import op

revision = "0006_directory_sync_ownership"
down_revision = "0005_directory_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "directory_sync_runs",
        sa.Column("execution_token", sa.String(64), nullable=True),
    )
    op.add_column(
        "directory_sync_runs",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("directory_sync_runs", "lease_expires_at")
    op.drop_column("directory_sync_runs", "execution_token")
