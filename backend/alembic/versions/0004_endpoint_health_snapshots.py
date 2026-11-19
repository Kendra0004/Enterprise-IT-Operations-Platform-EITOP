"""endpoint health states and immutable inventory snapshots

Revision ID: 0004_endpoint_health_snapshots
Revises: 0003_endpoints
Create Date: 2026-11-18

Changes:
- endpoints.status CHECK gains 'offline' (heartbeat health state; 'revoked'
  stays terminal) — no rows are rewritten, existing values remain valid.
- endpoints.last_inventory_at (nullable) — most recent accepted inventory.
- endpoint_snapshots — immutable per-submission history, unique per
  (endpoint_id, content_hash) so identical resubmissions never duplicate.
- endpoint_snapshot_software — normalized package rows per snapshot
  (composite PK), keeping package history SQL-queryable without storing the
  package list twice.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_endpoint_health_snapshots"
down_revision = "0003_endpoints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Endpoint health ---------------------------------------------------
    op.drop_constraint("ck_endpoints_status", "endpoints", type_="check")
    op.create_check_constraint(
        "ck_endpoints_status",
        "endpoints",
        "status IN ('active', 'offline', 'revoked')",
    )
    op.add_column(
        "endpoints",
        sa.Column("last_inventory_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- Immutable inventory snapshots ------------------------------------
    op.create_table(
        "endpoint_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_version", sa.String(32), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("system", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "hardware", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("network", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "filesystems", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("facts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "endpoint_id", "content_hash", name="uq_endpoint_snapshots_endpoint_content"
        ),
    )
    op.create_index(
        "ix_endpoint_snapshots_endpoint_id", "endpoint_snapshots", ["endpoint_id"]
    )
    op.create_index(
        "ix_endpoint_snapshots_received_at", "endpoint_snapshots", ["received_at"]
    )
    # Composite index matches the endpoint-scoped, time-ordered list queries.
    op.create_index(
        "ix_endpoint_snapshots_endpoint_received",
        "endpoint_snapshots",
        ["endpoint_id", "received_at"],
    )

    op.create_table(
        "endpoint_snapshot_software",
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("package_manager", sa.String(32), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.ForeignKeyConstraint(
            ["snapshot_id"], ["endpoint_snapshots.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("snapshot_id", "name", "package_manager"),
    )
    op.create_index(
        "ix_endpoint_snapshot_software_name",
        "endpoint_snapshot_software",
        ["name"],
    )


def downgrade() -> None:
    op.drop_table("endpoint_snapshot_software")
    op.drop_table("endpoint_snapshots")
    op.drop_column("endpoints", "last_inventory_at")
    op.drop_constraint("ck_endpoints_status", "endpoints", type_="check")
    op.create_check_constraint(
        "ck_endpoints_status", "endpoints", "status IN ('active', 'revoked')"
    )
