"""directory security findings (Phase 3.2.1)

Revision ID: 0007_directory_findings
Revises: 0006_directory_sync_ownership
Create Date: 2026-11-23

Changes:
- directory_findings — app-derived security findings over the read-only
  mirror: deterministic bounded fingerprint (unique per connection),
  severity/status/subject lifecycle, recurrence counter, evidence JSONB.
- ``subject_dn`` is NULL **iff** ``subject_type='connection'`` (CHECK);
  object-level findings must carry their DN as stable identity.
- Additive only: no existing table, column, or constraint is modified.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007_directory_findings"
down_revision = "0006_directory_sync_ownership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "directory_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(160), nullable=False),
        sa.Column("rule_key", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("subject_type", sa.String(16), nullable=False),
        sa.Column("access", sa.String(10), nullable=True),
        sa.Column("subject_guid", sa.String(64), nullable=True),
        sa.Column("subject_dn", sa.String(1024), nullable=True),
        sa.Column("subject_name", sa.String(256), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopen_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppressed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["acknowledged_by"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["directory_connections.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_directory_findings_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open','acknowledged','suppressed','resolved')",
            name="ck_directory_findings_status",
        ),
        sa.CheckConstraint(
            "subject_type IN ('user','group','computer','unknown','connection')",
            name="ck_directory_findings_subject_type",
        ),
        sa.CheckConstraint(
            "access IS NULL OR access IN ('direct','transitive')",
            name="ck_directory_findings_access",
        ),
        sa.CheckConstraint(
            "(subject_type = 'connection' AND subject_dn IS NULL "
            "AND subject_guid IS NULL) "
            "OR (subject_type <> 'connection' AND subject_dn IS NOT NULL)",
            name="ck_directory_findings_subject",
        ),
        sa.UniqueConstraint(
            "connection_id", "fingerprint", name="uq_directory_findings_conn_fp"
        ),
    )
    op.create_index(
        "ix_directory_findings_conn_status",
        "directory_findings",
        ["connection_id", "status"],
    )
    op.create_index(
        "ix_directory_findings_conn_severity",
        "directory_findings",
        ["connection_id", "severity"],
    )
    op.create_index("ix_directory_findings_rule", "directory_findings", ["rule_key"])
    op.create_index(
        "ix_directory_findings_subject", "directory_findings", ["subject_guid"]
    )


def downgrade() -> None:
    op.drop_index("ix_directory_findings_subject", table_name="directory_findings")
    op.drop_index("ix_directory_findings_rule", table_name="directory_findings")
    op.drop_index("ix_directory_findings_conn_severity", table_name="directory_findings")
    op.drop_index("ix_directory_findings_conn_status", table_name="directory_findings")
    op.drop_table("directory_findings")
