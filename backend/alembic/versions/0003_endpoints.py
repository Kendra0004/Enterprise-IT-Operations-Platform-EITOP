"""endpoint inventory, grouping, enrollment and agent credentials

Revision ID: 0003_endpoints
Revises: 0002_audit_append_only
Create Date: 2026-11-18

Tables:
- endpoint_groups + endpoint_group_members  (grouping)
- endpoints                                 (inventory core)
- endpoint_metadata                         (hardware/network, 1:1)
- endpoint_facts                            (extensible KV, unique per key)
- endpoint_software                         (packages, unique per endpoint+name)
- enrollment_tokens                         (single-use, hash-only)
- endpoint_credentials                      (agent auth, hash-only)
"""
import sqlalchemy as sa
from alembic import op

revision = "0003_endpoints"
down_revision = "0002_audit_append_only"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "endpoint_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_endpoint_groups_name", "endpoint_groups", ["name"], unique=True
    )

    op.create_table(
        "endpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("fqdn", sa.String(255), nullable=True),
        sa.Column("os", sa.String(64), nullable=False),
        sa.Column("os_version", sa.String(128), nullable=True),
        sa.Column("os_arch", sa.String(32), nullable=True),
        sa.Column("kernel_version", sa.String(64), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("agent_version", sa.String(32), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_endpoints_hostname", "endpoints", ["hostname"])
    op.create_index("ix_endpoints_status", "endpoints", ["status"])
    op.create_index("ix_endpoints_enrolled_at", "endpoints", ["enrolled_at"])
    op.create_index(
        "ix_endpoints_last_heartbeat_at", "endpoints", ["last_heartbeat_at"]
    )
    op.create_check_constraint(
        "ck_endpoints_status", "endpoints", "status IN ('active', 'revoked')"
    )

    op.create_table(
        "endpoint_group_members",
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["endpoint_groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("endpoint_id", "group_id"),
    )

    op.create_table(
        "endpoint_metadata",
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("manufacturer", sa.String(255), nullable=True),
        sa.Column("model", sa.String(255), nullable=True),
        sa.Column("serial_number", sa.String(128), nullable=True),
        sa.Column("cpu_model", sa.String(255), nullable=True),
        sa.Column("cpu_cores", sa.Integer(), nullable=True),
        sa.Column("memory_bytes", sa.BigInteger(), nullable=True),
        sa.Column("disk_bytes", sa.BigInteger(), nullable=True),
        sa.Column("ip_addresses", sa.JSON(), nullable=True),
        sa.Column("mac_addresses", sa.JSON(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("endpoint_id"),
    )
    op.create_index(
        "ix_endpoint_metadata_serial_number",
        "endpoint_metadata",
        ["serial_number"],
    )

    op.create_table(
        "endpoint_facts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint_id", "key", name="uq_endpoint_facts_endpoint_key"),
    )
    op.create_index("ix_endpoint_facts_endpoint_id", "endpoint_facts", ["endpoint_id"])
    op.create_index("ix_endpoint_facts_key", "endpoint_facts", ["key"])

    op.create_table(
        "endpoint_software",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("package_manager", sa.String(32), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "endpoint_id",
            "name",
            "package_manager",
            name="uq_endpoint_software_endpoint_name_manager",
        ),
    )
    op.create_index(
        "ix_endpoint_software_endpoint_id", "endpoint_software", ["endpoint_id"]
    )

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("group_id", sa.Uuid(), nullable=True),
        sa.Column("restrictions", sa.JSON(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["group_id"], ["endpoint_groups.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["consumed_by"], ["endpoints.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_enrollment_tokens_token_hash",
        "enrollment_tokens",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_enrollment_tokens_created_by", "enrollment_tokens", ["created_by"]
    )
    op.create_index("ix_enrollment_tokens_group_id", "enrollment_tokens", ["group_id"])
    op.create_index(
        "ix_enrollment_tokens_expires_at", "enrollment_tokens", ["expires_at"]
    )
    op.create_index(
        "ix_enrollment_tokens_created_at", "enrollment_tokens", ["created_at"]
    )

    op.create_table(
        "endpoint_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("rotated_from", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["rotated_from"], ["endpoint_credentials.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_endpoint_credentials_token_hash",
        "endpoint_credentials",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_endpoint_credentials_endpoint_id",
        "endpoint_credentials",
        ["endpoint_id"],
    )


def downgrade() -> None:
    op.drop_table("endpoint_credentials")
    op.drop_table("enrollment_tokens")
    op.drop_table("endpoint_software")
    op.drop_table("endpoint_facts")
    op.drop_table("endpoint_metadata")
    op.drop_table("endpoint_group_members")
    op.drop_table("endpoints")
    op.drop_table("endpoint_groups")
