"""read-only Active Directory integration (Phase 3.1)

Revision ID: 0005_directory_integration
Revises: 0004_endpoint_health_snapshots
Create Date: 2026-11-19

Changes:
- directory_connections — LDAP connection config (TLS mode restricted to
  ldaps/starttls; bind password stored Fernet-encrypted, never plaintext).
- directory_domains / _ous / _users / _groups / _group_memberships /
  _computers — normalized read-only mirror keyed by (connection_id,
  object_guid); soft-delete via missing_since (never hard-deleted).
- directory_sync_runs — per-category sync results (sanitized JSON) with a
  partial unique index guaranteeing one running run per connection.
- directory_reconciliations — AD computer ↔ endpoint link with explicit
  confidence; unique per computer.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_directory_integration"
down_revision = "0004_endpoint_health_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Connection configuration ------------------------------------------
    op.create_table(
        "directory_connections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("domain_dns", sa.String(255), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("tls_mode", sa.String(16), nullable=False),
        sa.Column("tls_ca_pem", sa.Text(), nullable=True),
        sa.Column("search_base", sa.String(1024), nullable=False),
        sa.Column("bind_username", sa.String(255), nullable=False),
        sa.Column("bind_password_encrypted", sa.Text(), nullable=False),
        sa.Column("connect_timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("search_timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("page_size", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("auto_sync", sa.Boolean(), nullable=False),
        sa.Column("sync_interval_minutes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "tls_mode IN ('ldaps', 'starttls')", name="ck_directory_connections_tls_mode"
        ),
        sa.CheckConstraint(
            "port > 0 AND port <= 65535", name="ck_directory_connections_port"
        ),
        sa.CheckConstraint(
            "page_size >= 1 AND page_size <= 5000",
            name="ck_directory_connections_page_size",
        ),
        sa.CheckConstraint(
            "sync_interval_minutes >= 5", name="ck_directory_connections_interval"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_directory_connections_name"),
    )

    # --- Domains ------------------------------------------------------------
    op.create_table(
        "directory_domains",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("domain_dns", sa.String(255), nullable=False),
        sa.Column("distinguished_name", sa.String(1024), nullable=False),
        sa.Column("sid", sa.String(128), nullable=True),
        sa.Column("functional_level", sa.String(64), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connection_id", "distinguished_name", name="uq_directory_domains_conn_dn"
        ),
    )

    # --- Organizational units ----------------------------------------------
    op.create_table(
        "directory_ous",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("object_guid", sa.String(64), nullable=False),
        sa.Column("distinguished_name", sa.String(1024), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("parent_dn", sa.String(1024), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("missing_since", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_ous_conn_guid"
        ),
    )
    op.create_index(
        "ix_directory_ous_dn", "directory_ous", ["distinguished_name"]
    )

    # --- Users --------------------------------------------------------------
    op.create_table(
        "directory_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("object_guid", sa.String(64), nullable=False),
        sa.Column("distinguished_name", sa.String(1024), nullable=False),
        sa.Column("sid", sa.String(128), nullable=True),
        sa.Column("sam_account_name", sa.String(64), nullable=False),
        sa.Column("user_principal_name", sa.String(256), nullable=True),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("email", sa.String(256), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("department", sa.String(256), nullable=True),
        sa.Column("title", sa.String(256), nullable=True),
        sa.Column("manager_dn", sa.String(1024), nullable=True),
        sa.Column("last_logon_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ad_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ad_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("missing_since", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_users_conn_guid"
        ),
    )
    op.create_index("ix_directory_users_sam", "directory_users", ["sam_account_name"])
    op.create_index("ix_directory_users_upn", "directory_users", ["user_principal_name"])
    op.create_index("ix_directory_users_enabled", "directory_users", ["enabled"])
    op.create_index("ix_directory_users_missing", "directory_users", ["missing_since"])

    # --- Groups -------------------------------------------------------------
    op.create_table(
        "directory_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("object_guid", sa.String(64), nullable=False),
        sa.Column("distinguished_name", sa.String(1024), nullable=False),
        sa.Column("sid", sa.String(128), nullable=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scope", sa.String(16), nullable=True),
        sa.Column("category", sa.String(16), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("missing_since", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "scope IS NULL OR scope IN ('global', 'domain_local', 'universal')",
            name="ck_directory_groups_scope",
        ),
        sa.CheckConstraint(
            "category IS NULL OR category IN ('security', 'distribution')",
            name="ck_directory_groups_category",
        ),
        sa.UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_groups_conn_guid"
        ),
    )
    op.create_index("ix_directory_groups_name", "directory_groups", ["name"])
    op.create_index("ix_directory_groups_missing", "directory_groups", ["missing_since"])

    # --- Computers ----------------------------------------------------------
    op.create_table(
        "directory_computers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("object_guid", sa.String(64), nullable=False),
        sa.Column("distinguished_name", sa.String(1024), nullable=False),
        sa.Column("sid", sa.String(128), nullable=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("dns_hostname", sa.String(256), nullable=True),
        sa.Column("os", sa.String(256), nullable=True),
        sa.Column("os_version", sa.String(128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("last_logon_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ad_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("missing_since", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_computers_conn_guid"
        ),
    )
    op.create_index(
        "ix_directory_computers_dns_hostname", "directory_computers", ["dns_hostname"]
    )
    op.create_index("ix_directory_computers_name", "directory_computers", ["name"])
    op.create_index(
        "ix_directory_computers_missing", "directory_computers", ["missing_since"]
    )

    # --- Group memberships --------------------------------------------------
    op.create_table(
        "directory_group_memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("member_type", sa.String(16), nullable=False),
        sa.Column("member_dn", sa.String(1024), nullable=False),
        sa.Column("member_object_guid", sa.String(64), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "member_type IN ('user', 'group', 'computer', 'unknown')",
            name="ck_directory_group_memberships_member_type",
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["group_id"], ["directory_groups.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "group_id",
            "member_type",
            "member_dn",
            name="uq_directory_group_memberships_group_member",
        ),
    )
    op.create_index(
        "ix_directory_group_memberships_member_guid",
        "directory_group_memberships",
        ["member_object_guid"],
    )

    # --- Sync runs ----------------------------------------------------------
    op.create_table(
        "directory_sync_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("objects_discovered", sa.Integer(), nullable=False),
        sa.Column("objects_created", sa.Integer(), nullable=False),
        sa.Column("objects_updated", sa.Integer(), nullable=False),
        sa.Column("objects_marked_missing", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("errors", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "category_results", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('running', 'success', 'failed')",
            name="ck_directory_sync_runs_status",
        ),
        sa.CheckConstraint(
            "trigger IN ('manual', 'scheduled')",
            name="ck_directory_sync_runs_trigger",
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_directory_sync_runs_conn_started",
        "directory_sync_runs",
        ["connection_id", "started_at"],
    )
    # Single-flight: at most one running sync per connection.
    op.create_index(
        "uq_directory_sync_runs_running",
        "directory_sync_runs",
        ["connection_id"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )

    # --- Reconciliation -----------------------------------------------------
    op.create_table(
        "directory_reconciliations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("computer_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=True),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("candidates", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("reviewed_by", sa.Uuid(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "method IN ('exact_fqdn', 'short_name', 'manual')",
            name="ck_directory_reconciliations_method",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_directory_reconciliations_confidence",
        ),
        sa.CheckConstraint(
            "status IN ('matched', 'needs_review', 'unmatched', 'rejected')",
            name="ck_directory_reconciliations_status",
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["directory_connections.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["computer_id"], ["directory_computers.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("computer_id", name="uq_directory_reconciliations_computer"),
    )
    op.create_index(
        "ix_directory_reconciliations_endpoint",
        "directory_reconciliations",
        ["endpoint_id"],
    )
    op.create_index(
        "ix_directory_reconciliations_status", "directory_reconciliations", ["status"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_directory_reconciliations_status", table_name="directory_reconciliations"
    )
    op.drop_index(
        "ix_directory_reconciliations_endpoint", table_name="directory_reconciliations"
    )
    op.drop_table("directory_reconciliations")
    op.drop_index(
        "uq_directory_sync_runs_running", table_name="directory_sync_runs"
    )
    op.drop_index(
        "ix_directory_sync_runs_conn_started", table_name="directory_sync_runs"
    )
    op.drop_table("directory_sync_runs")
    op.drop_index(
        "ix_directory_group_memberships_member_guid",
        table_name="directory_group_memberships",
    )
    op.drop_table("directory_group_memberships")
    op.drop_index("ix_directory_computers_missing", table_name="directory_computers")
    op.drop_index("ix_directory_computers_name", table_name="directory_computers")
    op.drop_index(
        "ix_directory_computers_dns_hostname", table_name="directory_computers"
    )
    op.drop_table("directory_computers")
    op.drop_index("ix_directory_groups_missing", table_name="directory_groups")
    op.drop_index("ix_directory_groups_name", table_name="directory_groups")
    op.drop_table("directory_groups")
    op.drop_index("ix_directory_users_missing", table_name="directory_users")
    op.drop_index("ix_directory_users_enabled", table_name="directory_users")
    op.drop_index("ix_directory_users_upn", table_name="directory_users")
    op.drop_index("ix_directory_users_sam", table_name="directory_users")
    op.drop_table("directory_users")
    op.drop_index("ix_directory_ous_dn", table_name="directory_ous")
    op.drop_table("directory_ous")
    op.drop_table("directory_domains")
    op.drop_table("directory_connections")
