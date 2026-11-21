"""Active Directory integration models (Phase 3.1) — READ-ONLY mirror.

Design notes:
- These tables are a local, read-only mirror of a remote directory. The
  only writes against Active Directory that exist are LDAP *reads*; nothing
  in this module ever issues a directory modification.
- Stable identity: every directory object is keyed uniquely by
  (connection_id, object_guid) — AD objectGUID + connection identity.
  sAMAccountName/displayName are attributes, never keys.
- Missing-object handling is soft: ``missing_since`` is set only by a
  fully-successful sync run after a grace period; rows are never hard
  deleted by the sync engine (history preserved).
- Bind secrets live ONLY in ``directory_connections.bind_password_encrypted``
  (Fernet, keyed from SECRET_KEY) and are never exposed through ORM
  ``repr``/serialization paths.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# --- Enumerated values (CHECK-constrained in the database) ------------------
DIRECTORY_TLS_LDAPS = "ldaps"
DIRECTORY_TLS_STARTTLS = "starttls"
DIRECTORY_TLS_MODES = (DIRECTORY_TLS_LDAPS, DIRECTORY_TLS_STARTTLS)

SYNC_RUNNING = "running"
SYNC_SUCCESS = "success"
SYNC_FAILED = "failed"
SYNC_STATUSES = (SYNC_RUNNING, SYNC_SUCCESS, SYNC_FAILED)

SYNC_TRIGGER_MANUAL = "manual"
SYNC_TRIGGER_SCHEDULED = "scheduled"
SYNC_TRIGGERS = (SYNC_TRIGGER_MANUAL, SYNC_TRIGGER_SCHEDULED)

GROUP_SCOPE_GLOBAL = "global"
GROUP_SCOPE_DOMAIN_LOCAL = "domain_local"
GROUP_SCOPE_UNIVERSAL = "universal"
GROUP_SCOPES = (GROUP_SCOPE_GLOBAL, GROUP_SCOPE_DOMAIN_LOCAL, GROUP_SCOPE_UNIVERSAL)

GROUP_CATEGORY_SECURITY = "security"
GROUP_CATEGORY_DISTRIBUTION = "distribution"
GROUP_CATEGORIES = (GROUP_CATEGORY_SECURITY, GROUP_CATEGORY_DISTRIBUTION)

MEMBER_USER = "user"
MEMBER_GROUP = "group"
MEMBER_COMPUTER = "computer"
MEMBER_TYPES = (MEMBER_USER, MEMBER_GROUP, MEMBER_COMPUTER)

RECON_EXACT_FQDN = "exact_fqdn"
RECON_SHORT_NAME = "short_name"
RECON_MANUAL = "manual"
RECON_METHODS = (RECON_EXACT_FQDN, RECON_SHORT_NAME, RECON_MANUAL)

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
RECON_CONFIDENCES = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)

RECON_MATCHED = "matched"
RECON_NEEDS_REVIEW = "needs_review"
RECON_UNMATCHED = "unmatched"
RECON_REJECTED = "rejected"
RECON_STATUSES = (
    RECON_MATCHED,
    RECON_NEEDS_REVIEW,
    RECON_UNMATCHED,
    RECON_REJECTED,
)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid.uuid4)


def _now() -> datetime:
    return datetime.now(UTC)


class DirectoryConnection(Base):
    """One configured LDAP connection to a domain controller."""

    __tablename__ = "directory_connections"
    __table_args__ = (
        CheckConstraint(
            "tls_mode IN ('ldaps', 'starttls')", name="ck_directory_connections_tls_mode"
        ),
        CheckConstraint("port > 0 AND port <= 65535", name="ck_directory_connections_port"),
        CheckConstraint(
            "page_size >= 1 AND page_size <= 5000",
            name="ck_directory_connections_page_size",
        ),
        CheckConstraint(
            "sync_interval_minutes >= 5", name="ck_directory_connections_interval"
        ),
        UniqueConstraint("name", name="uq_directory_connections_name"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128))
    domain_dns: Mapped[str] = mapped_column(String(255))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=636)
    tls_mode: Mapped[str] = mapped_column(String(16), default=DIRECTORY_TLS_LDAPS)
    # Optional PEM CA bundle for enterprise CAs. Never secret.
    tls_ca_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    search_base: Mapped[str] = mapped_column(String(1024))
    bind_username: Mapped[str] = mapped_column(String(255))
    # Fernet token — decrypted only inside the LDAP client at bind time.
    # Excluded from every response schema; never logged or audited.
    bind_password_encrypted: Mapped[str] = mapped_column(Text)
    connect_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    search_timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    page_size: Mapped[int] = mapped_column(Integer, default=500)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_sync: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        # Deliberately omits bind material.
        return f"<DirectoryConnection {self.name} {self.host}:{self.port} {self.tls_mode}>"


class DirectoryDomain(Base):
    """Discovered domain information for a connection."""

    __tablename__ = "directory_domains"
    __table_args__ = (
        UniqueConstraint(
            "connection_id", "distinguished_name", name="uq_directory_domains_conn_dn"
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    domain_dns: Mapped[str] = mapped_column(String(255))
    distinguished_name: Mapped[str] = mapped_column(String(1024))
    sid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    functional_level: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DirectoryOrganizationalUnit(Base):
    """Organizational unit (objectGUID-keyed per connection)."""

    __tablename__ = "directory_ous"
    __table_args__ = (
        UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_ous_conn_guid"
        ),
        Index("ix_directory_ous_dn", "distinguished_name"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    object_guid: Mapped[str] = mapped_column(String(64))
    distinguished_name: Mapped[str] = mapped_column(String(1024))
    name: Mapped[str] = mapped_column(String(256))
    parent_dn: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    missing_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DirectoryUser(Base):
    """AD user account (read-only mirror)."""

    __tablename__ = "directory_users"
    __table_args__ = (
        UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_users_conn_guid"
        ),
        Index("ix_directory_users_sam", "sam_account_name"),
        Index("ix_directory_users_upn", "user_principal_name"),
        Index("ix_directory_users_enabled", "enabled"),
        Index("ix_directory_users_missing", "missing_since"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    object_guid: Mapped[str] = mapped_column(String(64))
    distinguished_name: Mapped[str] = mapped_column(String(1024))
    sid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sam_account_name: Mapped[str] = mapped_column(String(64))
    user_principal_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    department: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str | None] = mapped_column(String(256), nullable=True)
    manager_dn: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_logon_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ad_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ad_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    missing_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DirectoryGroup(Base):
    """AD security/distribution group (read-only mirror)."""

    __tablename__ = "directory_groups"
    __table_args__ = (
        UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_groups_conn_guid"
        ),
        CheckConstraint(
            "scope IS NULL OR scope IN ('global', 'domain_local', 'universal')",
            name="ck_directory_groups_scope",
        ),
        CheckConstraint(
            "category IS NULL OR category IN ('security', 'distribution')",
            name="ck_directory_groups_category",
        ),
        Index("ix_directory_groups_name", "name"),
        Index("ix_directory_groups_missing", "missing_since"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    object_guid: Mapped[str] = mapped_column(String(64))
    distinguished_name: Mapped[str] = mapped_column(String(1024))
    sid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[str | None] = mapped_column(String(16), nullable=True)
    category: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    missing_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DirectoryGroupMembership(Base):
    """Group → member edge.

    The member side is polymorphic (user|group|computer|unknown) and
    identified by (member_type, member_dn, member_object_guid): members can
    be foreign security principals (e.g. well-known SIDs, other domains)
    or objects not present in the local mirror — ``unknown`` covers those
    honestly instead of guessing a type, and a cross-table FK would be
    wrong. Referential integrity is kept on the group side (CASCADE).
    Members that DO exist locally are resolved at read time in batched
    queries (no N+1).
    """

    __tablename__ = "directory_group_memberships"
    __table_args__ = (
        UniqueConstraint(
            "group_id", "member_type", "member_dn",
            name="uq_directory_group_memberships_group_member",
        ),
        CheckConstraint(
            "member_type IN ('user', 'group', 'computer', 'unknown')",
            name="ck_directory_group_memberships_member_type",
        ),
        Index(
            "ix_directory_group_memberships_member_guid", "member_object_guid"
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_groups.id", ondelete="CASCADE")
    )
    member_type: Mapped[str] = mapped_column(String(16))
    member_dn: Mapped[str] = mapped_column(String(1024))
    # Resolvable members carry their objectGUID; foreign/unresolved
    # principals leave this NULL (the DN remains the join key).
    member_object_guid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DirectoryComputer(Base):
    """AD computer account (read-only mirror)."""

    __tablename__ = "directory_computers"
    __table_args__ = (
        UniqueConstraint(
            "connection_id", "object_guid", name="uq_directory_computers_conn_guid"
        ),
        Index("ix_directory_computers_dns_hostname", "dns_hostname"),
        Index("ix_directory_computers_name", "name"),
        Index("ix_directory_computers_missing", "missing_since"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    object_guid: Mapped[str] = mapped_column(String(64))
    distinguished_name: Mapped[str] = mapped_column(String(1024))
    sid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name: Mapped[str] = mapped_column(String(64))
    dns_hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    os: Mapped[str | None] = mapped_column(String(256), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_logon_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ad_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    missing_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DirectorySyncRun(Base):
    """One synchronization execution with per-category results.

    ``category_results`` (JSON) tracks domains/ous/users/groups/computers/
    memberships/missing_scan status + sanitized error labels only — never
    raw exception content, credentials, or directory attribute payloads.
    A partial unique index guarantees at most one ``running`` row per
    connection (single-flight at the database level).
    """

    __tablename__ = "directory_sync_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'success', 'failed')",
            name="ck_directory_sync_runs_status",
        ),
        CheckConstraint(
            "trigger IN ('manual', 'scheduled')",
            name="ck_directory_sync_runs_trigger",
        ),
        Index("ix_directory_sync_runs_conn_started", "connection_id", "started_at"),
        Index(
            "uq_directory_sync_runs_running",
            "connection_id",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), default=SYNC_RUNNING)
    trigger: Mapped[str] = mapped_column(String(16), default=SYNC_TRIGGER_MANUAL)
    objects_discovered: Mapped[int] = mapped_column(Integer, default=0)
    objects_created: Mapped[int] = mapped_column(Integer, default=0)
    objects_updated: Mapped[int] = mapped_column(Integer, default=0)
    objects_marked_missing: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Sanitized list of {category, label, error_count} — see errors.py.
    errors: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # Per-category status map (see sync_engine.CATEGORIES).
    category_results: Mapped[dict] = mapped_column(JSONB, default=dict)


class DirectoryReconciliation(Base):
    """AD computer ↔ EITOP endpoint link with explicit confidence.

    Created by the sync engine only for exact-FQDN matches against a
    UNIQUE endpoint FQDN (high confidence) or as candidates
    (needs_review). Short-hostname matches are NEVER auto-confirmed.
    Manual decisions are audited and not overwritten by later runs.
    """

    __tablename__ = "directory_reconciliations"
    __table_args__ = (
        UniqueConstraint("computer_id", name="uq_directory_reconciliations_computer"),
        CheckConstraint(
            "method IN ('exact_fqdn', 'short_name', 'manual')",
            name="ck_directory_reconciliations_method",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_directory_reconciliations_confidence",
        ),
        CheckConstraint(
            "status IN ('matched', 'needs_review', 'unmatched', 'rejected')",
            name="ck_directory_reconciliations_status",
        ),
        Index("ix_directory_reconciliations_endpoint", "endpoint_id"),
        Index("ix_directory_reconciliations_status", "status"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_connections.id", ondelete="CASCADE")
    )
    computer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("directory_computers.id", ondelete="CASCADE")
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=True
    )
    method: Mapped[str] = mapped_column(String(16), default=RECON_SHORT_NAME)
    confidence: Mapped[str] = mapped_column(String(8), default=CONFIDENCE_LOW)
    status: Mapped[str] = mapped_column(String(16), default=RECON_UNMATCHED)
    # Candidate endpoint UUIDs presented for manual review (uuids only).
    candidates: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
