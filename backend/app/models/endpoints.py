"""Endpoint inventory, grouping, enrollment, agent credential and snapshot models (Phase 2).

Design notes:
- ``EndpointMetadata`` is 1:1 hardware/network identity (upserted, never
  duplicated per submission) — this is the "current state" layer.
- ``EndpointFact`` is an extensible key/value store for inventory attributes
  that do not deserve a column yet (uptime, filesystem usage, distribution).
- ``EndpointSoftware`` holds package rows keyed uniquely per endpoint so
  repeated submissions update instead of duplicating rows — current software
  state for fast detail reads.
- ``EndpointSnapshot`` (Phase 2.6) is the immutable history layer: one row
  per DISTINCT inventory submission (content-hash deduplicated) storing the
  report sections as JSONB. Packages are NOT duplicated inside the JSONB —
  they live in normalized ``endpoint_snapshot_software`` rows keyed by
  (snapshot, name, manager) so software history stays SQL-queryable without
  storing the package list twice.
- Current-state tables are overwritten in place; snapshots are never mutated
  after insert (append-only history).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

# Endpoint lifecycle states (CHECK-constrained in the database).
ENDPOINT_ACTIVE = "active"
ENDPOINT_OFFLINE = "offline"
ENDPOINT_REVOKED = "revoked"
ENDPOINT_STATUSES = (ENDPOINT_ACTIVE, ENDPOINT_OFFLINE, ENDPOINT_REVOKED)

# Audit/agent action sources for facts.
SOURCE_COLLECTOR = "collector"
SOURCE_MANUAL = "manual"

# Inventory payload schema version recorded on every snapshot. Bumped only on
# incompatible report-shape changes; agents may send their own value.
INVENTORY_SCHEMA_VERSION = 1


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid.uuid4)


def _now() -> datetime:
    return datetime.now(UTC)


# --- Association tables -----------------------------------------------------

endpoint_group_members = Table(
    "endpoint_group_members",
    Base.metadata,
    Column(
        "endpoint_id",
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "group_id",
        ForeignKey("endpoint_groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


# --- Models -----------------------------------------------------------------


class EndpointGroup(Base):
    """Named group for organizing endpoints (assignment, reporting scope)."""

    __tablename__ = "endpoint_groups"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    endpoints: Mapped[list[Endpoint]] = relationship(
        secondary=endpoint_group_members, back_populates="groups"
    )


class Endpoint(Base):
    """A managed machine. Identity comes from enrollment, never from
    agent-supplied hostname/MAC/serial (those are descriptive only)."""

    __tablename__ = "endpoints"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'offline', 'revoked')",
            name="ck_endpoints_status",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str] = mapped_column(String(64), default="linux")
    os_version: Mapped[str | None] = mapped_column(String(128))
    os_arch: Mapped[str | None] = mapped_column(String(32))
    kernel_version: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default=ENDPOINT_ACTIVE, index=True)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    # Timestamp of the most recent accepted inventory submission (nullable:
    # an endpoint may heartbeat before its first inventory arrives).
    last_inventory_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    groups: Mapped[list[EndpointGroup]] = relationship(
        secondary=endpoint_group_members, back_populates="endpoints", lazy="selectin"
    )
    metadata_row: Mapped[EndpointMetadata | None] = relationship(
        back_populates="endpoint",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    facts: Mapped[list[EndpointFact]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan", lazy="noload"
    )
    software: Mapped[list[EndpointSoftware]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan", lazy="noload"
    )
    credentials: Mapped[list[EndpointCredential]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan", lazy="noload"
    )


class EndpointMetadata(Base):
    """Hardware and network identity. One row per endpoint (upserted)."""

    __tablename__ = "endpoint_metadata"

    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), primary_key=True
    )
    manufacturer: Mapped[str | None] = mapped_column(String(255))
    model: Mapped[str | None] = mapped_column(String(255))
    serial_number: Mapped[str | None] = mapped_column(String(128), index=True)
    cpu_model: Mapped[str | None] = mapped_column(String(255))
    cpu_cores: Mapped[int | None] = mapped_column(Integer)
    memory_bytes: Mapped[int | None] = mapped_column(BigInteger)
    disk_bytes: Mapped[int | None] = mapped_column(BigInteger)
    ip_addresses: Mapped[list | None] = mapped_column(JSON)  # list[str]
    mac_addresses: Mapped[list | None] = mapped_column(JSON)  # list[str]
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    endpoint: Mapped[Endpoint] = relationship(back_populates="metadata_row")


class EndpointFact(Base):
    """Extensible inventory fact: one value per (endpoint, key).

    Upsert semantics keep submissions idempotent (no duplicate rows).
    """

    __tablename__ = "endpoint_facts"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "key", name="uq_endpoint_facts_endpoint_key"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    key: Mapped[str] = mapped_column(String(128), index=True)
    value: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(64), default=SOURCE_COLLECTOR)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    endpoint: Mapped[Endpoint] = relationship(back_populates="facts")


class EndpointSoftware(Base):
    """Installed package row. Unique per (endpoint, name, manager) so repeat
    submissions update versions instead of duplicating rows."""

    __tablename__ = "endpoint_software"
    __table_args__ = (
        UniqueConstraint(
            "endpoint_id",
            "name",
            "package_manager",
            name="uq_endpoint_software_endpoint_name_manager",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(128), default="")
    package_manager: Mapped[str] = mapped_column(String(32), default="unknown")
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

    endpoint: Mapped[Endpoint] = relationship(back_populates="software")


class EnrollmentToken(Base):
    """Single-use, expiring enrollment token. Only the SHA-256 digest is
    stored; the raw value is shown to the administrator exactly once."""

    __tablename__ = "enrollment_tokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoint_groups.id", ondelete="SET NULL"), index=True
    )
    # Optional enrollment restrictions, e.g.
    # {"allowed_hostname_patterns": ["*.example.com"]}. Enforced at enroll.
    restrictions: Mapped[dict | None] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )


class EndpointCredential(Base):
    """Agent authentication credential bound to exactly one endpoint.

    Stores only the SHA-256 digest. Never returned after issuance; revocation
    (``revoked_at``) takes effect on the next request because authentication
    checks it every time.
    """

    __tablename__ = "endpoint_credentials"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    rotated_from: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoint_credentials.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    endpoint: Mapped[Endpoint] = relationship(back_populates="credentials")


class EndpointSnapshot(Base):
    """Immutable inventory history row (Phase 2.6).

    One row per distinct inventory submission, identified by
    ``(endpoint_id, content_hash)`` — an identical resubmission (network
    retry, collector rerun with no state change) does NOT create a second
    snapshot. Rows are never updated or deleted by application code
    (retention pruning is an explicit, off-by-default background job).

    The payload sections are stored as JSONB for exact historical fidelity;
    packages are normalized into ``endpoint_snapshot_software`` instead of
    being duplicated here (see module docstring).
    """

    __tablename__ = "endpoint_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "endpoint_id",
            "content_hash",
            name="uq_endpoint_snapshots_endpoint_content",
        ),
        # List/history queries are always endpoint-scoped and time-ordered.
        Index("ix_endpoint_snapshots_endpoint_received", "endpoint_id", "received_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    # Agent-side collection time when supplied; falls back to received_at
    # (current collectors do not send one — documented behavior).
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )
    agent_version: Mapped[str | None] = mapped_column(String(32))
    schema_version: Mapped[int] = mapped_column(Integer, default=INVENTORY_SCHEMA_VERSION)
    content_hash: Mapped[str] = mapped_column(String(64))

    # Report sections (exact historical copy; null = not reported).
    # JSONB sections; absent optional sections are stored as SQL NULL
    # (none_as_null) so "no hardware reported" is distinguishable in SQL.
    system: Mapped[dict] = mapped_column(JSONB)
    hardware: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    network: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    filesystems: Mapped[list] = mapped_column(JSONB, default=list)
    facts: Mapped[dict] = mapped_column(JSONB, default=dict)

    endpoint: Mapped[Endpoint] = relationship()


class EndpointSnapshotSoftware(Base):
    """Normalized package row for one snapshot.

    Composite primary key (snapshot_id, name, package_manager) makes package
    insertion idempotent by construction and keeps a single copy of each
    package list (the snapshot JSONB deliberately excludes it).
    """

    __tablename__ = "endpoint_snapshot_software"

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoint_snapshots.id", ondelete="CASCADE"), primary_key=True
    )
    name: Mapped[str] = mapped_column(String(255), primary_key=True)
    package_manager: Mapped[str] = mapped_column(String(32), primary_key=True)
    version: Mapped[str] = mapped_column(String(128), default="")

    __table_args__ = (
        # Supports "history of package X across snapshots" without scanning
        # by snapshot first.
        Index("ix_endpoint_snapshot_software_name", "name"),
    )
