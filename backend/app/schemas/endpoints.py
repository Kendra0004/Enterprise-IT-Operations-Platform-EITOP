"""Pydantic schemas for the endpoints/agent API (Phase 2).

Conventions:
- ``extra="forbid"`` on agent-supplied payloads: clients cannot smuggle
  fields the server does not model (e.g. a forged ``endpoint_id``).
- No schema ever echoes a credential except the single issuance response.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --- Shared -----------------------------------------------------------------


class MetadataOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    manufacturer: str | None = None
    model: str | None = None
    serial_number: str | None = None
    cpu_model: str | None = None
    cpu_cores: int | None = None
    memory_bytes: int | None = None
    disk_bytes: int | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    updated_at: datetime | None = None


class FactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: str
    source: str
    collected_at: datetime


class SoftwareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    version: str
    package_manager: str
    collected_at: datetime


class EndpointOut(BaseModel):
    """List-row shape. Never contains credential material."""

    id: uuid.UUID
    hostname: str
    fqdn: str | None = None
    os: str
    os_version: str | None = None
    os_arch: str | None = None
    kernel_version: str | None = None
    status: str
    agent_version: str | None = None
    enrolled_at: datetime
    last_heartbeat_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    groups: list[str] = Field(default_factory=list)
    # Reported IPs from the last inventory (empty when none reported).
    ip_addresses: list[str] = Field(default_factory=list)
    # Last successful inventory submission (Phase 2.8 table column).
    last_inventory_at: datetime | None = None


class EndpointDetailOut(EndpointOut):
    """Detail shape: adds hardware, facts and package count (still no
    credential material)."""

    metadata: MetadataOut | None = None
    facts: list[FactOut] = Field(default_factory=list)
    software_count: int = 0


# --- Health (Phase 2.5) -----------------------------------------------------


class EndpointHealthOut(BaseModel):
    """Health snapshot for one endpoint. Read-time derived values are
    computed from UTC timestamps even between background scans."""

    endpoint_id: uuid.UUID
    status: str  # persisted lifecycle: active | offline | revoked
    collector_status: str  # derived: healthy | late | offline | pending | revoked
    last_heartbeat_at: datetime | None = None
    last_inventory_at: datetime | None = None
    seconds_since_heartbeat: int | None = None
    agent_version: str | None = None
    heartbeat_interval_seconds: int
    offline_threshold_seconds: int
    server_time: datetime


class OverviewStatsOut(BaseModel):
    """Aggregate counters for the endpoint overview page (real data only)."""

    total: int
    active: int
    offline: int
    revoked: int
    windows: int
    linux: int
    other_os: int
    # Endpoints that submitted at least one inventory (last_inventory_at set).
    # Powers the dashboard's inventory-collection-health indicator.
    inventory_reported: int = 0
    latest_enrollments: list[EndpointOut] = Field(default_factory=list)


# --- Inventory snapshots (Phase 2.6) ---------------------------------------


class SnapshotOut(BaseModel):
    """Snapshot list row — summary only, no full payload."""

    id: uuid.UUID
    endpoint_id: uuid.UUID
    collected_at: datetime
    received_at: datetime
    agent_version: str | None = None
    schema_version: int
    package_count: int = 0
    fact_count: int = 0
    has_hardware: bool = False
    has_network: bool = False


class SnapshotSoftwareOut(BaseModel):
    name: str
    version: str
    package_manager: str
    previous_version: str | None = None  # set on changed_packages diffs


class HardwareChangeOut(BaseModel):
    field: str
    before: object = None
    after: object = None


class SnapshotDiffOut(BaseModel):
    """Comparison of two snapshots of the SAME endpoint (compare_to → id)."""

    base_snapshot_id: uuid.UUID
    target_snapshot_id: uuid.UUID
    added_packages: list[SnapshotSoftwareOut] = Field(default_factory=list)
    removed_packages: list[SnapshotSoftwareOut] = Field(default_factory=list)
    changed_packages: list[SnapshotSoftwareOut] = Field(default_factory=list)
    hardware_changes: list[HardwareChangeOut] = Field(default_factory=list)


class SnapshotDetailOut(SnapshotOut):
    system: dict
    hardware: dict | None = None
    network: dict | None = None
    filesystems: list[dict] = Field(default_factory=list)
    facts: dict[str, str] = Field(default_factory=dict)
    packages: list[SnapshotSoftwareOut] = Field(default_factory=list)
    changes: SnapshotDiffOut | None = None  # present only with compare_to


class SoftwareHistoryOut(BaseModel):
    """One package row as seen in one snapshot (view=history)."""

    snapshot_id: uuid.UUID
    collected_at: datetime
    name: str
    version: str
    package_manager: str


class NetworkHistoryOut(BaseModel):
    """Network state as reported by one snapshot."""

    snapshot_id: uuid.UUID
    collected_at: datetime
    network: dict | None = None


# --- Administrator schemas --------------------------------------------------


class RestrictionsIn(BaseModel):
    """Optional enrollment restrictions carried by a token."""

    model_config = ConfigDict(extra="forbid")

    allowed_hostname_patterns: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("allowed_hostname_patterns")
    @classmethod
    def _clean_patterns(cls, v: list[str]) -> list[str]:
        out = []
        for pattern in v:
            pattern = pattern.strip().lower()
            if not pattern or len(pattern) > 255:
                raise ValueError("invalid hostname pattern")
            out.append(pattern)
        return out


class EnrollmentTokenCreate(BaseModel):
    expires_in_minutes: int = Field(default=60, ge=1, le=60 * 24 * 14)
    group_id: uuid.UUID | None = None
    restrictions: RestrictionsIn | None = None


class EnrollmentTokenOut(BaseModel):
    """Token metadata for listings. Deliberately has no token value."""

    id: uuid.UUID
    expires_at: datetime
    used_at: datetime | None = None
    group_id: uuid.UUID | None = None
    created_at: datetime
    consumed_by: uuid.UUID | None = None


class EnrollmentTokenCreatedOut(EnrollmentTokenOut):
    """Single issuance response — the ONLY place the raw token appears."""

    token: str


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)


class GroupOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    created_at: datetime
    updated_at: datetime
    endpoint_count: int = 0


class GroupDetailOut(GroupOut):
    """Group with its member endpoints (group details page)."""

    members: list[EndpointOut] = Field(default_factory=list)


class EndpointRevokeOut(BaseModel):
    id: uuid.UUID
    status: str
    revoked_credentials: int


class CredentialRotateOut(BaseModel):
    """The rotated credential — returned exactly once, never again."""

    endpoint_id: uuid.UUID
    credential: str
    issued_at: datetime


# --- Agent schemas ----------------------------------------------------------


class HardwareReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manufacturer: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=255)
    serial_number: str | None = Field(default=None, max_length=128)
    cpu_model: str | None = Field(default=None, max_length=255)
    cpu_cores: int | None = Field(default=None, ge=0, le=1024)
    memory_bytes: int | None = Field(default=None, ge=0)
    disk_bytes: int | None = Field(default=None, ge=0)


class NetworkInterfaceReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    mac: str | None = Field(default=None, max_length=32)
    ipv4: list[str] = Field(default_factory=list, max_length=64)
    ipv6: list[str] = Field(default_factory=list, max_length=64)
    is_up: bool = False


class NetworkReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interfaces: list[NetworkInterfaceReport] = Field(default_factory=list, max_length=64)
    ip_addresses: list[str] = Field(default_factory=list, max_length=128)
    mac_addresses: list[str] = Field(default_factory=list, max_length=64)


class FilesystemReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mount: str = Field(min_length=1, max_length=4096)
    fstype: str = Field(default="", max_length=64)
    total_bytes: int = Field(default=0, ge=0)
    used_bytes: int = Field(default=0, ge=0)


class SystemReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    os: str = Field(default="linux", max_length=64)
    distribution: str | None = Field(default=None, max_length=128)
    distribution_version: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    os_arch: str | None = Field(default=None, max_length=32)
    kernel: str | None = Field(default=None, max_length=64)
    uptime_seconds: int | None = Field(default=None, ge=0)


class PackageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    version: str = Field(default="", max_length=128)
    package_manager: str = Field(default="unknown", max_length=32)


class AgentEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=16, max_length=512)
    hostname: str = Field(min_length=1, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    os: str = Field(default="linux", max_length=64)
    os_version: str | None = Field(default=None, max_length=128)
    os_arch: str | None = Field(default=None, max_length=32)
    kernel_version: str | None = Field(default=None, max_length=64)
    agent_version: str | None = Field(default=None, max_length=32)


class AgentEnrollOut(BaseModel):
    endpoint_id: uuid.UUID
    credential: str  # raw value — issued exactly once
    issued_at: datetime


class AgentHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_version: str | None = Field(default=None, max_length=32)


class AgentHeartbeatOut(BaseModel):
    endpoint_id: uuid.UUID
    status: str
    server_time: datetime


class AgentInventoryRequest(BaseModel):
    """Full inventory submission. No endpoint identifier anywhere: the
    endpoint is derived exclusively from the authenticated credential."""

    model_config = ConfigDict(extra="forbid")

    system: SystemReport
    hardware: HardwareReport | None = None
    network: NetworkReport | None = None
    filesystems: list[FilesystemReport] = Field(default_factory=list, max_length=64)
    packages: list[PackageReport] = Field(default_factory=list, max_length=20000)
    facts: dict[str, str] = Field(default_factory=dict, max_length=512)
    # Optional history metadata (Phase 2.6). Backward compatible: existing
    # collectors omit both and receive server-side defaults.
    schema_version: int = Field(default=1, ge=1, le=1000)
    collected_at: datetime | None = None  # agent-side UTC collection time

    @field_validator("facts")
    @classmethod
    def _validate_facts(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 512:
            raise ValueError("too many facts")
        for key, value in v.items():
            if not key or len(key) > 128:
                raise ValueError("fact key must be 1..128 chars")
            if len(value) > 8192:
                raise ValueError(f"fact value too large: {key}")
        return v


class AgentInventoryOut(BaseModel):
    endpoint_id: uuid.UUID
    accepted: bool = True
    server_time: datetime
    counts: dict[str, int]


class AgentCredentialRotateOut(BaseModel):
    endpoint_id: uuid.UUID
    credential: str  # raw value — issued exactly once
    issued_at: datetime


SortField = Literal[
    "hostname",
    "status",
    "os",
    "agent_version",
    "enrolled_at",
    "last_heartbeat_at",
    "created_at",
]
