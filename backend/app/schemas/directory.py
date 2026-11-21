"""Pydantic schemas for the directory (Active Directory) API (Phase 3.1).

Conventions:
- **No secret is ever echoed**: the bind password exists only on the
  write-side schemas (``ConnectionCreate.bind_password`` /
  ``ConnectionUpdate.bind_password``) and is absent from every response
  model — including error paths.
- Response models never expose ``bind_password_encrypted`` (the ORM
  column is simply not mapped onto any Out schema).
- ``extra="forbid"`` on write payloads so clients cannot smuggle fields.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --- Connections -------------------------------------------------------------


class ConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    domain_dns: str = Field(min_length=1, max_length=255)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=636, ge=1, le=65535)
    tls_mode: Literal["ldaps", "starttls"] = "ldaps"
    tls_ca_pem: str | None = Field(default=None, max_length=20000)
    search_base: str = Field(min_length=1, max_length=1024)
    bind_username: str = Field(min_length=1, max_length=255)
    # Write-only: encrypted at rest, never present in any response schema.
    bind_password: str = Field(min_length=1, max_length=1024)
    connect_timeout_seconds: int = Field(default=10, ge=1, le=120)
    search_timeout_seconds: int = Field(default=30, ge=1, le=600)
    page_size: int = Field(default=500, ge=1, le=5000)
    enabled: bool = True
    auto_sync: bool = True
    sync_interval_minutes: int = Field(default=60, ge=5, le=10080)


class ConnectionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=128)
    domain_dns: str | None = Field(default=None, min_length=1, max_length=255)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    tls_mode: Literal["ldaps", "starttls"] | None = None
    tls_ca_pem: str | None = Field(default=None, max_length=20000)
    search_base: str | None = Field(default=None, min_length=1, max_length=1024)
    bind_username: str | None = Field(default=None, min_length=1, max_length=255)
    # Optional rotation: absent/null = leave unchanged; a value re-encrypts.
    bind_password: str | None = Field(default=None, min_length=1, max_length=1024)
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    search_timeout_seconds: int | None = Field(default=None, ge=1, le=600)
    page_size: int | None = Field(default=None, ge=1, le=5000)
    enabled: bool | None = None
    auto_sync: bool | None = None
    sync_interval_minutes: int | None = Field(default=None, ge=5, le=10080)


class ConnectionSummaryOut(BaseModel):
    """List-row shape: configuration without the CA bundle or secrets."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    domain_dns: str
    host: str
    port: int
    tls_mode: str
    search_base: str
    bind_username: str
    connect_timeout_seconds: int
    search_timeout_seconds: int
    page_size: int
    enabled: bool
    auto_sync: bool
    sync_interval_minutes: int
    has_custom_ca: bool = False
    last_run_status: str | None = None
    last_run_started_at: datetime | None = None
    last_success_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ConnectionOut(ConnectionSummaryOut):
    """Detail shape: adds the (non-secret) CA bundle for editing."""

    tls_ca_pem: str | None = None


class ConnectionTestOut(BaseModel):
    ok: bool
    label: str | None = None
    message: str | None = None
    duration_ms: int = 0
    default_naming_context: str | None = None
    dns_hostname: str | None = None


# --- Sync runs ---------------------------------------------------------------


class SyncRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    started_at: datetime
    finished_at: datetime | None = None
    status: str
    trigger: str
    objects_discovered: int = 0
    objects_created: int = 0
    objects_updated: int = 0
    objects_marked_missing: int = 0
    duration_ms: int | None = None


class SyncRunDetailOut(SyncRunOut):
    """History detail: sanitized per-category results + error labels."""

    errors: list[dict[str, Any]] | None = None
    category_results: dict[str, Any] = Field(default_factory=dict)


# --- Directory objects -------------------------------------------------------


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    domain_dns: str
    distinguished_name: str
    sid: str | None = None
    functional_level: str | None = None
    last_synced_at: datetime | None = None
    last_seen_at: datetime


class OrganizationalUnitOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    object_guid: str
    distinguished_name: str
    name: str
    parent_dn: str | None = None
    last_seen_at: datetime
    missing_since: datetime | None = None


class OrganizationalUnitDetailOut(OrganizationalUnitOut):
    """Detail adds direct-child counts (computed with bounded count
    queries — never per-child loops)."""

    child_ous: int = 0
    users: int = 0
    groups: int = 0
    computers: int = 0


class DirectoryUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    object_guid: str
    distinguished_name: str
    sid: str | None = None
    sam_account_name: str
    user_principal_name: str | None = None
    display_name: str | None = None
    email: str | None = None
    enabled: bool | None = None
    department: str | None = None
    title: str | None = None
    manager_dn: str | None = None
    last_logon_at: datetime | None = None
    ad_created_at: datetime | None = None
    ad_changed_at: datetime | None = None
    last_seen_at: datetime
    missing_since: datetime | None = None


class DirectoryGroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    object_guid: str
    distinguished_name: str
    sid: str | None = None
    name: str
    description: str | None = None
    scope: str | None = None
    category: str | None = None
    last_seen_at: datetime
    missing_since: datetime | None = None


class DirectoryGroupDetailOut(DirectoryGroupOut):
    member_count: int = 0


class GroupMemberOut(BaseModel):
    """One membership edge with batch-resolved local identity (or honest
    ``resolved=False`` for foreign security principals)."""

    member_type: str
    member_dn: str
    member_object_guid: str | None = None
    resolved: bool = False
    local_id: uuid.UUID | None = None
    display_name: str | None = None


class DirectoryComputerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    object_guid: str
    distinguished_name: str
    sid: str | None = None
    name: str
    dns_hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    enabled: bool | None = None
    last_logon_at: datetime | None = None
    ad_changed_at: datetime | None = None
    last_seen_at: datetime
    missing_since: datetime | None = None
    # Reconciliation view (batch-joined; never blocks or guesses).
    recon_status: str | None = None
    recon_method: str | None = None
    recon_confidence: str | None = None
    recon_endpoint_id: uuid.UUID | None = None


class DirectoryComputerDetailOut(DirectoryComputerOut):
    recon_candidates: list[uuid.UUID] = Field(default_factory=list)
    recon_reviewed_at: datetime | None = None


# --- Reconciliation ----------------------------------------------------------


class ReconciliationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    computer_id: uuid.UUID
    endpoint_id: uuid.UUID | None = None
    method: str
    confidence: str
    status: str
    candidates: list[uuid.UUID] = Field(default_factory=list)

    @field_validator("candidates", mode="before")
    @classmethod
    def _null_candidates(cls, value: object) -> object:
        # Rows written before a decision carry NULL; the API contract is a list.
        return [] if value is None else value
    reviewed_by: uuid.UUID | None = None
    reviewed_at: datetime | None = None
    updated_at: datetime
    # Display names resolved in-batch (not N+1).
    computer_name: str | None = None
    endpoint_hostname: str | None = None


class MatchDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["match", "reject"]
    # Required for decision=match: the endpoint the operator confirmed.
    endpoint_id: uuid.UUID | None = None


# --- Overview ----------------------------------------------------------------


class DirectoryOverviewOut(BaseModel):
    """Dashboard KPIs — every field comes from a real aggregate query."""

    domains: int = 0
    users_total: int = 0
    users_enabled: int = 0
    users_disabled: int = 0
    groups: int = 0
    computers: int = 0
    missing_objects: int = 0
    connections_total: int = 0
    connections_enabled: int = 0
    reconciliation_matched: int = 0
    reconciliation_needs_review: int = 0
    reconciliation_unmatched: int = 0
    reconciliation_rejected: int = 0
    running_syncs: int = 0
    failed_runs_24h: int = 0
    last_sync_success_at: datetime | None = None
    last_sync_failure_at: datetime | None = None


__all__ = [
    "ConnectionCreate",
    "ConnectionOut",
    "ConnectionSummaryOut",
    "ConnectionTestOut",
    "ConnectionUpdate",
    "DirectoryComputerDetailOut",
    "DirectoryComputerOut",
    "DirectoryGroupDetailOut",
    "DirectoryGroupOut",
    "DirectoryOverviewOut",
    "DirectoryUserOut",
    "DomainOut",
    "GroupMemberOut",
    "MatchDecisionIn",
    "OrganizationalUnitDetailOut",
    "OrganizationalUnitOut",
    "ReconciliationOut",
    "SyncRunDetailOut",
    "SyncRunOut",
]
