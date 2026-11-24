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

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


# --- Findings (Phase 3.2.1) ---------------------------------------------------


class FindingOut(BaseModel):
    """One finding with evidence. ``detail`` is mirror metadata only."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    fingerprint: str
    rule_key: str
    severity: str
    status: str
    subject_type: str
    access: str | None = None
    subject_guid: str | None = None
    subject_dn: str | None = None
    subject_name: str | None = None
    title: str
    detail: dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None = None
    reopen_count: int = 0
    acknowledged_at: datetime | None = None
    acknowledged_by: uuid.UUID | None = None
    suppressed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def _subject_identity(self) -> FindingOut:
        # Connection findings identify via connection_id alone; object
        # findings must carry their DN (DB CHECK mirrors this rule).
        if self.subject_type == "connection":
            if self.subject_dn is not None or self.subject_guid is not None:
                raise ValueError(
                    "connection findings must not carry subject_dn/subject_guid"
                )
        elif self.subject_dn is None:
            raise ValueError("object findings require subject_dn")
        return self


class FindingSummaryOut(BaseModel):
    """Findings rollup: counts + the effective-privilege visibility verdict."""

    total: int = 0
    open: int = 0
    acknowledged: int = 0
    suppressed: int = 0
    resolved: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)
    by_subject_type: dict[str, int] = Field(default_factory=dict)
    privilege_visibility: str
    visibility_reasons: list[str] = Field(default_factory=list)
    inventory_complete: bool = False


# --- Health (Phase 3.2.2) ------------------------------------------------------


class SyncRunHealthOut(BaseModel):
    """Newest sync run for the health view: sanitized category results only.

    ``errors`` (raw error labels list) is deliberately NOT exposed here —
    category results carry the same sanitized labels the sync-history
    detail endpoint already serves.
    """

    id: uuid.UUID
    status: str
    trigger: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int | None = None
    category_results: dict[str, Any] = Field(default_factory=dict)


class SyncFreshnessOut(BaseModel):
    """Freshness facts derived from the connection's own sync cadence."""

    last_success_at: datetime | None = None
    newest_run_started_at: datetime | None = None
    sync_interval_minutes: int
    sync_overdue: bool = True


class DirectoryHealthOut(BaseModel):
    """Directory health: inventory, newest run, visibility, findings.

    ``newest_run`` is ALWAYS the newest run regardless of status — an
    older successful run never backstops a newer failed/running one.
    """

    connection_id: uuid.UUID
    inventory_complete: bool = False
    missing_categories: list[str] = Field(default_factory=list)
    newest_run: SyncRunHealthOut | None = None
    privilege_visibility: str
    visibility_reasons: list[str] = Field(default_factory=list)
    findings: FindingSummaryOut
    sync_freshness: SyncFreshnessOut


# --- Correlation gaps (Phase 3.2.2) ---------------------------------------------


class CorrelationGapOut(BaseModel):
    """One directory computer without a resolved endpoint correlation.

    ``gap_type`` distinguishes the three honest gap states:
    - ``never_reconciled``: no reconciliation row yet (genuinely missing);
    - ``unmatched``: reconciled, endpoint not linked (genuinely missing);
    - ``ambiguous``: candidates exist but are ambiguous (needs review).

    ``matched`` and ``rejected`` rows are deliberate decisions and never
    appear as gaps.
    """

    computer_id: uuid.UUID
    computer_name: str
    dns_hostname: str | None = None
    distinguished_name: str
    object_guid: str | None = None
    gap_type: str
    recon_status: str | None = None
    recon_method: str | None = None
    recon_confidence: str | None = None
    candidates: list[uuid.UUID] = Field(default_factory=list)
    reviewed_at: datetime | None = None


__all__ = [
    "ConnectionCreate",
    "ConnectionOut",
    "ConnectionSummaryOut",
    "ConnectionTestOut",
    "ConnectionUpdate",
    "CorrelationGapOut",
    "DirectoryComputerDetailOut",
    "DirectoryComputerOut",
    "DirectoryGroupDetailOut",
    "DirectoryGroupOut",
    "DirectoryHealthOut",
    "DirectoryOverviewOut",
    "DirectoryUserOut",
    "DomainOut",
    "FindingOut",
    "FindingSummaryOut",
    "GroupMemberOut",
    "MatchDecisionIn",
    "OrganizationalUnitDetailOut",
    "OrganizationalUnitOut",
    "ReconciliationOut",
    "SyncFreshnessOut",
    "SyncRunDetailOut",
    "SyncRunHealthOut",
    "SyncRunOut",
]
