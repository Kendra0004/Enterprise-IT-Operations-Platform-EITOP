"""Endpoint service: enrollment lifecycle, agent credentials, inventory.

Security invariants enforced here:
- Enrollment tokens are single-use; consumption is an atomic conditional
  UPDATE so concurrent enrollments cannot both succeed.
- Agent credentials are bound to exactly one endpoint, stored as SHA-256
  digests, compared with ``secrets.compare_digest``, and checked for
  revocation/expiry on every request (revocation is immediate).
- Rejected enrollments and failed agent authentications are audited and
  committed BEFORE the error propagates (get_db would otherwise roll back).
- Inventory submissions never carry an endpoint identifier: the target is
  derived only from the authenticated credential.
"""

from __future__ import annotations

import fnmatch
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import NoReturn, cast

from fastapi import Request, status
from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.security import sha256_hex
from app.models import (
    ENDPOINT_ACTIVE,
    ENDPOINT_OFFLINE,
    ENDPOINT_REVOKED,
    Endpoint,
    EndpointCredential,
    EndpointFact,
    EndpointGroup,
    EndpointMetadata,
    EndpointSnapshot,
    EndpointSnapshotSoftware,
    EndpointSoftware,
    EnrollmentToken,
    User,
)
from app.schemas.endpoints import (
    AgentEnrollRequest,
    AgentInventoryRequest,
    EnrollmentTokenCreate,
)
from app.services.auth_service import _record_audit

# Credential transport: distinct prefix so agent credentials can never be
# confused with (or substituted for) user JWTs.
CREDENTIAL_PREFIX = "eitop_ep_"


# --- Token / credential primitives ------------------------------------------


def generate_enrollment_token() -> tuple[str, str]:
    """(raw_token, sha256_digest). Raw shown once; only digest persisted."""
    raw = secrets.token_urlsafe(32)
    return raw, sha256_hex(raw)


def generate_agent_credential() -> tuple[str, str]:
    """(raw_credential, sha256_digest) with a recognizable opaque prefix."""
    raw = CREDENTIAL_PREFIX + secrets.token_urlsafe(32)
    return raw, sha256_hex(raw)


# --- Enrollment -------------------------------------------------------------


def create_enrollment_token(
    db: Session, *, created_by: User, payload: EnrollmentTokenCreate
) -> tuple[EnrollmentToken, str]:
    """Mint a single-use enrollment token. Returns (row, raw_token)."""
    raw, digest = generate_enrollment_token()
    expires_at = datetime.now(UTC) + timedelta(minutes=payload.expires_in_minutes)

    if payload.group_id is not None and db.get(EndpointGroup, payload.group_id) is None:
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Unknown group",
            f"Group {payload.group_id} does not exist.",
        )

    row = EnrollmentToken(
        token_hash=digest,
        created_by=created_by.id,
        group_id=payload.group_id,
        restrictions=payload.restrictions.model_dump() if payload.restrictions else None,
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()
    _record_audit(
        db,
        event_type="endpoint.enrollment_token.created",
        outcome="success",
        actor=created_by,
        target=str(row.id),
        detail={
            "expires_in_minutes": payload.expires_in_minutes,
            "group_id": str(payload.group_id) if payload.group_id else None,
        },
    )
    return row, raw


def _reject_enrollment(
    db: Session, *, request: Request | None, reason: str, token_id: str | None
) -> NoReturn:
    """Audit a failed enrollment attempt and commit before raising."""
    _record_audit(
        db,
        event_type="endpoint.enrollment.rejected",
        outcome="failure",
        request=request,
        target=token_id,
        detail={"reason": reason},
    )
    db.commit()
    # Uniform response: never reveal whether the token exists, was used, or
    # expired (no enrollment-token oracle for guessing attacks).
    raise AppError(
        status.HTTP_401_UNAUTHORIZED,
        "Invalid enrollment token",
        "Enrollment token is invalid, expired, or already used.",
    )


def _hostname_allowed(restrictions: dict | None, hostname: str, fqdn: str | None) -> bool:
    if not restrictions:
        return True
    patterns = restrictions.get("allowed_hostname_patterns") or []
    if not patterns:
        return True
    candidates = [hostname.lower()]
    if fqdn:
        candidates.append(fqdn.lower())
    return any(
        fnmatch.fnmatchcase(candidate, pattern)
        for candidate in candidates
        for pattern in patterns
    )


def enroll(
    db: Session, payload: AgentEnrollRequest, *, request: Request | None = None
) -> tuple[Endpoint, str]:
    """Validate and atomically consume an enrollment token, create the
    endpoint identity and issue its first credential.

    Returns (endpoint, raw_credential). Raw credential exists only in this
    process's response — never logged, never stored.
    """
    now = datetime.now(UTC)
    digest = sha256_hex(payload.token)

    token = db.scalar(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == digest)
    )
    if token is None:
        _reject_enrollment(db, request=request, reason="unknown_token", token_id=None)

    if token.used_at is not None:
        _reject_enrollment(
            db,
            request=request,
            reason="already_used",
            token_id=str(token.id),
        )
    if token.expires_at <= now:
        _reject_enrollment(
            db, request=request, reason="expired", token_id=str(token.id)
        )
    if not _hostname_allowed(token.restrictions, payload.hostname, payload.fqdn):
        _reject_enrollment(
            db, request=request, reason="hostname_not_allowed", token_id=str(token.id)
        )

    # Atomic one-time claim: only one concurrent request can flip used_at.
    claimed = db.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.id == token.id,
            EnrollmentToken.used_at.is_(None),
        )
        .values(used_at=now)
        .returning(EnrollmentToken.id, EnrollmentToken.group_id)
    ).first()
    if claimed is None:
        # Lost a concurrent race — the winner consumed the token.
        _reject_enrollment(
            db, request=request, reason="concurrent_use", token_id=str(token.id)
        )

    endpoint = Endpoint(
        hostname=payload.hostname,
        fqdn=payload.fqdn,
        os=payload.os,
        os_version=payload.os_version,
        os_arch=payload.os_arch,
        kernel_version=payload.kernel_version,
        agent_version=payload.agent_version,
        status=ENDPOINT_ACTIVE,
        enrolled_at=now,
    )
    if claimed.group_id is not None:
        group = db.get(EndpointGroup, claimed.group_id)
        if group is not None:
            endpoint.groups.append(group)
    db.add(endpoint)
    db.flush()

    token.consumed_by = endpoint.id

    raw_credential, cred_digest = generate_agent_credential()
    credential = EndpointCredential(endpoint_id=endpoint.id, token_hash=cred_digest)
    db.add(credential)
    db.flush()

    _record_audit(
        db,
        event_type="endpoint.enrolled",
        outcome="success",
        request=request,
        actor_email="agent",
        target=str(endpoint.id),
        detail={
            "hostname": endpoint.hostname,
            "token_id": str(token.id),
            "group_id": str(claimed.group_id) if claimed.group_id else None,
        },
    )
    return endpoint, raw_credential


# --- Agent authentication ---------------------------------------------------


def authenticate_agent(
    db: Session, raw_credential: str, *, request: Request | None = None
) -> tuple[Endpoint, EndpointCredential]:
    """Resolve the endpoint for an agent credential.

    Raises AppError(401) for missing/unknown/revoked/expired credentials and
    for revoked endpoints — checked on every request so revocation is
    immediate.
    """
    if not raw_credential.startswith(CREDENTIAL_PREFIX):
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            "Missing or invalid endpoint credential.",
        )
    digest = sha256_hex(raw_credential)
    cred = db.scalar(
        select(EndpointCredential).where(EndpointCredential.token_hash == digest)
    )
    now = datetime.now(UTC)
    reason: str | None = None
    if cred is None or not secrets.compare_digest(cred.token_hash, digest):
        reason = "unknown_credential"
    elif cred.revoked_at is not None:
        reason = "credential_revoked"
    elif cred.expires_at is not None and cred.expires_at <= now:
        reason = "credential_expired"

    endpoint: Endpoint | None = None
    if reason is None:
        assert cred is not None  # reason stays None only when cred validated
        endpoint = db.get(Endpoint, cred.endpoint_id)
        if endpoint is None:
            reason = "endpoint_missing"
        elif endpoint.status == ENDPOINT_REVOKED:
            # Only revocation is terminal. "offline" endpoints keep working
            # credentials so a returning agent can heartbeat back to active —
            # missing heartbeats must never be confused with revocation.
            reason = "endpoint_revoked"

    if reason is not None:
        # Suspicious activity: record, commit (rollback would drop it), raise.
        _record_audit(
            db,
            event_type="auth.agent.failure",
            outcome="failure",
            request=request,
            actor_email="agent",
            target=str(cred.endpoint_id) if cred is not None else None,
            detail={"reason": reason},
        )
        db.commit()
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            "Missing or invalid endpoint credential.",
        )

    assert endpoint is not None and cred is not None  # reason is None above
    cred.last_used_at = now
    return endpoint, cred


# --- Credential lifecycle ---------------------------------------------------


def rotate_credential(
    db: Session,
    endpoint: Endpoint,
    old_credential: EndpointCredential,
    *,
    request: Request | None = None,
    actor_email: str | None = None,
) -> str:
    """Revoke the current credential and issue a replacement.

    Returns the raw credential (issuance response only — it is never stored
    in plaintext and never returned again).
    """
    raw, digest = generate_agent_credential()
    now = datetime.now(UTC)
    old_credential.revoked_at = now
    new_credential = EndpointCredential(
        endpoint_id=endpoint.id,
        token_hash=digest,
        rotated_from=old_credential.id,
    )
    db.add(new_credential)
    db.flush()
    _record_audit(
        db,
        event_type="endpoint.credential.rotated",
        outcome="success",
        request=request,
        actor_email=actor_email,
        target=str(endpoint.id),
        detail={"credential_id": str(new_credential.id)},
    )
    return raw


def revoke_endpoint(
    db: Session,
    endpoint: Endpoint,
    *,
    request: Request | None = None,
    actor: User | None = None,
) -> int:
    """Revoke an endpoint and every credential it holds (immediate)."""
    now = datetime.now(UTC)
    endpoint.status = ENDPOINT_REVOKED
    result = db.execute(
        update(EndpointCredential)
        .where(
            EndpointCredential.endpoint_id == endpoint.id,
            EndpointCredential.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    # CursorResult carries rowcount; the ORM Result stub does not expose it.
    revoked_count = cast(int, getattr(result, "rowcount", 0)) or 0
    _record_audit(
        db,
        event_type="endpoint.revoked",
        outcome="success",
        request=request,
        actor=actor,
        target=str(endpoint.id),
        detail={"revoked_credentials": revoked_count},
    )
    return revoked_count


# --- Inventory --------------------------------------------------------------


def apply_inventory(
    db: Session, endpoint: Endpoint, payload: AgentInventoryRequest
) -> dict[str, int]:
    """Upsert current inventory state AND append an immutable snapshot.

    Idempotent on both layers:
    - current state: facts/packages keyed uniquely per endpoint;
    - history: snapshot insert is ``ON CONFLICT (endpoint_id, content_hash)
      DO NOTHING`` — an identical resubmission (network retry) never creates
      a duplicate snapshot.
    """
    now = datetime.now(UTC)
    system = payload.system

    # Descriptive system fields (never used for authentication).
    endpoint.hostname = system.hostname
    endpoint.fqdn = system.fqdn
    endpoint.os = system.os
    endpoint.os_arch = system.os_arch
    endpoint.kernel_version = system.kernel
    if system.os_version:
        endpoint.os_version = system.os_version
    elif system.distribution_version:
        endpoint.os_version = system.distribution_version
    elif system.distribution:
        endpoint.os_version = system.distribution

    # Hardware + network metadata (single row, upserted).
    meta = db.get(EndpointMetadata, endpoint.id)
    if meta is None:
        meta = EndpointMetadata(endpoint_id=endpoint.id)
        db.add(meta)
    hw = payload.hardware
    if hw is not None:
        if hw.manufacturer is not None:
            meta.manufacturer = hw.manufacturer
        if hw.model is not None:
            meta.model = hw.model
        if hw.serial_number is not None:
            meta.serial_number = hw.serial_number
        if hw.cpu_model is not None:
            meta.cpu_model = hw.cpu_model
        if hw.cpu_cores is not None:
            meta.cpu_cores = hw.cpu_cores
        if hw.memory_bytes is not None:
            meta.memory_bytes = hw.memory_bytes
        if hw.disk_bytes is not None:
            meta.disk_bytes = hw.disk_bytes
    net = payload.network
    if net is not None:
        meta.ip_addresses = sorted(set(net.ip_addresses))
        meta.mac_addresses = sorted(set(net.mac_addresses))
    if meta.disk_bytes is None and payload.filesystems:
        meta.disk_bytes = sum(fs.total_bytes for fs in payload.filesystems)

    # Facts: merge into the unique (endpoint_id, key) rows.
    fact_values: dict[str, str] = dict(payload.facts)
    if system.distribution:
        fact_values["system.distribution"] = system.distribution
    if system.distribution_version:
        fact_values["system.distribution_version"] = system.distribution_version
    if system.uptime_seconds is not None:
        fact_values["system.uptime_seconds"] = str(system.uptime_seconds)
    if net is not None:
        fact_values["network.interfaces"] = _json_compact(
            [iface.model_dump() for iface in net.interfaces]
        )
    if payload.filesystems:
        fact_values["filesystem.usage"] = _json_compact(
            [fs.model_dump() for fs in payload.filesystems]
        )

    existing_facts = {
        f.key: f
        for f in db.scalars(
            select(EndpointFact).where(EndpointFact.endpoint_id == endpoint.id)
        ).all()
    }
    fact_count = 0
    for key, value in fact_values.items():
        row = existing_facts.get(key)
        if row is None:
            db.add(
                EndpointFact(
                    endpoint_id=endpoint.id,
                    key=key,
                    value=value,
                    source="collector",
                    collected_at=now,
                )
            )
            fact_count += 1
        else:
            row.value = value
            row.source = "collector"
            row.collected_at = now
            row.updated_at = now
            fact_count += 1

    # Packages: upsert per (endpoint, name, manager); drop rows no longer
    # reported so the table reflects the latest full submission.
    submitted = {
        (p.name, p.package_manager): p for p in payload.packages
    }
    existing_packages = {
        (s.name, s.package_manager): s
        for s in db.scalars(
            select(EndpointSoftware).where(EndpointSoftware.endpoint_id == endpoint.id)
        ).all()
    }
    package_count = 0
    for pkg_key, pkg in submitted.items():
        pkg_row = existing_packages.get(pkg_key)
        if pkg_row is None:
            db.add(
                EndpointSoftware(
                    endpoint_id=endpoint.id,
                    name=pkg.name,
                    version=pkg.version,
                    package_manager=pkg.package_manager,
                    collected_at=now,
                )
            )
        else:
            pkg_row.version = pkg.version
            pkg_row.collected_at = now
        package_count += 1
    stale_keys = set(existing_packages) - set(submitted)
    for stale_name, stale_manager in stale_keys:
        db.execute(
            delete(EndpointSoftware).where(
                EndpointSoftware.endpoint_id == endpoint.id,
                EndpointSoftware.name == stale_name,
                EndpointSoftware.package_manager == stale_manager,
            )
        )

    # --- Immutable history layer (Phase 2.6) -------------------------------
    endpoint.last_inventory_at = now
    snapshot_created = _append_snapshot(db, endpoint, payload, received_at=now)

    return {
        "facts": fact_count,
        "packages": package_count,
        "interfaces": len(net.interfaces) if net else 0,
        "snapshots": 1 if snapshot_created else 0,
    }


def _canonical_payload_hash(payload: AgentInventoryRequest) -> str:
    """Deterministic digest of the full submission (sorted keys, compact)."""
    canonical = json.dumps(
        payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return sha256_hex(canonical)


def _utc_normalized(value: datetime | None, fallback: datetime) -> datetime:
    """Agent timestamps are UTC; a naive datetime is assumed UTC."""
    if value is None:
        return fallback
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _append_snapshot(
    db: Session,
    endpoint: Endpoint,
    payload: AgentInventoryRequest,
    *,
    received_at: datetime,
) -> bool:
    """Append an immutable snapshot for this submission.

    Returns True when a new snapshot row was created, False for an exact
    duplicate (content hash already stored for this endpoint). Packages are
    written to the normalized table only for a NEW snapshot — never twice.
    """
    content_hash = _canonical_payload_hash(payload)
    result = db.execute(
        pg_insert(EndpointSnapshot)
        .values(
            endpoint_id=endpoint.id,
            collected_at=_utc_normalized(payload.collected_at, received_at),
            received_at=received_at,
            agent_version=endpoint.agent_version,
            schema_version=payload.schema_version,
            content_hash=content_hash,
            system=payload.system.model_dump(mode="json"),
            hardware=(
                payload.hardware.model_dump(mode="json") if payload.hardware else None
            ),
            network=(
                payload.network.model_dump(mode="json") if payload.network else None
            ),
            filesystems=[fs.model_dump(mode="json") for fs in payload.filesystems],
            facts=dict(payload.facts),
        )
        .on_conflict_do_nothing(index_elements=["endpoint_id", "content_hash"])
        .returning(EndpointSnapshot.id)
    )
    snapshot_id = result.scalar_one_or_none()
    if snapshot_id is None:
        return False  # identical submission already snapshotted

    # Normalize packages once (dedupe by name+manager, last write wins).
    packages = {
        (p.name, p.package_manager): p for p in payload.packages
    }
    if packages:
        db.execute(
            pg_insert(EndpointSnapshotSoftware),
            [
                {
                    "snapshot_id": snapshot_id,
                    "name": name,
                    "package_manager": manager,
                    "version": pkg.version,
                }
                for (name, manager), pkg in sorted(packages.items())
            ],
        )
    return True


def record_heartbeat(
    db: Session, endpoint: Endpoint, agent_version: str | None
) -> None:
    """Record a valid heartbeat and recover an offline endpoint.

    Audit is written ONLY on the offline→active transition — routine
    heartbeats are not security/lifecycle events and are never audited.
    Revoked endpoints never reach this function (authentication rejects
    them); the status guard below is defense in depth.
    """
    now = datetime.now(UTC)
    endpoint.last_heartbeat_at = now
    if agent_version:
        endpoint.agent_version = agent_version
    if endpoint.status == ENDPOINT_OFFLINE:
        # Recovery: a valid heartbeat is proof of life. Conditional update
        # guards against a concurrent scan/revocation racing this request.
        recovered = db.execute(
            update(Endpoint)
            .where(Endpoint.id == endpoint.id, Endpoint.status == ENDPOINT_OFFLINE)
            .values(status=ENDPOINT_ACTIVE, updated_at=now)
        )
        if getattr(recovered, "rowcount", 0):
            endpoint.status = ENDPOINT_ACTIVE
            _record_audit(
                db,
                event_type="endpoint.online",
                outcome="success",
                actor_email="agent",
                target=str(endpoint.id),
                detail={"hostname": endpoint.hostname, "agent_version": agent_version},
            )


def derive_collector_status(
    endpoint: Endpoint, now: datetime, *, interval: int, threshold: int
) -> tuple[str, int | None]:
    """Read-time health derivation: (collector_status, seconds_since_heartbeat).

    ``collector_status`` is computed from UTC timestamps so health stays
    accurate between background scans:
    - revoked      → terminal, always (never derived from missing beats)
    - pending      → enrolled, never heartbeated, still inside the grace window
    - offline      → past the threshold (or scan already flipped the column)
    - late         → heartbeat older than the expected interval
    - healthy      → heartbeat within the expected interval
    Missing heartbeat is never reported as "revoked".
    """

    def _age(moment: datetime | None) -> int | None:
        if moment is None:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return max(0, int((now - moment).total_seconds()))

    if endpoint.status == ENDPOINT_REVOKED:
        return "revoked", _age(endpoint.last_heartbeat_at)

    age = _age(endpoint.last_heartbeat_at)
    if age is None:
        # Never heartbeated: grace measured from enrollment.
        enrolled_age = _age(endpoint.enrolled_at) or 0
        if endpoint.status == ENDPOINT_OFFLINE or enrolled_age >= threshold:
            return "offline", None
        return "pending", None
    if endpoint.status == ENDPOINT_OFFLINE or age > threshold:
        return "offline", age
    if age > interval:
        return "late", age
    return "healthy", age


def scan_offline_endpoints(db: Session) -> int:
    """Mark active endpoints whose last heartbeat exceeds the threshold as
    offline. Returns the number of status transitions.

    Called ONLY from the Celery periodic task — never from a request
    handler (no database polling inside FastAPI). The conditional UPDATE
    (status='active' AND stale heartbeat) makes the transition atomic:
    concurrent runs or a just-arrived heartbeat cause rowcount 0, so the
    same endpoint is never transitioned (and audited) twice.
    """
    settings = get_settings()
    cutoff = datetime.now(UTC) - timedelta(
        seconds=settings.endpoint_offline_threshold_seconds
    )
    # Never-heartbeated endpoints age from enrollment; a fresh enrollment
    # inside the grace window stays active.
    stale = or_(
        Endpoint.last_heartbeat_at < cutoff,
        and_(
            Endpoint.last_heartbeat_at.is_(None),
            Endpoint.enrolled_at < cutoff,
        ),
    )
    result = db.execute(
        update(Endpoint)
        .where(Endpoint.status == ENDPOINT_ACTIVE, stale)
        .values(status=ENDPOINT_OFFLINE, updated_at=datetime.now(UTC))
        .returning(Endpoint.id, Endpoint.hostname)
    )
    rows = result.all()
    for row in rows:
        _record_audit(
            db,
            event_type="endpoint.offline",
            outcome="success",
            actor_email="system",
            target=str(row.id),
            detail={
                "hostname": row.hostname,
                "threshold_seconds": settings.endpoint_offline_threshold_seconds,
            },
        )
    return len(rows)


def _json_compact(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
