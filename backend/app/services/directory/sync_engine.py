"""Synchronization engine (Phase 3.1): full paginated read-only AD mirror.

Pipeline (fail-fast, one stage at a time):

    connect -> domains -> ous -> users -> groups -> computers
            -> memberships -> [missing gate] -> reconcile

Invariants (tested in tests/test_directory_sync.py):
- **One database transaction** for every mirror write: a failed run rolls
  back completely, preserving previously synchronized data untouched.
- **Missing-object marking runs only after EVERY required category
  reported success** — an explicit gate over the recorded category
  results, not just control flow. A partial or failed run never marks
  anything missing (belt: the gate; suspenders: the rollback).
- **Unparseable entries fail their whole category**
  (``UnparseableEntryError``, carrying no entry content) so an unreadable
  entry can never silently drop from the seen-set and later be marked
  missing.
- **Keyed upserts** on ``(connection_id, object_guid)`` and unique
  membership edges: retries and re-runs never duplicate rows.
- **category_results / errors persist sanitized labels only** (see
  errors.py) — never credentials, raw exception content, or directory
  attribute payloads.
- The engine only ever issues LDAP reads through ``DirectoryLdapClient``
  (bind + searches); it cannot modify Active Directory.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    ENDPOINT_REVOKED,
    GROUP_CATEGORY_DISTRIBUTION,
    GROUP_CATEGORY_SECURITY,
    GROUP_SCOPE_DOMAIN_LOCAL,
    GROUP_SCOPE_GLOBAL,
    GROUP_SCOPE_UNIVERSAL,
    MEMBER_COMPUTER,
    MEMBER_GROUP,
    MEMBER_USER,
    RECON_EXACT_FQDN,
    RECON_MATCHED,
    RECON_NEEDS_REVIEW,
    RECON_SHORT_NAME,
    RECON_UNMATCHED,
    SYNC_FAILED,
    SYNC_RUNNING,
    SYNC_SUCCESS,
    DirectoryComputer,
    DirectoryConnection,
    DirectoryDomain,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectoryOrganizationalUnit,
    DirectoryReconciliation,
    DirectorySyncRun,
    DirectoryUser,
    Endpoint,
)
from app.services.auth_service import _record_audit
from app.services.directory import factory
from app.services.directory.errors import (
    SearchBaseError,
    UnparseableEntryError,
    classify_error,
    error_entry,
)
from app.services.directory.ldap_client import DirectoryLdapClient, build_filter
from app.services.directory.normalize import (
    ad_sid,
    ad_time,
    as_list,
    dn_rdn_value,
    first,
    uac_enabled,
)

logger = logging.getLogger(__name__)

# Execution + recording order. missing_scan is gated on everything before it.
PIPELINE = (
    "connect",
    "domains",
    "ous",
    "users",
    "groups",
    "computers",
    "memberships",
    "missing_scan",
    "reconcile",
)
# Categories that must ALL report success before missing-marking may run.
GATE_REQUIRED = PIPELINE[: PIPELINE.index("missing_scan")]

_UPSERT_CHUNK = 500
_MEMBER_CHUNK = 1000


class _CategoryFailure(Exception):
    """Internal control-flow wrapper: which category failed and why."""

    def __init__(self, category: str, cause: BaseException) -> None:
        super().__init__(category)
        self.category = category
        self.cause = cause


def initial_category_results() -> dict[str, dict[str, Any]]:
    """Fresh pending results map for a newly created run row."""
    return {name: {"status": "pending"} for name in PIPELINE}


def failed_results(label: str) -> dict[str, dict[str, Any]]:
    """Results map for runs that never started their pipeline (submission
    failure, stale reaper): connect failed with the label, rest skipped."""
    out: dict[str, dict[str, Any]] = {name: {"status": "skipped"} for name in PIPELINE}
    out["connect"] = {"status": "failed", "label": label}
    out["missing_scan"] = {"status": "skipped"}
    return out


def execute_sync(
    run_id: uuid.UUID,
    *,
    session_factory: Callable[[], Session] = SessionLocal,
) -> str:
    """Execute a sync run to completion.

    Returns ``success`` / ``failed`` / ``skipped`` (stale task: the run was
    already finished or cascaded away). Three phases with separate
    sessions so a data rollback can never lose run bookkeeping:
    A) validate the run, B) mirror transaction, C) finalize + audit.
    """
    # --- Phase A: the run must still be actionable --------------------------
    with session_factory() as db:
        run = db.get(DirectorySyncRun, run_id)
        if run is None or run.status != SYNC_RUNNING:
            return "skipped"  # duplicate/stale task delivery
        connection_id = run.connection_id
        trigger = run.trigger

    # --- Phase B: mirror data (single transaction, rolls back on failure) ---
    started_at = datetime.now(UTC)
    results = initial_category_results()
    counters: dict[str, int] = {
        "discovered": 0,
        "created": 0,
        "updated": 0,
        "marked_missing": 0,
    }
    failure: _CategoryFailure | None = None
    try:
        with session_factory() as db:
            row = db.get(DirectoryConnection, connection_id)
            if row is None:
                return "skipped"  # connection deleted while queued
            _run_pipeline(db, row, results, counters)
            # Explicit commit: a Session used as a context manager only
            # CLOSES on exit (rolling back), so the mirror must be
            # persisted here. Any _CategoryFailure raised inside
            # _run_pipeline propagates BEFORE this line, so the session
            # closes without commit, rolling back every mirror write.
            db.commit()
    except _CategoryFailure as cf:
        failure = cf
        results[cf.category] = {
            "status": "failed",
            "label": classify_error(cf.cause),
            "error_type": type(cf.cause).__name__,
        }
        for name in PIPELINE:
            if results[name]["status"] in ("pending", "running"):
                results[name] = {"status": "skipped"}
        # Hard guarantee: a failed run marks nothing missing (the gate
        # already prevents it; recording it keeps the artifact honest).
        results["missing_scan"] = {"status": "skipped"}
        # Nothing was persisted (rollback): only "discovered" (entries
        # read from LDAP) remains a true statement about this attempt.
        counters["created"] = 0
        counters["updated"] = 0
        counters["marked_missing"] = 0
    except Exception as exc:  # noqa: BLE001 - never strand the run as running
        # Failure outside any stage (e.g. the Phase-B commit itself):
        # attribute it to the stage that was in flight, then normalize
        # exactly like a category failure so Phase C always runs.
        category = next(
            (
                name
                for name in reversed(PIPELINE)
                if results[name]["status"] == "running"
            ),
            "connect",
        )
        failure = _CategoryFailure(category, exc)
        results[category] = {
            "status": "failed",
            "label": classify_error(exc),
            "error_type": type(exc).__name__,
        }
        for name in PIPELINE:
            if results[name]["status"] in ("pending", "running"):
                results[name] = {"status": "skipped"}
        results["missing_scan"] = {"status": "skipped"}
        counters["created"] = 0
        counters["updated"] = 0
        counters["marked_missing"] = 0

    # --- Phase C: bookkeeping + audit (always commits) ----------------------
    final_status = SYNC_SUCCESS if failure is None else SYNC_FAILED
    finished_at = datetime.now(UTC)
    duration_ms = int((finished_at - started_at).total_seconds() * 1000)
    with session_factory() as db:
        run = db.get(DirectorySyncRun, run_id)
        if run is None:
            return "skipped"  # deleted mid-run (cascade)
        row = db.get(DirectoryConnection, run.connection_id)
        run.status = final_status
        run.finished_at = finished_at
        run.duration_ms = duration_ms
        run.category_results = results
        run.objects_discovered = counters["discovered"]
        run.objects_created = counters["created"]
        run.objects_updated = counters["updated"]
        run.objects_marked_missing = counters["marked_missing"]
        run.errors = (
            [error_entry(failure.category, failure.cause)] if failure else None
        )
        detail: dict[str, Any] = {
            "connection": row.name if row else None,
            "host": row.host if row else None,
            "trigger": trigger,
            "counts": {
                "discovered": counters["discovered"],
                "created": counters["created"],
                "updated": counters["updated"],
                "marked_missing": counters["marked_missing"],
            },
            "categories": results,  # sanitized labels only (errors.py)
        }
        if failure is not None:
            detail["failed_category"] = failure.category
            detail["label"] = classify_error(failure.cause)
        _record_audit(
            db,
            event_type=(
                "directory.sync.succeeded"
                if failure is None
                else "directory.sync.failed"
            ),
            outcome="success" if failure is None else "failure",
            target=str(run_id),
            detail=detail,
        )
        db.commit()
    logger.info(
        "directory_sync_finished",
        extra={
            "run_id": str(run_id),
            "status": final_status,
            "duration_ms": duration_ms,
        },
    )
    return final_status


# --- Pipeline ----------------------------------------------------------------


def _run_pipeline(
    db: Session,
    row: DirectoryConnection,
    results: dict[str, dict[str, Any]],
    counters: dict[str, int],
) -> None:
    now = datetime.now(UTC)
    client: DirectoryLdapClient | None = None
    try:
        # --- connect (probe TLS + bind) ---
        results["connect"] = {"status": "running"}
        try:
            client = factory.build_client(row)
            client.connect()
        except Exception as exc:  # noqa: BLE001 - wrapped below
            raise _CategoryFailure("connect", exc) from None
        results["connect"] = {"status": "success"}

        _stage("domains", results, _sync_domains, db, row, client, counters, now)
        _stage("ous", results, _sync_ous, db, row, client, counters, now)
        _stage("users", results, _sync_users, db, row, client, counters, now)
        _stage("groups", results, _sync_groups, db, row, client, counters, now)
        _stage("computers", results, _sync_computers, db, row, client, counters, now)
        _stage(
            "memberships", results, _sync_memberships, db, row, client, counters, now
        )

        # --- missing-object gate: explicit, recorded, all-or-nothing --------
        if all(results[name]["status"] == "success" for name in GATE_REQUIRED):
            _stage("missing_scan", results, _mark_missing, db, row, counters, now)
        else:  # pragma: no cover - fail-fast makes this unreachable
            results["missing_scan"] = {"status": "skipped"}

        _stage("reconcile", results, _reconcile, db, row, now)
    finally:
        if client is not None:
            client.close()


def _stage(
    category: str,
    results: dict[str, dict[str, Any]],
    fn: Callable[..., dict[str, Any] | None],
    *args: Any,
) -> None:
    """Run one category, recording success stats or failing the pipeline."""
    results[category] = {"status": "running"}
    try:
        stats = fn(*args)
    except _CategoryFailure:
        raise
    except Exception as exc:  # noqa: BLE001 - converted to category failure
        raise _CategoryFailure(category, exc) from None
    entry: dict[str, Any] = {"status": "success"}
    if stats:
        entry.update(stats)
    results[category] = entry


# --- Category implementations ------------------------------------------------


def _sync_domains(
    db: Session,
    row: DirectoryConnection,
    client: DirectoryLdapClient,
    counters: dict[str, int],
    now: datetime,
) -> dict[str, Any]:
    """Discover + validate the domain (rootDSE is best-effort by design)."""
    root = client.root_dse()
    default_dn = str(root.get("defaultNamingContext") or row.search_base)
    if not client.validate_search_base(row.search_base):
        raise SearchBaseError()

    sid: str | None = None
    domain_attrs = client.read_base(default_dn, ["objectSid"])
    if domain_attrs:
        sid = ad_sid(domain_attrs.get("objectsid"))

    stmt = pg_insert(DirectoryDomain).values(
        connection_id=row.id,
        domain_dns=row.domain_dns,
        distinguished_name=default_dn,
        sid=sid,
        functional_level=root.get("domainFunctionality"),
        last_synced_at=now,
        last_seen_at=now,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[
            DirectoryDomain.connection_id,
            DirectoryDomain.distinguished_name,
        ],
        set_={
            "domain_dns": stmt.excluded.domain_dns,
            "sid": stmt.excluded.sid,
            "functional_level": stmt.excluded.functional_level,
            "last_synced_at": now,
            "last_seen_at": now,
        },
    )
    db.execute(stmt)
    # Discovery result changed (config edited): drop stale domain rows —
    # the domains table mirrors current discovery, not object history.
    db.execute(
        delete(DirectoryDomain).where(
            DirectoryDomain.connection_id == row.id,
            DirectoryDomain.distinguished_name != default_dn,
        )
    )
    counters["discovered"] += 1
    return {"discovered": 1}


def _sync_ous(
    db: Session,
    row: DirectoryConnection,
    client: DirectoryLdapClient,
    counters: dict[str, int],
    now: datetime,
) -> dict[str, Any]:
    def map_entry(entry: dict[str, Any]) -> dict[str, Any]:
        dn = entry["dn"]
        guid = entry["guid"]
        attrs = entry["attrs"]
        name = first(attrs.get("ou")) or (dn_rdn_value(dn) if dn else None)
        if not guid or not dn or not name:
            raise UnparseableEntryError()
        return {
            "connection_id": row.id,
            "object_guid": guid,
            "distinguished_name": dn,
            "name": name,
            "parent_dn": dn.split(",", 1)[1] if "," in dn else None,
        }

    keys = ["distinguished_name", "name", "parent_dn"]
    return _stream_upsert(
        client,
        db,
        search_base=row.search_base,
        search_filter=build_filter({"objectClass": "organizationalUnit"}),
        attributes=["objectGUID", "distinguishedName", "ou"],
        model=DirectoryOrganizationalUnit,
        map_entry=map_entry,
        update_keys=keys,
        counters=counters,
    )


def _sync_users(
    db: Session,
    row: DirectoryConnection,
    client: DirectoryLdapClient,
    counters: dict[str, int],
    now: datetime,
) -> dict[str, Any]:
    # objectCategory=person excludes computer objects (which also carry
    # objectClass=user in AD).
    def map_entry(entry: dict[str, Any]) -> dict[str, Any]:
        dn = entry["dn"]
        guid = entry["guid"]
        attrs = entry["attrs"]
        sam = first(attrs.get("samaccountname"))
        if not guid or not dn or not sam:
            raise UnparseableEntryError()
        return {
            "connection_id": row.id,
            "object_guid": guid,
            "distinguished_name": dn,
            "sid": ad_sid(attrs.get("objectsid")),
            "sam_account_name": sam,
            "user_principal_name": first(attrs.get("userprincipalname")),
            "display_name": first(attrs.get("displayname")),
            "email": first(attrs.get("mail")),
            "enabled": uac_enabled(attrs.get("useraccountcontrol")),
            "department": first(attrs.get("department")),
            "title": first(attrs.get("title")),
            "manager_dn": first(attrs.get("manager")),
            "last_logon_at": ad_time(attrs.get("lastlogontimestamp")),
            "ad_created_at": ad_time(attrs.get("whencreated")),
            "ad_changed_at": ad_time(attrs.get("whenchanged")),
        }

    keys = [
        "distinguished_name",
        "sid",
        "sam_account_name",
        "user_principal_name",
        "display_name",
        "email",
        "enabled",
        "department",
        "title",
        "manager_dn",
        "last_logon_at",
        "ad_created_at",
        "ad_changed_at",
    ]
    return _stream_upsert(
        client,
        db,
        search_base=row.search_base,
        search_filter=build_filter({"objectCategory": "person", "objectClass": "user"}),
        attributes=[
            "objectGUID",
            "distinguishedName",
            "objectSid",
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "mail",
            "userAccountControl",
            "department",
            "title",
            "manager",
            "lastLogonTimestamp",
            "whenCreated",
            "whenChanged",
        ],
        model=DirectoryUser,
        map_entry=map_entry,
        update_keys=keys,
        counters=counters,
    )


def _sync_groups(
    db: Session,
    row: DirectoryConnection,
    client: DirectoryLdapClient,
    counters: dict[str, int],
    now: datetime,
) -> dict[str, Any]:
    def map_entry(entry: dict[str, Any]) -> dict[str, Any]:
        dn = entry["dn"]
        guid = entry["guid"]
        attrs = entry["attrs"]
        name = first(attrs.get("cn")) or (dn_rdn_value(dn) if dn else None)
        if not guid or not dn or not name:
            raise UnparseableEntryError()
        scope, category = _group_scope_category(attrs.get("grouptype"))
        return {
            "connection_id": row.id,
            "object_guid": guid,
            "distinguished_name": dn,
            "sid": ad_sid(attrs.get("objectsid")),
            "name": name,
            "description": first(attrs.get("description")),
            "scope": scope,
            "category": category,
        }

    keys = ["distinguished_name", "sid", "name", "description", "scope", "category"]
    return _stream_upsert(
        client,
        db,
        search_base=row.search_base,
        search_filter=build_filter({"objectClass": "group"}),
        attributes=[
            "objectGUID",
            "distinguishedName",
            "objectSid",
            "cn",
            "description",
            "groupType",
        ],
        model=DirectoryGroup,
        map_entry=map_entry,
        update_keys=keys,
        counters=counters,
    )


def _sync_computers(
    db: Session,
    row: DirectoryConnection,
    client: DirectoryLdapClient,
    counters: dict[str, int],
    now: datetime,
) -> dict[str, Any]:
    def map_entry(entry: dict[str, Any]) -> dict[str, Any]:
        dn = entry["dn"]
        guid = entry["guid"]
        attrs = entry["attrs"]
        name = first(attrs.get("name")) or (dn_rdn_value(dn) if dn else None)
        if not guid or not dn or not name:
            raise UnparseableEntryError()
        return {
            "connection_id": row.id,
            "object_guid": guid,
            "distinguished_name": dn,
            "sid": ad_sid(attrs.get("objectsid")),
            "name": name,
            "dns_hostname": first(attrs.get("dnshostname")),
            "os": first(attrs.get("operatingsystem")),
            "os_version": first(attrs.get("operatingsystemversion")),
            "enabled": uac_enabled(attrs.get("useraccountcontrol")),
            "last_logon_at": ad_time(attrs.get("lastlogontimestamp")),
            "ad_changed_at": ad_time(attrs.get("whenchanged")),
        }

    keys = [
        "distinguished_name",
        "sid",
        "name",
        "dns_hostname",
        "os",
        "os_version",
        "enabled",
        "last_logon_at",
        "ad_changed_at",
    ]
    return _stream_upsert(
        client,
        db,
        search_base=row.search_base,
        search_filter=build_filter({"objectClass": "computer"}),
        attributes=[
            "objectGUID",
            "distinguishedName",
            "objectSid",
            "name",
            "dNSHostName",
            "operatingSystem",
            "operatingSystemVersion",
            "userAccountControl",
            "lastLogonTimestamp",
            "whenChanged",
        ],
        model=DirectoryComputer,
        map_entry=map_entry,
        update_keys=keys,
        counters=counters,
    )


def _sync_memberships(
    db: Session,
    row: DirectoryConnection,
    client: DirectoryLdapClient,
    counters: dict[str, int],
    now: datetime,
) -> dict[str, Any]:
    """Rebuild this connection's group edges from the directory.

    The edge set is replaced wholesale INSIDE the sync transaction: a
    later failure rolls back, restoring the previous edge set exactly.
    Members are resolved against the mirror (batched, no N+1); members
    not present locally (foreign security principals) are stored as
    ``unknown`` with a NULL guid — never guessed.
    """
    db.execute(
        delete(DirectoryGroupMembership).where(
            DirectoryGroupMembership.connection_id == row.id
        )
    )
    discovered = 0
    buffer: list[dict[str, Any]] = []

    def flush(entries: list[dict[str, Any]]) -> None:
        nonlocal discovered
        if not entries:
            return
        guids = [e["guid"] for e in entries if e["guid"]]
        id_by_guid: dict[str, uuid.UUID] = {}
        if guids:
            id_by_guid = {
                guid: group_id
                for guid, group_id in db.execute(
                    select(
                        DirectoryGroup.object_guid, DirectoryGroup.id
                    ).where(
                        DirectoryGroup.connection_id == row.id,
                        DirectoryGroup.object_guid.in_(guids),
                    )
                ).all()
            }
        member_dns = {
            dn
            for e in entries
            for dn in as_list(e["attrs"].get("member"))
            if dn
        }
        type_by_dn, guid_by_dn = _resolve_members(db, row.id, member_dns)
        rows: list[dict[str, Any]] = []
        seen: set[tuple[uuid.UUID, str]] = set()
        for entry in entries:
            group_id = id_by_guid.get(entry["guid"] or "")
            if group_id is None:
                continue  # groups stage guarantees presence; defensive skip
            for dn in as_list(entry["attrs"].get("member")):
                if not dn:
                    continue
                key = (group_id, dn)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "connection_id": row.id,
                        "group_id": group_id,
                        "member_type": type_by_dn.get(dn, "unknown"),
                        "member_dn": dn,
                        "member_object_guid": guid_by_dn.get(dn),
                        "synced_at": now,
                    }
                )
        discovered += len(rows)
        for chunk in _chunks(rows, _MEMBER_CHUNK):
            stmt = pg_insert(DirectoryGroupMembership).values(chunk)
            # Duplicate edges (same group returned twice mid-sync) are
            # skipped instead of failing the category.
            stmt = stmt.on_conflict_do_nothing(
                constraint="uq_directory_group_memberships_group_member"
            )
            db.execute(stmt)

    for entry in client.paged_search(
        search_base=row.search_base,
        search_filter=build_filter({"objectClass": "group"}),
        attributes=["objectGUID", "member"],
    ):
        if not entry["guid"] or not entry["dn"]:
            raise UnparseableEntryError()
        buffer.append(entry)
        if len(buffer) >= _UPSERT_CHUNK:
            flush(buffer)
            buffer = []
    flush(buffer)

    counters["discovered"] += discovered
    return {"discovered": discovered}


def _resolve_members(
    db: Session, connection_id: uuid.UUID, dns: set[str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Batch-resolve member DNs against the local mirror (no N+1)."""
    type_by_dn: dict[str, str] = {}
    guid_by_dn: dict[str, str] = {}
    if not dns:
        return type_by_dn, guid_by_dn
    dns_list = list(dns)
    for chunk in _chunks(dns_list, _MEMBER_CHUNK):
        for model, member_type in (
            (DirectoryUser, MEMBER_USER),
            (DirectoryGroup, MEMBER_GROUP),
            (DirectoryComputer, MEMBER_COMPUTER),
        ):
            rows = db.execute(
                select(model.distinguished_name, model.object_guid).where(
                    model.connection_id == connection_id,
                    model.distinguished_name.in_(chunk),
                )
            ).all()
            for dn, guid in rows:
                type_by_dn[dn] = member_type
                guid_by_dn[dn] = guid
    return type_by_dn, guid_by_dn


def _mark_missing(
    db: Session,
    row: DirectoryConnection,
    counters: dict[str, int],
    now: datetime,
) -> dict[str, Any]:
    """Soft-delete objects absent longer than the grace period.

    Runs ONLY via the gate (all required categories succeeded). Single
    atomic UPDATE per table; rows are never hard-deleted (history kept).
    Objects seen again are revived by the upserts (missing_since=None).
    """
    settings = get_settings()
    cutoff = now - timedelta(days=settings.directory_missing_grace_days)
    marked = 0
    for model in (
        DirectoryOrganizationalUnit,
        DirectoryUser,
        DirectoryGroup,
        DirectoryComputer,
    ):
        result = db.execute(
            update(model)
            .where(
                model.connection_id == row.id,
                model.missing_since.is_(None),
                model.last_seen_at < cutoff,
            )
            .values(missing_since=now)
        )
        marked += int(getattr(result, "rowcount", 0) or 0)
    counters["marked_missing"] = marked
    return {"marked_missing": marked}


def _reconcile(
    db: Session,
    row: DirectoryConnection,
    now: datetime,
) -> dict[str, Any]:
    """AD computer <-> endpoint matching (never destructive, never guessed).

    - exact ``dNSHostName`` == endpoint FQDN, case-insensitive, and the
      endpoint FQDN is UNIQUE among non-revoked endpoints -> ``matched``
      (high). Two+ endpoints sharing the FQDN -> ``needs_review``.
    - short-hostname candidates -> ALWAYS ``needs_review`` (never auto).
    - rows created with method ``manual`` (operator decisions) are never
      overwritten by the engine.
    """
    fqdn_map, short_map = _endpoint_maps(db)
    existing = {
        r.computer_id: r
        for r in db.scalars(
            select(DirectoryReconciliation).where(
                DirectoryReconciliation.connection_id == row.id
            )
        )
    }
    decided = 0
    computers = db.scalars(
        select(DirectoryComputer).where(
            DirectoryComputer.connection_id == row.id,
            DirectoryComputer.missing_since.is_(None),
        )
    ).all()
    for computer in computers:
        method = RECON_SHORT_NAME
        confidence = CONFIDENCE_LOW
        status = RECON_UNMATCHED
        endpoint_id: uuid.UUID | None = None
        candidates: list[str] | None = None

        if computer.dns_hostname:
            ids = fqdn_map.get(computer.dns_hostname.lower(), [])
            if len(ids) == 1:
                # Unique FQDN match -> safe to auto-confirm.
                method = RECON_EXACT_FQDN
                confidence = CONFIDENCE_HIGH
                status = RECON_MATCHED
                endpoint_id = ids[0]
            elif len(ids) > 1:
                # Ambiguous FQDN -> manual review, never automatic.
                method = RECON_EXACT_FQDN
                confidence = CONFIDENCE_MEDIUM
                status = RECON_NEEDS_REVIEW
                candidates = [str(i) for i in ids]

        if status == RECON_UNMATCHED and computer.name:
            ids = short_map.get(computer.name.lower(), [])
            if len(ids) == 1:
                # Short hostname: candidate ONLY — never auto-confirmed.
                method = RECON_SHORT_NAME
                confidence = CONFIDENCE_MEDIUM
                status = RECON_NEEDS_REVIEW
                candidates = [str(i) for i in ids]
            elif len(ids) > 1:
                method = RECON_SHORT_NAME
                confidence = CONFIDENCE_LOW
                status = RECON_NEEDS_REVIEW
                candidates = [str(i) for i in ids]

        existing_row = existing.get(computer.id)
        if existing_row is not None and existing_row.method == "manual":
            continue  # manual decisions are never overwritten by the engine
        if existing_row is not None:
            existing_row.method = method
            existing_row.confidence = confidence
            existing_row.status = status
            existing_row.endpoint_id = endpoint_id
            existing_row.candidates = candidates
            existing_row.updated_at = now
        else:
            db.add(
                DirectoryReconciliation(
                    connection_id=row.id,
                    computer_id=computer.id,
                    endpoint_id=endpoint_id,
                    method=method,
                    confidence=confidence,
                    status=status,
                    candidates=candidates,
                )
            )
        decided += 1
    return {"reconciled": decided}


# --- Shared helpers ----------------------------------------------------------


def _endpoint_maps(
    db: Session,
) -> tuple[dict[str, list[uuid.UUID]], dict[str, list[uuid.UUID]]]:
    """lower(fqdn)/lower(hostname) -> endpoint ids (revoked excluded).

    The lists ARE the uniqueness check: len == 1 allows an automatic
    exact-FQDN match, len > 1 forces manual review.
    """
    fqdn_map: dict[str, list[uuid.UUID]] = {}
    short_map: dict[str, list[uuid.UUID]] = {}
    stmt = select(Endpoint.id, Endpoint.fqdn, Endpoint.hostname).where(
        Endpoint.status != ENDPOINT_REVOKED
    )
    for endpoint_id, fqdn, hostname in db.execute(stmt):
        if fqdn:
            fqdn_map.setdefault(fqdn.lower(), []).append(endpoint_id)
        if hostname:
            short_map.setdefault(hostname.lower(), []).append(endpoint_id)
    return fqdn_map, short_map


def _stream_upsert(
    client: DirectoryLdapClient,
    db: Session,
    *,
    search_base: str,
    search_filter: str,
    attributes: list[str],
    model: Any,
    map_entry: Callable[[dict[str, Any]], dict[str, Any]],
    update_keys: list[str],
    counters: dict[str, int],
) -> dict[str, Any]:
    """Stream a paged search into chunked keyed upserts.

    Memory stays O(chunk): entries are mapped and written every
    ``_UPSERT_CHUNK`` entries, never accumulated for the whole category.
    """
    discovered = 0
    buffer: list[dict[str, Any]] = []

    def flush(rows: list[dict[str, Any]]) -> None:
        _upsert_by_guid(db, model, rows, update_keys, counters)

    for entry in client.paged_search(
        search_base=search_base,
        search_filter=search_filter,
        attributes=attributes,
    ):
        buffer.append(map_entry(entry))  # raises UnparseableEntryError
        discovered += 1
        if len(buffer) >= _UPSERT_CHUNK:
            flush(buffer)
            buffer = []
    if buffer:
        flush(buffer)
    counters["discovered"] += discovered
    return {"discovered": discovered}


def _upsert_by_guid(
    db: Session,
    model: Any,
    rows: list[dict[str, Any]],
    update_keys: list[str],
    counters: dict[str, int],
) -> None:
    """Bulk upsert keyed (connection_id, object_guid).

    Seen-again rows get ``missing_since=None`` (revival). ``xmax = 0``
    distinguishes inserted from updated rows for the run counters.
    Duplicate GUIDs inside one chunk are collapsed (last wins) so the
    statement can never affect a row twice.
    """
    if not rows:
        return
    deduped = {row["object_guid"]: row for row in rows}
    for chunk in _chunks(list(deduped.values()), _UPSERT_CHUNK):
        insert_stmt = pg_insert(model).values(chunk)
        set_map = {key: getattr(insert_stmt.excluded, key) for key in update_keys}
        set_map["last_seen_at"] = datetime.now(UTC)
        set_map["missing_since"] = None
        upsert_stmt = insert_stmt.on_conflict_do_update(
            index_elements=[model.connection_id, model.object_guid],
            set_=set_map,
        ).returning(text("(xmax = 0)"))
        flags = db.execute(upsert_stmt).scalars().all()
        counters["created"] += sum(1 for inserted in flags if inserted)
        counters["updated"] += sum(1 for inserted in flags if not inserted)


def _group_scope_category(value: Any) -> tuple[str | None, str | None]:
    """AD groupType flags -> (scope, category); None when unparseable."""
    raw = first(value)
    if raw is None:
        return None, None
    try:
        flags = int(raw) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None, None
    if flags & 0x2:
        scope: str | None = GROUP_SCOPE_GLOBAL
    elif flags & 0x4:
        scope = GROUP_SCOPE_DOMAIN_LOCAL
    elif flags & 0x8:
        scope = GROUP_SCOPE_UNIVERSAL
    else:
        scope = None
    category = (
        GROUP_CATEGORY_SECURITY if flags & 0x80000000 else GROUP_CATEGORY_DISTRIBUTION
    )
    return scope, category


def _chunks(items: list[Any], size: int) -> Iterator[list[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


__all__ = [
    "GATE_REQUIRED",
    "PIPELINE",
    "execute_sync",
    "failed_results",
    "initial_category_results",
]
