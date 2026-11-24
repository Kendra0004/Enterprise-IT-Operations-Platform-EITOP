"""Directory security findings engine (Phase 3.2.1).

Read-only analytics over the AD mirror: identifies privileged principals
(SID-based, with an explicit DN/CN fallback), walks nested-group
membership with a bounded BFS, evaluates the rule catalog and drives the
finding lifecycle (create / refresh / auto-resolve / reopen) under a
per-connection advisory lock.

Hard rules:
- This module NEVER imports the LDAP client (test-enforced via AST): it
  only reads mirror tables and never writes to Active Directory.
- Inventory completeness is decided from the NEWEST sync run regardless
  of its status — an older successful run never backstops a newer failed
  one.
- Absence-based rules and auto-resolve only run against a complete
  inventory; ``suppressed`` findings are never touched by recomputation.
- Every lifecycle transition appends an audit_logs row with
  ``actor_email="system"``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request, status
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import AppError
from app.models import (
    ACCESS_DIRECT,
    ACCESS_TRANSITIVE,
    ENDPOINT_ACTIVE,
    FINDING_ACKNOWLEDGED,
    FINDING_OPEN,
    FINDING_RESOLVED,
    FINDING_SUBJECT_COMPUTER,
    FINDING_SUBJECT_CONNECTION,
    FINDING_SUBJECT_GROUP,
    FINDING_SUBJECT_UNKNOWN,
    FINDING_SUBJECT_USER,
    FINDING_SUPPRESSED,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SYNC_SUCCESS,
    VISIBILITY_FULL,
    VISIBILITY_INSUFFICIENT,
    VISIBILITY_PARTIAL,
    AuditLog,
    DirectoryComputer,
    DirectoryDomain,
    DirectoryFinding,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectoryReconciliation,
    DirectorySyncRun,
    DirectoryUser,
    Endpoint,
    User,
)
from app.services.auth_service import _record_audit

logger = logging.getLogger(__name__)

# --- Constants ---------------------------------------------------------------

# Advisory-lock namespace (distinct from the sync ownership namespace).
INSIGHTS_LOCK_NS = 846_211
# Hard bounds on the nested-group walk: depth comes from config, the node
# budget is a constant backstop against pathological graphs.
_NODE_BUDGET = 10_000
_ALTERNATE_PATH_CAP = 3
_FINGERPRINT_MAX = 160
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9_.:|=|-]+$")

# Mirrors sync_engine.PIPELINE — duplicated (not imported) on purpose:
# importing sync_engine would pull the LDAP client into this module's
# import graph. tests/test_directory_insights.py asserts equality.
INVENTORY_CATEGORIES = (
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

# --- Rule catalog ------------------------------------------------------------

RULE_DIRECT = "privileged.direct_member"
RULE_TRANSITIVE = "privileged.transitive_member"
RULE_UNKNOWN_MEMBER = "privileged.unknown_member"
RULE_DISABLED_MEMBER = "privileged.disabled_member"
RULE_DIST_ANOMALY = "privileged.distribution_member_anomaly"
RULE_DISABLED_PERSIST = "computer.disabled_persist"
RULE_MISSING_GRACE = "computer.missing_after_grace"
RULE_USER_INACTIVE = "user.inactive"
RULE_NO_LOGON = "user.no_logon_data"
RULE_COMPUTER_STALE = "computer.stale"
RULE_SYNC_FRESHNESS = "connection.sync_freshness"
RULE_INVENTORY_EMPTY = "connection.inventory_empty"

RULE_KEYS = (
    RULE_DIRECT,
    RULE_TRANSITIVE,
    RULE_UNKNOWN_MEMBER,
    RULE_DISABLED_MEMBER,
    RULE_DIST_ANOMALY,
    RULE_DISABLED_PERSIST,
    RULE_MISSING_GRACE,
    RULE_USER_INACTIVE,
    RULE_NO_LOGON,
    RULE_COMPUTER_STALE,
    RULE_SYNC_FRESHNESS,
    RULE_INVENTORY_EMPTY,
)

# --- Privileged SID identification (Fix 1) -----------------------------------

# Domain-relative privileged RIDs (511 is deliberately NOT privileged;
# 517 is opt-off). Matched only against an exact 8-token SID whose first
# seven tokens equal the domain SID — never a string prefix match.
PRIVILEGED_DOMAIN_RIDS = frozenset({512, 518, 519, 520})
# Builtin privileged RIDs: exact S-1-5-32-<RID> (five tokens). 547
# (Power Users) is opt-off.
PRIVILEGED_BUILTIN_RIDS = frozenset({544, 548, 549, 550, 551, 552})

# DN/CN fallback used ONLY when sid IS NULL (detection="dn_fallback").
_PRIVILEGED_CN_RIDS: dict[str, int] = {
    "domain admins": 512,
    "schema admins": 518,
    "enterprise admins": 519,
    "group policy creator owners": 520,
    "administrators": 544,
    "account operators": 548,
    "server operators": 549,
    "print operators": 550,
    "backup operators": 551,
    "replicator": 552,
}


def _parse_rid(token: str) -> int | None:
    """RID token → int; rejects empties, non-digits and leading zeros."""
    if not token or not token.isdigit():
        return None
    if len(token) > 1 and token[0] == "0":
        return None
    return int(token)


def builtin_privileged_rid(sid: str | None) -> int | None:
    """Privileged BUILTIN RID from an exact ``S-1-5-32-<RID>`` string.

    Exactly five tokens, ``S-1-5-32`` prefix, no leading zeros. Anything
    else (longer SIDs, other authorities, malformed RIDs) → None.
    """
    if not sid:
        return None
    parts = sid.split("-")
    if len(parts) != 5:
        return None
    if parts[0] != "S" or parts[1] != "1" or parts[2] != "5" or parts[3] != "32":
        return None
    rid = _parse_rid(parts[4])
    if rid is None or rid not in PRIVILEGED_BUILTIN_RIDS:
        return None
    return rid


def domain_privileged_rid(sid: str | None, domain_sid: str | None) -> int | None:
    """Privileged domain-relative RID with an exact token boundary.

    Requires exactly 8 tokens with ``tokens[:7] == domain_sid tokens`` —
    a string ``startswith`` prefix (e.g. domain ``...-333`` vs SID
    ``...-3330-512``) can never match.
    """
    if not sid or not domain_sid:
        return None
    parts = sid.split("-")
    dom = domain_sid.split("-")
    if len(dom) != 7 or len(parts) != 8:
        return None
    if parts[:7] != dom:
        return None
    rid = _parse_rid(parts[7])
    if rid is None or rid not in PRIVILEGED_DOMAIN_RIDS:
        return None
    return rid


# --- Fingerprints (deterministic, bounded, path-independent) -----------------


def object_key(guid: str | None, dn: str | None) -> str:
    """Stable object key: objectGUID when known, else sha256(lower DN)[:24].

    GUID-keyed identity survives renames/DN moves; long DNs are hashed,
    never truncated.
    """
    if guid:
        return f"g:{guid}"
    if dn:
        digest = hashlib.sha256(dn.lower().encode()).hexdigest()[:24]
        return f"n:{digest}"
    raise ValueError("object identity requires a guid or a dn")


def _finalize_fingerprint(raw: str) -> str:
    if len(raw) > _FINGERPRINT_MAX:
        raise ValueError(f"fingerprint exceeds {_FINGERPRINT_MAX} chars")
    if not _FINGERPRINT_RE.match(raw):
        raise ValueError("fingerprint contains unsupported characters")
    return raw


def member_fingerprint(rule_key: str, group_key: str, subject_key: str) -> str:
    """Membership fingerprint: anchor group + subject (path-independent)."""
    return _finalize_fingerprint(f"{rule_key}|m={group_key}|p={subject_key}")


def object_fingerprint(rule_key: str, subject_key: str) -> str:
    """Single-object fingerprint (absence/lifecycle rules)."""
    return _finalize_fingerprint(f"{rule_key}|o={subject_key}")


def connection_fingerprint(rule_key: str, connection_id: uuid.UUID) -> str:
    """Connection-level fingerprint."""
    return _finalize_fingerprint(f"{rule_key}|c={connection_id}")


# --- Inventory completeness (Fix 2) ------------------------------------------


def newest_sync_run(db: Session, connection_id: uuid.UUID) -> DirectorySyncRun | None:
    """NEWEST sync run by started_at — regardless of status."""
    return db.scalar(
        select(DirectorySyncRun)
        .where(DirectorySyncRun.connection_id == connection_id)
        .order_by(DirectorySyncRun.started_at.desc())
        .limit(1)
    )


def missing_categories(results: Any) -> list[str]:
    """PIPELINE categories that do not explicitly report success."""
    if not isinstance(results, dict):
        return list(INVENTORY_CATEGORIES)
    missing: list[str] = []
    for category in INVENTORY_CATEGORIES:
        entry = results.get(category)
        if not isinstance(entry, dict) or entry.get("status") != "success":
            missing.append(category)
    return missing


def inventory_complete(db: Session, connection_id: uuid.UUID) -> bool:
    """True only when the NEWEST run proves a complete inventory.

    No fallback to an older success: newest status must be ``success``
    and all nine PIPELINE categories must explicitly report
    ``{"status": "success"}``.
    """
    run = newest_sync_run(db, connection_id)
    if run is None or run.status != SYNC_SUCCESS:
        return False
    if not isinstance(run.category_results, dict) or not run.category_results:
        return False
    return not missing_categories(run.category_results)


# --- Privileged group identification -----------------------------------------


@dataclass(frozen=True)
class PrivilegedGroup:
    id: uuid.UUID
    guid: str | None
    dn: str
    name: str
    rid: int
    detection: str  # "sid" | "dn_fallback"
    category: str | None


def identify_privileged_groups(db: Session, connection_id: uuid.UUID) -> list[PrivilegedGroup]:
    """Privileged groups of one connection: SID proof first, CN fallback.

    The DN/CN fallback fires only when ``sid IS NULL`` and marks the row
    ``detection="dn_fallback"`` so evidence can distinguish proof from
    name-matching.
    """
    domain_sids = [
        s
        for s in db.scalars(
            select(DirectoryDomain.sid).where(
                DirectoryDomain.connection_id == connection_id,
                DirectoryDomain.sid.is_not(None),
            )
        )
        if s
    ]
    groups = db.scalars(
        select(DirectoryGroup).where(DirectoryGroup.connection_id == connection_id)
    ).all()

    out: list[PrivilegedGroup] = []
    for g in groups:
        rid: int | None = None
        detection = "sid"
        if g.sid:
            rid = builtin_privileged_rid(g.sid)
            if rid is None:
                for domain_sid in domain_sids:
                    rid = domain_privileged_rid(g.sid, domain_sid)
                    if rid is not None:
                        break
        if rid is None and g.sid is None:
            cn = (g.name or "").strip().lower() or _cn_from_dn(g.distinguished_name)
            mapped = _PRIVILEGED_CN_RIDS.get(cn)
            if mapped is not None:
                rid = mapped
                detection = "dn_fallback"
        if rid is not None:
            out.append(
                PrivilegedGroup(
                    id=g.id,
                    guid=g.object_guid,
                    dn=g.distinguished_name,
                    name=g.name,
                    rid=rid,
                    detection=detection,
                    category=g.category,
                )
            )
    return out


def _cn_from_dn(dn: str) -> str:
    first_rdn = dn.split(",", 1)[0]
    if first_rdn.upper().startswith("CN="):
        return first_rdn[3:]
    return first_rdn


# --- Bounded nested-group traversal ------------------------------------------


@dataclass
class _ObjectRef:
    guid: str
    name: str
    enabled: bool | None


@dataclass
class _MemberRecord:
    dn: str
    member_type: str
    guid: str | None
    name: str | None
    resolved: bool
    enabled: bool | None
    access: str
    hops: int
    path: list[str]
    confirmed: bool
    anchor: PrivilegedGroup


@dataclass
class _AnomalyRecord:
    dn: str
    guid: str | None
    name: str | None
    anchor: PrivilegedGroup
    path: list[str]
    hops: int


@dataclass
class _Traversal:
    members: dict[str, _MemberRecord]  # key: subject DN lower()
    alternates: dict[str, list[list[str]]]  # alternate routes, capped
    anomalies: dict[tuple[uuid.UUID, str], _AnomalyRecord]
    reasons: set[str]


def _resolve_group(
    edge_dn: str,
    edge_guid: str | None,
    groups_by_guid: dict[str, DirectoryGroup],
    groups_by_dn: dict[str, DirectoryGroup],
) -> DirectoryGroup | None:
    if edge_guid:
        hit = groups_by_guid.get(edge_guid)
        if hit is not None:
            return hit
    return groups_by_dn.get(edge_dn.lower())


def _remember(
    traversal: _Traversal,
    record: _MemberRecord,
) -> None:
    """Deduplicate by subject DN: shortest path wins, alternates capped."""
    key = record.dn.lower()
    current = traversal.members.get(key)
    if current is None:
        traversal.members[key] = record
        traversal.alternates[key] = []
        return
    if record.hops < current.hops:
        traversal.alternates[key].append(current.path)
        traversal.members[key] = record
    elif record.path != current.path and len(traversal.alternates[key]) < _ALTERNATE_PATH_CAP:
        traversal.alternates[key].append(record.path)


def _traverse(
    privileged: list[PrivilegedGroup],
    adjacency: dict[uuid.UUID, list[DirectoryGroupMembership]],
    groups_by_guid: dict[str, DirectoryGroup],
    groups_by_dn: dict[str, DirectoryGroup],
    users_by_dn: dict[str, _ObjectRef],
    computers_by_dn: dict[str, _ObjectRef],
    max_depth: int,
) -> _Traversal:
    """BFS from privileged groups: direct/transitive membership + verdict.

    Bounds: depth cap (config), node budget (constant), visited-set cycle
    detection. Unresolved members (FSPs, stale edges) become ``unknown``
    records and are never traversed; a distribution branch emits an
    anomaly only and is not traversed (its members inherit nothing).

    Every record keeps the ROOT privileged group as its anchor so the
    fingerprint collapses all nested routes to one row (path-independent).
    """
    traversal = _Traversal(
        members={},
        alternates={},
        anomalies={},
        reasons=set(),
    )
    visited: set[uuid.UUID] = set()
    nodes = 0
    # (current group id, depth, path ids, path DNs, confirmed, root anchor)
    queue: deque[
        tuple[uuid.UUID, int, list[uuid.UUID], list[str], bool, PrivilegedGroup]
    ] = deque()
    for pg in privileged:
        # SID proof implies a security group; a CN-fallback anchor only
        # counts as confirmed when its groupType says "security".
        anchor_confirmed = pg.detection == "sid" or pg.category == "security"
        if not anchor_confirmed:
            traversal.reasons.add("untyped_group")
        queue.append((pg.id, 0, [pg.id], [pg.dn], anchor_confirmed, pg))

    while queue:
        group_id, depth, path_ids, path_dns, confirmed, anchor = queue.popleft()
        if group_id in visited:
            continue
        visited.add(group_id)
        edges = adjacency.get(group_id, [])
        if depth >= max_depth:
            if edges:
                traversal.reasons.add("truncated_depth")
            continue
        for edge in edges:
            nodes += 1
            if nodes > _NODE_BUDGET:
                traversal.reasons.add("truncated_budget")
                queue.clear()
                break
            hops = depth + 1
            access = ACCESS_DIRECT if hops == 1 else ACCESS_TRANSITIVE
            member_dn = edge.member_dn

            if edge.member_type == "group":
                target = _resolve_group(
                    member_dn, edge.member_object_guid, groups_by_guid, groups_by_dn
                )
                if target is None:
                    traversal.reasons.add("missing_group")
                    _remember(
                        traversal,
                        _MemberRecord(
                            dn=member_dn,
                            member_type=FINDING_SUBJECT_UNKNOWN,
                            guid=None,
                            name=_cn_from_dn(member_dn),
                            resolved=False,
                            enabled=None,
                            access=access,
                            hops=hops,
                            path=[*path_dns, member_dn],
                            confirmed=confirmed,
                            anchor=anchor,
                        ),
                    )
                    continue
                if target.category == "distribution":
                    # Anomaly only: visibility is NOT downgraded and the
                    # branch is not traversed.
                    key = (anchor.id, member_dn.lower())
                    existing = traversal.anomalies.get(key)
                    record = _AnomalyRecord(
                        dn=member_dn,
                        guid=target.object_guid,
                        name=target.name,
                        anchor=anchor,
                        path=[*path_dns, member_dn],
                        hops=hops,
                    )
                    if existing is None or record.hops < existing.hops:
                        traversal.anomalies[key] = record
                    continue
                _remember(
                    traversal,
                    _MemberRecord(
                        dn=member_dn,
                        member_type=FINDING_SUBJECT_GROUP,
                        guid=target.object_guid,
                        name=target.name,
                        resolved=True,
                        enabled=None,
                        access=access,
                        hops=hops,
                        path=[*path_dns, member_dn],
                        confirmed=confirmed,
                        anchor=anchor,
                    ),
                )
                if target.id in path_ids:
                    traversal.reasons.add("cycle")
                    continue
                if target.id in visited:
                    continue
                if target.category is None:
                    # groupType unknown → everything beyond this point is
                    # unconfirmed and visibility becomes partial.
                    traversal.reasons.add("untyped_group")
                target_confirmed = confirmed and target.category == "security"
                queue.append(
                    (
                        target.id,
                        depth + 1,
                        [*path_ids, target.id],
                        [*path_dns, member_dn],
                        target_confirmed,
                        anchor,
                    )
                )
                continue

            if edge.member_type == FINDING_SUBJECT_UNKNOWN:
                # Foreign security principal / unresolved FSP: honest
                # "unknown" subject, never traversed.
                traversal.reasons.add("unresolved_member")
                _remember(
                    traversal,
                    _MemberRecord(
                        dn=member_dn,
                        member_type=FINDING_SUBJECT_UNKNOWN,
                        guid=None,
                        name=_cn_from_dn(member_dn),
                        resolved=False,
                        enabled=None,
                        access=access,
                        hops=hops,
                        path=[*path_dns, member_dn],
                        confirmed=confirmed,
                        anchor=anchor,
                    ),
                )
                continue

            ref: _ObjectRef | None = None
            subject_type = edge.member_type
            if edge.member_type == FINDING_SUBJECT_USER:
                ref = users_by_dn.get(member_dn.lower())
            elif edge.member_type == FINDING_SUBJECT_COMPUTER:
                ref = computers_by_dn.get(member_dn.lower())
            if ref is None:
                # Typed member with no mirror row: stale edge — report
                # honestly as unknown and mark visibility partial.
                traversal.reasons.add("unresolved_member")
                _remember(
                    traversal,
                    _MemberRecord(
                        dn=member_dn,
                        member_type=FINDING_SUBJECT_UNKNOWN,
                        guid=None,
                        name=_cn_from_dn(member_dn),
                        resolved=False,
                        enabled=None,
                        access=access,
                        hops=hops,
                        path=[*path_dns, member_dn],
                        confirmed=confirmed,
                        anchor=anchor,
                    ),
                )
                continue
            _remember(
                traversal,
                _MemberRecord(
                    dn=member_dn,
                    member_type=subject_type,
                    guid=ref.guid,
                    name=ref.name,
                    resolved=True,
                    enabled=ref.enabled,
                    access=access,
                    hops=hops,
                    path=[*path_dns, member_dn],
                    confirmed=confirmed,
                    anchor=anchor,
                ),
            )
    return traversal


# --- Pending finding payload -------------------------------------------------


@dataclass
class _Pending:
    fingerprint: str
    rule_key: str
    severity: str
    subject_type: str
    access: str | None
    subject_guid: str | None
    subject_dn: str | None
    subject_name: str | None
    title: str
    detail: dict[str, Any]


def _visibility(
    complete: bool, reasons: set[str]
) -> tuple[str, list[str]]:
    reason_list = sorted(reasons)
    if not complete:
        reason_list = ["inventory_incomplete", *reason_list]
        return VISIBILITY_INSUFFICIENT, reason_list
    if reason_list:
        return VISIBILITY_PARTIAL, reason_list
    return VISIBILITY_FULL, []


def _privileged_findings(
    traversal: _Traversal,
    visibility: str,
    visibility_reasons: list[str],
) -> list[_Pending]:
    out: list[_Pending] = []
    for record in traversal.members.values():
        anchor_key = object_key(record.anchor.guid, record.anchor.dn)
        subject_key = object_key(record.guid, record.dn)
        base_detail: dict[str, Any] = {
            "hops": record.hops,
            "path": record.path,
            "alternate_paths": traversal.alternates.get(record.dn.lower(), [])[
                :_ALTERNATE_PATH_CAP
            ],
            "privileged_group": {
                "name": record.anchor.name,
                "dn": record.anchor.dn,
                "rid": record.anchor.rid,
                "detection": record.anchor.detection,
            },
            "confirmed_security": record.confirmed,
            "privilege_visibility": visibility,
            "visibility_reasons": visibility_reasons,
        }
        if record.resolved:
            direct = record.access == ACCESS_DIRECT
            rule = RULE_DIRECT if direct else RULE_TRANSITIVE
            # Direct edges are proven; transitive through untyped
            # (groupType NULL) intermediates downgrade to medium.
            severity = SEVERITY_HIGH if direct or record.confirmed else SEVERITY_MEDIUM
            subject_type = record.member_type
            if subject_type not in (
                FINDING_SUBJECT_USER,
                FINDING_SUBJECT_GROUP,
                FINDING_SUBJECT_COMPUTER,
            ):
                subject_type = FINDING_SUBJECT_UNKNOWN
            verb = "Direct" if direct else "Transitive"
            out.append(
                _Pending(
                    fingerprint=member_fingerprint(rule, anchor_key, subject_key),
                    rule_key=rule,
                    severity=severity,
                    subject_type=subject_type,
                    access=record.access,
                    subject_guid=record.guid,
                    subject_dn=record.dn,
                    subject_name=record.name,
                    title=(
                        f"{verb} member of privileged group {record.anchor.name}"
                    )[:255],
                    detail=dict(base_detail),
                )
            )
            if (
                record.enabled is False
                and subject_type in (FINDING_SUBJECT_USER, FINDING_SUBJECT_COMPUTER)
            ):
                out.append(
                    _Pending(
                        fingerprint=member_fingerprint(
                            RULE_DISABLED_MEMBER, anchor_key, subject_key
                        ),
                        rule_key=RULE_DISABLED_MEMBER,
                        severity=SEVERITY_HIGH,
                        subject_type=subject_type,
                        access=record.access,
                        subject_guid=record.guid,
                        subject_dn=record.dn,
                        subject_name=record.name,
                        title=(
                            f"Disabled principal in privileged group "
                            f"{record.anchor.name}"
                        )[:255],
                        detail=dict(base_detail),
                    )
                )
        else:
            out.append(
                _Pending(
                    fingerprint=member_fingerprint(
                        RULE_UNKNOWN_MEMBER, anchor_key, subject_key
                    ),
                    rule_key=RULE_UNKNOWN_MEMBER,
                    severity=SEVERITY_MEDIUM,
                    subject_type=FINDING_SUBJECT_UNKNOWN,
                    access=record.access,
                    subject_guid=None,
                    subject_dn=record.dn,
                    subject_name=record.name,
                    title=(
                        f"Unresolved member of privileged group {record.anchor.name}"
                    )[:255],
                    detail=dict(base_detail),
                )
            )
    for anomaly in traversal.anomalies.values():
        anchor_key = object_key(anomaly.anchor.guid, anomaly.anchor.dn)
        subject_key = object_key(anomaly.guid, anomaly.dn)
        detail = {
            "hops": anomaly.hops,
            "path": anomaly.path,
            "category": "distribution",
            "privileged_group": {
                "name": anomaly.anchor.name,
                "dn": anomaly.anchor.dn,
                "rid": anomaly.anchor.rid,
                "detection": anomaly.anchor.detection,
            },
            "privilege_visibility": visibility,
            "visibility_reasons": visibility_reasons,
            "note": "distribution branch not traversed; visibility unchanged",
        }
        out.append(
            _Pending(
                fingerprint=member_fingerprint(RULE_DIST_ANOMALY, anchor_key, subject_key),
                rule_key=RULE_DIST_ANOMALY,
                severity=SEVERITY_LOW,
                subject_type=FINDING_SUBJECT_GROUP,
                access=None,
                subject_guid=anomaly.guid,
                subject_dn=anomaly.dn,
                subject_name=anomaly.name,
                title=(
                    f"Distribution group nested under privileged group "
                    f"{anomaly.anchor.name}"
                )[:255],
                detail=detail,
            )
        )
    return out


# --- Absence / connection rules ----------------------------------------------


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _absence_findings(
    db: Session,
    connection_id: uuid.UUID,
    now: datetime,
    settings: Settings,
) -> list[_Pending]:
    """Absence-based rules — caller gates on a COMPLETE inventory."""
    out: list[_Pending] = []
    user_cutoff = now - timedelta(days=settings.directory_inactive_user_days)
    computer_cutoff = now - timedelta(days=settings.directory_stale_computer_days)

    inactive = db.scalars(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection_id,
            DirectoryUser.missing_since.is_(None),
            DirectoryUser.last_logon_at.is_not(None),
            DirectoryUser.last_logon_at < user_cutoff,
        )
    ).all()
    for u in inactive:
        out.append(
            _Pending(
                fingerprint=object_fingerprint(
                    RULE_USER_INACTIVE,
                    object_key(u.object_guid, u.distinguished_name),
                ),
                rule_key=RULE_USER_INACTIVE,
                severity=SEVERITY_MEDIUM,
                subject_type=FINDING_SUBJECT_USER,
                access=None,
                subject_guid=u.object_guid,
                subject_dn=u.distinguished_name,
                subject_name=u.sam_account_name,
                title=f"User inactive for {settings.directory_inactive_user_days}+ days: "
                f"{u.sam_account_name}"[:255],
                detail={
                    "last_logon_at": _iso(u.last_logon_at),
                    "threshold_days": settings.directory_inactive_user_days,
                },
            )
        )

    no_logon = db.scalars(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection_id,
            DirectoryUser.missing_since.is_(None),
            DirectoryUser.last_logon_at.is_(None),
        )
    ).all()
    for u in no_logon:
        out.append(
            _Pending(
                fingerprint=object_fingerprint(
                    RULE_NO_LOGON,
                    object_key(u.object_guid, u.distinguished_name),
                ),
                rule_key=RULE_NO_LOGON,
                severity=SEVERITY_INFO,
                subject_type=FINDING_SUBJECT_USER,
                access=None,
                subject_guid=u.object_guid,
                subject_dn=u.distinguished_name,
                subject_name=u.sam_account_name,
                title=f"No logon data for user {u.sam_account_name}"[:255],
                detail={"last_logon_at": None},
            )
        )

    stale = db.scalars(
        select(DirectoryComputer).where(
            DirectoryComputer.connection_id == connection_id,
            # Missing objects are covered by computer.missing_after_grace
            # only — never double-reported as stale.
            DirectoryComputer.missing_since.is_(None),
            DirectoryComputer.last_logon_at.is_not(None),
            DirectoryComputer.last_logon_at < computer_cutoff,
        )
    ).all()
    for c in stale:
        out.append(
            _Pending(
                fingerprint=object_fingerprint(
                    RULE_COMPUTER_STALE,
                    object_key(c.object_guid, c.distinguished_name),
                ),
                rule_key=RULE_COMPUTER_STALE,
                severity=SEVERITY_MEDIUM,
                subject_type=FINDING_SUBJECT_COMPUTER,
                access=None,
                subject_guid=c.object_guid,
                subject_dn=c.distinguished_name,
                subject_name=c.name,
                title=(
                    f"Stale computer account (no logon in "
                    f"{settings.directory_stale_computer_days}+ days): {c.name}"
                )[:255],
                detail={
                    "last_logon_at": _iso(c.last_logon_at),
                    "threshold_days": settings.directory_stale_computer_days,
                },
            )
        )
    return out


def _live_endpoints(db: Session, connection_id: uuid.UUID) -> dict[uuid.UUID, str]:
    """computer_id → endpoint status for matched reconciliations."""
    rows = db.execute(
        select(DirectoryReconciliation.computer_id, Endpoint.status)
        .join(Endpoint, Endpoint.id == DirectoryReconciliation.endpoint_id)
        .where(
            DirectoryReconciliation.connection_id == connection_id,
            DirectoryReconciliation.endpoint_id.is_not(None),
        )
    ).all()
    return {row[0]: row[1] for row in rows}


def _disabled_computer_findings(
    db: Session, connection_id: uuid.UUID
) -> list[_Pending]:
    """Disabled computer accounts still present in the mirror.

    Not an absence rule (the object IS present) — runs regardless of
    inventory completeness; only absence rules and auto-resolve are
    gated.
    """
    rows = db.scalars(
        select(DirectoryComputer).where(
            DirectoryComputer.connection_id == connection_id,
            DirectoryComputer.enabled.is_(False),
            DirectoryComputer.missing_since.is_(None),
        )
    ).all()
    out: list[_Pending] = []
    for c in rows:
        out.append(
            _Pending(
                fingerprint=object_fingerprint(
                    RULE_DISABLED_PERSIST,
                    object_key(c.object_guid, c.distinguished_name),
                ),
                rule_key=RULE_DISABLED_PERSIST,
                severity=SEVERITY_MEDIUM,
                subject_type=FINDING_SUBJECT_COMPUTER,
                access=None,
                subject_guid=c.object_guid,
                subject_dn=c.distinguished_name,
                subject_name=c.name,
                title=f"Disabled computer account still present: {c.name}"[:255],
                detail={"enabled": False},
            )
        )
    return out


def _missing_findings(
    db: Session,
    connection_id: uuid.UUID,
    now: datetime,
    settings: Settings,
) -> list[_Pending]:
    """Missing-object rule — runs even under incomplete inventory
    (``missing_since`` is only ever set by a fully-gated sync run)."""
    grace_cutoff = now - timedelta(days=settings.directory_missing_grace_days)
    missing = db.scalars(
        select(DirectoryComputer).where(
            DirectoryComputer.connection_id == connection_id,
            DirectoryComputer.missing_since.is_not(None),
            DirectoryComputer.missing_since < grace_cutoff,
        )
    ).all()
    if not missing:
        return []
    live = _live_endpoints(db, connection_id)
    out: list[_Pending] = []
    for c in missing:
        live_status = live.get(c.id)
        is_live = live_status == ENDPOINT_ACTIVE
        out.append(
            _Pending(
                fingerprint=object_fingerprint(
                    RULE_MISSING_GRACE,
                    object_key(c.object_guid, c.distinguished_name),
                ),
                rule_key=RULE_MISSING_GRACE,
                severity=SEVERITY_HIGH if is_live else SEVERITY_MEDIUM,
                subject_type=FINDING_SUBJECT_COMPUTER,
                access=None,
                subject_guid=c.object_guid,
                subject_dn=c.distinguished_name,
                subject_name=c.name,
                title=f"Computer missing beyond grace period: {c.name}"[:255],
                detail={
                    "missing_since": _iso(c.missing_since),
                    "grace_days": settings.directory_missing_grace_days,
                    "live_endpoint": is_live,
                },
            )
        )
    return out


def _connection_findings(
    db: Session,
    connection_id: uuid.UUID,
    complete: bool,
    newest: DirectorySyncRun | None,
) -> list[_Pending]:
    out: list[_Pending] = []
    if newest is not None and newest.status != SYNC_SUCCESS:
        out.append(
            _Pending(
                fingerprint=connection_fingerprint(RULE_SYNC_FRESHNESS, connection_id),
                rule_key=RULE_SYNC_FRESHNESS,
                severity=SEVERITY_MEDIUM,
                subject_type=FINDING_SUBJECT_CONNECTION,
                access=None,
                subject_guid=None,
                subject_dn=None,
                subject_name=None,
                title="Latest directory sync run did not succeed",
                detail={
                    "status": newest.status,
                    "started_at": _iso(newest.started_at),
                },
            )
        )
    if not complete:
        missing = missing_categories(newest.category_results if newest else None)
        out.append(
            _Pending(
                fingerprint=connection_fingerprint(RULE_INVENTORY_EMPTY, connection_id),
                rule_key=RULE_INVENTORY_EMPTY,
                severity=SEVERITY_MEDIUM,
                subject_type=FINDING_SUBJECT_CONNECTION,
                access=None,
                subject_guid=None,
                subject_dn=None,
                subject_name=None,
                title="Directory inventory incomplete",
                detail={
                    "newest_run_status": newest.status if newest else None,
                    "newest_run_started_at": _iso(newest.started_at) if newest else None,
                    "missing_categories": missing,
                },
            )
        )
    return out


# --- Lifecycle ----------------------------------------------------------------


def _system_audit(
    db: Session,
    event_type: str,
    *,
    target: str,
    detail: dict[str, Any],
) -> None:
    """Append-only system audit row (actor is always "system")."""
    db.add(
        AuditLog(
            event_type=event_type,
            actor_email="system",
            target=target,
            outcome="success",
            detail=json.dumps(detail, default=str),
        )
    )


def _apply_payload(row: DirectoryFinding, pending: _Pending) -> None:
    row.rule_key = pending.rule_key
    row.severity = pending.severity
    row.subject_type = pending.subject_type
    row.access = pending.access
    row.subject_guid = pending.subject_guid
    row.subject_dn = pending.subject_dn
    row.subject_name = pending.subject_name
    row.title = pending.title
    row.detail = pending.detail


def _apply_lifecycle(
    db: Session,
    connection_id: uuid.UUID,
    pending: dict[str, _Pending],
    *,
    complete: bool,
    now: datetime,
) -> dict[str, int]:
    """Create / refresh / auto-resolve / reopen — with full audit.

    - ``suppressed`` rows are excluded from EVERY statement (not even
      last_seen_at moves);
    - auto-resolve only when the condition vanished AND inventory is
      complete;
    - recurrence reopens in place: status=open, resolved_at cleared,
      first_seen_at preserved, reopen_count+1, ack columns cleared.
    """
    counts = {
        "created": 0,
        "refreshed": 0,
        "reopened": 0,
        "resolved": 0,
        "suppressed_untouched": 0,
    }
    existing = {
        row.fingerprint: row
        for row in db.scalars(
            select(DirectoryFinding).where(DirectoryFinding.connection_id == connection_id)
        ).all()
    }

    for fingerprint, item in pending.items():
        row = existing.get(fingerprint)
        if row is None:
            db.add(
                DirectoryFinding(
                    connection_id=connection_id,
                    fingerprint=fingerprint,
                    rule_key=item.rule_key,
                    severity=item.severity,
                    status=FINDING_OPEN,
                    subject_type=item.subject_type,
                    access=item.access,
                    subject_guid=item.subject_guid,
                    subject_dn=item.subject_dn,
                    subject_name=item.subject_name,
                    title=item.title,
                    detail=item.detail,
                    first_seen_at=now,
                    last_seen_at=now,
                    reopen_count=0,
                )
            )
            _system_audit(
                db,
                "directory.finding.created",
                target=fingerprint,
                detail={
                    "connection_id": str(connection_id),
                    "rule_key": item.rule_key,
                    "severity": item.severity,
                    "subject_type": item.subject_type,
                    "subject_dn": item.subject_dn,
                },
            )
            counts["created"] += 1
            continue
        if row.status == FINDING_SUPPRESSED:
            # Suppressed is terminal for recomputation: completely
            # untouched — not even last_seen_at advances.
            counts["suppressed_untouched"] += 1
            continue
        if row.status == FINDING_RESOLVED:
            _apply_payload(row, item)
            row.status = FINDING_OPEN
            row.resolved_at = None
            row.acknowledged_by = None
            row.acknowledged_at = None
            row.reopen_count = (row.reopen_count or 0) + 1
            row.last_seen_at = now
            _system_audit(
                db,
                "directory.finding.reopened",
                target=fingerprint,
                detail={
                    "connection_id": str(connection_id),
                    "rule_key": item.rule_key,
                    "reopen_count": row.reopen_count,
                    "first_seen_at": _iso(row.first_seen_at),
                },
            )
            counts["reopened"] += 1
            continue
        # open | acknowledged → refresh (status and first_seen_at kept).
        _apply_payload(row, item)
        row.last_seen_at = now
        counts["refreshed"] += 1

    if complete:
        for fingerprint, row in existing.items():
            if fingerprint in pending:
                continue
            if row.status in (FINDING_OPEN, FINDING_ACKNOWLEDGED):
                row.status = FINDING_RESOLVED
                row.resolved_at = now
                _system_audit(
                    db,
                    "directory.finding.resolved",
                    target=fingerprint,
                    detail={
                        "connection_id": str(connection_id),
                        "rule_key": row.rule_key,
                        "subject_dn": row.subject_dn,
                        "first_seen_at": _iso(row.first_seen_at),
                    },
                )
                counts["resolved"] += 1
    return counts


# --- Manual lifecycle (Phase 3.2.2) -------------------------------------------


def acknowledge_finding(
    db: Session,
    row: DirectoryFinding,
    *,
    actor: User,
    request: Request | None = None,
    now: datetime | None = None,
) -> DirectoryFinding:
    """Manual ``open -> acknowledged`` transition (``directory:write``).

    State machine rules enforced here (validation BEFORE any mutation,
    so a rejected transition leaves zero writes and zero audit rows —
    the request session rolls back on ``AppError``):

    - already ``acknowledged``: idempotent no-op — no state change,
      no duplicate audit event;
    - ``suppressed``: REJECTED — suppression is only ever lifted via
      ``reopen_finding`` (an ack must not bypass suppressed-state
      protection, which shields the row from recomputation);
    - ``resolved``: REJECTED — the condition is gone; recurrence or an
      explicit reopen is the way back.
    """
    if row.status == FINDING_ACKNOWLEDGED:
        return row
    if row.status != FINDING_OPEN:
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Invalid transition",
            f"Cannot acknowledge a {row.status} finding.",
        )
    clock = now or datetime.now(UTC)
    from_status = row.status
    row.status = FINDING_ACKNOWLEDGED
    row.acknowledged_by = actor.id
    row.acknowledged_at = clock
    _record_audit(
        db,
        event_type="directory.finding.acknowledged",
        outcome="success",
        request=request,
        actor=actor,
        target=row.fingerprint,
        detail={
            "connection_id": str(row.connection_id),
            "finding_id": str(row.id),
            "rule_key": row.rule_key,
            "from_status": from_status,
            "to_status": FINDING_ACKNOWLEDGED,
        },
    )
    return row


def suppress_finding(
    db: Session,
    row: DirectoryFinding,
    *,
    actor: User,
    request: Request | None = None,
    now: datetime | None = None,
) -> DirectoryFinding:
    """Manual ``open|acknowledged -> suppressed`` transition.

    - already ``suppressed``: idempotent no-op (no duplicate audit);
    - ``resolved``: REJECTED (nothing active to suppress);
    - ``suppressed`` is terminal for recomputation — this is the ONLY
      way a row becomes suppressed, and ``reopen_finding`` is the only
      way out;
    - prior ack columns are kept as history (``suppressed_at`` marks
      the current state); a later reopen clears them.
    """
    if row.status == FINDING_SUPPRESSED:
        return row
    if row.status not in (FINDING_OPEN, FINDING_ACKNOWLEDGED):
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Invalid transition",
            f"Cannot suppress a {row.status} finding.",
        )
    clock = now or datetime.now(UTC)
    from_status = row.status
    row.status = FINDING_SUPPRESSED
    row.suppressed_at = clock
    _record_audit(
        db,
        event_type="directory.finding.suppressed",
        outcome="success",
        request=request,
        actor=actor,
        target=row.fingerprint,
        detail={
            "connection_id": str(row.connection_id),
            "finding_id": str(row.id),
            "rule_key": row.rule_key,
            "from_status": from_status,
            "to_status": FINDING_SUPPRESSED,
        },
    )
    return row


def reopen_finding(
    db: Session,
    row: DirectoryFinding,
    *,
    actor: User,
    request: Request | None = None,
    now: datetime | None = None,
) -> DirectoryFinding:
    """Manual transition back to ``open`` from any non-open state.

    - ``resolved -> open`` and ``suppressed -> open`` increment
      ``reopen_count`` — the same counter the automatic recurrence
      uses, so manual and system reopens stay consistent;
    - ``acknowledged -> open`` is an un-acknowledge: ack columns are
      cleared but ``reopen_count`` is NOT bumped (the finding never
      closed);
    - already ``open``: idempotent no-op (no duplicate audit);
    - ``resolved_at``/``suppressed_at``/ack columns are always cleared,
      ``first_seen_at`` is never touched.
    """
    if row.status == FINDING_OPEN:
        return row
    if row.status not in (
        FINDING_RESOLVED,
        FINDING_SUPPRESSED,
        FINDING_ACKNOWLEDGED,
    ):
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Invalid transition",
            f"Cannot reopen a {row.status} finding.",
        )
    from_status = row.status
    row.status = FINDING_OPEN
    row.resolved_at = None
    row.suppressed_at = None
    row.acknowledged_by = None
    row.acknowledged_at = None
    if from_status in (FINDING_RESOLVED, FINDING_SUPPRESSED):
        row.reopen_count = (row.reopen_count or 0) + 1
    _record_audit(
        db,
        event_type="directory.finding.reopened",
        outcome="success",
        request=request,
        actor=actor,
        target=row.fingerprint,
        detail={
            "connection_id": str(row.connection_id),
            "finding_id": str(row.id),
            "rule_key": row.rule_key,
            "from_status": from_status,
            "to_status": FINDING_OPEN,
            "reopen_count": row.reopen_count,
        },
    )
    return row


# --- Entry point --------------------------------------------------------------


@dataclass
class _Graph:
    """Mirror rows the nested-group traversal runs on."""

    privileged: list[PrivilegedGroup]
    adjacency: dict[uuid.UUID, list[DirectoryGroupMembership]]
    groups_by_guid: dict[str, DirectoryGroup]
    groups_by_dn: dict[str, DirectoryGroup]
    users_by_dn: dict[str, _ObjectRef]
    computers_by_dn: dict[str, _ObjectRef]


def _load_graph(db: Session, connection_id: uuid.UUID) -> _Graph:
    """Load the traversal inputs for one connection (read-only).

    Shared by ``recompute_connection`` and the API-facing
    ``privilege_visibility`` so both always walk the exact same graph.
    """
    adjacency: dict[uuid.UUID, list[DirectoryGroupMembership]] = {}
    groups_by_guid: dict[str, DirectoryGroup] = {}
    groups_by_dn: dict[str, DirectoryGroup] = {}
    for g in db.scalars(
        select(DirectoryGroup).where(DirectoryGroup.connection_id == connection_id)
    ).all():
        if g.object_guid:
            groups_by_guid[g.object_guid] = g
        groups_by_dn[g.distinguished_name.lower()] = g
    for edge in db.scalars(
        select(DirectoryGroupMembership).where(
            DirectoryGroupMembership.connection_id == connection_id
        )
    ).all():
        adjacency.setdefault(edge.group_id, []).append(edge)

    users_by_dn: dict[str, _ObjectRef] = {}
    for u in db.execute(
        select(
            DirectoryUser.distinguished_name,
            DirectoryUser.object_guid,
            DirectoryUser.sam_account_name,
            DirectoryUser.display_name,
            DirectoryUser.enabled,
        ).where(DirectoryUser.connection_id == connection_id)
    ).all():
        users_by_dn[u[0].lower()] = _ObjectRef(
            guid=u[1], name=u[2] or u[3] or "unknown", enabled=u[4]
        )
    computers_by_dn: dict[str, _ObjectRef] = {}
    for c in db.execute(
        select(
            DirectoryComputer.distinguished_name,
            DirectoryComputer.object_guid,
            DirectoryComputer.name,
            DirectoryComputer.enabled,
        ).where(DirectoryComputer.connection_id == connection_id)
    ).all():
        computers_by_dn[c[0].lower()] = _ObjectRef(guid=c[1], name=c[2], enabled=c[3])

    return _Graph(
        privileged=identify_privileged_groups(db, connection_id),
        adjacency=adjacency,
        groups_by_guid=groups_by_guid,
        groups_by_dn=groups_by_dn,
        users_by_dn=users_by_dn,
        computers_by_dn=computers_by_dn,
    )


def privilege_visibility(
    db: Session,
    connection_id: uuid.UUID,
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Effective privilege-visibility verdict — read-only, no writes.

    Reuses the same completeness check, graph loader and bounded BFS as
    ``recompute_connection`` (single implementation), so the API can
    never report a verdict different from what the engine would derive.
    """
    settings = settings or get_settings()
    complete = inventory_complete(db, connection_id)
    graph = _load_graph(db, connection_id)
    traversal = _traverse(
        graph.privileged,
        graph.adjacency,
        graph.groups_by_guid,
        graph.groups_by_dn,
        graph.users_by_dn,
        graph.computers_by_dn,
        settings.directory_nested_group_max_depth,
    )
    visibility, reasons = _visibility(complete, traversal.reasons)
    return {
        "privilege_visibility": visibility,
        "visibility_reasons": reasons,
        "inventory_complete": complete,
    }


def findings_summary(db: Session, connection_id: uuid.UUID) -> dict[str, Any]:
    """Aggregate finding counts + the visibility verdict for one connection.

    Single GROUP BY over ``directory_findings`` (one query, no N+1) plus
    ``privilege_visibility`` for the connection-level verdict. The
    connection must already exist — callers resolve it first.
    """
    rows = db.execute(
        select(
            DirectoryFinding.status,
            DirectoryFinding.severity,
            DirectoryFinding.rule_key,
            DirectoryFinding.subject_type,
            func.count(DirectoryFinding.id),
        )
        .where(DirectoryFinding.connection_id == connection_id)
        .group_by(
            DirectoryFinding.status,
            DirectoryFinding.severity,
            DirectoryFinding.rule_key,
            DirectoryFinding.subject_type,
        )
    ).all()

    counts: dict[str, int] = {
        FINDING_OPEN: 0,
        FINDING_ACKNOWLEDGED: 0,
        FINDING_SUPPRESSED: 0,
        FINDING_RESOLVED: 0,
    }
    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    by_subject_type: dict[str, int] = {}
    total = 0
    for row_status, row_severity, row_rule, row_subject, row_count in rows:
        n = int(row_count)
        total += n
        if row_status in counts:
            counts[row_status] += n
        by_severity[row_severity] = by_severity.get(row_severity, 0) + n
        by_rule[row_rule] = by_rule.get(row_rule, 0) + n
        by_subject_type[row_subject] = by_subject_type.get(row_subject, 0) + n

    visibility = privilege_visibility(db, connection_id)
    return {
        "total": total,
        "open": counts[FINDING_OPEN],
        "acknowledged": counts[FINDING_ACKNOWLEDGED],
        "suppressed": counts[FINDING_SUPPRESSED],
        "resolved": counts[FINDING_RESOLVED],
        "by_severity": by_severity,
        "by_rule": by_rule,
        "by_subject_type": by_subject_type,
        "privilege_visibility": visibility["privilege_visibility"],
        "visibility_reasons": visibility["visibility_reasons"],
        "inventory_complete": visibility["inventory_complete"],
    }


def recompute_connection(
    db: Session,
    connection_id: uuid.UUID,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Recompute all findings for one connection (idempotent).

    First statement in the transaction is a transaction-scoped advisory
    lock on (INSIGHTS_LOCK_NS, hash(connection_id)): a competing
    recomputation makes this one skip with ZERO writes. The lock is
    released when the transaction ends.
    """
    settings = settings or get_settings()
    clock = now or datetime.now(UTC)

    acquired = db.execute(
        text("SELECT pg_try_advisory_xact_lock(:ns, hashtext(:cid))"),
        {"ns": INSIGHTS_LOCK_NS, "cid": str(connection_id)},
    ).scalar()
    if not acquired:
        # Label-only log: no DNs, no finding content.
        logger.info("insights_recompute_skipped")
        db.rollback()
        return {"skipped": True, "reason": "lock_held"}

    complete = inventory_complete(db, connection_id)
    newest = newest_sync_run(db, connection_id)
    graph = _load_graph(db, connection_id)

    traversal = _traverse(
        graph.privileged,
        graph.adjacency,
        graph.groups_by_guid,
        graph.groups_by_dn,
        graph.users_by_dn,
        graph.computers_by_dn,
        settings.directory_nested_group_max_depth,
    )
    visibility, visibility_reasons = _visibility(complete, traversal.reasons)

    pending: dict[str, _Pending] = {}
    items = _privileged_findings(traversal, visibility, visibility_reasons)
    if complete:
        items.extend(
            _absence_findings(db, connection_id, clock, settings)
        )
    items.extend(_disabled_computer_findings(db, connection_id))
    items.extend(_missing_findings(db, connection_id, clock, settings))
    items.extend(_connection_findings(db, connection_id, complete, newest))
    for item in items:
        # Dedupe by fingerprint; first (stable) payload wins.
        pending.setdefault(item.fingerprint, item)

    counts = _apply_lifecycle(
        db, connection_id, pending, complete=complete, now=clock
    )
    db.commit()
    return {
        "skipped": False,
        "privilege_visibility": visibility,
        "visibility_reasons": visibility_reasons,
        "inventory_complete": complete,
        **counts,
    }


__all__ = [
    "INSIGHTS_LOCK_NS",
    "INVENTORY_CATEGORIES",
    "PRIVILEGED_BUILTIN_RIDS",
    "PRIVILEGED_DOMAIN_RIDS",
    "RULE_DIRECT",
    "RULE_DISABLED_MEMBER",
    "RULE_DISABLED_PERSIST",
    "RULE_DIST_ANOMALY",
    "RULE_INVENTORY_EMPTY",
    "RULE_KEYS",
    "RULE_MISSING_GRACE",
    "RULE_NO_LOGON",
    "RULE_SYNC_FRESHNESS",
    "RULE_TRANSITIVE",
    "RULE_UNKNOWN_MEMBER",
    "RULE_USER_INACTIVE",
    "RULE_COMPUTER_STALE",
    "acknowledge_finding",
    "builtin_privileged_rid",
    "connection_fingerprint",
    "domain_privileged_rid",
    "findings_summary",
    "identify_privileged_groups",
    "inventory_complete",
    "member_fingerprint",
    "missing_categories",
    "newest_sync_run",
    "object_fingerprint",
    "object_key",
    "privilege_visibility",
    "recompute_connection",
    "reopen_finding",
    "suppress_finding",
]
