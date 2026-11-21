"""AD attribute normalization (Phase 3.1).

ldap3 returns protocol-level values when no server schema is fetched
(``get_info=NONE``): bytes for binary attributes (objectGUID/objectSid),
bytes or str for generalized-time attributes, and either scalars or
single-element lists for ordinary attributes (mock always returns lists;
live servers vary by attribute). These helpers produce stable Python
types. Unparseable values become ``None`` — callers decide whether that
is fatal (required fields mark the whole sync category failed so an
unreadable entry can never be silently dropped from the seen-set).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

# LDAP generalized time: YYYYMMDDHHMMSS[.fraction](Z|±HHMM); AD uses Z.
_GENERALIZED_TIME = re.compile(r"^(\d{14})(?:\.\d+)?Z?$")

# userAccountControl flag: ACCOUNTDISABLE
_UAC_ACCOUNTDISABLE = 0x2


def first(value: Any) -> Any:
    """Collapse a single-element list to a scalar; empty list -> None."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def as_list(value: Any) -> list[Any]:
    """Normalize a possibly scalar/list/None attribute to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def ad_guid(value: Any) -> str | None:
    """objectGUID bytes (little-endian) | str -> canonical UUID string."""
    v = first(value)
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        try:
            return str(uuid.UUID(bytes_le=bytes(v)))
        except (ValueError, AttributeError):
            return None
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, str):
        try:
            return str(uuid.UUID(v.strip()))
        except ValueError:
            return None
    return None


def ad_sid(value: Any) -> str | None:
    """objectSid bytes -> S-R-ID-SUBAUTH... string (RFC 4519 SID form)."""
    v = first(value)
    if isinstance(v, (bytes, bytearray)) and len(v) >= 8:
        raw = bytes(v)
        revision = raw[0]
        sub_count = raw[1]
        authority = int.from_bytes(raw[2:8], "big")
        parts = [f"S-{revision}", str(authority)]
        offset = 8
        for _ in range(sub_count):
            if offset + 4 > len(raw):
                break
            parts.append(str(int.from_bytes(raw[offset : offset + 4], "little")))
            offset += 4
        return "-".join(parts)
    if isinstance(v, str) and v.startswith("S-"):
        return v
    return None


def ad_time(value: Any) -> datetime | None:
    """Generalized time / ISO-8601 -> aware UTC datetime; None if unparseable."""
    v = first(value)
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo is not None else v.replace(tzinfo=UTC)
    if isinstance(v, (bytes, bytearray)):
        v = bytes(v).decode("ascii", "ignore")
    if not isinstance(v, str):
        return None
    v = v.strip()
    match = _GENERALIZED_TIME.match(v)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC)
        except ValueError:
            return None
    try:
        parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def uac_enabled(value: Any) -> bool | None:
    """userAccountControl flags -> enabled flag; None when unparseable."""
    v = first(value)
    if v is None:
        return None
    try:
        flags = int(v)  # str | bytes | int
    except (TypeError, ValueError):
        return None
    return not (flags & _UAC_ACCOUNTDISABLE)


def dn_rdn_value(dn: str) -> str:
    """Value of the first RDN — display fallback when cn/ou is absent."""
    head = dn.split(",", 1)[0]
    if "=" in head:
        return head.split("=", 1)[1].strip()
    return head.strip()


__all__ = [
    "ad_guid",
    "ad_sid",
    "ad_time",
    "as_list",
    "dn_rdn_value",
    "first",
    "uac_enabled",
]
