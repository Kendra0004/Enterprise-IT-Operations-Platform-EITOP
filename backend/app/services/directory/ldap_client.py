"""Read-only LDAP client for the directory integration (Phase 3.1).

Security invariants enforced by this module:
- **No plaintext LDAP**: ``tls_mode`` must be ``ldaps`` or ``starttls``
  (validated by the schema AND re-asserted here). For LDAPS a pre-flight
  stdlib TLS handshake (``probe_tls``) verifies chain, validity period and
  hostname with ``CERT_REQUIRED`` before ldap3 connects; StartTLS upgrades
  the socket before any LDAP operation. There is no bypass switch.
- **Read-only**: the only LDAP operations used are bind, rootDSE read,
  BASE/SUBTREE searches with the standard paged-results control. No add /
  modify / delete / compare / extended operations exist here — this module
  cannot write to Active Directory.
- **Referrals are never chased** (``auto_referrals=False``; referral
  responses are skipped in ``paged_search``).
- **No full-directory buffering**: entries stream page by page.
- **Filter safety**: callers build filters through ``build_filter`` so user
  input is always escaped (never concatenated raw).

Test seams: ``server_factory`` / ``connection_factory`` inject ldap3.mock
strategies (MOCK_SYNC) so the whole suite runs without a real directory.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import (
    LDAPCommunicationError,
    LDAPExceptionError,
    LDAPOperationResult,
)
from ldap3.utils.conv import escape_filter_chars

from app.services.directory.errors import InvalidCaError, PagingError
from app.services.directory.normalize import ad_guid, first

# RFC 2696 simple paged results control OID.
PAGED_OID = "1.2.840.113556.1.4.319"
# Hard guard against a misbehaving server that returns a non-empty cookie
# forever (ldap3's own generator has no unchanged-cookie guard).
MAX_PAGES = 10_000

_DIRECTORY_TLS_MODES = ("ldaps", "starttls")

ServerFactory = Callable[["LdapEndpoint"], Any]
ConnectionFactory = Callable[[Any, str, str, "LdapEndpoint"], Any]


@dataclass(frozen=True)
class LdapEndpoint:
    """Transport-level view of a directory connection (never a secret)."""

    host: str
    port: int
    tls_mode: str
    ca_pem: str | None
    connect_timeout: float
    search_timeout: float
    page_size: int

    def __post_init__(self) -> None:
        # Defense in depth: plaintext LDAP does not exist in this codebase.
        if self.tls_mode not in _DIRECTORY_TLS_MODES:
            raise ValueError(f"unsupported tls_mode: {self.tls_mode!r}")


def probe_tls(endpoint: LdapEndpoint) -> None:
    """Pre-flight transport verification, separated from LDAP protocol work.

    - ``ldaps``: full TLS handshake with the stdlib context
      (``CERT_REQUIRED`` + hostname verification — the same trust rules as
      ldap3's ``Tls``, using ``cadata=ca_pem`` so the connection's CA bundle
      is honoured exactly). Raises ``ssl.SSLCertVerificationError`` for
      expired/untrusted/mismatched certificates, ``socket.timeout`` on
      timeout, ``OSError`` on refused/unreachable hosts.
    - ``starttls``: TCP reachability only — the TLS upgrade requires the
      LDAP protocol exchange first and is verified by ``start_tls()``
      (``LDAPStartTLSError`` -> ``tls_error``).
    """
    if endpoint.tls_mode == "starttls":
        with socket.create_connection(
            (endpoint.host, endpoint.port), timeout=endpoint.connect_timeout
        ):
            return
    try:
        # Matches ldap3.core.tls.Tls: create_default_context with the
        # connection's CA data (system CAs when no bundle is configured).
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cadata=endpoint.ca_pem
        )
    except (ValueError, ssl.SSLError):
        raise InvalidCaError("invalid tls_ca_pem bundle") from None
    with (
        socket.create_connection(
            (endpoint.host, endpoint.port), timeout=endpoint.connect_timeout
        ) as raw_sock,
        context.wrap_socket(raw_sock, server_hostname=endpoint.host) as tls_sock,
    ):
        tls_sock.getpeercert()  # handshake done, peer certificate verified


def build_filter(clauses: dict[str, str]) -> str:
    """Build an AND filter with every value escaped (LDAP injection safety).

    ``{"objectClass": "user", "sAMAccountName": user_input}`` ->
    ``(&(objectClass=user)(sAMAccountName=<escaped>))``. Keys are attribute
    names from our own code (never user input); values are always escaped.
    """
    if not clauses:
        raise ValueError("at least one filter clause is required")
    parts = [
        f"({name}={escape_filter_chars(value)})" for name, value in clauses.items()
    ]
    return f"(&{''.join(parts)})" if len(parts) > 1 else parts[0]


class DirectoryLdapClient:
    """One bound, read-only LDAP session against a directory endpoint."""

    def __init__(
        self,
        *,
        endpoint: LdapEndpoint,
        bind_dn: str,
        bind_password: str,
        server_factory: ServerFactory | None = None,
        connection_factory: ConnectionFactory | None = None,
        probe_on_connect: bool = True,
    ) -> None:
        self._endpoint = endpoint
        self._bind_dn = bind_dn
        # Decrypted in memory only for the bind; never logged, never stored.
        self._bind_password = bind_password
        self._server_factory = server_factory
        self._connection_factory = connection_factory
        # Tests that inject mock factories set this False (no network is
        # involved there); every production construction keeps it True.
        self._probe_on_connect = probe_on_connect
        self._conn: Any = None

    @property
    def connected(self) -> bool:
        return self._conn is not None

    def connect(self) -> None:
        """Verify transport (probe), upgrade StartTLS if configured, bind."""
        if self._conn is not None:
            raise RuntimeError("client already connected")
        ep = self._endpoint
        if self._probe_on_connect:
            probe_tls(ep)

        if self._server_factory is not None and self._connection_factory is not None:
            server = self._server_factory(ep)
            conn = self._connection_factory(server, self._bind_dn, self._bind_password, ep)
        else:
            # version is deliberately NOT set: ldap3 expects ssl.PROTOCOL_*
            # constants there, and modern Python defaults are TLS 1.2+.
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=ep.ca_pem)
            server = Server(
                ep.host,
                port=ep.port,
                use_ssl=ep.tls_mode == "ldaps",
                connect_timeout=ep.connect_timeout,
                tls=tls,
                get_info=NONE,  # no schema fetch; attributes normalized manually
            )
            conn = Connection(
                server,
                user=self._bind_dn,
                password=self._bind_password,
                auto_referrals=False,
                raise_exceptions=True,
                # ldap3 packs SO_RCVTIMEO with struct.pack('LL', ...) which
                # rejects floats — an integer seconds value is required.
                receive_timeout=int(ep.search_timeout),
            )

        if ep.tls_mode == "starttls":
            # Upgrade happens BEFORE any bind/search — never a plaintext probe.
            conn.start_tls()
        conn.bind()
        self._conn = conn

    def root_dse(self) -> dict[str, Any]:
        """Best-effort rootDSE read.

        Some DCs restrict anonymous/rootDSE reads; callers must treat an
        empty result as "use the connection configuration values". Transport
        failures still propagate (they are not "empty" answers).
        """
        conn = self._require_connection()
        try:
            conn.search(
                "",
                "(objectClass=*)",
                search_scope=BASE,
                attributes=[
                    "defaultNamingContext",
                    "dnsHostName",
                    "rootDomainNamingContext",
                    "domainFunctionality",
                    "forestFunctionality",
                ],
            )
        except LDAPCommunicationError:
            raise  # transport failures are real failures, not "empty" answers
        except (LDAPExceptionError, LDAPOperationResult):
            # Server refused/failed the (often restricted) rootDSE read —
            # callers fall back to the connection configuration values.
            return {}
        out: dict[str, Any] = {}
        for entry in conn.response or []:
            if entry.get("type") != "searchResEntry":
                continue
            attrs = entry.get("attributes") or {}
            for key in (
                "defaultNamingContext",
                "dnsHostName",
                "rootDomainNamingContext",
                "domainFunctionality",
                "forestFunctionality",
            ):
                value = first(attrs.get(key))
                if isinstance(value, (bytes, bytearray)):
                    value = bytes(value).decode("utf-8", "replace")
                if value is not None:
                    out[key] = value
        return out

    def validate_search_base(self, search_base: str) -> bool:
        """BASE read at the configured search base.

        True when the bound identity can see the scope we intend to sync.
        ``noSuchObject`` maps to False; other error results raise
        (``raise_exceptions``); an empty-but-successful answer returns False.
        """
        conn = self._require_connection()
        try:
            conn.search(
                search_base,
                "(objectClass=*)",
                search_scope=BASE,
                attributes=["objectClass"],
            )
        except LDAPOperationResult as exc:
            if getattr(exc, "result", None) == 32:  # noSuchObject
                return False
            raise
        return any(
            entry.get("type") == "searchResEntry" for entry in conn.response or []
        )

    def read_base(
        self, dn: str, attributes: list[str]
    ) -> dict[str, Any] | None:
        """BASE read of one entry's attributes (e.g. the domain object SID).

        Returns the normalized attribute map, or None when the entry does
        not exist. Transport and other operation errors propagate.
        """
        conn = self._require_connection()
        try:
            conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=attributes)
        except LDAPOperationResult as exc:
            if getattr(exc, "result", None) == 32:  # noSuchObject
                return None
            raise
        for entry in conn.response or []:
            if entry.get("type") != "searchResEntry":
                continue
            attrs = entry.get("attributes") or {}
            return {key.lower(): _attr_value(value) for key, value in attrs.items()}
        return None

    def paged_search(
        self,
        *,
        search_base: str,
        search_filter: str,
        attributes: list[str],
        page_size: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Stream entries via the standard paged-results control (RFC 2696).

        Yields ``{"dn", "guid", "attrs"}`` for search entries only —
        referral responses are skipped (never followed) and non-entry
        responses are ignored. Loop guards: empty cookie stops the loop, an
        unchanged cookie on an empty page stops the loop, and a hard page
        cap raises ``PagingError``. Errors mid-pagination propagate so the
        caller can fail the whole category (previous pages' DB writes roll
        back with the transaction).
        """
        conn = self._require_connection()
        size = page_size or self._endpoint.page_size
        cookie: bytes | None = None
        previous_cookie: bytes | None = None
        pages = 0
        while True:
            pages += 1
            if pages > MAX_PAGES:
                raise PagingError(f"paged search exceeded {MAX_PAGES} pages")
            conn.search(
                search_base,
                search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=size,
                paged_cookie=cookie,
            )
            response = conn.response or []
            result = conn.result or {}
            entry_count = 0
            for entry in response:
                if entry.get("type") != "searchResEntry":
                    continue  # referrals are skipped, never chased
                entry_count += 1
                yield _normalize_entry(entry)
            try:
                cookie = result["controls"][PAGED_OID]["value"]["cookie"]
            except (KeyError, TypeError):
                cookie = None
            if not cookie:
                break
            if entry_count == 0 and cookie == previous_cookie:
                # Server echoed a cookie without entries: stop, don't loop.
                break
            previous_cookie = cookie

    def close(self) -> None:
        if self._conn is not None:
            # Closing must never mask whatever error brought us here.
            with contextlib.suppress(Exception):
                self._conn.unbind()
            self._conn = None

    def __enter__(self) -> DirectoryLdapClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _require_connection(self) -> Any:
        if self._conn is None:
            raise RuntimeError("LDAP client is not connected")
        return self._conn


def _attr_value(value: Any) -> Any:
    """Single-element list -> scalar; multi-element -> list; empty -> None."""
    if isinstance(value, list):
        if not value:
            return None
        return value[0] if len(value) == 1 else list(value)
    return value


def _normalize_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize an ldap3 search response entry for the sync engine."""
    dn = entry.get("dn") or ""
    raw = entry.get("raw_attributes") or {}
    attrs = entry.get("attributes") or {}
    guid = ad_guid(raw.get("objectGUID"))
    if guid is None:
        guid = ad_guid(attrs.get("objectGUID"))
    normalized: dict[str, Any] = {}
    for key, value in attrs.items():
        if key.lower() == "objectguid":
            continue  # always taken from raw bytes above
        normalized[key.lower()] = _attr_value(value)
    return {"dn": dn, "guid": guid, "attrs": normalized}


__all__ = [
    "MAX_PAGES",
    "PAGED_OID",
    "DirectoryLdapClient",
    "LdapEndpoint",
    "build_filter",
    "probe_tls",
]
