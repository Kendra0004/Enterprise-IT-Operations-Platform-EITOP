"""Directory LDAP client tests (Phase 3.1).

Coverage map (honest labels for the final report):

- **TLS handshake layer — real protocol**: a local TLS listener with
  locally-generated certificates exercises the actual ``ssl`` handshake
  (trusted / expired / untrusted-CA / hostname-mismatch / invalid CA
  bundle / TCP-only StartTLS probe / connection refused). This is NOT a
  real Active Directory: no AD DC was available.
- **LDAP protocol behavior — ldap3.mock**: bind success and rejected
  bind, rootDSE fallback, search-base visibility, paged search with
  attribute normalization. Mock strategy, not a live server.
- **Paging loop guards — scripted connection**: deterministic control
  over cookies, mid-stream failures, referrals and the page cap.

No test in this file needs PostgreSQL or Redis.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import ipaddress
import socket
import ssl
import tempfile
import threading
import uuid
from collections import deque
from pathlib import Path
from typing import Any

import pytest
from app.services.directory import ldap_client as lc
from app.services.directory.errors import (
    LABEL_CONNECTION,
    LABEL_INVALID_CREDENTIALS,
    LABEL_PROTOCOL,
    LABEL_TIMEOUT,
    LABEL_TLS,
    InvalidCaError,
    PagingError,
    classify_error,
    message_for,
    static_error,
)
from app.services.directory.ldap_client import (
    DirectoryLdapClient,
    LdapEndpoint,
    build_filter,
    probe_tls,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ldap3 import MOCK_SYNC, NONE, Connection, Server

# ---------------------------------------------------------------------------
# Local TLS listener (real handshake, locally generated certificates)
# ---------------------------------------------------------------------------

_CA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EITOP Test CA")])
_NOW = dt.datetime.now(dt.UTC)

_CA_CERT = (
    x509.CertificateBuilder()
    .subject_name(_CA_NAME)
    .issuer_name(_CA_NAME)
    .public_key(_CA_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(_NOW - dt.timedelta(days=2))
    .not_valid_after(_NOW + dt.timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(_CA_KEY, hashes.SHA256())
)
_CA_PEM = _CA_CERT.public_bytes(serialization.Encoding.PEM).decode()


def _leaf(
    *,
    san: x509.SubjectAlternativeName,
    not_before: dt.datetime,
    not_after: dt.datetime,
    issuer_key: Any = _CA_KEY,
    issuer_cert: Any = _CA_CERT,
    subject_cn: str = "localhost",
) -> tuple[Any, str, str]:
    """Sign a leaf certificate; returns (key, cert_pem, key_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        )
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return key, cert_pem, key_pem


class _TlsListener:
    """Tiny TLS server: accepts, handshakes, reads a byte, closes."""

    def __init__(self, cert_pem: str, key_pem: str) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tmp = tempfile.TemporaryDirectory(prefix="eitop-dir-tls-")
        tmp = Path(self._tmp.name)
        cert_file = tmp / "server.pem"
        key_file = tmp / "server.key"
        cert_file.write_text(cert_pem)
        key_file.write_text(key_pem)
        self._ctx.load_cert_chain(str(cert_file), str(key_file))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            try:
                with (
                    self._ctx.wrap_socket(conn, server_side=True) as tls,
                    contextlib.suppress(Exception),
                ):
                    tls.recv(64)
            except Exception:  # noqa: BLE001 - rejected handshakes are the point
                pass

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=3)
        self._tmp.cleanup()


class _PlainListener:
    """TCP-only listener (for the StartTLS pre-flight probe)."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            try:
                with conn:
                    conn.recv(64)
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=3)


def _endpoint(port: int, *, tls_mode: str = "ldaps", ca_pem: str | None = None):
    return LdapEndpoint(
        host="127.0.0.1",
        port=port,
        tls_mode=tls_mode,
        ca_pem=ca_pem,
        connect_timeout=5.0,
        search_timeout=5.0,
        page_size=100,
    )


@pytest.fixture()
def trusted_listener():
    listener = _TlsListener(
        *_leaf_cert(san_names=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    )
    try:
        yield listener
    finally:
        listener.close()


def _leaf_cert(
    *,
    san_names: list[Any],
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    subject_cn: str = "localhost",
    issuer_key: Any = _CA_KEY,
    issuer_cert: Any = _CA_CERT,
) -> tuple[str, str]:
    _, cert_pem, key_pem = _leaf(
        san=x509.SubjectAlternativeName(san_names),
        not_before=not_before or (_NOW - dt.timedelta(days=1)),
        not_after=not_after or (_NOW + dt.timedelta(days=30)),
        subject_cn=subject_cn,
        issuer_key=issuer_key,
        issuer_cert=issuer_cert,
    )
    return cert_pem, key_pem


def _other_ca_pem() -> str:
    """A second, unrelated CA — its bundle must not verify our leaf."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - dt.timedelta(days=2))
        .not_valid_after(_NOW + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# TLS handshake layer (real ssl handshake against the local listener)
# ---------------------------------------------------------------------------


class TestProbeTls:
    def test_trusted_certificate_with_ip_san_passes(self, trusted_listener):
        probe_tls(_endpoint(trusted_listener.port, ca_pem=_CA_PEM))

    def test_untrusted_ca_is_rejected(self):
        # Leaf signed by our test CA; the client trusts a DIFFERENT CA.
        cert_pem, key_pem = _leaf_cert(
            san_names=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        )
        listener = _TlsListener(cert_pem, key_pem)
        try:
            with pytest.raises(ssl.SSLCertVerificationError):
                probe_tls(_endpoint(listener.port, ca_pem=_other_ca_pem()))
        finally:
            listener.close()

    def test_expired_certificate_is_rejected(self):
        cert_pem, key_pem = _leaf_cert(
            san_names=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
            not_before=_NOW - dt.timedelta(days=5),
            not_after=_NOW - dt.timedelta(days=1),
        )
        listener = _TlsListener(cert_pem, key_pem)
        try:
            with pytest.raises(ssl.SSLCertVerificationError) as excinfo:
                probe_tls(_endpoint(listener.port, ca_pem=_CA_PEM))
            assert "expired" in str(excinfo.value).lower()
        finally:
            listener.close()

    def test_hostname_mismatch_is_rejected(self):
        cert_pem, key_pem = _leaf_cert(
            san_names=[x509.DNSName("wrong.example.test")],
            subject_cn="wrong.example.test",
        )
        listener = _TlsListener(cert_pem, key_pem)
        try:
            # Connecting to 127.0.0.1 while the certificate only names
            # wrong.example.test -> hostname verification must fail.
            with pytest.raises(ssl.SSLCertVerificationError):
                probe_tls(_endpoint(listener.port, ca_pem=_CA_PEM))
        finally:
            listener.close()

    def test_untrusted_ca_without_custom_bundle_uses_system_roots(self):
        """Default trust store must NOT accept our private test CA."""
        cert_pem, key_pem = _leaf_cert(
            san_names=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        )
        listener = _TlsListener(cert_pem, key_pem)
        try:
            with pytest.raises(ssl.SSLCertVerificationError):
                probe_tls(_endpoint(listener.port, ca_pem=None))
        finally:
            listener.close()

    def test_invalid_ca_bundle_is_a_tls_label(self):
        with pytest.raises(InvalidCaError):
            probe_tls(_endpoint(636, ca_pem="this-is-not-a-pem-bundle"))

    def test_connection_refused_is_connection_error(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()  # nothing listens here now
        with pytest.raises(OSError):
            probe_tls(_endpoint(port, ca_pem=_CA_PEM))

    def test_starttls_probe_is_tcp_only(self):
        """StartTLS pre-flight does not speak TLS (upgrade needs LDAP first)."""
        listener = _PlainListener()
        try:
            probe_tls(_endpoint(listener.port, tls_mode="starttls", ca_pem=_CA_PEM))
        finally:
            listener.close()

    def test_starttls_probe_reports_refused_connection(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with pytest.raises(OSError):
            probe_tls(_endpoint(port, tls_mode="starttls", ca_pem=_CA_PEM))

    def test_probe_requires_full_verification_and_has_no_bypass(self):
        """No bypass switch: CERT_REQUIRED only, no unverified context."""
        source = Path(lc.__file__).read_text()
        assert "CERT_REQUIRED" in source
        assert "CERT_NONE" not in source
        assert "_create_unverified_context" not in source
        assert "check_hostname=False" not in source
        # The endpoint dataclass exposes no validation-toggle field.
        assert set(LdapEndpoint.__dataclass_fields__) == {
            "host",
            "port",
            "tls_mode",
            "ca_pem",
            "connect_timeout",
            "search_timeout",
            "page_size",
        }

    def test_plaintext_tls_mode_is_rejected(self):
        with pytest.raises(ValueError, match="unsupported tls_mode"):
            LdapEndpoint(
                host="127.0.0.1",
                port=389,
                tls_mode="ldap",  # plaintext: must not exist
                ca_pem=None,
                connect_timeout=1.0,
                search_timeout=1.0,
                page_size=100,
            )


# ---------------------------------------------------------------------------
# Paging loop guards (scripted connection: full control over cookies)
# ---------------------------------------------------------------------------


class _FakeConn:
    """Scripted ldap3 connection: pages are consumed in order."""

    def __init__(self, pages: list[tuple[list[dict], dict | None]], fail_at: int | None = None):
        self._pages = deque(pages)
        self._fail_at = fail_at
        self.calls: list[dict] = []
        self.response: list[dict] = []
        self.result: dict = {}
        self.bound = False

    def bind(self) -> bool:
        self.bound = True
        return True

    def unbind(self) -> None:
        self.bound = False

    def search(self, *_args: Any, **kwargs: Any) -> bool:
        call_index = len(self.calls)
        self.calls.append(kwargs)
        if self._fail_at is not None and call_index == self._fail_at:
            raise TimeoutError("simulated read timeout")
        if not self._pages:
            raise AssertionError("unexpected extra search call")
        entries, controls = self._pages.popleft()
        self.response = entries
        self.result = {"controls": controls} if controls else {}
        return True


def _entry(dn: str, guid: str) -> dict:
    head = dn.split(",", 1)[0]
    value = head.split("=", 1)[1] if "=" in head else head
    return {
        "type": "searchResEntry",
        "dn": dn,
        "attributes": {"objectGUID": guid, "cn": value},
        "raw_attributes": {"objectGUID": guid.encode()},
    }


def _cookie(cookie: bytes, count: int = 1) -> dict:
    return {
        "1.2.840.113556.1.4.319": {
            "type": "1.2.840.113556.1.4.319",
            "value": {"cookie": cookie, "size": count},
        }
    }


def _client_with(pages: list, fail_at: int | None = None) -> DirectoryLdapClient:
    conn = _FakeConn(pages, fail_at=fail_at)
    client = DirectoryLdapClient(
        endpoint=_endpoint(636, ca_pem=_CA_PEM),
        bind_dn="CN=svc-eitop,DC=eitop,DC=test",
        bind_password="sentinel-bind-password",
        server_factory=lambda ep: object(),
        connection_factory=lambda server, dn, pw, ep: conn,
        probe_on_connect=False,
    )
    client.connect()
    return client


class TestPagedSearch:
    def test_single_page_stops_on_empty_cookie(self):
        guid1, guid2 = str(uuid.uuid4()), str(uuid.uuid4())
        client = _client_with(
            [
                (
                    [
                        _entry("CN=a,DC=eitop,DC=test", guid1),
                        _entry("CN=b,DC=eitop,DC=test", guid2),
                    ],
                    _cookie(b""),
                )
            ]
        )
        entries = list(
            client.paged_search(
                search_base="DC=eitop,DC=test",
                search_filter="(objectClass=*)",
                attributes=["objectGUID"],
            )
        )
        assert [e["guid"] for e in entries] == [guid1, guid2]
        assert len(client._conn.calls) == 1

    def test_multi_page_walks_with_cookie(self):
        guid1, guid2 = str(uuid.uuid4()), str(uuid.uuid4())
        client = _client_with(
            [
                ([_entry("CN=a,DC=eitop,DC=test", guid1)], _cookie(b"page-2")),
                ([_entry("CN=b,DC=eitop,DC=test", guid2)], _cookie(b"")),
            ]
        )
        entries = list(
            client.paged_search(
                search_base="DC=eitop,DC=test",
                search_filter="(objectClass=*)",
                attributes=["objectGUID"],
            )
        )
        assert [e["guid"] for e in entries] == [guid1, guid2]
        calls = client._conn.calls
        assert len(calls) == 2
        assert calls[0]["paged_cookie"] is None
        assert calls[1]["paged_cookie"] == b"page-2"

    def test_partial_response_without_controls_stops(self):
        """A server that omits the paged control ends the loop after one page."""
        guid = str(uuid.uuid4())
        client = _client_with([([_entry("CN=a,DC=eitop,DC=test", guid)], None)])
        entries = list(
            client.paged_search(
                search_base="DC=eitop,DC=test",
                search_filter="(objectClass=*)",
                attributes=["objectGUID"],
            )
        )
        assert len(entries) == 1
        assert len(client._conn.calls) == 1

    def test_unchanged_cookie_on_empty_page_stops(self):
        """Misbehaving server: same cookie, zero entries -> stop, no spin."""
        client = _client_with(
            [
                ([], _cookie(b"same")),
                ([], _cookie(b"same")),
                ([], _cookie(b"same")),
            ]
        )
        entries = list(
            client.paged_search(
                search_base="DC=eitop,DC=test",
                search_filter="(objectClass=*)",
                attributes=["objectGUID"],
            )
        )
        assert entries == []
        assert len(client._conn.calls) == 2  # third call never happens

    def test_mid_stream_failure_propagates_after_prior_pages(self):
        guid1, guid2 = str(uuid.uuid4()), str(uuid.uuid4())
        client = _client_with(
            [
                ([_entry("CN=a,DC=eitop,DC=test", guid1)], _cookie(b"page-2")),
                ([_entry("CN=b,DC=eitop,DC=test", guid2)], _cookie(b"page-3")),
            ],
            fail_at=1,  # second page read dies mid-stream
        )
        seen: list[str] = []
        with pytest.raises(TimeoutError):
            for entry in client.paged_search(
                search_base="DC=eitop,DC=test",
                search_filter="(objectClass=*)",
                attributes=["objectGUID"],
            ):
                seen.append(entry["guid"])
        # Page 1 was delivered; page 2 never arrives; the error propagates
        # so the sync category fails and the transaction rolls back.
        assert seen == [guid1]

    def test_referrals_are_skipped_never_chased(self):
        guid = str(uuid.uuid4())
        referral = {"type": "searchResRef", "uri": ["ldap://other.example"]}
        client = _client_with([([referral, _entry("CN=a,DC=eitop,DC=test", guid)], _cookie(b""))])
        entries = list(
            client.paged_search(
                search_base="DC=eitop,DC=test",
                search_filter="(objectClass=*)",
                attributes=["objectGUID"],
            )
        )
        assert [e["guid"] for e in entries] == [guid]

    def test_page_cap_raises_paging_error(self, monkeypatch):
        """Endless non-empty pages hit MAX_PAGES instead of looping forever."""
        monkeypatch.setattr(lc, "MAX_PAGES", 2)
        endless = [
            ([_entry(f"CN={i},DC=eitop,DC=test", str(uuid.uuid4()))], _cookie(b"never"))
            for i in range(10)
        ]
        client = _client_with(endless)
        with pytest.raises(PagingError):
            list(
                client.paged_search(
                    search_base="DC=eitop,DC=test",
                    search_filter="(objectClass=*)",
                    attributes=["objectGUID"],
                )
            )
        assert len(client._conn.calls) == 2  # cap trips before a 3rd search

    def test_normalizes_guid_and_dn(self):
        guid = str(uuid.uuid4())
        client = _client_with([([_entry("CN=x,OU=HQ,DC=eitop,DC=test", guid)], _cookie(b""))])
        entry = next(
            client.paged_search(
                search_base="DC=eitop,DC=test",
                search_filter="(objectClass=*)",
                attributes=["objectGUID", "cn"],
            )
        )
        assert entry["guid"] == guid
        assert entry["dn"] == "CN=x,OU=HQ,DC=eitop,DC=test"
        assert entry["attrs"]["cn"] == "x"


# ---------------------------------------------------------------------------
# Filter construction (LDAP injection safety)
# ---------------------------------------------------------------------------


class TestBuildFilter:
    def test_single_clause(self):
        assert build_filter({"objectClass": "user"}) == "(objectClass=user)"

    def test_multiple_clauses_are_anded(self):
        assert build_filter({"a": "1", "b": "2"}) == "(&(a=1)(b=2))"

    def test_values_are_fully_escaped(self):
        malicious = "a*)(uid=*)(cn=*"
        result = build_filter({"sAMAccountName": malicious})
        # Single clause: no (&...) wrapper, but every special byte escaped.
        assert result == "(sAMAccountName=a\\2a\\29\\28uid=\\2a\\29\\28cn=\\2a)"
        assert "*" not in result
        assert "uid=*" not in result

    def test_backslash_and_nul_are_escaped(self):
        result = build_filter({"cn": "x\\y\x00z"})
        assert result == "(cn=x\\5cy\\00z)"

    def test_empty_clauses_rejected(self):
        with pytest.raises(ValueError):
            build_filter({})


# ---------------------------------------------------------------------------
# LDAP protocol behavior (ldap3.mock — NOT a real directory)
# ---------------------------------------------------------------------------

_DC_DN = "DC=eitop,DC=test"
_BIND_DN = "CN=svc-eitop,DC=eitop,DC=test"
_BIND_PASSWORD = "sentinel-bind-password"
_SEARCH_BASE = "OU=HQ,DC=eitop,DC=test"


def _mock_connection_factory(entries: list[dict]):
    """Build an ldap3.mock-backed connection factory for the client.

    Entries (including the bind DN with its ``userPassword``) are loaded
    before the client issues ``bind()`` — the mock then validates the
    supplied password exactly like a real server would.
    """

    def factory(server: Any, bind_dn: str, bind_password: str, ep: LdapEndpoint) -> Any:
        conn = Connection(
            server,
            user=bind_dn,
            password=bind_password,
            client_strategy=MOCK_SYNC,
            raise_exceptions=True,
        )
        for entry in entries:
            conn.strategy.add_entry(entry["dn"], entry["attributes"])
        return conn

    return factory


def _mock_server_factory(ep: LdapEndpoint) -> Any:
    return Server(ep.host, port=ep.port, use_ssl=True, get_info=NONE)


_MOCK_ENTRIES = [
    {
        "dn": _BIND_DN,
        "attributes": {
            "objectClass": ["top", "person"],
            "cn": "svc-eitop",
            "userPassword": _BIND_PASSWORD,
        },
    },
    {
        "dn": _DC_DN,
        "attributes": {"objectClass": ["top", "domain"], "dc": "eitop"},
    },
    {
        "dn": _SEARCH_BASE,
        "attributes": {"objectClass": ["top", "organizationalUnit"], "ou": "HQ"},
    },
]


def _mock_client(bind_password: str = _BIND_PASSWORD) -> DirectoryLdapClient:
    return DirectoryLdapClient(
        endpoint=LdapEndpoint(
            host="mock.example.test",
            port=636,
            tls_mode="ldaps",
            ca_pem=None,
            connect_timeout=5.0,
            search_timeout=5.0,
            page_size=2,
        ),
        bind_dn=_BIND_DN,
        bind_password=bind_password,
        server_factory=_mock_server_factory,
        connection_factory=_mock_connection_factory(_MOCK_ENTRIES),
        probe_on_connect=False,
    )


class TestMockProtocolBehavior:
    """ldap3.mock covers protocol behavior — labeled as mock, not real AD."""

    def test_bind_succeeds_with_correct_password(self):
        client = _mock_client()
        client.connect()
        assert client.connected
        client.close()
        assert not client.connected

    def test_rejected_bind_classifies_as_invalid_credentials(self):
        client = _mock_client(bind_password="wrong-password")
        with pytest.raises(Exception) as excinfo:
            client.connect()
        label = classify_error(excinfo.value)
        assert label == LABEL_INVALID_CREDENTIALS
        # The sentinel must not leak through the classification path.
        assert _BIND_PASSWORD not in message_for(label)

    def test_root_dse_restricted_read_falls_back_to_empty(self):
        """Mock refuses the empty-DN rootDSE read -> best-effort {}."""
        client = _mock_client()
        client.connect()
        assert client.root_dse() == {}
        client.close()

    def test_search_base_visible(self):
        client = _mock_client()
        client.connect()
        assert client.validate_search_base(_SEARCH_BASE) is True
        client.close()

    def test_missing_search_base_returns_false(self):
        client = _mock_client()
        client.connect()
        assert client.validate_search_base("OU=DoesNotExist,DC=eitop,DC=test") is False
        client.close()

    def test_read_base_returns_attributes_or_none(self):
        client = _mock_client()
        client.connect()
        attrs = client.read_base(_SEARCH_BASE, ["ou"])
        assert attrs == {"ou": "HQ"}
        assert client.read_base("OU=Nope,DC=eitop,DC=test", ["ou"]) is None
        client.close()


# ---------------------------------------------------------------------------
# Error classification / sanitization (labels only, never raw content)
# ---------------------------------------------------------------------------


class TestErrorClassification:
    def test_timeout_label(self):
        assert classify_error(TimeoutError("secret-detail")) == LABEL_TIMEOUT
        assert classify_error(TimeoutError("secret-detail")) == LABEL_TIMEOUT

    def test_connection_label(self):
        assert classify_error(ConnectionRefusedError("1.2.3.4:636")) == LABEL_CONNECTION

    def test_tls_label(self):
        assert classify_error(ssl.SSLError("handshake failure: secret")) == LABEL_TLS

    def test_protocol_label_for_paging(self):
        assert classify_error(PagingError("page cap")) == LABEL_PROTOCOL

    def test_unknown_exception_is_unexpected(self):
        assert classify_error(RuntimeError("boom with details")) == "unexpected"

    def test_messages_are_static_and_label_allowlisted(self):
        for label in (
            LABEL_TIMEOUT,
            LABEL_CONNECTION,
            LABEL_TLS,
            LABEL_INVALID_CREDENTIALS,
            LABEL_PROTOCOL,
            "unexpected",
        ):
            message = message_for(label)
            assert message  # static text exists
            assert "Traceback" not in message
        # Unknown labels fall back to the static unexpected message.
        assert message_for("not-a-label") == message_for("unexpected")

    def test_static_error_rejects_unknown_labels(self):
        with pytest.raises(ValueError, match="unknown error label"):
            static_error("connect", "made-up-label")

    def test_error_entry_carries_no_message_text(self):
        from app.services.directory.errors import error_entry

        entry = error_entry("users", TimeoutError("bind DN: CN=svc, password=hunter2"))
        assert set(entry) == {"category", "label", "error_type", "error_count"}
        assert "hunter2" not in str(entry)
        assert "CN=svc" not in str(entry)
        assert entry["error_type"] == "TimeoutError"
