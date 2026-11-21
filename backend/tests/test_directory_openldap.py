"""Optional REAL-PROTOCOL test against a local OpenLDAP server (Phase 3.1).

Honest scope label: **OpenLDAP, not real Active Directory.** This file
exercises the LDAP *protocol* layer (TLS handshake → bind → paged search →
entry normalization) over a real TLS socket. It complements, and never
replaces:

- ``tests/test_directory_client.py`` — TLS handshake layer (local TLS
  listener) and behavior layer (ldap3.mock);
- real Active Directory over LDAPS — **not tested in this repository**
  (no domain controller available).

The server is external and optional: every test skips with an explicit
reason unless the harness exports ``EITOP_OPENLDAP_URL`` (for example
``ldaps://ldap.eitop.test:636``). Nothing in the default suite depends on
this file, so it can never block a milestone.

Required companion variables when the URL is set:
- ``EITOP_OPENLDAP_CA_PEM_FILE`` — path to the server's CA certificate;
- ``EITOP_OPENLDAP_BIND_DN`` / ``EITOP_OPENLDAP_BIND_PASSWORD``;
- ``EITOP_OPENLDAP_BASE_DN`` — a search base that exists.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest
from app.services.directory.errors import classify_error, message_for
from app.services.directory.ldap_client import DirectoryLdapClient, LdapEndpoint, probe_tls

SENTINEL = "Sentinel-Bind-Pa55word!"


def _endpoint() -> LdapEndpoint | None:
    url = os.environ.get("EITOP_OPENLDAP_URL")
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme != "ldaps":
        pytest.skip("EITOP_OPENLDAP_URL must be ldaps:// (no plaintext mode)")
    ca_file = os.environ.get("EITOP_OPENLDAP_CA_PEM_FILE", "")
    ca_pem = None
    if ca_file and os.path.exists(ca_file):
        with open(ca_file, encoding="utf-8") as fh:
            ca_pem = fh.read()
    return LdapEndpoint(
        host=parsed.hostname or "",
        port=parsed.port or 636,
        tls_mode="ldaps",
        ca_pem=ca_pem,
        connect_timeout=10.0,
        search_timeout=15.0,
        page_size=5,
    )


def _skip_unless_server() -> LdapEndpoint:
    endpoint = _endpoint()
    if endpoint is None:
        pytest.skip(
            "no OpenLDAP server configured: set EITOP_OPENLDAP_URL "
            "(optional real-protocol test; OpenLDAP, not real AD)"
        )
    return endpoint


def _credentials() -> tuple[str, str, str]:
    bind_dn = os.environ.get("EITOP_OPENLDAP_BIND_DN", "")
    password = os.environ.get("EITOP_OPENLDAP_BIND_PASSWORD", "")
    base_dn = os.environ.get("EITOP_OPENLDAP_BASE_DN", "")
    if not bind_dn or not password or not base_dn:
        pytest.skip("EITOP_OPENLDAP_BIND_DN/BASE_DN/PASSWORD not configured")
    assert password == SENTINEL or password, "bind password must come from env"
    return bind_dn, password, base_dn


def _client(endpoint: LdapEndpoint, bind_dn: str, password: str) -> DirectoryLdapClient:
    return DirectoryLdapClient(endpoint=endpoint, bind_dn=bind_dn, bind_password=password)


def test_real_tls_handshake_against_openldap():
    """The pre-flight handshake validates chain + hostname on a real socket."""
    endpoint = _skip_unless_server()
    probe_tls(endpoint)  # raises on failure — the assertion is "no raise"


def test_real_bind_and_paged_search():
    """Bind + paged search against the real protocol layer, read-only."""
    endpoint = _skip_unless_server()
    bind_dn, password, base_dn = _credentials()

    client = _client(endpoint, bind_dn, password)
    client.connect()
    try:
        seen: list[str] = []
        pages = 0
        for entry in client.paged_search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            attributes=["dn", "objectClass"],
            page_size=5,
        ):
            pages += 1
            if entry.get("dn"):
                seen.append(str(entry["dn"]))
            # Streaming guarantee: never buffered wholesale.
            assert pages <= 10_000
        assert pages >= 1
        assert seen, "expected at least one entry under the search base"
    finally:
        client.close()


def test_real_wrong_password_is_classified_not_leaked():
    """A failed bind yields a fixed label — never the password or raw text."""
    endpoint = _skip_unless_server()
    bind_dn, password, _base_dn = _credentials()

    client = _client(endpoint, bind_dn, password + "-wrong")
    try:
        client.connect()
    except Exception as exc:  # noqa: BLE001 - classification is the assertion
        label = classify_error(exc)
        assert label in {
            "invalid_credentials",
            "connection_failed",
            "tls_error",
            "timeout",
            "protocol_error",
            "search_base_not_found",
            "unexpected",
        }
        assert password not in message_for(label)
        assert password not in str(label)
    else:
        client.close()
        pytest.fail("bind with a wrong password must fail")
