"""Client construction for directory connections (Phase 3.1).

This is the single seam where the encrypted bind password is decrypted —
in memory, immediately before an LDAP bind. The plaintext password never
leaves this call chain: it is passed straight to ``ldap3`` and dropped
when the client is closed. Tests patch ``build_client`` here to inject
ldap3.mock-backed clients (no network, no real directory).
"""

from __future__ import annotations

from app.models import DirectoryConnection
from app.services.directory.ldap_client import DirectoryLdapClient, LdapEndpoint
from app.services.directory.secrets import decrypt_password


def endpoint_from_connection(row: DirectoryConnection) -> LdapEndpoint:
    """Transport view of a connection row (no secrets involved)."""
    return LdapEndpoint(
        host=row.host,
        port=row.port,
        tls_mode=row.tls_mode,
        ca_pem=row.tls_ca_pem,
        connect_timeout=float(row.connect_timeout_seconds),
        search_timeout=float(row.search_timeout_seconds),
        page_size=row.page_size,
    )


def build_client(row: DirectoryConnection) -> DirectoryLdapClient:
    """Build an unbound client for a connection.

    Raises ``CredentialDecryptionError`` when the stored password cannot
    be decrypted (SECRET_KEY rotated) — callers map that to the
    ``credential_undecryptable`` label.
    """
    password = decrypt_password(row.bind_password_encrypted)
    return DirectoryLdapClient(
        endpoint=endpoint_from_connection(row),
        bind_dn=row.bind_username,
        bind_password=password,
    )


__all__ = ["build_client", "endpoint_from_connection"]
