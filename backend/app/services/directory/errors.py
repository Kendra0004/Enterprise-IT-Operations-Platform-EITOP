"""Sanitized error classification for directory operations (Phase 3.1).

Hard rule (security): raw exception *content* (``str(exc)``/traceback
text) is NEVER persisted to sync-run ``category_results``, audit details,
or application logs — exception messages can embed bind DNs, server
replies or other sensitive material. Only:

- a fixed allowlist ``label`` (mapped here), and
- the exception class *name* (a code identifier, no instance data),

are ever written anywhere durable. API error responses follow the same
rule: our own static text + label, never the underlying message.
"""

from __future__ import annotations

import ssl

from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPCertificateError,
    LDAPExceptionError,
    LDAPOperationResult,
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
    LDAPStartTLSError,
)

# Fixed label allowlist — persisted verbatim in category_results/audit/logs.
LABEL_TIMEOUT = "timeout"
LABEL_CONNECTION = "connection_failed"
LABEL_TLS = "tls_error"
LABEL_INVALID_CREDENTIALS = "invalid_credentials"
LABEL_SEARCH_FAILED = "search_failed"
LABEL_PROTOCOL = "protocol_error"
LABEL_UNEXPECTED = "unexpected"
LABEL_TASK_SUBMISSION = "task_submission_failed"
LABEL_STALE_RUN = "stale_run_reaped"
LABEL_CREDENTIAL = "credential_undecryptable"
LABEL_SEARCH_BASE = "search_base_not_found"

_ALL_LABELS = frozenset(
    {
        LABEL_TIMEOUT,
        LABEL_CONNECTION,
        LABEL_TLS,
        LABEL_INVALID_CREDENTIALS,
        LABEL_SEARCH_FAILED,
        LABEL_PROTOCOL,
        LABEL_UNEXPECTED,
        LABEL_TASK_SUBMISSION,
        LABEL_STALE_RUN,
        LABEL_CREDENTIAL,
        LABEL_SEARCH_BASE,
    }
)

# Static, credential-free operator-facing messages per label. Never derived
# from exception content.
LABEL_MESSAGES: dict[str, str] = {
    LABEL_TIMEOUT: "Directory did not respond within the configured timeout.",
    LABEL_CONNECTION: "Could not connect to the directory host.",
    LABEL_TLS: (
        "TLS handshake failed (certificate expired, untrusted, or hostname mismatch)."
    ),
    LABEL_INVALID_CREDENTIALS: "Bind was rejected: invalid credentials.",
    LABEL_SEARCH_FAILED: "A directory search operation failed.",
    LABEL_PROTOCOL: "The directory returned an unexpected protocol result.",
    LABEL_UNEXPECTED: "Unexpected directory error.",
    LABEL_TASK_SUBMISSION: "Sync task could not be queued; please retry.",
    LABEL_STALE_RUN: (
        "A previous sync run exceeded the stale-run threshold and was reaped."
    ),
    LABEL_CREDENTIAL: (
        "Stored credential could not be decrypted (SECRET_KEY may have changed) "
        "— re-enter the bind password."
    ),
    LABEL_SEARCH_BASE: (
        "Search base not found or not visible to the bind account."
    ),
}

_RESULT_INVALID_CREDENTIALS = 49  # LDAP result code for invalidCredentials
_RESULT_NO_SUCH_OBJECT = 32  # LDAP result code for noSuchObject


class PagingError(Exception):
    """Paged search exceeded its loop guards (misbehaving server)."""


class InvalidCaError(ValueError):
    """The configured ``tls_ca_pem`` bundle could not be loaded."""


class UnparseableEntryError(Exception):
    """A directory entry failed required-field validation.

    Deliberately carries NO entry content (no DN, no attribute values):
    only the exception class name is ever persisted. Raised so an
    unreadable entry fails its whole category instead of silently dropping
    from the seen-set (which could later mark the object missing).
    """


class SearchBaseError(Exception):
    """The configured search base is missing or invisible to the bind DN."""


class CredentialDecryptionError(Exception):
    """Stored bind password could not be decrypted (SECRET_KEY rotated)."""


def classify_error(exc: BaseException) -> str:
    """Map an exception to a sanitized label. Never inspects messages."""
    # bind failures: ldap3 raises LDAPBindError (live) or an LDAPOperationResult
    # with result code 49 (ldap3.mock).
    if isinstance(exc, LDAPBindError):
        return LABEL_INVALID_CREDENTIALS
    if isinstance(exc, LDAPOperationResult) and getattr(exc, "result", None) == (
        _RESULT_INVALID_CREDENTIALS
    ):
        return LABEL_INVALID_CREDENTIALS
    # TLS: pre-flight probe raises ssl.SSLError subclasses (incl.
    # SSLCertVerificationError); ldap3 raises these for StartTLS/post-handshake.
    if isinstance(exc, (LDAPCertificateError, LDAPStartTLSError)):
        return LABEL_TLS
    if isinstance(exc, InvalidCaError):
        return LABEL_TLS
    if isinstance(exc, CredentialDecryptionError):
        return LABEL_CREDENTIAL
    if isinstance(exc, ssl.SSLError):
        return LABEL_TLS
    if isinstance(exc, (LDAPSocketReceiveError, TimeoutError)):
        # socket.timeout is an alias of TimeoutError on Python >= 3.10.
        return LABEL_TIMEOUT
    if isinstance(exc, LDAPSocketOpenError):
        return LABEL_CONNECTION
    if isinstance(exc, UnparseableEntryError):
        # An entry arrived but failed required-field validation.
        return LABEL_PROTOCOL
    if isinstance(exc, SearchBaseError):
        return LABEL_SEARCH_BASE
    if isinstance(exc, PagingError):
        return LABEL_PROTOCOL
    if isinstance(exc, LDAPOperationResult):
        # Post-bind operation failures in our flow are searches
        # (noSuchObject, unavailable, ...).
        return LABEL_SEARCH_FAILED
    if isinstance(exc, LDAPExceptionError):
        return LABEL_PROTOCOL
    if isinstance(exc, OSError):
        # Connection refused/reset, DNS failures, etc.
        return LABEL_CONNECTION
    return LABEL_UNEXPECTED


def message_for(label: str) -> str:
    """Static operator-facing message for a label (never exception text)."""
    return LABEL_MESSAGES.get(label, LABEL_MESSAGES[LABEL_UNEXPECTED])


def error_entry(category: str, exc: BaseException, *, count: int = 1) -> dict:
    """Build a persistable error record: label + class name + count only."""
    return {
        "category": category,
        "label": classify_error(exc),
        "error_type": type(exc).__name__,
        "error_count": count,
    }


def static_error(category: str, label: str, *, count: int = 1) -> dict:
    """Persistable error record for failures without an exception object
    (e.g. task submission). ``label`` must come from this module."""
    if label not in _ALL_LABELS:
        raise ValueError(f"unknown error label: {label}")
    return {"category": category, "label": label, "error_count": count}


__all__ = [
    "LABEL_CONNECTION",
    "LABEL_CREDENTIAL",
    "LABEL_INVALID_CREDENTIALS",
    "LABEL_PROTOCOL",
    "LABEL_SEARCH_BASE",
    "LABEL_SEARCH_FAILED",
    "LABEL_STALE_RUN",
    "LABEL_TASK_SUBMISSION",
    "LABEL_TLS",
    "LABEL_TIMEOUT",
    "LABEL_UNEXPECTED",
    "LABEL_MESSAGES",
    "InvalidCaError",
    "CredentialDecryptionError",
    "PagingError",
    "SearchBaseError",
    "UnparseableEntryError",
    "classify_error",
    "error_entry",
    "message_for",
    "static_error",
]
