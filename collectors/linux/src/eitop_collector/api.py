"""HTTP client for the EITOP agent API.

- Agent credential is sent only as an Authorization bearer header.
- Retries: network errors, timeouts, 5xx and 429 with capped exponential
  backoff; other 4xx fail immediately (retrying a 401/422 is pointless).
- Secrets (credential, enrollment token) are never logged.
- Responses are validated as RFC 9457 problem+json on failure.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Backoff: base * 2^attempt, capped (seconds).
_BACKOFF_BASE = 1.0
_BACKOFF_CAP = 60.0
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class CollectorError(Exception):
    """Server rejected the request or retries were exhausted."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class EitopClient:
    """Thin, retrying client for /api/v1/agent/*."""

    def __init__(
        self,
        server_url: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 5,
        transport: httpx.BaseTransport | None = None,
        sleep=time.sleep,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.max_retries = max_retries
        self._sleep = sleep
        self._http = httpx.Client(
            base_url=self.server_url,
            timeout=timeout,
            transport=transport,  # None → real network; tests inject MockTransport
            headers={"User-Agent": "eitop-collector/0.1"},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> EitopClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- Core request with retry -------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        credential: str | None = None,
    ) -> httpx.Response:
        headers: dict[str, str] = {}
        if credential:
            headers["Authorization"] = f"Bearer {credential}"

        last_error: str = "request failed"
        for attempt in range(self.max_retries + 1):
            if attempt:
                delay = min(_BACKOFF_BASE * (2 ** (attempt - 1)), _BACKOFF_CAP)
                logger.debug("retry_backoff path=%s attempt=%d delay=%.1fs", path, attempt, delay)
                self._sleep(delay)
            try:
                resp = self._http.request(
                    method, path, json=json_body, headers=headers
                )
            except httpx.TimeoutException:
                last_error = "timeout"
                logger.warning("request_timeout path=%s attempt=%d", path, attempt)
                continue
            except httpx.TransportError as exc:
                last_error = f"network error: {exc.__class__.__name__}"
                logger.warning(
                    "request_network_error path=%s attempt=%d type=%s",
                    path,
                    attempt,
                    exc.__class__.__name__,
                )
                continue

            if resp.status_code < 400:
                return resp
            if resp.status_code in _RETRYABLE_STATUS and attempt < self.max_retries:
                last_error = f"HTTP {resp.status_code}"
                continue
            raise CollectorError(
                self._error_message(resp), status_code=resp.status_code
            )

        raise CollectorError(
            f"Giving up after {self.max_retries + 1} attempts: {last_error}"
        )

    @staticmethod
    def _error_message(resp: httpx.Response) -> str:
        """Extract a safe message from an RFC 9457 problem response."""
        try:
            body = resp.json()
            title = body.get("title", "")
            detail = body.get("detail", "")
            return f"HTTP {resp.status_code}: {title} {detail}".strip()
        except ValueError:
            return f"HTTP {resp.status_code}"

    # --- Endpoints ----------------------------------------------------------

    def enroll(
        self, token: str, system_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Exchange an enrollment token for an endpoint credential.

        Returns ``{"endpoint_id": ..., "credential": ...}``. The caller must
        persist the credential securely; it is never logged here.
        """
        body = {"token": token, **system_info}
        resp = self._request("POST", "/api/v1/agent/enroll", json_body=body)
        data = resp.json()
        if "credential" not in data or "endpoint_id" not in data:
            raise CollectorError("Enrollment response missing credential")
        return data

    def heartbeat(self, credential: str, agent_version: str) -> dict[str, Any]:
        resp = self._request(
            "POST",
            "/api/v1/agent/heartbeat",
            json_body={"agent_version": agent_version},
            credential=credential,
        )
        return resp.json()

    def submit_inventory(
        self, credential: str, inventory: dict[str, Any]
    ) -> dict[str, Any]:
        resp = self._request(
            "POST",
            "/api/v1/agent/inventory",
            json_body=inventory,
            credential=credential,
        )
        return resp.json()

    def rotate_credential(self, credential: str) -> dict[str, Any]:
        resp = self._request(
            "POST", "/api/v1/agent/rotate-credential", credential=credential
        )
        return resp.json()
