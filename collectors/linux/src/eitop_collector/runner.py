"""Collector runtime: enrollment flow, heartbeat/inventory loop, backoff.

- Never executes anything received from the server (payloads are data only).
- Graceful shutdown on SIGINT/SIGTERM.
- Repeated failures back off exponentially up to one hour.
"""

from __future__ import annotations

import logging
import signal
import time

from eitop_collector import __version__
from eitop_collector.api import CollectorError, EitopClient
from eitop_collector.collect import collect_all, enroll_payload
from eitop_collector.config import CollectorConfig
from eitop_collector.credentials import (
    CredentialError,
    load_credentials,
    save_credentials,
)

logger = logging.getLogger(__name__)

MAX_BACKOFF = 3600  # seconds


class Runner:
    def __init__(
        self,
        config: CollectorConfig,
        client: EitopClient | None = None,
        *,
        sleep=time.sleep,
        monotonic=time.monotonic,
    ) -> None:
        self.config = config
        self.client = client or EitopClient(
            config.server_url,
            timeout=config.timeout_seconds,
            max_retries=config.max_retries,
            sleep=sleep,
        )
        self._sleep = sleep
        self._monotonic = monotonic
        self._stop = False

    def request_stop(self, *_args: object) -> None:
        logger.info("shutdown_requested")
        self._stop = True

    # --- Flows --------------------------------------------------------------

    def enroll(self, token: str) -> tuple[str, str]:
        """Enroll this host; persist the issued credential. Returns ids."""
        payload = enroll_payload(token)
        result = self.client.enroll(token, payload)
        save_credentials(
            self.config.credential_file, result["endpoint_id"], result["credential"]
        )
        logger.info("enrolled endpoint_id=%s", result["endpoint_id"])
        return result["endpoint_id"], result["credential"]

    def rotate(self) -> str:
        """Rotate this endpoint's credential and persist the replacement."""
        stored = load_credentials(self.config.credential_file)
        result = self.client.rotate_credential(stored.credential)
        save_credentials(
            self.config.credential_file, result["endpoint_id"], result["credential"]
        )
        logger.info("credential_rotated endpoint_id=%s", result["endpoint_id"])
        return result["credential"]

    def heartbeat_once(self) -> None:
        stored = load_credentials(self.config.credential_file)
        self.client.heartbeat(stored.credential, __version__)

    def inventory_once(self) -> dict:
        stored = load_credentials(self.config.credential_file)
        payload = collect_all()
        result = self.client.submit_inventory(stored.credential, payload)
        logger.info(
            "inventory_submitted endpoint_id=%s facts=%s packages=%s",
            stored.endpoint_id,
            result.get("counts", {}).get("facts"),
            result.get("counts", {}).get("packages"),
        )
        return result

    def run_forever(self) -> None:
        """Heartbeat + inventory loop until stopped (SIGINT/SIGTERM)."""
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)

        next_heartbeat = 0.0
        next_inventory = 0.0
        consecutive_failures = 0

        while not self._stop:
            now = self._monotonic()
            try:
                if now >= next_heartbeat:
                    self.heartbeat_once()
                    next_heartbeat = now + self.config.heartbeat_interval_seconds
                if now >= next_inventory:
                    self.inventory_once()
                    next_inventory = now + self.config.interval_seconds
                consecutive_failures = 0
            except CredentialError as exc:
                # Credential gone or insecure — cannot continue safely.
                logger.error("credential_error: %s", exc)
                return
            except CollectorError as exc:
                consecutive_failures += 1
                delay = min(
                    self.config.heartbeat_interval_seconds
                    * (2 ** min(consecutive_failures, 8)),
                    MAX_BACKOFF,
                )
                logger.warning(
                    "submission_failed attempt=%d next_retry=%ds error=%s",
                    consecutive_failures,
                    delay,
                    exc,
                )
                self._sleep(delay)
                continue

            # Sleep in small slices so signals stop us promptly.
            slept = 0.0
            while slept < 5.0 and not self._stop:
                self._sleep(1.0)
                slept += 1.0

        logger.info("stopped")


def run_once(config: CollectorConfig, client: EitopClient | None = None) -> dict:
    """Single heartbeat + inventory submission (used by tests and cron mode)."""
    runner = Runner(config, client)
    runner.heartbeat_once()
    return runner.inventory_once()
