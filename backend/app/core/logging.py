"""Structured JSON logging.

Every log line is a single JSON object so logs can be ingested by any
ELK/Loki-style pipeline without custom parsers. Secrets (passwords, tokens)
are never attached to log records; callers must not pass them as ``extra``.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

# Attributes present on every LogRecord that are noise for our pipeline.
_RESERVED = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    """Format records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    """Configure root + uvicorn loggers idempotently."""
    root = logging.getLogger()
    root.setLevel(level.upper())
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return  # already configured (e.g. tests re-creating the app)

    formatter = JsonFormatter()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root.handlers = [handler]

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
