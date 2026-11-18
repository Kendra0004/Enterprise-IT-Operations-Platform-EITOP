"""Centralized exception handling with RFC 9457 problem responses.

All error responses use ``application/problem+json`` with the shape:

    {"type": ..., "title": ..., "status": ..., "detail": ..., "errors": [...]}

so API clients get one consistent error contract.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

PROBLEM_MEDIA_TYPE = "application/problem+json"

# Maps common HTTP status codes to stable RFC 9457 type URIs.
_DEFAULT_TYPES = {
    400: "about:blank",
    401: "about:blank",
    403: "about:blank",
    404: "about:blank",
    409: "about:blank",
    422: "about:blank",
    429: "about:blank",
    500: "about:blank",
}


def problem(
    status: int,
    title: str,
    detail: str = "",
    *,
    type_uri: str | None = None,
    errors: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build an RFC 9457 problem+json response."""
    body: dict[str, Any] = {
        "type": type_uri or _DEFAULT_TYPES.get(status, "about:blank"),
        "title": title,
        "status": status,
    }
    if detail:
        body["detail"] = detail
    if errors:
        body["errors"] = errors
    return JSONResponse(
        status_code=status,
        content=body,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )


class AppError(Exception):
    """Domain error carrying an HTTP status — raised by services, not routes."""

    def __init__(self, status: int, title: str, detail: str = "") -> None:
        super().__init__(detail or title)
        self.status = status
        self.title = title
        self.detail = detail


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = [
            {
                # Strip the FastAPI "body"/"query" container prefix so clients
                # see just the field path (e.g. "email", not "body.email").
                "field": ".".join(
                    str(p) for p in err.get("loc", []) if p not in ("body", "query", "path")
                )
                or "payload",
                "message": err.get("msg", ""),
            }
            for err in exc.errors()
        ]
        return problem(
            422,
            "Validation error",
            "Request payload failed validation.",
            errors=errors,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return problem(
            exc.status_code,
            str(exc.detail) if exc.detail else "Error",
            headers=dict(exc.headers) if exc.headers else None,
        )

    @app.exception_handler(AppError)
    async def _app_error(_request: Request, exc: AppError) -> JSONResponse:
        return problem(exc.status, exc.title, exc.detail)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log with traceback for operators; never leak internals to clients.
        logger.exception(
            "unhandled_error",
            extra={"path": request.url.path, "method": request.method},
        )
        return problem(
            500,
            "Internal server error",
            "An unexpected error occurred. The incident has been logged.",
        )
