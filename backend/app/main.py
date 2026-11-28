"""FastAPI application factory."""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response as StarletteResponse

from app.api.health import router as health_router
from app.api.v1 import api_router
from app.core.config import get_settings
from app.core.exceptions import PROBLEM_MEDIA_TYPE, problem, register_exception_handlers
from app.core.logging import request_id_var, setup_logging

API_V1_PREFIX = "/api/v1"

# Safe methods never mutate state and are exempt from the Origin check.
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _origin_check_middleware(app: FastAPI) -> None:
    """Reject cross-origin state-changing requests (CSRF defense-in-depth).

    Browsers always attach an ``Origin`` header to cross-site POSTs; if it is
    present but not in the configured allowlist the request is refused.
    Non-browser clients (curl, tests) send no ``Origin`` and are unaffected.
    Cookie-borne auth (the refresh cookie) makes this mandatory.
    """
    settings = get_settings()
    allowed = set(settings.cors_origin_list)

    @app.middleware("http")
    async def check_origin(
        request: Request, call_next: RequestResponseEndpoint
    ) -> StarletteResponse:
        if (
            request.method not in _SAFE_METHODS
            and request.url.path.startswith(API_V1_PREFIX)
        ):
            origin = request.headers.get("origin")
            # Defense-in-depth for clients that reach the API without an
            # Origin header: browsers label cross-site requests via
            # Sec-Fetch-Site. Non-browser clients send neither and are
            # unaffected (Phase 6 audit A7).
            cross_site = (
                request.headers.get("sec-fetch-site", "").lower() == "cross-site"
            )
            if cross_site or (origin is not None and origin not in allowed):
                return JSONResponse(
                    status_code=403,
                    content={
                        "type": "about:blank",
                        "title": "Cross-origin request rejected",
                        "status": 403,
                        "detail": "Request origin is not allowed.",
                    },
                    media_type=PROBLEM_MEDIA_TYPE,
                )
        return await call_next(request)


# Path-prefix → maximum request body size in bytes. Checked before any
# parsing so oversized payloads never reach a handler (413).
_BODY_LIMITS: tuple[tuple[str, int], ...] = (
    ("/api/v1/agent/inventory", 5 * 1024 * 1024),  # full package lists
    ("/api/v1/agent/enroll", 16 * 1024),
    ("/api/v1/agent/", 8 * 1024),  # heartbeat, rotate-credential
    ("/api/v1/endpoints/", 256 * 1024),
    ("/api/v1/", 64 * 1024),
)


def _body_size_middleware(app: FastAPI) -> None:
    """Reject oversized request bodies (413) and enforce header discipline.

    Content-Length carries the size; a chunked request has none, which
    previously skipped every limit (Phase 6 audit A8). None of our
    clients (frontend fetch, collectors, Pester) use chunked encoding,
    and both reverse proxies buffer and re-send bodies with
    Content-Length, so chunked requests to the API are refused outright
    with 411 instead of being metered byte-by-byte.
    """
    limits = sorted(_BODY_LIMITS, key=lambda item: -len(item[0]))

    @app.middleware("http")
    async def check_body_size(
        request: Request, call_next: RequestResponseEndpoint
    ) -> StarletteResponse:
        if request.method in ("POST", "PUT", "PATCH") and request.url.path.startswith(
            API_V1_PREFIX
        ):
            if request.headers.get("transfer-encoding"):
                return problem(
                    411,
                    "Length required",
                    "Chunked transfer encoding is not supported; "
                    "send a Content-Length header.",
                )
            raw_length = request.headers.get("content-length")
            if raw_length is not None:
                try:
                    size = int(raw_length)
                except ValueError:
                    return problem(
                        400, "Invalid request", "Malformed Content-Length header."
                    )
                for prefix, limit in limits:
                    if request.url.path.startswith(prefix):
                        if size > limit:
                            return problem(
                                413,
                                "Payload too large",
                                f"Request body exceeds {limit} bytes.",
                            )
                        break
        return await call_next(request)


def _security_headers_middleware(app: FastAPI) -> None:
    """Baseline security headers + per-request correlation id.

    ``X-Request-ID`` is ALWAYS synthesized here (never copied from the
    request — an inbound value is attacker-controlled): the id is echoed
    on the response and injected into every JSON log line produced while
    handling the request, which is what makes request correlation real
    (Phase 6 audit F15 — previously the header was exposed via CORS but
    never set by anyone).
    """
    settings = get_settings()

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: RequestResponseEndpoint
    ) -> StarletteResponse:
        request_id = uuid.uuid4().hex
        token = request_id_var.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            )
        return response


def create_app() -> FastAPI:
    """Build the application. Used by uvicorn and by tests."""
    settings = get_settings()
    setup_logging(settings.log_level)

    # Interactive API docs expose the full route surface — keep them out of
    # production deployments (still available in dev/testing).
    docs_url = None if settings.is_production else "/docs"
    redoc_url = None if settings.is_production else "/redoc"
    openapi_url = None if settings.is_production else "/openapi.json"

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Enterprise IT Operations Platform API",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    # Restrictive CORS: explicit allowlist, credentials allowed only for
    # configured origins (never "*" with credentials).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )

    register_exception_handlers(app)
    _origin_check_middleware(app)
    _body_size_middleware(app)
    _security_headers_middleware(app)

    app.include_router(health_router)
    app.include_router(api_router, prefix=API_V1_PREFIX)

    return app


app = create_app()
