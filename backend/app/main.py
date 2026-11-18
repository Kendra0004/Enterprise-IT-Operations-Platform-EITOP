"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response as StarletteResponse

from app.api.health import router as health_router
from app.api.v1 import api_router
from app.core.config import get_settings
from app.core.exceptions import PROBLEM_MEDIA_TYPE, register_exception_handlers
from app.core.logging import setup_logging

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
            if origin is not None and origin not in allowed:
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


def _security_headers_middleware(app: FastAPI) -> None:
    """Baseline security headers on every response (API + errors)."""
    settings = get_settings()

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: RequestResponseEndpoint
    ) -> StarletteResponse:
        response = await call_next(request)
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
    _security_headers_middleware(app)

    app.include_router(health_router)
    app.include_router(api_router, prefix=API_V1_PREFIX)

    return app


app = create_app()
