"""CORS configuration for the Pentra API Gateway.

Applies CORS headers based on the ``allowed_origins`` setting.
In development mode, the default allows ``http://localhost:3000``
(the Next.js dev server).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse

from pentra_common.config.settings import get_settings


def _loopback_origin_variants(origin: str) -> set[str]:
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {origin}

    hostname = parsed.hostname or ""
    if hostname not in {"localhost", "127.0.0.1"}:
        return {origin}

    port = f":{parsed.port}" if parsed.port is not None else ""
    variants = {
        f"{parsed.scheme}://localhost{port}",
        f"{parsed.scheme}://127.0.0.1{port}",
    }
    return variants


def _normalize_allowed_origins(origins: list[str], *, frontend_base_url: str) -> list[str]:
    normalized: set[str] = set()
    for origin in origins:
        normalized.update(_loopback_origin_variants(origin))
    normalized.update(_loopback_origin_variants(frontend_base_url))
    return sorted(normalized)


def configure_cors(app: FastAPI) -> None:
    """Attach the CORS middleware to the FastAPI application.

    Settings are loaded from ``pentra_common.config.settings``:
    - ``allowed_origins`` — list of allowed origins
    - ``app_env`` — if ``development``, allows all origins as fallback
    """
    settings = get_settings()

    origins = settings.allowed_origins
    if settings.app_env == "development" and not origins:
        origins = ["*"]
    elif origins and origins != ["*"]:
        origins = _normalize_allowed_origins(
            origins,
            frontend_base_url=settings.frontend_base_url,
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
        ],
    )
