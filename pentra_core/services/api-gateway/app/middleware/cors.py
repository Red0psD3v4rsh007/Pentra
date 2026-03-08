"""CORS configuration for the Pentra API Gateway.

Applies CORS headers based on the ``allowed_origins`` setting.
In development mode, the default allows ``http://localhost:3000``
(the Next.js dev server).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pentra_common.config.settings import get_settings


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
