"""Structured JSON logging for all Pentra services."""

from __future__ import annotations

import logging
import sys

from pentra_common.config.settings import get_settings


def setup_logging() -> None:
    """Configure structured logging for the current process.

    Uses JSON format in production, human-readable in development.
    """
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    if settings.app_env == "development":
        fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    else:
        # Structured JSON for CloudWatch / log aggregation
        fmt = (
            '{"ts":"%(asctime)s","level":"%(levelname)s",'
            '"logger":"%(name)s","msg":"%(message)s"}'
        )

    logging.basicConfig(
        level=log_level,
        format=fmt,
        stream=sys.stdout,
        force=True,
    )

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.db_echo else logging.WARNING
    )
