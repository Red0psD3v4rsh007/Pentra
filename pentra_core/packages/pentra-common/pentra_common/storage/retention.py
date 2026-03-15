"""Artifact retention metadata helpers."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any


def apply_artifact_retention_metadata(
    metadata: dict[str, Any] | None,
    *,
    policy: str = "standard",
    retention_days: int | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    env_days = os.getenv("ARTIFACT_RETENTION_DAYS", "30")
    try:
        default_days = int(env_days)
    except ValueError:
        default_days = 30
    effective_days = max(
        int(retention_days if retention_days is not None else default_days),
        1,
    )
    enriched = dict(metadata or {})
    enriched["retention_policy"] = policy
    enriched["retention_days"] = effective_days
    enriched["expires_at"] = (now + timedelta(days=effective_days)).isoformat()
    return enriched
