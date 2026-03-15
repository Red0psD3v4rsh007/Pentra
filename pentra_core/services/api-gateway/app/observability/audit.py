"""Structured audit logging helpers for security-sensitive actions."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import Request

from pentra_common.auth.tenant_context import CurrentUser

logger = logging.getLogger("pentra.audit")


def log_audit_event(
    *,
    request: Request,
    user: CurrentUser | None,
    action: str,
    outcome: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    payload = {
        "action": action,
        "outcome": outcome,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "path": request.url.path,
        "method": request.method,
        "request_id": getattr(request.state, "request_id", None),
        "tenant_id": str(user.tenant_id) if user else None,
        "user_id": str(user.user_id) if user else None,
        "roles": list(user.roles) if user else [],
        "details": details or {},
    }
    logger.info("audit_event=%s", json.dumps(payload, sort_keys=True, default=str))
