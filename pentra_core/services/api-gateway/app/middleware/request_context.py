"""Request context middleware for request IDs and lightweight tracing."""

from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from pentra_common.config.settings import get_settings

logger = logging.getLogger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id to each request/response and log completion."""

    def __init__(self, app, **kwargs):
        super().__init__(app, **kwargs)
        settings = get_settings()
        self._request_id_header = settings.request_id_header

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        started_at = time.perf_counter()
        request_id = request.headers.get(self._request_id_header) or str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)

        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
        response.headers[self._request_id_header] = request_id
        response.headers["X-Process-Time-Ms"] = str(duration_ms)

        logger.info(
            "request.complete request_id=%s method=%s path=%s status=%s duration_ms=%s tenant=%s",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            getattr(request.state, "tenant_id", None),
        )
        return response
