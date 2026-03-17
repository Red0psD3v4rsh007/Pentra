"""Response collector — captures request/response metadata.

MOD-13.5: Stores HTTP request/response pairs with metadata (endpoint,
parameters, headers, status, body length, content hash, timing) for
differential analysis during scan execution.
"""

from __future__ import annotations

__classification__ = "experimental"

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ResponseRecord:
    """Captured request/response pair."""

    record_id: str
    endpoint: str
    method: str = "GET"
    parameters: dict[str, str] = field(default_factory=dict)
    request_headers: dict[str, str] = field(default_factory=dict)
    status_code: int = 200
    response_headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    body_hash: str = ""
    elapsed_ms: float = 0.0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.record_id, "endpoint": self.endpoint,
            "method": self.method, "status": self.status_code,
            "body_length": self.body_length, "elapsed_ms": self.elapsed_ms,
        }


class ResponseCollector:
    """Collects and indexes request/response records.

    Usage::

        collector = ResponseCollector()
        collector.collect(endpoint="/api/users", method="GET", ...)
        records = collector.get_by_endpoint("/api/users")
    """

    def __init__(self) -> None:
        self._records: list[ResponseRecord] = []
        self._by_endpoint: dict[str, list[ResponseRecord]] = {}
        self._counter = 0

    @property
    def total(self) -> int:
        return len(self._records)

    def collect(
        self,
        endpoint: str,
        method: str = "GET",
        parameters: dict[str, str] | None = None,
        request_headers: dict[str, str] | None = None,
        status_code: int = 200,
        response_headers: dict[str, str] | None = None,
        body: str = "",
        elapsed_ms: float = 0.0,
        tags: list[str] | None = None,
    ) -> ResponseRecord:
        """Collect a request/response pair."""
        self._counter += 1
        body_hash = hashlib.md5(body.encode()).hexdigest()[:12]
        record = ResponseRecord(
            record_id=f"resp:{self._counter}",
            endpoint=endpoint, method=method,
            parameters=parameters or {},
            request_headers=request_headers or {},
            status_code=status_code,
            response_headers=response_headers or {},
            body=body, body_length=len(body),
            body_hash=body_hash, elapsed_ms=elapsed_ms,
            tags=tags or [],
        )
        self._records.append(record)
        self._by_endpoint.setdefault(endpoint, []).append(record)
        return record

    def get_all(self) -> list[ResponseRecord]:
        return list(self._records)

    def get_by_endpoint(self, endpoint: str) -> list[ResponseRecord]:
        return self._by_endpoint.get(endpoint, [])

    def get_endpoints(self) -> list[str]:
        return list(self._by_endpoint.keys())

    def get_by_status(self, status_code: int) -> list[ResponseRecord]:
        return [r for r in self._records if r.status_code == status_code]

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "endpoints": len(self._by_endpoint),
            "statuses": list({r.status_code for r in self._records}),
        }
