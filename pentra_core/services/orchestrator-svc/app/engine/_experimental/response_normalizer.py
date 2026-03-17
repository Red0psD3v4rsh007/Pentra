"""Response normalizer — removes noise from responses for comparison.

MOD-13.5: Strips timestamps, random identifiers, session tokens, CSRF
tokens, and other dynamic content to enable meaningful differential
comparison between responses.
"""

from __future__ import annotations

__classification__ = "experimental"

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from app.engine.response_collector import ResponseRecord

logger = logging.getLogger(__name__)


@dataclass
class NormalizedResponse:
    """A response with noise removed."""

    original_id: str
    endpoint: str
    status_code: int
    normalized_body: str
    normalized_hash: str
    body_length: int
    elapsed_ms: float
    noise_removed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.original_id, "endpoint": self.endpoint,
            "status": self.status_code, "hash": self.normalized_hash,
            "length": self.body_length, "noise_types": len(self.noise_removed),
        }


# ── Noise patterns ──────────────────────────────────────────────

_NOISE_PATTERNS: list[tuple[str, str]] = [
    # Timestamps (ISO)
    (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*Z?", "timestamp"),
    # UUIDs (must run before unix_timestamp to avoid partial matches)
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "uuid"),
    (r"\b\d{10,13}\b", "unix_timestamp"),
    # Session/CSRF tokens (hex strings 24+ chars)
    (r"[0-9a-f]{24,}", "hex_token"),
    # JWT tokens
    (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "jwt"),
    # Random IDs (alphanumeric 16+ chars)
    (r"\b[A-Za-z0-9]{16,}\b", "random_id"),
]

_HEADER_NOISE = {"set-cookie", "date", "x-request-id", "x-trace-id", "etag"}


class ResponseNormalizer:
    """Normalizes responses by removing dynamic noise.

    Usage::

        normalizer = ResponseNormalizer()
        normalized = normalizer.normalize(response_record)
    """

    def normalize(self, record: ResponseRecord) -> NormalizedResponse:
        """Normalize a single response."""
        body = record.body
        noise_removed: list[str] = []

        for pattern, noise_type in _NOISE_PATTERNS:
            cleaned = re.sub(pattern, f"[{noise_type}]", body, flags=re.IGNORECASE)
            if cleaned != body:
                noise_removed.append(noise_type)
                body = cleaned

        norm_hash = hashlib.md5(body.encode()).hexdigest()[:12]

        return NormalizedResponse(
            original_id=record.record_id,
            endpoint=record.endpoint,
            status_code=record.status_code,
            normalized_body=body,
            normalized_hash=norm_hash,
            body_length=len(body),
            elapsed_ms=record.elapsed_ms,
            noise_removed=noise_removed,
        )

    def normalize_batch(self, records: list[ResponseRecord]) -> list[NormalizedResponse]:
        """Normalize multiple responses."""
        return [self.normalize(r) for r in records]

    def filter_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Remove noisy headers for comparison."""
        return {k: v for k, v in headers.items() if k.lower() not in _HEADER_NOISE}
