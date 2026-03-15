"""Helpers for redacting secrets from API responses and logs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_REDACTED = "[REDACTED]"
_SECRET_KEY_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "credential",
    "private_key",
    "access_key",
    "refresh_token",
)


def redact_secrets(value: Any) -> Any:
    """Recursively redact known secret-bearing fields."""
    return _redact(value, parent_key=None)


def _redact(value: Any, *, parent_key: str | None) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if _is_secret_key(key):
                redacted[key] = _REDACTED
            else:
                redacted[key] = _redact(raw_value, parent_key=key)
        return redacted

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact(item, parent_key=parent_key) for item in value]

    if isinstance(value, str) and parent_key and _is_secret_key(parent_key):
        return _REDACTED

    return value


def _is_secret_key(key: str) -> bool:
    lowered = key.strip().lower()
    return any(fragment in lowered for fragment in _SECRET_KEY_FRAGMENTS)
