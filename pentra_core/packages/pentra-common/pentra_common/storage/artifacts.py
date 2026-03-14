"""Helpers for resolving and reading artifact storage references."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


DEFAULT_ARTIFACT_STORE = "/tmp/pentra/artifacts"


def get_artifact_store_root() -> Path:
    """Return the configured local artifact store root."""
    return Path(os.getenv("ARTIFACT_STORE_PATH", DEFAULT_ARTIFACT_STORE))


def resolve_storage_ref(storage_ref: str) -> Path:
    """Resolve a storage_ref into a local filesystem path."""
    if storage_ref.startswith("artifacts/"):
        relative = storage_ref.removeprefix("artifacts/")
        return get_artifact_store_root() / relative

    if storage_ref.startswith("graphs/"):
        return get_artifact_store_root() / storage_ref

    return get_artifact_store_root() / storage_ref


def ensure_parent_dir(storage_ref: str) -> Path:
    """Ensure the parent directory for a storage_ref exists."""
    path = resolve_storage_ref(storage_ref)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def read_json_artifact(storage_ref: str) -> dict[str, Any] | list[Any] | None:
    """Read a JSON payload from the given storage_ref if it exists."""
    path = resolve_storage_ref(storage_ref)
    if not path.exists():
        return None

    return json.loads(path.read_text())


def write_json_artifact(storage_ref: str, payload: Any) -> tuple[int, str]:
    """Write JSON payload and return the byte length and SHA-256 checksum."""
    path = ensure_parent_dir(storage_ref)
    raw = json.dumps(payload, indent=2, default=str)
    path.write_text(raw)
    return len(raw.encode("utf-8")), sha256_text(raw)


def sha256_text(value: str) -> str:
    """Hash a UTF-8 string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(payload: Any) -> str:
    """Hash a JSON payload deterministically."""
    raw = json.dumps(payload, sort_keys=True, default=str)
    return sha256_text(raw)
