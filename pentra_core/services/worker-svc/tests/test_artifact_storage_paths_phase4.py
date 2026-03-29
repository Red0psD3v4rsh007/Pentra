"""Phase 4 regression tests for shared artifact storage path handling."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
from pathlib import Path

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_artifact_resolver_defaults_to_shared_store_root(monkeypatch, tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    monkeypatch.setenv("ARTIFACT_STORE_PATH", str(artifact_root))

    from app.engine.artifact_resolver import ArtifactResolver
    from pentra_common.storage.artifacts import get_artifact_store_root

    resolver = ArtifactResolver()

    assert resolver._storage_base == get_artifact_store_root()
    assert resolver._storage_base == artifact_root


def test_artifact_resolver_resolves_artifacts_prefixed_refs(
    monkeypatch,
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    monkeypatch.setenv("ARTIFACT_STORE_PATH", str(artifact_root))

    from app.engine.artifact_resolver import ArtifactResolver

    storage_ref = "artifacts/tenant-1/scan-1/node-1/subfinder.json"
    payload_path = artifact_root / "tenant-1" / "scan-1" / "node-1" / "subfinder.json"
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path.write_text(json.dumps([{"host": "app.local"}, {"host": "api.local"}]))

    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "subdomains.ref").write_text(storage_ref)

    resolver = ArtifactResolver()
    resolved = asyncio.run(resolver.resolve_input_refs(input_dir))

    assert resolved == 1
    assert (input_dir / "subdomains.txt").read_text() == "app.local\napi.local\n"


def test_artifact_handler_uses_shared_store_root(monkeypatch, tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    monkeypatch.setenv("ARTIFACT_STORE_PATH", str(artifact_root))

    import app.engine.artifact_handler as artifact_handler
    from pentra_common.storage.artifacts import get_artifact_store_root

    artifact_handler = importlib.reload(artifact_handler)

    assert Path(artifact_handler.ARTIFACT_STORE) == get_artifact_store_root()
    assert Path(artifact_handler.ARTIFACT_STORE) == artifact_root
