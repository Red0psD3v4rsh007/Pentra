from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import uuid
from typing import Any, Mapping


CONTRACT_VERSION = 1
DEFAULT_FRESHNESS_WINDOW_SECONDS = int(os.getenv("PENTRA_PROOF_MAX_AGE_SECONDS", "21600"))
COMMON_ENVIRONMENT_KEYS = (
    "api_base_url",
    "orchestrator_base_url",
    "demo_target_url",
)


class ProofContractError(RuntimeError):
    """Raised when a proof artifact is stale, malformed, or inconsistent."""


@dataclass(frozen=True)
class ValidatedProofArtifact:
    name: str
    path: Path
    payload: dict[str, Any]
    metadata: dict[str, Any]
    generated_at: datetime
    age_seconds: float


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def new_run_id() -> str:
    return uuid.uuid4().hex


def _json_ready(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _git_output(root_dir: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root_dir,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = completed.stdout.strip()
    return value or None


def _git_metadata(root_dir: Path) -> dict[str, Any]:
    revision = _git_output(root_dir, "rev-parse", "HEAD") or "unknown"
    short_revision = _git_output(root_dir, "rev-parse", "--short", "HEAD") or revision[:12]
    branch = _git_output(root_dir, "rev-parse", "--abbrev-ref", "HEAD") or "unknown"
    dirty = bool(_git_output(root_dir, "status", "--short"))
    return {
        "revision": revision,
        "short_revision": short_revision,
        "branch": branch,
        "dirty": dirty,
    }


def _system_context() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
    }


def _environment_stamp(*, system: Mapping[str, Any], context: Mapping[str, Any]) -> str:
    shared_context = {
        key: context[key]
        for key in COMMON_ENVIRONMENT_KEYS
        if key in context
    } or dict(context)
    payload = json.dumps(
        {
            "system": _json_ready(system),
            "context": _json_ready(shared_context),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def build_proof_metadata(
    *,
    artifact_kind: str,
    phase: str,
    script_path: str,
    root_dir: Path,
    environment_context: Mapping[str, Any],
    run_id: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or utc_now()
    system = _system_context()
    context = _json_ready(dict(environment_context))
    return {
        "contract_version": CONTRACT_VERSION,
        "artifact_kind": artifact_kind,
        "phase": phase,
        "run_id": run_id or new_run_id(),
        "generated_at": generated,
        "generator": {"script": script_path},
        "git": _git_metadata(root_dir),
        "environment": {
            "system": system,
            "context": context,
        },
        "environment_stamp": _environment_stamp(system=system, context=context),
    }


def stamp_proof_payload(
    payload: Mapping[str, Any],
    *,
    artifact_kind: str,
    phase: str,
    script_path: str,
    root_dir: Path,
    environment_context: Mapping[str, Any],
    run_id: str,
) -> dict[str, Any]:
    stamped = dict(_json_ready(dict(payload)))
    generated_at = utc_now()
    metadata = build_proof_metadata(
        artifact_kind=artifact_kind,
        phase=phase,
        script_path=script_path,
        root_dir=root_dir,
        environment_context=environment_context,
        run_id=run_id,
        generated_at=generated_at,
    )
    stamped["generated_at"] = generated_at
    stamped["run_id"] = metadata["run_id"]
    stamped["git_revision"] = str(metadata["git"]["revision"])
    stamped["environment_stamp"] = str(metadata["environment_stamp"])
    stamped["proof_metadata"] = metadata
    return stamped


def _load_payload(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise ProofContractError(f"Missing proof artifact: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProofContractError(f"Invalid JSON proof artifact: {path}") from exc
    if not isinstance(payload, dict):
        raise ProofContractError(f"Proof artifact is not a JSON object: {path}")
    return payload


def validate_proof_artifact(
    *,
    name: str,
    path: Path,
    artifact_kind: str,
    max_age_seconds: int = DEFAULT_FRESHNESS_WINDOW_SECONDS,
    required_status: str = "passed",
) -> ValidatedProofArtifact:
    payload = _load_payload(path)
    metadata = payload.get("proof_metadata")
    if not isinstance(metadata, dict):
        raise ProofContractError(f"{name} missing proof_metadata: {path}")
    if int(metadata.get("contract_version") or 0) != CONTRACT_VERSION:
        raise ProofContractError(f"{name} has unexpected proof contract version: {path}")
    if str(metadata.get("artifact_kind") or "") != artifact_kind:
        raise ProofContractError(
            f"{name} has wrong artifact kind {metadata.get('artifact_kind')!r}: {path}"
        )
    run_id = str(metadata.get("run_id") or "")
    git_revision = str((metadata.get("git") or {}).get("revision") or "")
    environment_stamp = str(metadata.get("environment_stamp") or "")
    generated_at_raw = str(metadata.get("generated_at") or "")
    if not run_id or not git_revision or not environment_stamp or not generated_at_raw:
        raise ProofContractError(f"{name} missing required metadata fields: {path}")
    generated_at = _parse_datetime(generated_at_raw)
    if generated_at is None:
        raise ProofContractError(f"{name} has invalid generated_at: {path}")
    age_seconds = (datetime.now(UTC) - generated_at).total_seconds()
    if age_seconds < 0:
        raise ProofContractError(f"{name} generated_at is in the future: {path}")
    if age_seconds > max_age_seconds:
        raise ProofContractError(
            f"{name} is stale ({round(age_seconds, 2)}s old, max {max_age_seconds}s): {path}"
        )
    status = payload.get("status")
    if required_status and status != required_status:
        raise ProofContractError(
            f"{name} has status {status!r}, expected {required_status!r}: {path}"
        )
    return ValidatedProofArtifact(
        name=name,
        path=path,
        payload=payload,
        metadata=metadata,
        generated_at=generated_at,
        age_seconds=age_seconds,
    )


def validate_proof_bundle(
    artifacts: Mapping[str, tuple[Path, str]],
    *,
    max_age_seconds: int = DEFAULT_FRESHNESS_WINDOW_SECONDS,
    required_status: str = "passed",
) -> dict[str, Any]:
    validated: dict[str, ValidatedProofArtifact] = {}
    for name, (path, artifact_kind) in artifacts.items():
        validated[name] = validate_proof_artifact(
            name=name,
            path=path,
            artifact_kind=artifact_kind,
            max_age_seconds=max_age_seconds,
            required_status=required_status,
        )
    revisions = {
        str(artifact.metadata["git"]["revision"])
        for artifact in validated.values()
    }
    if len(revisions) != 1:
        raise ProofContractError(f"Proof artifacts disagree on git revision: {sorted(revisions)}")
    environment_stamps = {
        str(artifact.metadata["environment_stamp"])
        for artifact in validated.values()
    }
    if len(environment_stamps) != 1:
        raise ProofContractError(
            f"Proof artifacts disagree on environment stamp: {sorted(environment_stamps)}"
        )
    return {
        "git_revision": revisions.pop(),
        "environment_stamp": environment_stamps.pop(),
        "artifacts": validated,
    }
