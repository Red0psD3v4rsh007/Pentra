"""Live validator for the real external graphql_cop execution lane."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES_DIR = REPO_ROOT / "pentra_core" / "packages" / "pentra-common"
WORKER_APP_ROOT = REPO_ROOT / "pentra_core" / "services" / "worker-svc"
if str(PACKAGES_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGES_DIR))
if str(WORKER_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_APP_ROOT))

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from phase10_live_benchmark_helpers import (
        ensure_target,
        load_benchmark,
        OUTPUT_DIR,
        resolve_scan_config,
        utc_now,
        wait_for_http,
    )
else:
    from .phase10_live_benchmark_helpers import (
        ensure_target,
        load_benchmark,
        OUTPUT_DIR,
        resolve_scan_config,
        utc_now,
        wait_for_http,
    )

from pentra_common.storage.artifacts import read_json_artifact, read_text_artifact, resolve_storage_ref

from app.engine.artifact_handler import normalize_output, store_artifact
from app.engine.container_runner import ContainerRunner
from app.services.worker_service import WorkerService
from app.tools.tool_registry import get_tool, render_command


BENCHMARK_PATH = (
    REPO_ROOT / "pentra_core" / "dev_targets" / "capability_benchmarks" / "repo_demo_api.json"
)
RESULT_PATH = OUTPUT_DIR / "graphql_cop_live_latest.json"


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, timezone.__class__)):
        return str(value)
    return str(value)


def _storage_ref_exists(storage_ref: str | None) -> bool:
    if not storage_ref:
        return False
    path = resolve_storage_ref(storage_ref)
    return path.exists()


def _read_json_if_ref(storage_ref: str | None) -> dict[str, Any] | list[Any] | None:
    if not storage_ref:
        return None
    return read_json_artifact(storage_ref)


def _read_text_if_ref(storage_ref: str | None) -> str:
    if not storage_ref:
        return ""
    return read_text_artifact(storage_ref) or ""


async def _run_live_validation() -> dict[str, Any]:
    target_spec = load_benchmark(BENCHMARK_PATH)
    target_status = await ensure_target(target_spec)
    if str(target_status.get("status") or "") not in {"ok", "already_running"}:
        retry_health = await wait_for_http("http://127.0.0.1:8088/healthz", 45)
        target_status["health_retry"] = retry_health
        if not retry_health.get("reachable"):
            raise RuntimeError(f"Target not ready: {target_status}")

    _plan, scan_config = resolve_scan_config(target_spec)
    graphql_target_url = "http://127.0.0.1:8088/graphql"
    base_target = "http://127.0.0.1:8088"

    execution = scan_config.setdefault("execution", {})
    if not isinstance(execution, dict):
        execution = {}
        scan_config["execution"] = execution
    execution["mode"] = "controlled_live_scoped"
    execution["target_policy"] = "in_scope"
    execution["allowed_live_tools"] = ["graphql_cop"]

    scope = scan_config.setdefault("scope", {})
    if not isinstance(scope, dict):
        scope = {}
        scan_config["scope"] = scope
    scope["allowed_hosts"] = ["127.0.0.1", "localhost"]

    targeting = scan_config.setdefault("targeting", {})
    if not isinstance(targeting, dict):
        targeting = {}
        scan_config["targeting"] = targeting
    targeting["base_url"] = base_target
    targeting["host"] = "127.0.0.1"

    command_context = scan_config.setdefault("command_context", {})
    if not isinstance(command_context, dict):
        command_context = {}
        scan_config["command_context"] = command_context
    command_context["graphql_target_url"] = graphql_target_url

    tool = get_tool("graphql_cop")
    if tool is None:
        raise RuntimeError("graphql_cop tool spec not found")

    command = render_command(
        tool,
        target=base_target,
        output_dir="/work/output",
        input_dir="/work/input",
        config_file="/work/config.json",
        context={"graphql_target_url": graphql_target_url},
    )

    runner = ContainerRunner()
    job_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    node_id = uuid.uuid4()

    result = await runner.run(
        image=tool.image,
        command=command,
        working_dir=tool.working_dir,
        entrypoint=tool.entrypoint,
        tool_name=tool.name,
        target=base_target,
        job_id=job_id,
        worker_family=tool.worker_family,
        timeout=tool.default_timeout,
        env_vars=tool.env_vars or {},
        input_refs={},
        scan_config=scan_config,
    )

    worker = WorkerService(redis=object())  # type: ignore[arg-type]
    execution_log = worker._store_execution_log_artifacts(
        scan_id=scan_id,
        tenant_id=tenant_id,
        node_id=node_id,
        tool_name=tool.name,
        execution_class=result.execution_class,
        policy_state="auto_live",
        command=command,
        stdout=result.stdout,
        stderr=result.stderr,
    )

    normalized = normalize_output(
        output_dir=result.output_dir,
        output_parser=tool.output_parser,
        tool_name=tool.name,
        artifact_type=tool.artifact_type,
        scan_id=str(scan_id),
        node_id=str(node_id),
        tenant_id=str(tenant_id),
        exit_code=result.exit_code,
        duration_ms=0,
        scan_config=scan_config,
        execution_mode=result.execution_mode,
        execution_provenance=result.execution_provenance,
        execution_reason=result.execution_reason,
        execution_class=result.execution_class,
    )
    normalized_ref = store_artifact(
        normalized,
        scan_id=str(scan_id),
        node_id=str(node_id),
        tenant_id=str(tenant_id),
        tool_name=tool.name,
    )

    command_ref = str(execution_log.get("command_artifact_ref") or "").strip() or None
    session_ref = str(execution_log.get("session_artifact_ref") or "").strip() or None
    stdout_ref = str(execution_log.get("full_stdout_artifact_ref") or "").strip() or None
    stderr_ref = str(execution_log.get("full_stderr_artifact_ref") or "").strip() or None
    command_payload = _read_json_if_ref(command_ref)
    session_payload = _read_json_if_ref(session_ref)
    stdout_text = _read_text_if_ref(stdout_ref)
    stderr_text = _read_text_if_ref(stderr_ref)

    findings_blob = json.dumps(normalized.get("findings") or [], default=str).lower()
    items_blob = json.dumps(normalized.get("items") or [], default=str).lower()
    vulnerability_types = sorted(
        {
            str(item.get("vulnerability_type") or "").strip().lower()
            for item in list(normalized.get("items") or [])
            if str(item.get("vulnerability_type") or "").strip()
        }
    )
    introspection_preserved = "graphql_introspection" in findings_blob or "__schema" in items_blob or "introspection" in items_blob

    validation = {
        "command_renders_expected_target": "-t" in command and graphql_target_url in command and "-o" in command and "json" in command,
        "execution_class_is_external_tool": result.execution_class == "external_tool",
        "execution_provenance_is_live": result.execution_provenance == "live",
        "command_artifact_persisted": bool(command_payload) and _storage_ref_exists(command_ref),
        "stdout_artifact_persisted": bool(stdout_text) and _storage_ref_exists(stdout_ref),
        "stderr_artifact_persisted": bool(stderr_ref and _storage_ref_exists(stderr_ref)) or not stderr_text,
        "session_artifact_persisted": bool(session_payload) and _storage_ref_exists(session_ref),
        "normalized_output_has_items": int(normalized.get("item_count") or 0) > 0,
        "normalized_output_preserves_introspection_surface": introspection_preserved,
        "normalized_output_preserves_multiple_surface_types": len(vulnerability_types) >= 2,
    }

    return {
        "generated_at": utc_now(),
        "target_key": str(target_spec.get("key") or "repo_demo_api"),
        "target_status": target_status,
        "graphql_target_url": graphql_target_url,
        "tool": tool.name,
        "image": tool.image,
        "command": command,
        "execution_result": {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "execution_mode": result.execution_mode,
            "execution_provenance": result.execution_provenance,
            "execution_reason": result.execution_reason,
            "execution_class": result.execution_class,
        },
        "execution_log": execution_log,
        "normalized_artifact_ref": normalized_ref,
        "normalized_summary": {
            "item_count": normalized.get("item_count"),
            "finding_count": len(normalized.get("findings") or []),
            "vulnerability_types": vulnerability_types,
            "summary": normalized.get("summary"),
            "findings_preview": (normalized.get("findings") or [])[:5],
            "items_preview": (normalized.get("items") or [])[:5],
        },
        "validation": validation,
        "passed": all(validation.values()) and result.exit_code == 0 and not result.timed_out,
    }


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = asyncio.run(_run_live_validation())
    RESULT_PATH.write_text(json.dumps(payload, indent=2, default=_json_default) + "\n")
    if not payload.get("passed"):
        print(json.dumps(payload, indent=2, default=_json_default))
        return 1
    print(json.dumps({"passed": True, "artifact": str(RESULT_PATH)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
