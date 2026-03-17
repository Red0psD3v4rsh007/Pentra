"""Worker service — coordinates the full job execution lifecycle.

Flow:
  1. Receive job payload from JobConsumer
  2. Resolve tool from ToolRegistry
  3. Render command template with runtime values
  4. Execute tool inside Docker container via ContainerRunner
  5. Normalize output via ArtifactHandler
  6. Emit job.completed or job.failed via EventEmitter
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import redis.asyncio as aioredis

from app.engine.artifact_handler import (
    build_execution_status_artifact,
    normalize_output,
    store_artifact,
)
from app.engine.container_runner import ContainerRunner
from app.events.event_emitter import EventEmitter
from app.tools.tool_registry import get_tool, render_command

logger = logging.getLogger(__name__)


class WorkerService:
    """Coordinates job execution: consume → execute → normalize → emit."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis
        self._runner = ContainerRunner()
        self._emitter = EventEmitter(redis)

    async def execute_job(self, payload: dict[str, Any]) -> None:
        """Execute a single scan job.

        Called by JobConsumer for each dequeued message.
        """
        job_id = uuid.UUID(payload["job_id"])
        scan_id = uuid.UUID(payload["scan_id"])
        tenant_id = uuid.UUID(payload["tenant_id"])
        node_id = uuid.UUID(payload["node_id"])
        dag_id = uuid.UUID(payload["dag_id"])
        tool_name = payload["tool"]
        target = payload.get("target", "")
        worker_family = payload.get("worker_family", "recon")
        input_refs = payload.get("input_refs", {})
        if isinstance(input_refs, str):
            import json
            input_refs = json.loads(input_refs)

        config = payload.get("config", {})
        if isinstance(config, str):
            import json
            config = json.loads(config)

        logger.info(
            "Executing job %s: tool=%s scan=%s target=%s",
            job_id, tool_name, scan_id, target,
        )

        # 1 — Resolve tool definition
        tool = get_tool(tool_name)
        if tool is None:
            logger.error("Unknown tool: %s", tool_name)
            await self._emitter.emit_job_failed(
                job_id=job_id, scan_id=scan_id, tenant_id=tenant_id,
                node_id=node_id, dag_id=dag_id, tool=tool_name,
                error_code="UNKNOWN_TOOL",
                error_message=f"Tool '{tool_name}' not found in registry",
                target=target,
            )
            return

        artifact_type = str(config.get("artifact_type_override") or tool.artifact_type)

        # 2 — Render command
        output_dir = f"/work/output"
        input_dir = f"/work/input"
        config_file = f"/work/config.json"
        base_url = _command_target_for_tool(
            tool_name="httpx_probe",
            target=target,
            config=config,
        )

        command_context = {
            "http_rate_limit": _bounded_int(
                ((config.get("rate_limits") or {}).get("http_requests_per_minute", 120)),
                default=120,
                minimum=1,
                maximum=120,
            ),
            "ffuf_rate_limit": _bounded_int(
                ((config.get("rate_limits") or {}).get("ffuf_requests_per_minute", 60)),
                default=60,
                minimum=1,
                maximum=60,
            ),
            "nuclei_rate_limit": _bounded_int(
                ((config.get("rate_limits") or {}).get("nuclei_requests_per_minute", 35)),
                default=35,
                minimum=1,
                maximum=35,
            ),
            "nuclei_tags": "exposure,misconfig,sqli,idor,swagger,graphql,cors,api",
            "zap_minutes": _bounded_int(
                ((config.get("rate_limits") or {}).get("zap_minutes", 3)),
                default=3,
                minimum=1,
                maximum=3,
            ),
            "sqlmap_threads": _bounded_int(
                ((config.get("rate_limits") or {}).get("sqlmap_threads", 2)),
                default=2,
                minimum=1,
                maximum=2,
            ),
            "ffuf_extensions": "json,txt,php,html,js",
            "httpx_targets_file": f"{input_dir}/httpx_targets.txt",
            "ffuf_wordlist": f"{input_dir}/ffuf_wordlist.txt",
            "nuclei_targets_file": f"{input_dir}/nuclei_targets.txt",
            "nuclei_templates_dir": f"{input_dir}/nuclei-templates",
            "sqlmap_target_url": _sqlmap_target_url(base_url=base_url, config=config),
            **(config.get("command_context", {}) if isinstance(config.get("command_context"), dict) else {}),
        }

        command_target = _command_target_for_tool(
            tool_name=tool_name,
            target=target,
            config=config,
        )

        command = render_command(
            tool,
            target=command_target,
            output_dir=output_dir,
            input_dir=input_dir,
            config_file=config_file,
            context=command_context,
        )

        # 3 — Execute in container
        timeout = config.get("timeout_seconds", tool.default_timeout)
        start_time = time.monotonic()

        result = await self._runner.run(
            image=tool.image,
            command=command,
            tool_name=tool_name,
            target=target,
            job_id=job_id,
            worker_family=worker_family,
            timeout=timeout,
            env_vars=tool.env_vars,
            input_refs=input_refs,
            scan_config=config,
        )

        duration_ms = int((time.monotonic() - start_time) * 1000)

        # 4 — Handle result
        if result.exit_code != 0 or result.timed_out:
            error_code = "TIMEOUT" if result.timed_out else f"EXIT_{result.exit_code}"
            error_msg = result.stderr[:1000] if result.stderr else f"Exit code: {result.exit_code}"

            logger.warning(
                "Job %s FAILED: code=%s msg=%s",
                job_id, error_code, error_msg[:100],
            )

            await self._emitter.emit_job_failed(
                job_id=job_id, scan_id=scan_id, tenant_id=tenant_id,
                node_id=node_id, dag_id=dag_id, tool=tool_name,
                error_code=error_code, error_message=error_msg,
                target=target,
            )
            return

        # 5 — Normalize output
        if result.execution_provenance == "blocked":
            artifact = build_execution_status_artifact(
                tool_name=tool_name,
                artifact_type=artifact_type,
                scan_id=str(scan_id),
                node_id=str(node_id),
                tenant_id=str(tenant_id),
                exit_code=result.exit_code,
                duration_ms=duration_ms,
                execution_mode=result.execution_mode,
                execution_provenance=result.execution_provenance,
                execution_reason=result.execution_reason,
            )
        else:
            artifact = normalize_output(
                output_dir=result.output_dir,
                output_parser=tool.output_parser,
                tool_name=tool_name,
                artifact_type=artifact_type,
                scan_id=str(scan_id),
                node_id=str(node_id),
                tenant_id=str(tenant_id),
                exit_code=result.exit_code,
                duration_ms=duration_ms,
                scan_config=config,
                execution_mode=result.execution_mode,
                execution_provenance=result.execution_provenance,
                execution_reason=result.execution_reason,
            )

        # 6 — Store artifact
        storage_ref = store_artifact(
            artifact,
            scan_id=str(scan_id),
            node_id=str(node_id),
            tenant_id=str(tenant_id),
            tool_name=tool_name,
        )

        # 7 — Build output summary for orchestrator
        output_summary = {
            "item_count": artifact["item_count"],
            "artifact_type": artifact["artifact_type"],
            "duration_ms": duration_ms,
            "tool": tool_name,
            "summary": artifact.get("summary", {}),
            "finding_count": len(artifact.get("findings", [])),
            "evidence_count": len(artifact.get("evidence", [])),
            "severity_counts": artifact.get("summary", {}).get("severity_counts", {}),
            "content_type": artifact.get("metadata", {}).get("content_type", "application/json"),
            "checksum": artifact.get("metadata", {}).get("checksum"),
            "size_bytes": artifact.get("metadata", {}).get("normalized_size_bytes")
            or artifact.get("metadata", {}).get("raw_size_bytes", 0),
            "preview_items": artifact.get("items", [])[:10],
            "preview_findings": artifact.get("findings", [])[:10],
            "execution_mode": result.execution_mode,
            "execution_provenance": result.execution_provenance,
            "execution_reason": result.execution_reason,
        }

        # 8 — Emit completion
        await self._emitter.emit_job_completed(
            job_id=job_id, scan_id=scan_id, tenant_id=tenant_id,
            node_id=node_id, dag_id=dag_id, tool=tool_name,
            output_ref=storage_ref,
            output_summary=output_summary,
            target=target,
        )

        # 9 — Cleanup
        await self._runner.cleanup_job(job_id)

        logger.info(
            "Job %s COMPLETED: tool=%s items=%d duration=%dms ref=%s",
            job_id, tool_name, artifact["item_count"], duration_ms, storage_ref,
        )


def _command_target_for_tool(
    *,
    tool_name: str,
    target: str,
    config: dict[str, Any],
) -> str:
    targeting = config.get("targeting", {})
    if not isinstance(targeting, dict):
        targeting = {}

    base_url = str(targeting.get("base_url") or "").strip()
    host = str(targeting.get("host") or "").strip()
    normalized_target = str(target or "").strip()

    if tool_name in {"subfinder", "amass", "nmap_discovery", "nmap_svc", "scope_check"}:
        if host:
            return host
        return _host_from_target(normalized_target)

    if tool_name in {
        "httpx_probe",
        "ffuf",
        "nuclei",
        "zap",
        "sqlmap",
        "sqlmap_verify",
        "custom_poc",
        "web_interact",
        "ai_triage",
        "report_gen",
    }:
        if base_url:
            return base_url
        return _base_url_from_target(normalized_target)

    return normalized_target


def _host_from_target(target: str) -> str:
    if "://" not in target:
        return target.split("/", 1)[0]

    parsed = urlparse(target)
    return parsed.hostname or target


def _base_url_from_target(target: str) -> str:
    if not target:
        return ""
    if "://" not in target:
        host = target.split("/", 1)[0]
        return f"https://{host}"

    parsed = urlparse(target)
    host = parsed.hostname or target
    if parsed.port:
        host = f"{host}:{parsed.port}"
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}"


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _sqlmap_target_url(*, base_url: str, config: dict[str, Any]) -> str:
    verification_context = config.get("verification_context", {})
    if isinstance(verification_context, dict):
        request_url = str(verification_context.get("request_url") or "").strip()
        endpoint = str(verification_context.get("endpoint") or "").strip()
        if request_url:
            return request_url
        if endpoint:
            return endpoint

    selected_checks = config.get("selected_checks", {})
    if not isinstance(selected_checks, dict):
        selected_checks = {}

    sqlmap_config = selected_checks.get("sqlmap", {})
    if isinstance(sqlmap_config, dict):
        path = str(sqlmap_config.get("path") or "").strip()
        if path:
            if path.startswith("http://") or path.startswith("https://"):
                return path
            return f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    return base_url.rstrip("/")
