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

import redis.asyncio as aioredis

from app.engine.artifact_handler import normalize_output, store_artifact
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

        # 2 — Render command
        output_dir = f"/work/output"
        input_dir = f"/work/input"
        config_file = f"/work/config.json"

        command = render_command(
            tool,
            target=target,
            output_dir=output_dir,
            input_dir=input_dir,
            config_file=config_file,
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
        artifact = normalize_output(
            output_dir=result.output_dir,
            output_parser=tool.output_parser,
            tool_name=tool_name,
            artifact_type=tool.artifact_type,
            scan_id=str(scan_id),
            node_id=str(node_id),
            tenant_id=str(tenant_id),
            exit_code=result.exit_code,
            duration_ms=duration_ms,
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
