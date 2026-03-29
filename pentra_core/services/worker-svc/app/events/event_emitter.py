"""Event emitter — publishes job.completed / job.failed to Redis Streams.

Maintains the exact event contract expected by
``orchestrator-svc/app/events/job_event_handler.py``.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from pentra_common.schemas import ScanStreamEvent

logger = logging.getLogger(__name__)

STREAM_JOB_EVENTS = "pentra:stream:job_events"
_MAX_STREAM_LEN = 100_000
_SCAN_CHANNEL_PREFIX = "pentra:pubsub:scan"


class EventEmitter:
    """Publishes worker events to the orchestrator's job_events stream."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis

    async def _publish_scan_event(
        self,
        *,
        scan_id: uuid.UUID,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        channel = f"{_SCAN_CHANNEL_PREFIX}:{scan_id}"
        event = ScanStreamEvent.model_validate(
            {
                "event_type": event_type,
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc),
                **payload,
            }
        )
        try:
            await self._redis.publish(
                channel,
                json.dumps(event.model_dump(mode="json"), default=str),
            )
        except Exception:
            logger.debug("Failed to publish %s for scan %s", event_type, scan_id)

    async def emit_job_completed(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        dag_id: uuid.UUID,
        tool: str,
        output_ref: str,
        output_summary: dict | None = None,
        target: str = "",
        priority: str = "normal",
    ) -> str:
        """Publish a job.completed event."""
        payload = {
            "event_type": "job.completed",
            "event_id": str(uuid.uuid4()),
            "job_id": str(job_id),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "node_id": str(node_id),
            "dag_id": str(dag_id),
            "tool": tool,
            "output_ref": output_ref,
            "output_summary": output_summary or {},
            "target": target,
            "priority": priority,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        msg_id = await self._redis.xadd(
            STREAM_JOB_EVENTS,
            {"data": json.dumps(payload, default=str)},
            maxlen=_MAX_STREAM_LEN,
            approximate=True,
        )
        logger.info("Emitted job.completed: job=%s tool=%s msg=%s", job_id, tool, msg_id)
        return msg_id

    async def emit_job_failed(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        dag_id: uuid.UUID,
        tool: str,
        error_code: str,
        error_message: str,
        output_summary: dict | None = None,
        output_ref: str | None = None,
        target: str = "",
        priority: str = "normal",
    ) -> str:
        """Publish a job.failed event."""
        payload = {
            "event_type": "job.failed",
            "event_id": str(uuid.uuid4()),
            "job_id": str(job_id),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "node_id": str(node_id),
            "dag_id": str(dag_id),
            "tool": tool,
            "error_code": error_code,
            "error_message": error_message,
            "output_summary": output_summary or {},
            "output_ref": output_ref or "",
            "target": target,
            "priority": priority,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        msg_id = await self._redis.xadd(
            STREAM_JOB_EVENTS,
            {"data": json.dumps(payload, default=str)},
            maxlen=_MAX_STREAM_LEN,
            approximate=True,
        )
        logger.warning("Emitted job.failed: job=%s tool=%s err=%s", job_id, tool, error_code)
        return msg_id

    async def publish_scan_job_update(
        self,
        *,
        scan_id: uuid.UUID,
        job_id: uuid.UUID | None,
        node_id: uuid.UUID | None,
        tool: str,
        status: str,
        phase_number: int | None = None,
        execution_provenance: str | None = None,
        execution_reason: str | None = None,
        execution_class: str | None = None,
        policy_state: str | None = None,
        runtime_stage: str | None = None,
        last_chunk_at: str | None = None,
        stream_complete: bool | None = None,
        artifact_ref: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        await self._publish_scan_event(
            scan_id=scan_id,
            event_type="scan.job",
            payload={
                "job_id": job_id,
                "node_id": node_id,
                "tool": tool,
                "status": status,
                "phase_number": phase_number,
                "execution_provenance": execution_provenance,
                "execution_reason": execution_reason,
                "execution_class": execution_class,
                "policy_state": policy_state,
                "runtime_stage": runtime_stage,
                "last_chunk_at": last_chunk_at,
                "stream_complete": stream_complete,
                "artifact_ref": artifact_ref,
                "duration_ms": duration_ms,
            },
        )

    async def publish_scan_command_update(
        self,
        *,
        scan_id: uuid.UUID,
        job_id: uuid.UUID | None,
        node_id: uuid.UUID | None,
        tool: str,
        status: str,
        phase_number: int | None = None,
        execution_provenance: str | None = None,
        execution_reason: str | None = None,
        execution_class: str | None = None,
        policy_state: str | None = None,
        runtime_stage: str | None = None,
        last_chunk_at: str | None = None,
        stream_complete: bool | None = None,
        command: list[str] | None = None,
        display_command: str | None = None,
        tool_binary: str | None = None,
        container_image: str | None = None,
        entrypoint: list[str] | None = None,
        working_dir: str | None = None,
        channel: str | None = None,
        chunk_text: str | None = None,
        chunk_seq: int | None = None,
        stdout_preview: str | None = None,
        stderr_preview: str | None = None,
        exit_code: int | None = None,
        duration_ms: int | None = None,
        artifact_ref: str | None = None,
        full_stdout_artifact_ref: str | None = None,
        full_stderr_artifact_ref: str | None = None,
        command_artifact_ref: str | None = None,
        session_artifact_ref: str | None = None,
    ) -> None:
        await self._publish_scan_event(
            scan_id=scan_id,
            event_type="scan.command",
            payload={
                "job_id": job_id,
                "node_id": node_id,
                "tool": tool,
                "status": status,
                "phase_number": phase_number,
                "execution_provenance": execution_provenance,
                "execution_reason": execution_reason,
                "execution_class": execution_class,
                "policy_state": policy_state,
                "runtime_stage": runtime_stage,
                "last_chunk_at": last_chunk_at,
                "stream_complete": stream_complete,
                "command": list(command or []),
                "display_command": display_command,
                "tool_binary": tool_binary,
                "container_image": container_image,
                "entrypoint": list(entrypoint or []),
                "working_dir": working_dir,
                "channel": channel,
                "chunk_text": chunk_text,
                "chunk_seq": chunk_seq,
                "stdout_preview": stdout_preview,
                "stderr_preview": stderr_preview,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "artifact_ref": artifact_ref,
                "full_stdout_artifact_ref": full_stdout_artifact_ref,
                "full_stderr_artifact_ref": full_stderr_artifact_ref,
                "command_artifact_ref": command_artifact_ref,
                "session_artifact_ref": session_artifact_ref,
            },
        )
