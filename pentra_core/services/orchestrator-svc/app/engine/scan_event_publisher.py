"""Scan event publisher — broadcasts real-time scan events via Redis Pub/Sub.

Used by the orchestrator to push progress, phase transitions, node completions,
and findings to the API gateway WebSocket layer.

Channel format: ``pentra:pubsub:scan:{scan_id}``

Events are JSON with:
  - event_type: scan.progress | scan.phase | scan.node | scan.status | scan.finding
  - scan_id
  - timestamp
  - payload (type-specific data)
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

_CHANNEL_PREFIX = "pentra:pubsub:scan"


class ScanEventPublisher:
    """Publishes real-time scan events to Redis Pub/Sub channels."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis

    async def publish_progress(
        self, scan_id: uuid.UUID, progress: int, phase: str = "",
    ) -> None:
        """Broadcast scan progress update."""
        await self._publish(scan_id, "scan.progress", {
            "progress": progress,
            "phase": phase,
        })

    async def publish_phase_transition(
        self, scan_id: uuid.UUID, phase_number: int,
        phase_name: str, phase_status: str,
    ) -> None:
        """Broadcast phase transition (started, completed, failed)."""
        await self._publish(scan_id, "scan.phase", {
            "phase_number": phase_number,
            "phase_name": phase_name,
            "phase_status": phase_status,
        })

    async def publish_node_update(
        self, scan_id: uuid.UUID, node_id: uuid.UUID,
        tool: str, status: str, output_summary: dict | None = None,
    ) -> None:
        """Broadcast node completion/failure."""
        await self._publish(scan_id, "scan.node", {
            "node_id": str(node_id),
            "tool": tool,
            "status": status,
            "summary": output_summary or {},
        })

    async def publish_job_update(
        self,
        scan_id: uuid.UUID,
        *,
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
        await self._publish(
            scan_id,
            "scan.job",
            {
                "job_id": str(job_id) if job_id is not None else None,
                "node_id": str(node_id) if node_id is not None else None,
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

    async def publish_command_update(
        self,
        scan_id: uuid.UUID,
        *,
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
        await self._publish(
            scan_id,
            "scan.command",
            {
                "job_id": str(job_id) if job_id is not None else None,
                "node_id": str(node_id) if node_id is not None else None,
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

    async def publish_advisory_update(
        self,
        scan_id: uuid.UUID,
        *,
        pack_key: str,
        provider: str | None,
        model: str | None,
        transport: str | None,
        fallback_status: str | None,
        artifact_ref: str | None,
        summary: dict[str, Any] | None = None,
    ) -> None:
        await self._publish(
            scan_id,
            "scan.advisory",
            {
                "pack_key": pack_key,
                "provider": provider,
                "model": model,
                "transport": transport,
                "fallback_status": fallback_status,
                "artifact_ref": artifact_ref,
                "summary": summary or {},
            },
        )

    async def publish_status_change(
        self, scan_id: uuid.UUID, old_status: str, new_status: str,
    ) -> None:
        """Broadcast scan status transition."""
        await self._publish(scan_id, "scan.status", {
            "old_status": old_status,
            "new_status": new_status,
        })

    async def publish_finding(
        self, scan_id: uuid.UUID, severity: str, title: str,
        tool: str, count: int = 1,
    ) -> None:
        """Broadcast new finding discovery."""
        await self._publish(scan_id, "scan.finding", {
            "severity": severity,
            "title": title,
            "tool": tool,
            "count": count,
        })

    async def _publish(
        self, scan_id: uuid.UUID, event_type: str, payload: dict[str, Any],
    ) -> None:
        """Publish an event to the scan's Pub/Sub channel."""
        channel = f"{_CHANNEL_PREFIX}:{scan_id}"
        event = ScanStreamEvent.model_validate(
            {
                "event_type": event_type,
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc),
                **payload,
            }
        )
        message = json.dumps(event.model_dump(mode="json"), default=str)

        try:
            await self._redis.publish(channel, message)
        except Exception:
            # Pub/Sub is best-effort — don't crash the pipeline
            logger.debug("Failed to publish %s for scan %s", event_type, scan_id)
