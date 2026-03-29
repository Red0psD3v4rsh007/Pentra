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
import shlex
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import redis.asyncio as aioredis
from sqlalchemy import text

from pentra_common.db.rls import set_tenant_context
from pentra_common.db.session import async_session_factory
from pentra_common.storage.artifacts import write_json_artifact, write_text_artifact
from pentra_common.execution_truth import classify_tool_execution, classify_tool_policy_state
from app.engine.artifact_handler import (
    build_execution_status_artifact,
    normalize_output,
    store_artifact,
)
from app.engine.container_runner import ContainerRunner
from app.engine.credential_injector import (
    inject_credentials,
    get_credential_env_vars,
    redact_command_for_logging,
)
from app.engine.web_interaction_runner import WebInteractionRunner
from app.events.event_emitter import EventEmitter
from app.observability.runtime_state import WorkerRuntimeState
from app.tools.tool_registry import get_tool, render_command

logger = logging.getLogger(__name__)


class WorkerService:
    """Coordinates job execution: consume → execute → normalize → emit."""

    def __init__(
        self,
        redis: aioredis.Redis,
        runtime_state: WorkerRuntimeState | None = None,
    ) -> None:
        self._redis = redis
        self._runner = ContainerRunner()
        self._web_runner = WebInteractionRunner()
        self._emitter = EventEmitter(redis)
        self._runtime_state = runtime_state

    def planned_prewarm_images(self, *, worker_family: str) -> list[str]:
        """Return the startup image warmup plan for a worker family."""
        return self._runner.planned_prewarm_images(worker_family=worker_family)

    async def prewarm_startup_images(
        self,
        *,
        worker_family: str,
    ) -> dict[str, dict[str, str]]:
        """Warm the worker family's Docker images before the first live job."""
        return await self._runner.prewarm_images(worker_family=worker_family)

    async def _mark_job_started(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tool_name: str,
        target: str,
        scheduled_at: str | None,
        claimed_at: str | None,
        started_at: str,
    ) -> None:
        if self._runtime_state is None:
            return
        try:
            await self._runtime_state.mark_job_started(
                job_id=str(job_id),
                scan_id=str(scan_id),
                tool_name=tool_name,
                target=target,
                scheduled_at=scheduled_at,
                claimed_at=claimed_at,
                started_at=started_at,
            )
        except Exception:
            logger.warning("Failed to update runtime_state for job start", exc_info=True)

    async def _mark_job_claimed(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tool_name: str,
        target: str,
        scheduled_at: str | None,
        claimed_at: str | None,
    ) -> None:
        if self._runtime_state is None:
            return
        try:
            await self._runtime_state.mark_job_claimed(
                job_id=str(job_id),
                scan_id=str(scan_id),
                tool_name=tool_name,
                target=target,
                scheduled_at=scheduled_at,
                claimed_at=claimed_at,
            )
        except Exception:
            logger.warning("Failed to update runtime_state for job claim", exc_info=True)

    async def _mark_job_succeeded(self) -> None:
        if self._runtime_state is None:
            return
        try:
            await self._runtime_state.mark_job_succeeded()
        except Exception:
            logger.warning("Failed to update runtime_state for job success", exc_info=True)

    async def _mark_job_failed(self, *, reason: str) -> None:
        if self._runtime_state is None:
            return
        try:
            await self._runtime_state.mark_job_failed(reason=reason)
        except Exception:
            logger.warning("Failed to update runtime_state for job failure", exc_info=True)

    async def _persist_job_claimed(
        self,
        *,
        job_id: uuid.UUID,
        tenant_id: uuid.UUID,
        worker_id: str | None,
        claimed_at: str | None,
    ) -> None:
        claimed_at_dt = _parse_iso_datetime(claimed_at)
        if claimed_at_dt is None:
            return
        try:
            async with async_session_factory() as session:
                await set_tenant_context(session, tenant_id)
                await session.execute(
                    text("""
                        UPDATE scan_jobs
                        SET worker_id = COALESCE(worker_id, :worker_id),
                            claimed_at = COALESCE(claimed_at, :claimed_at)
                        WHERE id = :job_id
                          AND tenant_id = :tenant_id
                    """),
                    {
                        "job_id": str(job_id),
                        "tenant_id": str(tenant_id),
                        "worker_id": worker_id,
                        "claimed_at": claimed_at_dt,
                    },
                )
                await session.commit()
        except Exception:
            logger.warning("Failed to persist claim timing for job %s", job_id, exc_info=True)

    async def _persist_job_started(
        self,
        *,
        job_id: uuid.UUID,
        tenant_id: uuid.UUID,
        worker_id: str | None,
        claimed_at: str | None,
        started_at: str,
    ) -> None:
        started_at_dt = _parse_iso_datetime(started_at)
        claimed_at_dt = _parse_iso_datetime(claimed_at)
        if started_at_dt is None:
            return
        try:
            async with async_session_factory() as session:
                await set_tenant_context(session, tenant_id)
                await session.execute(
                    text("""
                        UPDATE scan_jobs
                        SET status = 'running',
                            worker_id = COALESCE(worker_id, :worker_id),
                            claimed_at = COALESCE(claimed_at, :claimed_at),
                            started_at = COALESCE(started_at, :started_at)
                        WHERE id = :job_id
                          AND tenant_id = :tenant_id
                          AND status IN ('queued', 'scheduled', 'assigned', 'running')
                    """),
                    {
                        "job_id": str(job_id),
                        "tenant_id": str(tenant_id),
                        "worker_id": worker_id,
                        "claimed_at": claimed_at_dt,
                        "started_at": started_at_dt,
                    },
                )
                await session.commit()
        except Exception:
            logger.warning("Failed to persist start timing for job %s", job_id, exc_info=True)

    async def _load_scan_status(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> str | None:
        try:
            async with async_session_factory() as session:
                await set_tenant_context(session, tenant_id)
                result = await session.execute(
                    text("""
                        SELECT status
                        FROM scans
                        WHERE id = :scan_id
                          AND tenant_id = :tenant_id
                    """),
                    {
                        "scan_id": str(scan_id),
                        "tenant_id": str(tenant_id),
                    },
                )
                value = result.scalar_one_or_none()
                return str(value).strip().lower() if value is not None else None
        except Exception:
            logger.warning("Failed to load scan status for %s", scan_id, exc_info=True)
            return None

    async def _mark_job_cancelled(
        self,
        *,
        job_id: uuid.UUID,
        tenant_id: uuid.UUID,
        worker_id: str | None,
        claimed_at: str | None,
        reason: str,
    ) -> None:
        claimed_at_dt = _parse_iso_datetime(claimed_at)
        try:
            async with async_session_factory() as session:
                await set_tenant_context(session, tenant_id)
                await session.execute(
                    text("""
                        UPDATE scan_jobs
                        SET status = 'cancelled',
                            worker_id = COALESCE(worker_id, :worker_id),
                            claimed_at = COALESCE(claimed_at, :claimed_at),
                            completed_at = COALESCE(completed_at, now()),
                            error_message = COALESCE(error_message, :reason)
                        WHERE id = :job_id
                          AND tenant_id = :tenant_id
                          AND status NOT IN ('completed', 'failed', 'cancelled')
                    """),
                    {
                        "job_id": str(job_id),
                        "tenant_id": str(tenant_id),
                        "worker_id": worker_id,
                        "claimed_at": claimed_at_dt,
                        "reason": reason[:500],
                    },
                )
                await session.commit()
        except Exception:
            logger.warning("Failed to cancel job %s", job_id, exc_info=True)

    def _execution_log_storage_refs(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        tool_name: str,
    ) -> dict[str, str]:
        base_ref = f"artifacts/{tenant_id}/{scan_id}/{node_id}/execution_logs/{tool_name}"
        return {
            "base_ref": base_ref,
            "command_artifact_ref": f"{base_ref}_command.json",
            "full_stdout_artifact_ref": f"{base_ref}_stdout.txt",
            "full_stderr_artifact_ref": f"{base_ref}_stderr.txt",
            "session_artifact_ref": f"{base_ref}_session.json",
        }

    def _live_session_payload(
        self,
        *,
        tool_name: str,
        execution_class: str,
        policy_state: str,
        live_state: dict[str, Any],
        status: str,
        runtime_stage: str,
        started_at: str,
        completed_at: str | None = None,
        exit_code: int | None = None,
    ) -> dict[str, Any]:
        refs = live_state["refs"]
        return {
            "tool": tool_name,
            "status": status,
            "execution_class": execution_class,
            "policy_state": policy_state,
            "runtime_stage": runtime_stage,
            "last_chunk_at": live_state.get("last_chunk_at"),
            "stream_complete": bool(live_state.get("stream_complete", False)),
            "started_at": started_at,
            "completed_at": completed_at,
            "exit_code": exit_code,
            "frames": live_state["frames"],
            "command": live_state["command"],
            "display_command": live_state["display_command"],
            "canonical_command": live_state["canonical_command"],
            "command_artifact_ref": refs["command_artifact_ref"],
            "full_stdout_artifact_ref": refs["full_stdout_artifact_ref"],
            "full_stderr_artifact_ref": refs["full_stderr_artifact_ref"],
            "session_artifact_ref": refs["session_artifact_ref"],
        }

    def _start_live_execution_tracking(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        tool_name: str,
        execution_class: str,
        policy_state: str,
        command: list[str],
        image: str,
        entrypoint: list[str] | None,
        working_dir: str | None,
        started_at: str,
    ) -> dict[str, Any]:
        refs = self._execution_log_storage_refs(
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_id=node_id,
            tool_name=tool_name,
        )
        canonical_command = self._build_canonical_command_record(
            command=command,
            image=image,
            entrypoint=entrypoint,
            working_dir=working_dir,
            execution_class=execution_class,
            policy_state=policy_state,
        )
        display_command = str(canonical_command.get("display_command") or "")
        command_payload = {
            "tool": tool_name,
            "execution_class": execution_class,
            "policy_state": policy_state,
            "command": list(command),
            "canonical_command": canonical_command,
            "display_command": display_command,
        }
        write_json_artifact(refs["command_artifact_ref"], command_payload)

        frames: list[dict[str, Any]] = []
        next_chunk_seq = 0
        if display_command:
            frames.append(
                {
                    "channel": "command",
                    "chunk_seq": next_chunk_seq,
                    "chunk_text": display_command,
                    "timestamp": started_at,
                    "artifact_ref": refs["command_artifact_ref"],
                }
            )
            next_chunk_seq += 1

        live_state = {
            "refs": refs,
            "command": list(command),
            "display_command": display_command,
            "canonical_command": canonical_command,
            "frames": frames,
            "next_chunk_seq": next_chunk_seq,
            "stdout": "",
            "stderr": "",
            "runtime_stage": "command_resolved",
            "last_chunk_at": started_at if display_command else None,
            "stream_complete": False,
        }
        write_json_artifact(
            refs["session_artifact_ref"],
            self._live_session_payload(
                tool_name=tool_name,
                execution_class=execution_class,
                policy_state=policy_state,
                live_state=live_state,
                status="running",
                runtime_stage="command_resolved",
                started_at=started_at,
            ),
        )
        return live_state

    def _append_live_execution_chunk(
        self,
        *,
        tool_name: str,
        execution_class: str,
        policy_state: str,
        live_state: dict[str, Any],
        started_at: str,
        channel: str,
        chunk_text: str,
        timestamp: str,
    ) -> None:
        text = str(chunk_text or "")
        if not text:
            return
        refs = live_state["refs"]
        if channel == "stdout":
            live_state["stdout"] = f"{live_state['stdout']}{text}"
            write_text_artifact(refs["full_stdout_artifact_ref"], live_state["stdout"])
        elif channel == "stderr":
            live_state["stderr"] = f"{live_state['stderr']}{text}"
            write_text_artifact(refs["full_stderr_artifact_ref"], live_state["stderr"])
        live_state["runtime_stage"] = "streaming"
        live_state["last_chunk_at"] = timestamp
        live_state["stream_complete"] = False

        for start in range(0, len(text), 4000):
            live_state["frames"].append(
                {
                    "channel": channel,
                    "chunk_seq": int(live_state["next_chunk_seq"]),
                    "chunk_text": text[start : start + 4000],
                    "timestamp": timestamp,
                    "artifact_ref": (
                        refs["full_stdout_artifact_ref"]
                        if channel == "stdout"
                        else refs["full_stderr_artifact_ref"]
                        if channel == "stderr"
                        else None
                    ),
                }
            )
            live_state["next_chunk_seq"] = int(live_state["next_chunk_seq"]) + 1

        write_json_artifact(
            refs["session_artifact_ref"],
            self._live_session_payload(
                tool_name=tool_name,
                execution_class=execution_class,
                policy_state=policy_state,
                live_state=live_state,
                status="running",
                runtime_stage="streaming",
                started_at=started_at,
            ),
        )

    def _finalize_live_execution_tracking(
        self,
        *,
        tool_name: str,
        execution_class: str,
        policy_state: str,
        live_state: dict[str, Any] | None,
        started_at: str,
        completed_at: str,
        status: str,
        exit_code: int | None,
    ) -> None:
        if not live_state:
            return
        refs = live_state["refs"]
        live_state["runtime_stage"] = status
        live_state["last_chunk_at"] = live_state.get("last_chunk_at") or completed_at
        live_state["stream_complete"] = True
        write_json_artifact(
            refs["session_artifact_ref"],
            self._live_session_payload(
                tool_name=tool_name,
                execution_class=execution_class,
                policy_state=policy_state,
                live_state=live_state,
                status=status,
                runtime_stage=status,
                started_at=started_at,
                completed_at=completed_at,
                exit_code=exit_code,
            ),
        )

    def _store_execution_log_artifacts(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        tool_name: str,
        execution_class: str,
        policy_state: str,
        command: list[str],
        image: str = "",
        entrypoint: list[str] | None = None,
        working_dir: str | None = None,
        stdout: str,
        stderr: str,
        live_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        refs = self._execution_log_storage_refs(
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_id=node_id,
            tool_name=tool_name,
        )
        stdout_text = str(live_state.get("stdout") if live_state else stdout or "")
        stderr_text = str(live_state.get("stderr") if live_state else stderr or "")
        canonical_command = (
            live_state.get("canonical_command")
            if isinstance(live_state, dict) and isinstance(live_state.get("canonical_command"), dict)
            else self._build_canonical_command_record(
                command=command,
                image=image,
                entrypoint=entrypoint,
                working_dir=working_dir,
                execution_class=execution_class,
                policy_state=policy_state,
            )
        )
        command_payload = {
            "tool": tool_name,
            "execution_class": execution_class,
            "policy_state": policy_state,
            "command": command,
            "canonical_command": canonical_command,
            "display_command": str(canonical_command.get("display_command") or ""),
        }
        write_json_artifact(refs["command_artifact_ref"], command_payload)

        stdout_ref: str | None = None
        stderr_ref: str | None = None
        if stdout_text:
            stdout_ref = refs["full_stdout_artifact_ref"]
            write_text_artifact(stdout_ref, stdout_text)
        if stderr_text:
            stderr_ref = refs["full_stderr_artifact_ref"]
            write_text_artifact(stderr_ref, stderr_text)

        session_frames = (
            list(live_state.get("frames") or [])
            if isinstance(live_state, dict) and isinstance(live_state.get("frames"), list)
            else self._build_execution_session_frames(
                command=command,
                stdout=stdout_text,
                stderr=stderr_text,
                command_artifact_ref=refs["command_artifact_ref"],
                stdout_artifact_ref=stdout_ref,
                stderr_artifact_ref=stderr_ref,
            )
        )
        write_json_artifact(
            refs["session_artifact_ref"],
            {
                "tool": tool_name,
                "execution_class": execution_class,
                "policy_state": policy_state,
                "runtime_stage": (
                    str(live_state.get("runtime_stage") or "").strip()
                    if isinstance(live_state, dict)
                    else "completed"
                )
                or "completed",
                "last_chunk_at": (
                    live_state.get("last_chunk_at")
                    if isinstance(live_state, dict)
                    else None
                ),
                "stream_complete": bool(
                    live_state.get("stream_complete", True)
                    if isinstance(live_state, dict)
                    else True
                ),
                "frames": session_frames,
                "command": command,
                "canonical_command": canonical_command,
                "display_command": str(canonical_command.get("display_command") or ""),
                "command_artifact_ref": refs["command_artifact_ref"],
                "full_stdout_artifact_ref": stdout_ref,
                "full_stderr_artifact_ref": stderr_ref,
            },
        )

        return {
            "execution_class": execution_class,
            "policy_state": policy_state,
            "runtime_stage": (
                str(live_state.get("runtime_stage") or "").strip()
                if isinstance(live_state, dict)
                else "completed"
            )
            or "completed",
            "last_chunk_at": (
                live_state.get("last_chunk_at")
                if isinstance(live_state, dict)
                else None
            ),
            "stream_complete": bool(
                live_state.get("stream_complete", True)
                if isinstance(live_state, dict)
                else True
            ),
            "command": command,
            "display_command": str(canonical_command.get("display_command") or ""),
            "tool_binary": canonical_command.get("tool_binary"),
            "container_image": canonical_command.get("container_image"),
            "entrypoint": list(canonical_command.get("entrypoint") or []),
            "working_dir": canonical_command.get("working_dir"),
            "canonical_command": canonical_command,
            "command_artifact_ref": refs["command_artifact_ref"],
            "stdout_preview": stdout_text[-5_000:],
            "stderr_preview": stderr_text[-2_000:],
            "full_stdout_artifact_ref": stdout_ref,
            "full_stderr_artifact_ref": stderr_ref,
            "session_artifact_ref": refs["session_artifact_ref"],
        }

    def _build_execution_session_frames(
        self,
        *,
        command: list[str],
        stdout: str,
        stderr: str,
        command_artifact_ref: str,
        stdout_artifact_ref: str | None,
        stderr_artifact_ref: str | None,
    ) -> list[dict[str, Any]]:
        frames: list[dict[str, Any]] = []
        chunk_seq = 0

        rendered_command = shlex.join([str(item) for item in command if str(item).strip()]) if command else ""
        if rendered_command.strip():
            frames.append(
                {
                    "channel": "command",
                    "chunk_seq": chunk_seq,
                    "chunk_text": rendered_command,
                    "artifact_ref": command_artifact_ref,
                }
            )
            chunk_seq += 1

        for channel, payload, artifact_ref in (
            ("stdout", stdout, stdout_artifact_ref),
            ("stderr", stderr, stderr_artifact_ref),
        ):
            text = str(payload or "")
            if not text:
                continue
            for start in range(0, len(text), 4000):
                frames.append(
                    {
                        "channel": channel,
                        "chunk_seq": chunk_seq,
                        "chunk_text": text[start : start + 4000],
                        "artifact_ref": artifact_ref,
                    }
                )
                chunk_seq += 1

        return frames

    def _build_canonical_command_record(
        self,
        *,
        command: list[str],
        image: str,
        entrypoint: list[str] | None,
        working_dir: str | None,
        execution_class: str,
        policy_state: str,
    ) -> dict[str, Any]:
        argv = [str(item) for item in command if str(item).strip()]
        entrypoint_items = [str(item) for item in list(entrypoint or []) if str(item).strip()]
        tool_binary = entrypoint_items[0] if entrypoint_items else (argv[0] if argv else None)
        return {
            "argv": argv,
            "display_command": shlex.join(argv) if argv else "",
            "tool_binary": tool_binary,
            "container_image": image or None,
            "entrypoint": entrypoint_items,
            "working_dir": working_dir or None,
            "channel": "native" if execution_class == "pentra_native" else "container",
            "execution_class": execution_class,
            "policy_state": policy_state,
        }

    def _build_failed_output_summary(
        self,
        *,
        artifact_type: str,
        tool_name: str,
        error_code: str,
        error_message: str,
        duration_ms: int,
        execution_mode: str,
        execution_provenance: str,
        execution_reason: str | None,
        execution_class: str,
        policy_state: str,
        execution_log: dict[str, Any],
        exit_code: int,
    ) -> dict[str, Any]:
        return {
            "item_count": 0,
            "artifact_type": artifact_type,
            "duration_ms": duration_ms,
            "tool": tool_name,
            "summary": {
                "status": "failed",
                "message": error_message,
                "error_code": error_code,
                "execution": {
                    "mode": execution_mode,
                    "provenance": execution_provenance,
                    "reason": execution_reason,
                    "class": execution_class,
                },
            },
            "finding_count": 0,
            "evidence_count": 0,
            "severity_counts": {},
            "content_type": "application/json",
            "checksum": None,
            "size_bytes": 0,
            "preview_items": [],
            "preview_findings": [],
            "execution_mode": execution_mode,
            "execution_provenance": execution_provenance,
            "execution_reason": execution_reason,
            "execution_class": execution_class,
            "policy_state": policy_state,
            "execution_log": {
                **execution_log,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
            },
        }

    async def execute_job(self, payload: dict[str, Any]) -> None:
        """Execute a single scan job.

        Called by JobConsumer for each dequeued message.
        """
        job_id = uuid.UUID(payload["job_id"])
        scan_id = uuid.UUID(payload["scan_id"])
        tenant_id = uuid.UUID(payload["tenant_id"])
        node_id = uuid.UUID(payload["node_id"])
        dag_id = uuid.UUID(payload["dag_id"])
        phase_number = int(payload.get("phase") or 0) or None
        tool_name = payload["tool"]
        target = payload.get("target", "")
        worker_family = payload.get("worker_family", "recon")
        input_refs = payload.get("input_refs", {})
        if isinstance(input_refs, str):
            import json
            input_refs = json.loads(input_refs)
        worker_id = str(payload.get("worker_id") or "").strip() or None
        scheduled_at = str(payload.get("scheduled_at") or "").strip() or None
        claimed_at = str(payload.get("claimed_at") or "").strip() or None

        config = payload.get("config", {})
        if isinstance(config, str):
            import json
            config = json.loads(config)

        logger.info(
            "Executing job %s: tool=%s scan=%s target=%s",
            job_id, tool_name, scan_id, target,
        )

        scan_status = await self._load_scan_status(
            scan_id=scan_id,
            tenant_id=tenant_id,
        )
        if scan_status in {"cancelled", "completed", "failed", "rejected"}:
            reason = f"Skipped worker execution because scan is {scan_status}"
            logger.info(
                "Skipping job %s — scan %s is already %s",
                job_id,
                scan_id,
                scan_status,
            )
            await self._mark_job_cancelled(
                job_id=job_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                claimed_at=claimed_at,
                reason=reason,
            )
            return

        await self._mark_job_claimed(
            job_id=job_id,
            scan_id=scan_id,
            tool_name=tool_name,
            target=target,
            scheduled_at=scheduled_at,
            claimed_at=claimed_at,
        )
        await self._persist_job_claimed(
            job_id=job_id,
            tenant_id=tenant_id,
            worker_id=worker_id,
            claimed_at=claimed_at,
        )

        try:
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
                await self._mark_job_failed(reason="UNKNOWN_TOOL")
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
                    ((config.get("rate_limits") or {}).get("http_requests_per_minute",
                     (config.get("rate_limits") or {}).get("requests_per_minute", 120))),
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
                "graphql_target_url": _graphql_target_url(base_url=base_url, config=config),
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

            # 2b — Inject credentials into command
            scan_credentials = config.get("credentials", {})
            if not isinstance(scan_credentials, dict):
                scan_credentials = {}
            runtime_credentials = await _resolve_runtime_credentials(
                tool_name=tool_name,
                base_url=base_url,
                config=config,
                explicit_credentials=scan_credentials,
                web_runner=self._web_runner,
            )
            if runtime_credentials:
                command = inject_credentials(tool_name, command, runtime_credentials)
                logger.info(
                    "Command after credential injection (redacted): %s",
                    redact_command_for_logging(command),
                )

            # 2c — Credential env vars for container
            credential_env = get_credential_env_vars(
                runtime_credentials
            )
            combined_env = {**(tool.env_vars or {}), **credential_env}
            execution_decision = self._runner.resolve_execution_decision(
                tool_name=tool_name,
                target=target,
                scan_config=config,
            )
            planned_execution_class = classify_tool_execution(tool_name)

            # 3 — Execute in container
            timeout = config.get("timeout_seconds", tool.default_timeout)
            started_at = datetime.now(timezone.utc).isoformat()
            await self._persist_job_started(
                job_id=job_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                claimed_at=claimed_at,
                started_at=started_at,
            )
            await self._mark_job_started(
                job_id=job_id,
                scan_id=scan_id,
                tool_name=tool_name,
                target=target,
                scheduled_at=scheduled_at,
                claimed_at=claimed_at,
                started_at=started_at,
            )
            live_policy_state = classify_tool_policy_state(
                tool_name=tool_name,
                scan_config=config,
                execution_provenance=execution_decision.provenance,
                execution_reason=execution_decision.reason,
            )
            live_execution_state: dict[str, Any] | None = None
            if execution_decision.live:
                await self._emitter.publish_scan_job_update(
                    scan_id=scan_id,
                    job_id=job_id,
                    node_id=node_id,
                    tool=tool_name,
                    status="running",
                    phase_number=phase_number,
                    execution_provenance="live",
                    execution_reason="container_starting",
                    execution_class=planned_execution_class,
                    policy_state=live_policy_state,
                    runtime_stage="container_starting",
                    stream_complete=False,
                )
                live_execution_state = self._start_live_execution_tracking(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    node_id=node_id,
                    tool_name=tool_name,
                    execution_class=planned_execution_class,
                    policy_state=live_policy_state,
                    command=command,
                    image=tool.image,
                    entrypoint=tool.entrypoint,
                    working_dir=tool.working_dir,
                    started_at=started_at,
                )
                await self._emitter.publish_scan_job_update(
                    scan_id=scan_id,
                    job_id=job_id,
                    node_id=node_id,
                    tool=tool_name,
                    status="running",
                    phase_number=phase_number,
                    execution_provenance="live",
                    execution_reason="command_started",
                    execution_class=planned_execution_class,
                    policy_state=live_policy_state,
                    runtime_stage="command_resolved",
                    last_chunk_at=live_execution_state.get("last_chunk_at"),
                    stream_complete=False,
                )
                await self._emitter.publish_scan_command_update(
                    scan_id=scan_id,
                    job_id=job_id,
                    node_id=node_id,
                    tool=tool_name,
                    status="running",
                    phase_number=phase_number,
                    execution_provenance="live",
                    execution_reason="command_started",
                    execution_class=planned_execution_class,
                    policy_state=live_policy_state,
                    runtime_stage="command_resolved",
                    last_chunk_at=live_execution_state.get("last_chunk_at"),
                    stream_complete=False,
                    command=command,
                    display_command=str(
                        live_execution_state["canonical_command"].get("display_command") or ""
                    ),
                    tool_binary=live_execution_state["canonical_command"].get("tool_binary"),
                    container_image=live_execution_state["canonical_command"].get("container_image"),
                    entrypoint=list(live_execution_state["canonical_command"].get("entrypoint") or []),
                    working_dir=live_execution_state["canonical_command"].get("working_dir"),
                    channel="command",
                    chunk_text=str(
                        live_execution_state["canonical_command"].get("display_command") or ""
                    )
                    or None,
                    chunk_seq=0,
                    command_artifact_ref=live_execution_state["refs"]["command_artifact_ref"],
                    session_artifact_ref=live_execution_state["refs"]["session_artifact_ref"],
                )
            start_time = time.monotonic()

            async def _handle_output_chunk(channel: str, chunk_text: str) -> None:
                if not live_execution_state:
                    return
                chunk_timestamp = datetime.now(timezone.utc).isoformat()
                chunk_seq = int(live_execution_state["next_chunk_seq"])
                self._append_live_execution_chunk(
                    tool_name=tool_name,
                    execution_class=planned_execution_class,
                    policy_state=live_policy_state,
                    live_state=live_execution_state,
                    started_at=started_at,
                    channel=channel,
                    chunk_text=chunk_text,
                    timestamp=chunk_timestamp,
                )
                await self._emitter.publish_scan_command_update(
                    scan_id=scan_id,
                    job_id=job_id,
                    node_id=node_id,
                    tool=tool_name,
                    status="running",
                    phase_number=phase_number,
                    execution_provenance="live",
                    execution_reason="streaming_output",
                    execution_class=planned_execution_class,
                    policy_state=live_policy_state,
                    runtime_stage="streaming",
                    last_chunk_at=chunk_timestamp,
                    stream_complete=False,
                    command=command,
                    display_command=str(
                        live_execution_state["canonical_command"].get("display_command") or ""
                    ),
                    tool_binary=live_execution_state["canonical_command"].get("tool_binary"),
                    container_image=live_execution_state["canonical_command"].get("container_image"),
                    entrypoint=list(live_execution_state["canonical_command"].get("entrypoint") or []),
                    working_dir=live_execution_state["canonical_command"].get("working_dir"),
                    channel=channel,
                    chunk_text=chunk_text,
                    chunk_seq=chunk_seq,
                    stdout_preview=str(live_execution_state.get("stdout") or "")[-5_000:] or None,
                    stderr_preview=str(live_execution_state.get("stderr") or "")[-2_000:] or None,
                    artifact_ref=(
                        live_execution_state["refs"]["full_stdout_artifact_ref"]
                        if channel == "stdout"
                        else live_execution_state["refs"]["full_stderr_artifact_ref"]
                        if channel == "stderr"
                        else None
                    ),
                    full_stdout_artifact_ref=live_execution_state["refs"]["full_stdout_artifact_ref"],
                    full_stderr_artifact_ref=live_execution_state["refs"]["full_stderr_artifact_ref"],
                    command_artifact_ref=live_execution_state["refs"]["command_artifact_ref"],
                    session_artifact_ref=live_execution_state["refs"]["session_artifact_ref"],
                )

            result = await self._runner.run(
                image=tool.image,
                command=command,
                working_dir=tool.working_dir,
                entrypoint=tool.entrypoint,
                tool_name=tool_name,
                target=target,
                job_id=job_id,
                worker_family=worker_family,
                timeout=timeout,
                env_vars=combined_env,
                input_refs=input_refs,
                scan_config=config,
                on_output_chunk=_handle_output_chunk if execution_decision.live else None,
            )

            duration_ms = int((time.monotonic() - start_time) * 1000)
            completed_at = datetime.now(timezone.utc).isoformat()
            self._finalize_live_execution_tracking(
                tool_name=tool_name,
                execution_class=planned_execution_class,
                policy_state=live_policy_state,
                live_state=live_execution_state,
                started_at=started_at,
                completed_at=completed_at,
                status="completed" if result.exit_code == 0 and not result.timed_out else "failed",
                exit_code=result.exit_code,
            )
            execution_log = self._store_execution_log_artifacts(
                scan_id=scan_id,
                tenant_id=tenant_id,
                node_id=node_id,
                tool_name=tool_name,
                execution_class=result.execution_class,
                policy_state=classify_tool_policy_state(
                    tool_name=tool_name,
                    scan_config=config,
                    execution_provenance=result.execution_provenance,
                    execution_reason=result.execution_reason,
                ),
                command=command,
                image=tool.image,
                entrypoint=tool.entrypoint,
                working_dir=tool.working_dir,
                stdout=result.stdout,
                stderr=result.stderr,
                live_state=live_execution_state,
            )
            policy_state = str(execution_log.get("policy_state") or "")

            # 4 — Handle result
            if result.exit_code != 0 or result.timed_out:
                error_code = "TIMEOUT" if result.timed_out else f"EXIT_{result.exit_code}"
                error_msg = result.stderr[:1000] if result.stderr else f"Exit code: {result.exit_code}"
                failed_output_summary = self._build_failed_output_summary(
                    artifact_type=artifact_type,
                    tool_name=tool_name,
                    error_code=error_code,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    execution_mode=result.execution_mode,
                    execution_provenance=result.execution_provenance,
                    execution_reason=result.execution_reason,
                    execution_class=result.execution_class,
                    policy_state=policy_state,
                    execution_log=execution_log,
                    exit_code=result.exit_code,
                )

                logger.warning(
                    "Job %s FAILED: code=%s msg=%s",
                    job_id, error_code, error_msg[:100],
                )

                await self._emitter.emit_job_failed(
                    job_id=job_id, scan_id=scan_id, tenant_id=tenant_id,
                    node_id=node_id, dag_id=dag_id, tool=tool_name,
                    error_code=error_code, error_message=error_msg,
                    output_summary=failed_output_summary,
                    target=target,
                )
                await self._mark_job_failed(reason=error_code)
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
                    execution_class=result.execution_class,
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
                    execution_class=result.execution_class,
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
                "execution_class": result.execution_class,
                "policy_state": policy_state,
                "execution_log": {
                    **execution_log,
                    "exit_code": result.exit_code,
                    "duration_ms": duration_ms,
                },
            }

            # 8 — Emit completion
            await self._emitter.emit_job_completed(
                job_id=job_id, scan_id=scan_id, tenant_id=tenant_id,
                node_id=node_id, dag_id=dag_id, tool=tool_name,
                output_ref=storage_ref,
                output_summary=output_summary,
                target=target,
            )

            await self._mark_job_succeeded()

            logger.info(
                "Job %s COMPLETED: tool=%s items=%d duration=%dms ref=%s",
                job_id, tool_name, artifact["item_count"], duration_ms, storage_ref,
            )
        except Exception:
            await self._mark_job_failed(reason="UNHANDLED_EXCEPTION")
            logger.exception("Unhandled exception executing job %s", job_id)
            raise
        finally:
            try:
                await self._runner.cleanup_job(job_id)
            except Exception:
                logger.warning("Failed to clean work dir for job %s", job_id, exc_info=True)


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
        "dalfox",
        "graphql_cop",
        "cors_scanner",
        "jwt_tool",
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
    path_prefix = (parsed.path or "").rstrip("/")
    return f"{scheme}://{host}{path_prefix}".rstrip("/")


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


def _graphql_target_url(*, base_url: str, config: dict[str, Any]) -> str:
    selected_checks = config.get("selected_checks", {})
    if isinstance(selected_checks, dict):
        for collection_key in ("http_probe_paths", "content_paths"):
            values = selected_checks.get(collection_key, [])
            if not isinstance(values, list):
                continue
            for value in values:
                path = str(value or "").strip()
                if "graphql" not in path.lower():
                    continue
                if path.startswith("http://") or path.startswith("https://"):
                    return path
                return f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    return f"{base_url.rstrip('/')}/graphql"


async def _resolve_runtime_credentials(
    *,
    tool_name: str,
    base_url: str,
    config: dict[str, Any],
    explicit_credentials: dict[str, Any],
    web_runner: WebInteractionRunner,
) -> dict[str, Any]:
    if explicit_credentials:
        return explicit_credentials
    if tool_name not in {
        "sqlmap",
        "sqlmap_verify",
        "nuclei",
        "ffuf",
        "httpx_probe",
        "nikto",
        "dalfox",
        "graphql_cop",
        "cors_scanner",
    }:
        return {}

    stateful = config.get("stateful_testing", {})
    if not isinstance(stateful, dict) or not stateful.get("enabled"):
        return {}
    auth = stateful.get("auth", {})
    if not isinstance(auth, dict):
        return {}
    credentials = auth.get("credentials", [])
    if not isinstance(credentials, list) or not credentials:
        return {}
    first_credential = credentials[0]
    if not isinstance(first_credential, dict):
        return {}

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "Pentra-AuthBootstrap/phase9"},
        ) as client:
            login_result = await web_runner._login(
                client=client,
                base_url=base_url,
                scan_config=config,
                credentials=first_credential,
            )
            if not login_result.get("success"):
                return {}
            cookie = "; ".join(f"{key}={value}" for key, value in client.cookies.items())
            if not cookie:
                return {}
            return {"type": "cookie", "cookie": cookie}
    except Exception:
        logger.warning(
            "Failed to bootstrap stateful auth cookie for %s %s",
            tool_name,
            base_url,
            exc_info=True,
        )
    return {}
