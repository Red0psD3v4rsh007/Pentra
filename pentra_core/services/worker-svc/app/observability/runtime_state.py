"""Worker runtime health and telemetry state."""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _seconds_between_iso(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
    except ValueError:
        return None
    return round((end_dt - start_dt).total_seconds(), 3)


class WorkerRuntimeState:
    """Tracks worker lifecycle, job execution, and image prewarm telemetry."""

    def __init__(
        self,
        *,
        worker_family: str,
        health_host: str,
        health_port: int,
        prewarm_enabled: bool,
    ) -> None:
        started_at = _utc_now()
        self._lock = asyncio.Lock()
        self._started_at = started_at
        self._started_monotonic = time.monotonic()
        self._last_activity = started_at
        self._worker_family = worker_family
        self._health_host = health_host
        self._health_port = health_port
        self._pid = os.getpid()
        self._consumer_name: str | None = None
        self._jobs_processed = 0
        self._jobs_failed = 0
        self._current_job: dict[str, str] | None = None
        self._prewarm: dict[str, Any] = {
            "enabled": prewarm_enabled,
            "status": "pending" if prewarm_enabled else "disabled",
            "started_at": None,
            "completed_at": None,
            "images": {},
            "summary": {
                "requested": 0,
                "cached": 0,
                "pulled": 0,
                "failed": 0,
                "skipped": 0,
            },
            "reason": None,
        }

    async def set_consumer_name(self, consumer_name: str) -> None:
        async with self._lock:
            self._consumer_name = consumer_name
            self._last_activity = _utc_now()

    async def mark_job_started(
        self,
        *,
        job_id: str,
        scan_id: str,
        tool_name: str,
        target: str,
        scheduled_at: str | None = None,
        claimed_at: str | None = None,
        started_at: str | None = None,
    ) -> None:
        async with self._lock:
            now = _utc_now()
            started_at_iso = started_at or now.isoformat()
            self._current_job = {
                "job_id": job_id,
                "scan_id": scan_id,
                "tool_name": tool_name,
                "target": target,
                "scheduled_at": scheduled_at,
                "claimed_at": claimed_at,
                "started_at": started_at_iso,
                "queue_delay_seconds": _seconds_between_iso(scheduled_at, claimed_at),
                "claim_to_start_seconds": _seconds_between_iso(claimed_at, started_at_iso),
            }
            self._last_activity = now

    async def mark_job_claimed(
        self,
        *,
        job_id: str,
        scan_id: str,
        tool_name: str,
        target: str,
        scheduled_at: str | None = None,
        claimed_at: str | None = None,
    ) -> None:
        async with self._lock:
            now = _utc_now()
            claimed_at_iso = claimed_at or now.isoformat()
            self._current_job = {
                "job_id": job_id,
                "scan_id": scan_id,
                "tool_name": tool_name,
                "target": target,
                "scheduled_at": scheduled_at,
                "claimed_at": claimed_at_iso,
                "started_at": None,
                "queue_delay_seconds": _seconds_between_iso(scheduled_at, claimed_at_iso),
                "claim_to_start_seconds": None,
            }
            self._last_activity = now

    async def mark_job_succeeded(self) -> None:
        async with self._lock:
            self._jobs_processed += 1
            self._current_job = None
            self._last_activity = _utc_now()

    async def mark_job_failed(self, *, reason: str | None = None) -> None:
        async with self._lock:
            self._jobs_failed += 1
            self._current_job = None
            self._last_activity = _utc_now()

    async def mark_prewarm_started(self, images: list[str]) -> None:
        async with self._lock:
            now = _utc_now()
            self._prewarm["status"] = "running"
            self._prewarm["started_at"] = now.isoformat()
            self._prewarm["completed_at"] = None
            self._prewarm["images"] = {
                image: {"status": "pending", "detail": None}
                for image in images
            }
            self._prewarm["summary"] = {
                "requested": len(images),
                "cached": 0,
                "pulled": 0,
                "failed": 0,
                "skipped": 0,
            }
            self._prewarm["reason"] = None
            self._last_activity = now

    async def mark_prewarm_skipped(self, *, reason: str) -> None:
        async with self._lock:
            now = _utc_now()
            self._prewarm["status"] = "skipped"
            self._prewarm["started_at"] = now.isoformat()
            self._prewarm["completed_at"] = now.isoformat()
            self._prewarm["images"] = {}
            self._prewarm["summary"] = {
                "requested": 0,
                "cached": 0,
                "pulled": 0,
                "failed": 0,
                "skipped": 0,
            }
            self._prewarm["reason"] = reason
            self._last_activity = now

    async def mark_prewarm_completed(
        self,
        results: dict[str, dict[str, str]],
        *,
        reason: str | None = None,
    ) -> None:
        async with self._lock:
            now = _utc_now()
            images: dict[str, dict[str, str | None]] = {}
            summary = {
                "requested": len(results),
                "cached": 0,
                "pulled": 0,
                "failed": 0,
                "skipped": 0,
            }
            for image, result in results.items():
                status = str(result.get("status") or "failed")
                detail = result.get("detail")
                images[image] = {"status": status, "detail": detail}
                if status in summary:
                    summary[status] += 1
                else:
                    summary["failed"] += 1

            self._prewarm["status"] = "completed"
            self._prewarm["completed_at"] = now.isoformat()
            self._prewarm["images"] = images
            self._prewarm["summary"] = summary
            self._prewarm["reason"] = reason
            self._last_activity = now

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "status": "ok",
                "worker_family": self._worker_family,
                "consumer_name": self._consumer_name,
                "pid": self._pid,
                "started_at": self._started_at.isoformat(),
                "uptime_seconds": round(time.monotonic() - self._started_monotonic, 2),
                "jobs_processed": self._jobs_processed,
                "jobs_failed": self._jobs_failed,
                "current_job": dict(self._current_job) if self._current_job else None,
                "last_activity": self._last_activity.isoformat(),
                "health_endpoint": {
                    "host": self._health_host,
                    "port": self._health_port,
                },
                "prewarm": {
                    "enabled": bool(self._prewarm["enabled"]),
                    "status": str(self._prewarm["status"]),
                    "started_at": self._prewarm["started_at"],
                    "completed_at": self._prewarm["completed_at"],
                    "images": dict(self._prewarm["images"]),
                    "summary": dict(self._prewarm["summary"]),
                    "reason": self._prewarm["reason"],
                },
            }
