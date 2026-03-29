from __future__ import annotations

import asyncio
import json


def test_runtime_state_tracks_job_and_prewarm_metrics() -> None:
    from app.observability.runtime_state import WorkerRuntimeState

    async def _exercise() -> None:
        state = WorkerRuntimeState(
            worker_family="web",
            health_host="127.0.0.1",
            health_port=9103,
            prewarm_enabled=True,
        )

        await state.set_consumer_name("worker-web-123")
        await state.mark_job_claimed(
            job_id="job-1",
            scan_id="scan-1",
            tool_name="nuclei",
            target="http://127.0.0.1:8088",
            scheduled_at="2026-03-22T10:00:00+00:00",
            claimed_at="2026-03-22T10:00:02+00:00",
        )
        await state.mark_job_started(
            job_id="job-1",
            scan_id="scan-1",
            tool_name="nuclei",
            target="http://127.0.0.1:8088",
            scheduled_at="2026-03-22T10:00:00+00:00",
            claimed_at="2026-03-22T10:00:02+00:00",
            started_at="2026-03-22T10:00:05+00:00",
        )

        started_snapshot = await state.snapshot()
        assert started_snapshot["consumer_name"] == "worker-web-123"
        assert started_snapshot["jobs_processed"] == 0
        assert started_snapshot["jobs_failed"] == 0
        assert started_snapshot["current_job"]["job_id"] == "job-1"
        assert started_snapshot["current_job"]["scheduled_at"] == "2026-03-22T10:00:00+00:00"
        assert started_snapshot["current_job"]["claimed_at"] == "2026-03-22T10:00:02+00:00"
        assert started_snapshot["current_job"]["queue_delay_seconds"] == 2.0
        assert started_snapshot["current_job"]["claim_to_start_seconds"] == 3.0
        assert started_snapshot["prewarm"]["status"] == "pending"

        await state.mark_job_succeeded()
        await state.mark_job_claimed(
            job_id="job-2",
            scan_id="scan-2",
            tool_name="ffuf",
            target="http://127.0.0.1:8088",
            scheduled_at="2026-03-22T10:01:00+00:00",
            claimed_at="2026-03-22T10:01:01+00:00",
        )
        await state.mark_job_started(
            job_id="job-2",
            scan_id="scan-2",
            tool_name="ffuf",
            target="http://127.0.0.1:8088",
            scheduled_at="2026-03-22T10:01:00+00:00",
            claimed_at="2026-03-22T10:01:01+00:00",
            started_at="2026-03-22T10:01:04+00:00",
        )
        await state.mark_job_failed(reason="EXIT_2")
        await state.mark_prewarm_started(["tool-a:latest", "tool-b:latest"])
        await state.mark_prewarm_completed(
            {
                "tool-a:latest": {"status": "cached", "detail": "already_present"},
                "tool-b:latest": {"status": "pulled", "detail": "pulled_on_startup"},
            }
        )

        completed_snapshot = await state.snapshot()
        assert completed_snapshot["jobs_processed"] == 1
        assert completed_snapshot["jobs_failed"] == 1
        assert completed_snapshot["current_job"] is None
        assert completed_snapshot["prewarm"]["status"] == "completed"
        assert completed_snapshot["prewarm"]["summary"] == {
            "requested": 2,
            "cached": 1,
            "pulled": 1,
            "failed": 0,
            "skipped": 0,
        }

    asyncio.run(_exercise())


def test_health_server_serves_runtime_snapshot() -> None:
    from app.observability.health_server import WorkerHealthServer
    from app.observability.runtime_state import WorkerRuntimeState

    class _FakeWriter:
        def __init__(self) -> None:
            self.buffer = bytearray()
            self.closed = False

        def writelines(self, data: list[bytes]) -> None:
            for chunk in data:
                self.buffer.extend(chunk)

        def write(self, data: bytes) -> None:
            self.buffer.extend(data)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    async def _exercise() -> None:
        state = WorkerRuntimeState(
            worker_family="recon",
            health_host="127.0.0.1",
            health_port=0,
            prewarm_enabled=False,
        )
        server = WorkerHealthServer(
            host="127.0.0.1",
            port=0,
            snapshot_provider=state.snapshot,
        )

        reader = asyncio.StreamReader()
        reader.feed_data(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        reader.feed_eof()
        writer = _FakeWriter()

        await server._handle_connection(reader, writer)

        response = bytes(writer.buffer)
        raw_headers, raw_body = response.split(b"\r\n\r\n", 1)
        body = json.loads(raw_body.decode("utf-8"))
        assert b"200 OK" in raw_headers
        assert body["status"] == "ok"
        assert body["worker_family"] == "recon"
        assert body["prewarm"]["status"] == "disabled"
        assert writer.closed is True

    asyncio.run(_exercise())


def test_container_runner_plans_family_scoped_prewarm_images() -> None:
    from app.engine.container_runner import (
        LIVE_EXECUTION_TOOLS,
        _PREWARM_EXCLUDED_TOOLS,
        ContainerRunner,
    )
    from app.tools.tool_registry import get_tools_for_family

    runner = ContainerRunner()
    planned_images = runner.planned_prewarm_images(worker_family="web")

    expected_images: list[str] = []
    seen: set[str] = set()
    for tool in get_tools_for_family("web"):
        if tool.name not in LIVE_EXECUTION_TOOLS:
            continue
        if tool.name in _PREWARM_EXCLUDED_TOOLS:
            continue
        if tool.image in seen:
            continue
        seen.add(tool.image)
        expected_images.append(tool.image)

    assert planned_images == expected_images
    assert len(planned_images) == len(set(planned_images))
    assert planned_images
