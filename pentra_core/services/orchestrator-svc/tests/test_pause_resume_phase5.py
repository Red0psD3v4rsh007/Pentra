from __future__ import annotations

import asyncio
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_paused_scan_transitions_allow_terminal_completion() -> None:
    from app.engine.state_manager import _SCAN_TRANSITIONS

    assert "completed" in _SCAN_TRANSITIONS["paused"]
    assert "failed" in _SCAN_TRANSITIONS["paused"]


def test_orchestrator_routes_scan_resumed_events() -> None:
    from app.services.orchestrator_service import OrchestratorService

    service = OrchestratorService(lambda: None, None)  # type: ignore[arg-type]
    seen: list[dict[str, str]] = []

    async def fake_handle_scan_resumed(event: dict[str, str]) -> None:
        seen.append(event)

    service.handle_scan_resumed = fake_handle_scan_resumed  # type: ignore[method-assign]

    asyncio.run(service.handle_scan_event({"event_type": "scan.resumed", "scan_id": "x"}))

    assert seen == [{"event_type": "scan.resumed", "scan_id": "x"}]


def test_resume_pipeline_dispatches_unique_ready_nodes() -> None:
    from app.engine.dependency_resolver import ReadyNode
    from app.engine.pipeline_executor import PipelineExecutor

    node_one = ReadyNode(
        node_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        dag_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        phase_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        tool="httpx_probe",
        worker_family="web",
        config={},
        input_refs={},
    )
    node_two = ReadyNode(
        node_id=uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
        dag_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        phase_id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
        tool="nuclei",
        worker_family="vuln",
        config={},
        input_refs={},
    )

    class _FakeResolver:
        async def resolve_ready_nodes(self, dag_id: uuid.UUID) -> list[ReadyNode]:
            assert dag_id == node_one.dag_id
            return [node_one]

        async def get_ready_nodes(self, dag_id: uuid.UUID) -> list[ReadyNode]:
            assert dag_id == node_one.dag_id
            return [node_one, node_two]

    class _FakeDispatcher:
        def __init__(self) -> None:
            self.dispatched_nodes: list[ReadyNode] = []

        async def dispatch_nodes(self, nodes, **kwargs):
            self.dispatched_nodes = list(nodes)
            return [
                uuid.UUID("11111111-1111-1111-1111-111111111111"),
                uuid.UUID("22222222-2222-2222-2222-222222222222"),
            ]

    class _FakeState:
        async def update_scan_progress(self, scan_id: uuid.UUID) -> int:
            assert scan_id == uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
            return 66

    executor = PipelineExecutor(session=None, redis=None)  # type: ignore[arg-type]
    executor._resolver = _FakeResolver()  # type: ignore[assignment]
    executor._dispatcher = _FakeDispatcher()  # type: ignore[assignment]
    executor._state = _FakeState()  # type: ignore[assignment]

    async def fake_load_scan_config(scan_id: uuid.UUID) -> dict[str, str]:
        assert scan_id == uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
        return {"profile_id": "external_web_api_v1"}

    executor._load_scan_config = fake_load_scan_config  # type: ignore[method-assign]

    result = asyncio.run(
        executor.resume_pipeline(
            dag_id=node_one.dag_id,
            scan_id=uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            tenant_id=uuid.UUID("99999999-9999-9999-9999-999999999999"),
            target="https://example.com",
            priority="high",
        )
    )

    dispatched = executor._dispatcher.dispatched_nodes  # type: ignore[attr-defined]
    assert {node.node_id for node in dispatched} == {node_one.node_id, node_two.node_id}
    assert result["dispatched_count"] == 2
    assert result["progress"] == 66
