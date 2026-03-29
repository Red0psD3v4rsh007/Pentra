from __future__ import annotations

import asyncio
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeResult:
    def __init__(self, rows: list[dict[str, object]] | None = None) -> None:
        self._rows = rows or []

    def mappings(self) -> "_FakeResult":
        return self

    def first(self) -> dict[str, object] | None:
        return self._rows[0] if self._rows else None


class _PhaseAdvanceSession:
    def __init__(self) -> None:
        self.phase_updates: list[tuple[str, int | None]] = []
        self.dag_completed = False
        self.flush_count = 0

    async def execute(self, stmt: object, params: dict[str, object] | None = None) -> _FakeResult:
        sql = str(stmt)
        params = params or {}

        if "SELECT id, phase_number FROM scan_phases" in sql and "phase_number > :pn" in sql:
            phase_number = int(params["pn"])
            if phase_number == 3:
                return _FakeResult(
                    [{"id": "44444444-4444-4444-4444-444444444444", "phase_number": 4}]
                )
            if phase_number == 4:
                return _FakeResult(
                    [{"id": "55555555-5555-5555-5555-555555555555", "phase_number": 5}]
                )
            return _FakeResult([])

        if "UPDATE scan_phases SET status = 'running'" in sql:
            self.phase_updates.append(("running", int(params["pid"][-1], 16) if False else None))
            return _FakeResult([])

        if "UPDATE scan_phases SET status = :st, completed_at = :now" in sql:
            self.phase_updates.append((str(params["st"]), int(params["pn"])))
            return _FakeResult([])

        if "UPDATE scan_dags SET current_phase = :pn" in sql:
            self.phase_updates.append(("current_phase", int(params["pn"])))
            return _FakeResult([])

        if "UPDATE scan_dags SET status = 'completed'" in sql:
            self.dag_completed = True
            return _FakeResult([])

        raise AssertionError(f"Unexpected SQL: {sql}")

    async def flush(self) -> None:
        self.flush_count += 1


class _FakeResolver:
    def __init__(self) -> None:
        self.resolve_calls = 0
        self.check_calls: list[int] = []

    async def resolve_ready_nodes(self, _dag_id: uuid.UUID):  # type: ignore[no-untyped-def]
        from app.engine.dependency_resolver import ReadyNode

        self.resolve_calls += 1
        if self.resolve_calls == 2:
            return [
                ReadyNode(
                    node_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                    dag_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                    phase_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                    tool="ai_triage",
                    worker_family="recon",
                    config={},
                    input_refs={},
                )
            ]
        return []

    async def check_phase_complete(self, _dag_id: uuid.UUID, phase_number: int) -> str:
        self.check_calls.append(phase_number)
        if phase_number == 3:
            return "completed"
        if phase_number == 4:
            return "completed"
        if phase_number == 5:
            return "running"
        raise AssertionError(f"Unexpected phase_number: {phase_number}")


def test_phase_controller_auto_skips_empty_running_phase() -> None:
    from app.engine.phase_controller import PhaseController

    session = _PhaseAdvanceSession()
    controller = PhaseController(session)  # type: ignore[arg-type]
    controller._resolver = _FakeResolver()  # type: ignore[assignment]

    dag_status, ready_nodes, phase_transitioned = asyncio.run(
        controller.evaluate_and_advance(
            uuid.UUID("99999999-9999-9999-9999-999999999999"),
            3,
        )
    )

    assert dag_status == "executing"
    assert phase_transitioned is True
    assert [node.tool for node in ready_nodes] == ["ai_triage"]
    assert controller._resolver.check_calls == [3, 4, 5]  # type: ignore[attr-defined]
    assert ("completed", 4) in session.phase_updates
    assert ("current_phase", 5) in session.phase_updates
    assert session.dag_completed is False
    assert session.flush_count >= 2
