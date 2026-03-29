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

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _ResolveReadySession:
    def __init__(self) -> None:
        self.select_sql = ""
        self.updated_node_ids: list[str] = []
        self.flushed = False

    async def execute(self, stmt: object, params: dict[str, object] | None = None) -> _FakeResult:
        sql = str(stmt)
        if "SELECT n.id, n.dag_id, n.phase_id, n.tool, n.worker_family" in sql:
            self.select_sql = sql
            return _FakeResult(
                [
                    {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "dag_id": "22222222-2222-2222-2222-222222222222",
                        "phase_id": "33333333-3333-3333-3333-333333333333",
                        "tool": "ai_triage",
                        "worker_family": "recon",
                        "config": {"timeout_seconds": 300},
                        "input_refs": {},
                    }
                ]
            )
        if "UPDATE scan_nodes SET status = 'ready'" in sql:
            if params is not None and "id" in params:
                self.updated_node_ids.append(str(params["id"]))
            return _FakeResult([])
        raise AssertionError(f"Unexpected SQL: {sql}")

    async def flush(self) -> None:
        self.flushed = True


def test_resolve_ready_nodes_ignores_skipped_upstream_dependencies() -> None:
    from app.engine.dependency_resolver import DependencyResolver

    session = _ResolveReadySession()
    resolver = DependencyResolver(session)  # type: ignore[arg-type]

    nodes = asyncio.run(
        resolver.resolve_ready_nodes(uuid.UUID("44444444-4444-4444-4444-444444444444"))
    )

    assert "JOIN scan_nodes src ON src.id = e.source_node_id" in session.select_sql
    assert "src.status <> 'skipped'" in session.select_sql
    assert len(nodes) == 1
    assert nodes[0].tool == "ai_triage"
    assert session.updated_node_ids == ["11111111-1111-1111-1111-111111111111"]
    assert session.flushed is True
