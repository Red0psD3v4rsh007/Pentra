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
    def __init__(self, row: dict[str, object] | None) -> None:
        self._row = row

    def mappings(self) -> "_FakeResult":
        return self

    def first(self) -> dict[str, object] | None:
        return self._row


class _ResolverSession:
    def __init__(self, row: dict[str, object] | None) -> None:
        self._row = row

    async def execute(self, stmt: object, params: dict[str, object] | None = None) -> _FakeResult:
        return _FakeResult(self._row)


def test_phase_below_threshold_now_fails() -> None:
    from app.engine.dependency_resolver import DependencyResolver

    resolver = DependencyResolver(
        _ResolverSession(
            {
                "min_success_ratio": 0.75,
                "active": 0,
                "completed": 1,
                "failed": 2,
                "skipped": 0,
                "total": 3,
            }
        )
    )

    status = asyncio.run(
        resolver.check_phase_complete(
            uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            3,
        )
    )

    assert status == "failed"


def test_phase_at_threshold_remains_partial_success() -> None:
    from app.engine.dependency_resolver import DependencyResolver

    resolver = DependencyResolver(
        _ResolverSession(
            {
                "min_success_ratio": 0.5,
                "active": 0,
                "completed": 1,
                "failed": 1,
                "skipped": 0,
                "total": 2,
            }
        )
    )

    status = asyncio.run(
        resolver.check_phase_complete(
            uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            2,
        )
    )

    assert status == "partial_success"


def test_phase_with_only_skipped_nodes_is_still_completed() -> None:
    from app.engine.dependency_resolver import DependencyResolver

    resolver = DependencyResolver(
        _ResolverSession(
            {
                "min_success_ratio": 1.0,
                "active": 0,
                "completed": 0,
                "failed": 0,
                "skipped": 3,
                "total": 3,
            }
        )
    )

    status = asyncio.run(
        resolver.check_phase_complete(
            uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            4,
        )
    )

    assert status == "completed"


def test_dependency_resolver_no_longer_force_advances_below_threshold() -> None:
    import inspect
    from app.engine.dependency_resolver import DependencyResolver

    source = inspect.getsource(DependencyResolver.check_phase_complete)

    assert "force-advancing as partial_success" not in source
    assert "return \"failed\"" in source
