from __future__ import annotations

import asyncio
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object] | None]] = []
        self.commits = 0

    async def execute(self, stmt: object, params: dict[str, object] | None = None) -> None:
        self.calls.append((str(stmt), params))

    async def commit(self) -> None:
        self.commits += 1


class _SessionFactory:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def __call__(self) -> "_SessionFactory":
        return self

    async def __aenter__(self) -> _FakeSession:
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


def test_worker_service_persists_claim_and_start_timing(monkeypatch) -> None:
    from app.services import worker_service

    recorded_tenants: list[uuid.UUID] = []
    session = _FakeSession()
    service = worker_service.WorkerService(redis=None)  # type: ignore[arg-type]

    async def fake_set_tenant_context(db_session: _FakeSession, tenant_id: uuid.UUID) -> None:
        assert db_session is session
        recorded_tenants.append(tenant_id)

    monkeypatch.setattr(worker_service, "async_session_factory", _SessionFactory(session))
    monkeypatch.setattr(worker_service, "set_tenant_context", fake_set_tenant_context)

    job_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    tenant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")

    asyncio.run(
        service._persist_job_claimed(
            job_id=job_id,
            tenant_id=tenant_id,
            worker_id="worker-web-123",
            claimed_at="2026-03-22T10:00:02+00:00",
        )
    )
    asyncio.run(
        service._persist_job_started(
            job_id=job_id,
            tenant_id=tenant_id,
            worker_id="worker-web-123",
            claimed_at="2026-03-22T10:00:02+00:00",
            started_at="2026-03-22T10:00:05+00:00",
        )
    )

    assert recorded_tenants == [tenant_id, tenant_id]
    assert session.commits == 2
    assert "claimed_at = COALESCE(claimed_at, :claimed_at)" in session.calls[0][0]
    assert session.calls[0][1]["worker_id"] == "worker-web-123"
    assert "started_at = COALESCE(started_at, :started_at)" in session.calls[1][0]
    assert session.calls[1][1]["worker_id"] == "worker-web-123"
