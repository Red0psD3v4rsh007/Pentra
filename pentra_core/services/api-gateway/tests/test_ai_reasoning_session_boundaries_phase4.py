from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeSession:
    def __init__(self, scan: object) -> None:
        self._scan = scan
        self.commit_calls = 0
        self._in_transaction = True

    async def execute(self, stmt: object) -> _FakeResult:
        return _FakeResult(self._scan)

    async def commit(self) -> None:
        self.commit_calls += 1
        self._in_transaction = False

    def in_transaction(self) -> bool:
        return self._in_transaction


def _scan(*, scan_id: uuid.UUID, tenant_id: uuid.UUID) -> object:
    return SimpleNamespace(
        id=scan_id,
        tenant_id=tenant_id,
        asset=None,
        findings=[],
    )


def test_get_scan_ai_reasoning_releases_transaction_before_provider_call(monkeypatch) -> None:
    from app.services import ai_reasoning_service

    scan_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    user_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    session = _FakeSession(_scan(scan_id=scan_id, tenant_id=tenant_id))

    async def fake_get_attack_graph(**kwargs: object) -> dict[str, object]:
        return {}

    async def fake_get_scan_report(**kwargs: object) -> dict[str, object]:
        return {}

    async def fake_list_evidence(**kwargs: object) -> list[object]:
        return []

    async def fake_load_cached_reasoning(**kwargs: object) -> None:
        return None

    async def fake_generate_reasoning_run(**kwargs: object) -> object:
        assert session.commit_calls == 1
        return SimpleNamespace(
            generated_at=datetime.now(timezone.utc),
            advisory_mode="advisory_only",
            prompt_version="phase4-test",
            provider="fallback",
            model="deterministic",
            status="fallback",
            fallback_reason="test",
            parsed={"attack_graph": {}, "report": {}, "findings": []},
        )

    async def fake_store_reasoning_artifact(**kwargs: object) -> object:
        return SimpleNamespace(
            id=uuid.uuid4(),
            storage_ref="artifacts/test/advisory.json",
            metadata_={},
        )

    async def fake_record_reasoning_audit(**kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        ai_reasoning_service.scan_service,
        "get_attack_graph",
        fake_get_attack_graph,
    )
    monkeypatch.setattr(
        ai_reasoning_service.scan_service,
        "get_scan_report",
        fake_get_scan_report,
    )
    monkeypatch.setattr(
        ai_reasoning_service.scan_service,
        "list_evidence_references",
        fake_list_evidence,
    )
    monkeypatch.setattr(
        ai_reasoning_service,
        "_build_reasoning_context",
        lambda **kwargs: {"scan": {"id": str(scan_id)}},
    )
    monkeypatch.setattr(ai_reasoning_service, "_load_cached_reasoning", fake_load_cached_reasoning)
    monkeypatch.setattr(ai_reasoning_service, "_generate_reasoning_run", fake_generate_reasoning_run)
    monkeypatch.setattr(
        ai_reasoning_service,
        "_store_reasoning_artifact",
        fake_store_reasoning_artifact,
    )
    monkeypatch.setattr(
        ai_reasoning_service,
        "_record_reasoning_audit",
        fake_record_reasoning_audit,
    )
    monkeypatch.setattr(
        ai_reasoning_service,
        "_artifact_payload_for_response",
        lambda **kwargs: {"payload": "ok"},
    )
    monkeypatch.setattr(
        ai_reasoning_service,
        "_build_reasoning_response",
        lambda **kwargs: {"status": "ok"},
    )

    result = asyncio.run(
        ai_reasoning_service.get_scan_ai_reasoning(
            scan_id=scan_id,
            tenant_id=tenant_id,
            user_id=user_id,
            session=session,  # type: ignore[arg-type]
        )
    )

    assert result == {"status": "ok"}
    assert session.commit_calls == 1


@pytest.mark.parametrize(
    ("function_name", "fallback_name", "extra_patches"),
    [
        (
            "suggest_exploitation_paths",
            "_build_deterministic_exploitation_paths",
            ("get_attack_graph", "list_evidence_references"),
        ),
        (
            "prioritize_attack_vectors",
            "_build_deterministic_vector_priorities",
            (),
        ),
        (
            "generate_remediation_report",
            "_build_deterministic_remediation",
            ("get_scan_report",),
        ),
    ],
)
def test_specialized_ai_flows_release_transaction_before_prompt(
    monkeypatch,
    function_name: str,
    fallback_name: str,
    extra_patches: tuple[str, ...],
) -> None:
    from app.services import ai_reasoning_service

    scan_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    tenant_id = uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
    user_id = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
    session = _FakeSession(_scan(scan_id=scan_id, tenant_id=tenant_id))

    async def fake_attack_graph(**kwargs: object) -> dict[str, object]:
        return {}

    async def fake_scan_report(**kwargs: object) -> dict[str, object]:
        return {}

    async def fake_evidence(**kwargs: object) -> list[object]:
        return []

    async def fake_run_specialized_prompt(**kwargs: object) -> dict[str, object]:
        assert session.commit_calls == 1
        return {"_is_fallback": True}

    monkeypatch.setattr(
        ai_reasoning_service,
        "_build_reasoning_context",
        lambda **kwargs: {"scan": {"id": str(scan_id)}},
    )
    monkeypatch.setattr(
        ai_reasoning_service,
        "_run_specialized_prompt",
        fake_run_specialized_prompt,
    )
    monkeypatch.setattr(
        ai_reasoning_service,
        fallback_name,
        lambda *args, **kwargs: {"items": []},
    )
    if "get_attack_graph" in extra_patches:
        monkeypatch.setattr(
            ai_reasoning_service.scan_service,
            "get_attack_graph",
            fake_attack_graph,
        )
    if "list_evidence_references" in extra_patches:
        monkeypatch.setattr(
            ai_reasoning_service.scan_service,
            "list_evidence_references",
            fake_evidence,
        )
    if "get_scan_report" in extra_patches:
        monkeypatch.setattr(
            ai_reasoning_service.scan_service,
            "get_scan_report",
            fake_scan_report,
        )

    result = asyncio.run(
        getattr(ai_reasoning_service, function_name)(
            scan_id=scan_id,
            tenant_id=tenant_id,
            user_id=user_id,
            session=session,  # type: ignore[arg-type]
        )
    )

    assert result["scan_id"] == str(scan_id)
    assert session.commit_calls == 1
