from __future__ import annotations

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from pydantic import ValidationError


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.flush_calls = 0

    def add(self, obj: object) -> None:
        self.added.append(obj)
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", uuid.uuid4())

    async def flush(self) -> None:
        self.flush_calls += 1


def test_multi_asset_scan_schema_requires_exactly_one_selector() -> None:
    from pentra_common.schemas import MultiAssetScanCreate

    payload = {
        "scan_type": "full",
        "priority": "high",
        "config": {"profile_id": "external_web_api_v1"},
    }

    with pytest.raises(ValidationError):
        MultiAssetScanCreate(**payload)

    with pytest.raises(ValidationError):
        MultiAssetScanCreate(
            **payload,
            asset_ids=["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
            asset_group_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        )

    valid = MultiAssetScanCreate(
        **payload,
        asset_ids=["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
    )
    assert valid.asset_group_id is None


def test_asset_group_model_exposes_membership_table() -> None:
    from app.models.asset_group import AssetGroup, AssetGroupMember

    assert AssetGroup.__tablename__ == "asset_groups"
    assert AssetGroupMember.__tablename__ == "asset_group_members"
    assert "project_id" in AssetGroup.__table__.c
    assert "asset_group_id" in AssetGroupMember.__table__.c
    assert "asset_id" in AssetGroupMember.__table__.c


def test_create_asset_group_creates_group_and_members(monkeypatch) -> None:
    from app.services import asset_group_service

    tenant_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    project_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    created_by = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    asset_one = SimpleNamespace(id=uuid.UUID("11111111-1111-1111-1111-111111111111"))
    asset_two = SimpleNamespace(id=uuid.UUID("22222222-2222-2222-2222-222222222222"))
    session = _FakeSession()

    async def fake_load_project(*, project_id: uuid.UUID, tenant_id: uuid.UUID, session: object) -> object:
        assert project_id
        assert tenant_id
        assert session is not None
        return SimpleNamespace(id=project_id)

    async def fake_load_assets_for_group(
        *,
        asset_ids: list[uuid.UUID],
        project_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session: object,
    ) -> list[object]:
        assert asset_ids == [asset_one.id, asset_two.id]
        assert project_id
        assert tenant_id
        assert session is not None
        return [asset_one, asset_two]

    monkeypatch.setattr(asset_group_service, "_load_project", fake_load_project)
    monkeypatch.setattr(asset_group_service, "_load_assets_for_group", fake_load_assets_for_group)

    group = asyncio.run(
        asset_group_service.create_asset_group(
            tenant_id=tenant_id,
            project_id=project_id,
            created_by=created_by,
            name="Internet-facing APIs",
            description="Primary external estate",
            asset_ids=[asset_one.id, asset_two.id],
            session=session,
        )
    )

    assert group.project_id == project_id
    assert group.asset_ids == [asset_one.id, asset_two.id]
    assert group.asset_count == 2
    assert len(session.added) == 3
    assert session.flush_calls == 2


def test_create_multi_asset_scan_batch_derives_per_asset_idempotency_and_metadata(monkeypatch) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    created_by = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    asset_one = SimpleNamespace(
        id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        name="App One",
        asset_type="web_app",
        target="https://one.example.com",
        project_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
    )
    asset_two = SimpleNamespace(
        id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        name="App Two",
        asset_type="web_app",
        target="https://two.example.com",
        project_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
    )
    create_calls: list[dict[str, object]] = []

    async def fake_resolve_multi_asset_batch_assets(**kwargs: object) -> tuple[list[object], uuid.UUID]:
        assert kwargs["tenant_id"] == tenant_id
        return [asset_one, asset_two], uuid.UUID("44444444-4444-4444-4444-444444444444")

    async def fake_preflight_multi_asset_batch_capacity(**kwargs: object) -> None:
        assert kwargs["tenant_id"] == tenant_id
        assert kwargs["requested_count"] == 2

    async def fake_create_scan(**kwargs: object) -> object:
        create_calls.append(kwargs)
        return SimpleNamespace(id=uuid.uuid4(), config=kwargs["config"], status="queued")

    monkeypatch.setattr(scan_service, "_resolve_multi_asset_batch_assets", fake_resolve_multi_asset_batch_assets)
    monkeypatch.setattr(scan_service, "_preflight_multi_asset_batch_capacity", fake_preflight_multi_asset_batch_capacity)
    monkeypatch.setattr(scan_service, "create_scan", fake_create_scan)

    result = asyncio.run(
        scan_service.create_multi_asset_scan_batch(
            tenant_id=tenant_id,
            created_by=created_by,
            scan_type="full",
            priority="high",
            config={"profile_id": "external_web_api_v1"},
            asset_ids=[asset_one.id, asset_two.id],
            asset_group_id=None,
            scheduled_at=None,
            idempotency_key="batch-123",
            stream_publisher=object(),
            session=object(),
        )
    )

    assert result["batch_request_id"] == "batch-123"
    assert result["created_count"] == 2
    assert result["failed_count"] == 0
    assert create_calls[0]["idempotency_key"] == f"batch-123:{asset_one.id}"
    assert create_calls[1]["idempotency_key"] == f"batch-123:{asset_two.id}"
    assert create_calls[0]["config"]["batch"]["asset_name"] == "App One"
    assert create_calls[1]["config"]["batch"]["batch_size"] == 2


def test_create_multi_asset_scan_batch_collects_business_failures(monkeypatch) -> None:
    from app.services import scan_service

    asset_one = SimpleNamespace(
        id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        name="App One",
        asset_type="web_app",
        target="https://one.example.com",
        project_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
    )
    asset_two = SimpleNamespace(
        id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        name="App Two",
        asset_type="web_app",
        target="https://two.example.com",
        project_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
    )

    async def fake_resolve_multi_asset_batch_assets(**kwargs: object) -> tuple[list[object], None]:
        return [asset_one, asset_two], None

    async def fake_preflight_multi_asset_batch_capacity(**kwargs: object) -> None:
        return None

    async def fake_create_scan(**kwargs: object) -> object:
        if kwargs["asset_id"] == asset_two.id:
            raise ValueError("Concurrent scan limit reached (5)")
        return SimpleNamespace(id=uuid.uuid4(), config=kwargs["config"], status="queued")

    monkeypatch.setattr(scan_service, "_resolve_multi_asset_batch_assets", fake_resolve_multi_asset_batch_assets)
    monkeypatch.setattr(scan_service, "_preflight_multi_asset_batch_capacity", fake_preflight_multi_asset_batch_capacity)
    monkeypatch.setattr(scan_service, "create_scan", fake_create_scan)

    result = asyncio.run(
        scan_service.create_multi_asset_scan_batch(
            tenant_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            created_by=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            scan_type="full",
            priority="normal",
            config=None,
            asset_ids=[asset_one.id, asset_two.id],
            asset_group_id=None,
            scheduled_at=None,
            idempotency_key=None,
            stream_publisher=object(),
            session=object(),
        )
    )

    assert result["created_count"] == 1
    assert result["failed_count"] == 1
    assert result["failures"] == [
        {
            "asset_id": asset_two.id,
            "asset_name": "App Two",
            "reason": "Concurrent scan limit reached (5)",
        }
    ]
