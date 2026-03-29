"""Scan service — scan lifecycle management, quota enforcement, event publishing.

Framework-agnostic: accepts plain arguments, returns ORM objects.
No FastAPI Request dependency.

**MOD-04 compatibility**: This service creates only the ``Scan`` record
and publishes ``scan.created`` to Redis Streams.  All DAG planning and
``ScanJob`` creation is delegated to the orchestrator service.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from html import escape as html_escape
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentra_common.events.stream_publisher import StreamPublisher
from pentra_common.execution_truth import classify_tool_execution, classify_tool_policy_state
from pentra_common.profiles import (
    FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID,
    enforce_safe_scan_config,
    prepare_scan_config,
)
from pentra_common.storage.artifacts import read_json_artifact
from pentra_common.storage.artifacts import read_text_artifact
from pentra_common.schemas import SCAN_TERMINAL_STATES
from pentra_common.config.settings import get_settings

from app.models.attack_graph import ScanArtifact
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.tenant import TenantQuota

logger = logging.getLogger(__name__)


_DEFAULT_EXPORT_FORMATS = ["markdown", "json", "csv", "html"]
_DERIVED_EXECUTION_TOOLS = frozenset({"ai_triage", "report_gen"})
_FIX_GUIDANCE_LIBRARY: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "title": "Eliminate injectable database queries",
        "owner_hint": "Backend Engineering",
        "actions": [
            "Replace dynamic SQL construction with parameterized queries.",
            "Add regression tests for injectable parameters on authenticated and unauthenticated routes.",
            "Review database permissions to reduce blast radius for compromised queries.",
        ],
    },
    "idor": {
        "title": "Enforce object-level authorization consistently",
        "owner_hint": "Application Engineering",
        "actions": [
            "Authorize access on every object lookup, not only on list endpoints.",
            "Add tenant and ownership checks to direct object reference handlers.",
            "Add replay tests that exercise cross-user and cross-tenant requests.",
        ],
    },
    "auth_bypass": {
        "title": "Close authorization bypass paths in authenticated workflows",
        "owner_hint": "Identity Engineering",
        "actions": [
            "Enforce session validation before serving privileged workflow steps.",
            "Bind privileged actions to the authenticated principal and current session state.",
            "Add workflow replay regression tests for cross-session and skipped-step access.",
        ],
    },
    "workflow_bypass": {
        "title": "Protect stateful workflows against step and order bypass",
        "owner_hint": "Product Engineering",
        "actions": [
            "Validate server-side workflow state before completing high-impact actions.",
            "Reject replayed, duplicated, or out-of-order requests for stateful actions.",
            "Add end-to-end tests for checkout, onboarding, and approval workflows.",
        ],
    },
    "unsafe_deserialization": {
        "title": "Remove unsafe deserialization attack paths",
        "owner_hint": "Platform Engineering",
        "actions": [
            "Disable unsafe object deserialization for untrusted input.",
            "Use allow-listed serializers and signed payloads where serialization is required.",
            "Review internal endpoints and background jobs for gadget-friendly libraries.",
        ],
    },
    "graphql_introspection": {
        "title": "Reduce GraphQL schema exposure and tighten resolver auth",
        "owner_hint": "API Platform",
        "actions": [
            "Disable introspection for production users where possible.",
            "Review resolver authorization and rate limiting for sensitive schema paths.",
            "Gate developer-only schema features behind authenticated admin roles.",
        ],
    },
}

_COMPLIANCE_LIBRARY: dict[str, dict[str, list[str]]] = {
    "sql_injection": {"owasp": ["A03:2021-Injection"], "cwe": ["CWE-89"]},
    "idor": {"owasp": ["A01:2021-Broken Access Control"], "cwe": ["CWE-639"]},
    "auth_bypass": {"owasp": ["A01:2021-Broken Access Control", "A07:2021-Authentication Failures"], "cwe": ["CWE-287"]},
    "workflow_bypass": {"owasp": ["A01:2021-Broken Access Control"], "cwe": ["CWE-285"]},
    "unsafe_deserialization": {"owasp": ["A08:2021-Software and Data Integrity Failures"], "cwe": ["CWE-502"]},
    "graphql_introspection": {"owasp": ["A05:2021-Security Misconfiguration"], "cwe": ["CWE-200"]},
}


def _with_request_metadata(
    config: dict[str, Any] | None,
    *,
    idempotency_key: str | None,
    scheduled_at: datetime | None = None,
) -> dict[str, Any]:
    normalized = deepcopy(config or {})
    if not isinstance(normalized, dict):
        normalized = {}

    request_metadata = (
        deepcopy(normalized.get("request_metadata"))
        if isinstance(normalized.get("request_metadata"), dict)
        else {}
    )
    request_metadata["submitted_at"] = datetime.now(timezone.utc).isoformat()
    if idempotency_key:
        request_metadata["idempotency_key"] = idempotency_key
    if scheduled_at is not None:
        request_metadata["scheduled_at"] = _normalize_utc_datetime(
            scheduled_at
        ).isoformat()

    normalized["request_metadata"] = request_metadata
    return normalized


def _normalize_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _seconds_between_datetimes(
    start: datetime | None,
    end: datetime | None,
) -> float | None:
    if start is None or end is None:
        return None
    return round((end - start).total_seconds(), 3)


def _scan_counts_as_active(scan: Scan) -> bool:
    return scan.status in {"running", "queued", "validating"} or (
        scan.status == "paused" and scan.started_at is not None
    )


def _active_scan_filter(tenant_id: uuid.UUID):
    return and_(
        Scan.tenant_id == tenant_id,
        or_(
            Scan.status.in_(["running", "queued", "validating"]),
            and_(Scan.status == "paused", Scan.started_at.is_not(None)),
        ),
    )


def _is_deferred_scan_start(
    *,
    scheduled_at: datetime | None,
    now: datetime | None = None,
) -> bool:
    if scheduled_at is None:
        return False
    current = now or datetime.now(timezone.utc)
    return _normalize_utc_datetime(scheduled_at) > current


def _dedupe_asset_ids(asset_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    return list(dict.fromkeys(asset_ids))


def _build_batch_scan_config(
    *,
    base_config: dict | None,
    batch_request_id: str,
    asset_group_id: uuid.UUID | None,
    asset: Asset,
    batch_index: int,
    batch_size: int,
) -> dict[str, Any]:
    config = deepcopy(base_config or {})
    if not isinstance(config, dict):
        config = {}
    config["batch"] = {
        "batch_request_id": batch_request_id,
        "asset_group_id": str(asset_group_id) if asset_group_id else None,
        "asset_id": str(asset.id),
        "asset_name": asset.name,
        "batch_index": batch_index,
        "batch_size": batch_size,
    }
    return config


async def _find_existing_idempotent_scan(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    asset_id: uuid.UUID,
    scan_type: str,
    idempotency_key: str,
    session: AsyncSession,
) -> Scan | None:
    stmt = (
        select(Scan)
        .where(
            Scan.tenant_id == tenant_id,
            Scan.created_by == created_by,
            Scan.asset_id == asset_id,
            Scan.scan_type == scan_type,
            Scan.idempotency_key == idempotency_key,
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _get_scan_for_tenant(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> Scan | None:
    stmt = select(Scan).where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _get_scan_for_tenant_for_update(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> Scan | None:
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .with_for_update()
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _revert_unpublished_scan(
    *,
    scan: Scan,
    quota: TenantQuota | None,
    session: AsyncSession,
) -> None:
    """Compensate a committed scan create if stream publication fails."""
    try:
        if quota is not None:
            quota.active_scans = max(int(quota.active_scans) - 1, 0)
            quota.scans_today = max(int(quota.scans_today) - 1, 0)
        await session.delete(scan)
        await session.commit()
    except Exception:
        await session.rollback()
        logger.exception(
            "Failed to revert unpublished scan %s after publish failure",
            scan.id,
        )


async def _revert_resumed_scan_activation(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> None:
    """Compensate a scheduled-start activation if enqueue fails after commit."""
    try:
        quota_stmt = (
            select(TenantQuota)
            .where(TenantQuota.tenant_id == tenant_id)
            .with_for_update()
        )
        quota = (await session.execute(quota_stmt)).scalar_one_or_none()
        scan = await _get_scan_for_tenant_for_update(
            scan_id=scan_id,
            tenant_id=tenant_id,
            session=session,
        )
        if scan is None:
            return
        scan.status = "paused"
        if quota is not None and quota.active_scans > 0:
            quota.active_scans -= 1
            quota.scans_today = max(int(quota.scans_today) - 1, 0)
        await session.commit()
    except Exception:
        await session.rollback()
        logger.exception("Failed to revert resumed scheduled scan %s", scan_id)


async def _revert_running_resume(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> None:
    """Compensate a running resume if the orchestrator event publish fails."""
    try:
        scan = await _get_scan_for_tenant_for_update(
            scan_id=scan_id,
            tenant_id=tenant_id,
            session=session,
        )
        if scan is None:
            return
        scan.status = "paused"
        await session.commit()
    except Exception:
        await session.rollback()
        logger.exception("Failed to revert resumed running scan %s", scan_id)


# ── Public service functions ─────────────────────────────────────────


async def create_scan(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    asset_id: uuid.UUID,
    scan_type: str,
    priority: str,
    config: dict | None,
    idempotency_key: str | None,
    scheduled_at: datetime | None = None,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Create a scan with quota validation and post-commit event publishing.

    1. Validate asset exists and belongs to tenant
    2. Check tenant quota (concurrent + daily limits)
    3. Create Scan record
    4. Increment quota counters
    5. Commit the row so the orchestrator can see it
    6. Publish ``scan.created`` event to Redis Stream (XADD)

    All DAG planning and ScanJob creation is handled by the orchestrator
    after it consumes the ``scan.created`` event.
    """
    # 1 — validate asset
    asset = await session.get(Asset, asset_id)
    if asset is None or not asset.is_active:
        raise ValueError("Asset not found or inactive")

    if str(asset.tenant_id) != str(tenant_id):
        raise ValueError("Asset does not belong to this tenant")

    normalized_scheduled_at = (
        _normalize_utc_datetime(scheduled_at) if scheduled_at is not None else None
    )
    request_config = _with_request_metadata(
        config,
        idempotency_key=idempotency_key,
        scheduled_at=normalized_scheduled_at,
    )
    deferred_start = _is_deferred_scan_start(scheduled_at=normalized_scheduled_at)

    # 2 — serialize tenant scan admission and idempotency checks on the quota row
    quota_stmt = (
        select(TenantQuota)
        .where(TenantQuota.tenant_id == tenant_id)
        .with_for_update()
    )
    quota = (await session.execute(quota_stmt)).scalar_one_or_none()

    if idempotency_key:
        existing = await _find_existing_idempotent_scan(
            tenant_id=tenant_id,
            created_by=created_by,
            asset_id=asset_id,
            scan_type=scan_type,
            idempotency_key=idempotency_key,
            session=session,
        )
        if existing is not None:
            logger.info(
                "Returning existing scan for idempotency key: scan_id=%s key=%s",
                existing.id,
                idempotency_key,
            )
            return existing

    if quota:
        # Reconcile: count real active scans from the scans table
        real_active_stmt = select(func.count()).select_from(Scan).where(
            _active_scan_filter(tenant_id),
        )
        real_active = (await session.execute(real_active_stmt)).scalar() or 0

        if quota.active_scans != real_active:
            logger.warning(
                "Quota active_scans drift: recorded=%d actual=%d — auto-correcting",
                quota.active_scans,
                real_active,
            )
            quota.active_scans = real_active
            await session.flush()

        if quota.active_scans >= quota.max_concurrent_scans:
            raise ValueError(
                f"Concurrent scan limit reached ({quota.max_concurrent_scans})"
            )
        if quota.scans_today >= quota.max_daily_scans:
            raise ValueError(
                f"Daily scan limit reached ({quota.max_daily_scans})"
            )

    normalized_config = prepare_scan_config(
        scan_type=scan_type,
        asset_type=asset.asset_type,
        asset_target=asset.target,
        config=request_config,
    )
    normalized_config = enforce_safe_scan_config(
        scan_type=scan_type,
        asset_type=asset.asset_type,
        asset_target=asset.target,
        config=normalized_config,
    )

    # 3 — create scan record
    scan = Scan(
        tenant_id=tenant_id,
        asset_id=asset_id,
        created_by=created_by,
        scan_type=scan_type,
        priority=priority,
        idempotency_key=idempotency_key,
        config=normalized_config,
        status="paused" if deferred_start else "queued",
        progress=0,
        scheduled_at=normalized_scheduled_at,
    )
    session.add(scan)
    try:
        await session.flush()
    except IntegrityError:
        if not idempotency_key:
            raise
        await session.rollback()
        existing = await _find_existing_idempotent_scan(
            tenant_id=tenant_id,
            created_by=created_by,
            asset_id=asset_id,
            scan_type=scan_type,
            idempotency_key=idempotency_key,
            session=session,
        )
        if existing is not None:
            logger.info(
                "Returning existing scan after idempotency conflict: scan_id=%s key=%s",
                existing.id,
                idempotency_key,
            )
            return existing
        raise

    # 4 — increment quota counters only for immediately activated scans
    if quota and not deferred_start:
        quota.active_scans += 1
        quota.scans_today += 1
        await session.flush()

    # 5 — commit before publish so the orchestrator never races an
    # uncommitted scan row.
    await session.commit()

    # 6 — publish scan.created event to Redis Stream only when the scan
    # should start immediately. Deferred scans remain paused until resumed
    # or picked up by the scheduled launcher.
    if not deferred_start:
        try:
            await stream_publisher.publish_scan_created(
                scan_id=scan.id,
                tenant_id=tenant_id,
                asset_id=asset_id,
                project_id=asset.project_id,
                scan_type=scan_type,
                priority=priority,
                target=asset.target,
                asset_type=asset.asset_type,
                config=normalized_config,
                created_by=created_by,
            )
        except Exception as exc:
            await _revert_unpublished_scan(
                scan=scan,
                quota=quota,
                session=session,
            )
            raise RuntimeError("Failed to enqueue scan after commit") from exc

    logger.info(
        "Scan created: scan_id=%s tenant=%s type=%s priority=%s profile=%s scheduled_at=%s",
        scan.id,
        tenant_id,
        scan_type,
        priority,
        normalized_config.get("profile_id"),
        normalized_scheduled_at.isoformat() if normalized_scheduled_at else None,
    )

    return scan


async def list_scans(
    *,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    status_filter: str | None = None,
    asset_id: uuid.UUID | None = None,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Scan], int]:
    """List scans for the current tenant (paginated, filterable).

    RLS enforces tenant scope automatically.
    """
    conditions = []
    if status_filter:
        conditions.append(Scan.status == status_filter)
    if asset_id:
        conditions.append(Scan.asset_id == asset_id)
    conditions.append(Scan.tenant_id == tenant_id)

    # Count
    count_q = select(func.count()).select_from(Scan)
    for cond in conditions:
        count_q = count_q.where(cond)
    total = (await session.execute(count_q)).scalar_one()

    # Fetch
    offset = (page - 1) * page_size
    stmt = select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(page_size)
    for cond in conditions:
        stmt = stmt.where(cond)
    result = await session.execute(stmt)
    return list(result.scalars().all()), total


async def get_scan(
    *, scan_id: uuid.UUID, tenant_id: uuid.UUID, session: AsyncSession
) -> Scan | None:
    """Fetch a scan by ID."""
    return await _get_scan_for_tenant(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )


async def cancel_scan(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Cancel a running scan and emit durable cancellation events."""
    scan = await _get_scan_for_tenant(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if scan is None:
        raise ValueError("Scan not found")

    # Verify it's not already in a terminal state
    if scan.status in {s.value for s in SCAN_TERMINAL_STATES}:
        raise ValueError(f"Scan is already in terminal state: {scan.status}")

    consumed_active_slot = _scan_counts_as_active(scan)
    old_status = scan.status
    scan.status = "cancelled"
    scan.error_message = "Cancelled by user"
    scan.completed_at = datetime.now(timezone.utc)
    await session.flush()

    # Decrement active scans quota only if this scan was consuming a slot.
    quota_stmt = select(TenantQuota).where(TenantQuota.tenant_id == tenant_id)
    quota = (await session.execute(quota_stmt)).scalar_one_or_none()
    if quota and consumed_active_slot and quota.active_scans > 0:
        quota.active_scans -= 1
        await session.flush()

    # Publish a durable cancellation event so the orchestrator can set the
    # Redis cancellation flag that workers already honor.
    await stream_publisher.publish_scan_cancelled(
        scan_id=scan.id,
        tenant_id=tenant_id,
        old_status=old_status,
    )

    # Keep the status stream updated for any dashboard/API consumers.
    await stream_publisher.publish_scan_status_changed(
        scan_id=scan.id,
        tenant_id=tenant_id,
        old_status=old_status,
        new_status="cancelled",
    )

    return scan


async def pause_scan(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Pause an active running scan without releasing its active quota slot."""
    scan = await _get_scan_for_tenant_for_update(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if scan is None:
        raise ValueError("Scan not found")

    if scan.status in {s.value for s in SCAN_TERMINAL_STATES}:
        raise ValueError(f"Scan is already in terminal state: {scan.status}")
    if scan.status == "paused":
        raise ValueError("Scan is already paused")
    if scan.status != "running":
        raise ValueError("Only running scans can be paused")

    old_status = scan.status
    scan.status = "paused"
    await session.flush()
    await stream_publisher.publish_scan_status_changed(
        scan_id=scan.id,
        tenant_id=tenant_id,
        old_status=old_status,
        new_status="paused",
        progress=scan.progress,
    )
    return scan


async def resume_scan(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    resumed_by: uuid.UUID | None,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
    allow_before_schedule: bool = True,
) -> Scan:
    """Resume a paused scan or activate a deferred scheduled scan."""
    scan = await _get_scan_for_tenant_for_update(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if scan is None:
        raise ValueError("Scan not found")

    if scan.status in {s.value for s in SCAN_TERMINAL_STATES}:
        raise ValueError(f"Scan is already in terminal state: {scan.status}")
    if scan.status != "paused":
        raise ValueError("Only paused scans can be resumed")

    scheduled_resume = scan.started_at is None
    if scheduled_resume and scan.scheduled_at is not None:
        due_at = _normalize_utc_datetime(scan.scheduled_at)
        if due_at > datetime.now(timezone.utc) and not allow_before_schedule:
            raise ValueError("Scan is not due to start yet")

    asset = await session.get(Asset, scan.asset_id)
    if asset is None or not asset.is_active or str(asset.tenant_id) != str(tenant_id):
        raise ValueError("Asset not found or inactive")

    old_status = scan.status

    if scheduled_resume:
        quota_stmt = (
            select(TenantQuota)
            .where(TenantQuota.tenant_id == tenant_id)
            .with_for_update()
        )
        quota = (await session.execute(quota_stmt)).scalar_one_or_none()

        if quota:
            real_active_stmt = select(func.count()).select_from(Scan).where(
                _active_scan_filter(tenant_id)
            )
            real_active = (await session.execute(real_active_stmt)).scalar() or 0
            if quota.active_scans != real_active:
                quota.active_scans = real_active
                await session.flush()
            if quota.active_scans >= quota.max_concurrent_scans:
                raise ValueError(
                    f"Concurrent scan limit reached ({quota.max_concurrent_scans})"
                )
            if quota.scans_today >= quota.max_daily_scans:
                raise ValueError(
                    f"Daily scan limit reached ({quota.max_daily_scans})"
                )
            quota.active_scans += 1
            quota.scans_today += 1
            await session.flush()

        scan.status = "queued"
        await session.flush()
        await session.commit()

        try:
            await stream_publisher.publish_scan_created(
                scan_id=scan.id,
                tenant_id=tenant_id,
                asset_id=scan.asset_id,
                project_id=asset.project_id,
                scan_type=scan.scan_type,
                priority=scan.priority,
                target=asset.target,
                asset_type=asset.asset_type,
                config=scan.config,
                created_by=scan.created_by,
            )
        except Exception as exc:
            await _revert_resumed_scan_activation(
                scan_id=scan.id,
                tenant_id=tenant_id,
                session=session,
            )
            raise RuntimeError("Failed to enqueue resumed scan") from exc

        await stream_publisher.publish_scan_status_changed(
            scan_id=scan.id,
            tenant_id=tenant_id,
            old_status=old_status,
            new_status="queued",
            progress=scan.progress,
        )
        return scan

    scan.status = "running"
    await session.flush()
    await session.commit()

    try:
        await stream_publisher.publish_scan_resumed(
            scan_id=scan.id,
            tenant_id=tenant_id,
            old_status=old_status,
            new_status="running",
            resume_mode="continue",
            resumed_by=resumed_by,
        )
    except Exception as exc:
        await _revert_running_resume(
            scan_id=scan.id,
            tenant_id=tenant_id,
            session=session,
        )
        raise RuntimeError("Failed to enqueue scan resume") from exc

    await stream_publisher.publish_scan_status_changed(
        scan_id=scan.id,
        tenant_id=tenant_id,
        old_status=old_status,
        new_status="running",
        progress=scan.progress,
    )
    return scan


async def activate_due_scheduled_scans(
    *,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
    limit: int = 10,
) -> list[uuid.UUID]:
    """Activate scans whose scheduled_at is due."""
    result = await session.execute(
        text("""
            SELECT id, tenant_id
            FROM scans
            WHERE status = 'paused'
              AND started_at IS NULL
              AND scheduled_at IS NOT NULL
              AND scheduled_at <= NOW()
            ORDER BY scheduled_at ASC
            LIMIT :limit
        """),
        {"limit": limit},
    )
    due_rows = result.mappings().all()
    activated: list[uuid.UUID] = []
    for row in due_rows:
        try:
            resumed = await resume_scan(
                scan_id=uuid.UUID(str(row["id"])),
                tenant_id=uuid.UUID(str(row["tenant_id"])),
                resumed_by=None,
                stream_publisher=stream_publisher,
                session=session,
                allow_before_schedule=False,
            )
            activated.append(uuid.UUID(str(resumed.id)))
        except ValueError:
            await session.rollback()
        except Exception:
            await session.rollback()
            logger.exception("Failed to activate scheduled scan %s", row["id"])
    return activated


async def _resolve_multi_asset_batch_assets(
    *,
    tenant_id: uuid.UUID,
    asset_ids: list[uuid.UUID] | None,
    asset_group_id: uuid.UUID | None,
    session: AsyncSession,
) -> tuple[list[Asset], uuid.UUID | None]:
    if asset_group_id is not None:
        from app.services import asset_group_service

        assets = await asset_group_service.list_asset_group_assets(
            asset_group_id=asset_group_id,
            tenant_id=tenant_id,
            session=session,
        )
        if not assets:
            raise ValueError("Asset group has no active assets")
        return assets, asset_group_id

    unique_asset_ids = _dedupe_asset_ids(list(asset_ids or []))
    if not unique_asset_ids:
        raise ValueError("At least one asset_id is required")

    stmt = select(Asset).where(
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,  # noqa: E712
        Asset.id.in_(unique_asset_ids),
    )
    assets = list((await session.execute(stmt)).unique().scalars().all())
    if len(assets) != len(unique_asset_ids):
        raise ValueError("One or more assets were not found or are inactive")

    asset_map = {asset.id: asset for asset in assets}
    ordered_assets = [asset_map[asset_id] for asset_id in unique_asset_ids]
    return ordered_assets, None


async def _preflight_multi_asset_batch_capacity(
    *,
    tenant_id: uuid.UUID,
    requested_count: int,
    scheduled_at: datetime | None,
    session: AsyncSession,
) -> None:
    if requested_count <= 0 or _is_deferred_scan_start(scheduled_at=scheduled_at):
        return

    quota_stmt = (
        select(TenantQuota)
        .where(TenantQuota.tenant_id == tenant_id)
        .with_for_update()
    )
    quota = (await session.execute(quota_stmt)).scalar_one_or_none()
    if quota is None:
        return

    real_active_stmt = select(func.count()).select_from(Scan).where(
        _active_scan_filter(tenant_id)
    )
    real_active = (await session.execute(real_active_stmt)).scalar() or 0
    if quota.active_scans != real_active:
        quota.active_scans = real_active
        await session.flush()

    if real_active + requested_count > quota.max_concurrent_scans:
        raise ValueError(
            "Concurrent scan limit would be exceeded for this batch "
            f"({quota.max_concurrent_scans} max)"
        )
    if quota.scans_today + requested_count > quota.max_daily_scans:
        raise ValueError(
            "Daily scan limit would be exceeded for this batch "
            f"({quota.max_daily_scans} max)"
        )


async def create_multi_asset_scan_batch(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    scan_type: str,
    priority: str,
    config: dict | None,
    asset_ids: list[uuid.UUID] | None,
    asset_group_id: uuid.UUID | None,
    scheduled_at: datetime | None,
    idempotency_key: str | None,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> dict[str, Any]:
    """Create one normal scan per target asset for a multi-target request."""
    assets, resolved_group_id = await _resolve_multi_asset_batch_assets(
        tenant_id=tenant_id,
        asset_ids=asset_ids,
        asset_group_id=asset_group_id,
        session=session,
    )
    await _preflight_multi_asset_batch_capacity(
        tenant_id=tenant_id,
        requested_count=len(assets),
        scheduled_at=scheduled_at,
        session=session,
    )

    batch_request_id = idempotency_key or str(uuid.uuid4())
    scans: list[Scan] = []
    failures: list[dict[str, Any]] = []

    for index, asset in enumerate(assets, start=1):
        per_asset_idempotency_key = (
            f"{idempotency_key}:{asset.id}" if idempotency_key else None
        )
        batch_config = _build_batch_scan_config(
            base_config=config,
            batch_request_id=batch_request_id,
            asset_group_id=resolved_group_id,
            asset=asset,
            batch_index=index,
            batch_size=len(assets),
        )
        try:
            scan = await create_scan(
                tenant_id=tenant_id,
                created_by=created_by,
                asset_id=asset.id,
                scan_type=scan_type,
                priority=priority,
                config=batch_config,
                idempotency_key=per_asset_idempotency_key,
                scheduled_at=scheduled_at,
                stream_publisher=stream_publisher,
                session=session,
            )
        except ValueError as exc:
            failures.append(
                {
                    "asset_id": asset.id,
                    "asset_name": asset.name,
                    "reason": str(exc),
                }
            )
            continue
        scans.append(scan)

    return {
        "batch_request_id": batch_request_id,
        "asset_group_id": resolved_group_id,
        "requested_asset_count": len(assets),
        "created_count": len(scans),
        "failed_count": len(failures),
        "scans": scans,
        "failures": failures,
    }


async def create_retest_scan(
    *,
    source_scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    priority: str | None,
    config_overrides: dict | None,
    idempotency_key: str | None,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Create a retest scan using a completed scan as the baseline."""
    stmt = (
        select(Scan)
        .where(Scan.id == source_scan_id, Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.findings), selectinload(Scan.asset))
    )
    source_scan = (await session.execute(stmt)).scalar_one_or_none()
    if source_scan is None:
        raise ValueError("Source scan not found")

    if source_scan.status != "completed":
        raise ValueError("Only completed scans can be used as a retest baseline")

    merged_config = _build_retest_config(
        source_scan=source_scan,
        config_overrides=config_overrides or {},
    )

    recommended_priority = priority or _recommended_retest_priority(source_scan)
    return await create_scan(
        tenant_id=tenant_id,
        created_by=created_by,
        asset_id=source_scan.asset_id,
        scan_type=source_scan.scan_type,
        priority=recommended_priority,
        config=merged_config,
        idempotency_key=idempotency_key,
        scheduled_at=None,
        stream_publisher=stream_publisher,
        session=session,
    )


async def list_scan_jobs(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[Any] | None:
    """List jobs for a tenant-scoped scan."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return None
    execution_contract = _scan_execution_contract(scan)
    result = await session.execute(
        text(
            """
            SELECT j.id,
                   j.scan_id,
                   n.id AS node_id,
                   j.phase,
                   j.tool,
                   j.status,
                   j.priority,
                   j.worker_id,
                   j.output_ref,
                   j.scheduled_at,
                   j.claimed_at,
                   j.started_at,
                   j.completed_at,
                   j.error_message,
                   j.retry_count,
                   j.created_at,
                   n.output_summary
            FROM scan_jobs j
            LEFT JOIN scan_nodes n ON n.job_id = j.id
            WHERE j.scan_id = :scan_id AND j.tenant_id = :tenant_id
            ORDER BY j.phase ASC, j.created_at ASC
            """
        ),
        {"scan_id": str(scan_id), "tenant_id": str(tenant_id)},
    )
    jobs: list[dict[str, Any]] = []
    for row in result.mappings().all():
        output_summary = row.get("output_summary") or {}
        if not isinstance(output_summary, dict):
            output_summary = {}
        execution_mode, provenance, execution_reason = _normalize_execution_truth(
            tool_name=str(row["tool"] or ""),
            execution_mode=output_summary.get("execution_mode"),
            execution_provenance=output_summary.get("execution_provenance"),
            execution_reason=output_summary.get("execution_reason"),
        )
        execution_class = _normalize_execution_class(
            tool_name=str(row["tool"] or ""),
            execution_class=output_summary.get("execution_class"),
        )
        policy_state = classify_tool_policy_state(
            tool_name=str(row["tool"] or ""),
            execution_contract=execution_contract,
            scan_config=_scan_config_dict(scan),
            execution_provenance=provenance,
            execution_reason=execution_reason,
        )
        status = str(row["status"])
        jobs.append(
            {
                "id": row["id"],
                "scan_id": row["scan_id"],
                "node_id": row["node_id"],
                "phase": int(row["phase"]),
                "tool": row["tool"],
                "status": status,
                "priority": row["priority"],
                "worker_id": row["worker_id"],
                "output_ref": row["output_ref"],
                "scheduled_at": row["scheduled_at"],
                "claimed_at": row["claimed_at"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "error_message": row["error_message"],
                "retry_count": int(row["retry_count"] or 0),
                "queue_delay_seconds": _seconds_between_datetimes(
                    row["scheduled_at"],
                    row["claimed_at"],
                ),
                "claim_to_start_seconds": _seconds_between_datetimes(
                    row["claimed_at"],
                    row["started_at"],
                ),
                "execution_duration_seconds": _seconds_between_datetimes(
                    row["started_at"],
                    row["completed_at"],
                ),
                "end_to_end_seconds": _seconds_between_datetimes(
                    row["scheduled_at"],
                    row["completed_at"],
                ),
                "execution_mode": execution_mode,
                "execution_provenance": provenance,
                "execution_reason": execution_reason,
                "execution_class": execution_class,
                "policy_state": policy_state,
                "created_at": row["created_at"],
            }
        )
    return jobs


async def approve_scan_tools(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    tools: list[str],
    session: AsyncSession,
    stream_publisher: StreamPublisher,
) -> dict[str, Any] | None:
    scan = await _get_scan_for_tenant_for_update(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if scan is None:
        return None

    normalized_tools = _dedupe_strings([str(item or "").strip().lower() for item in tools])
    if not normalized_tools:
        raise ValueError("At least one tool must be provided for approval.")

    config = deepcopy(_scan_config_dict(scan))
    execution_contract = _scan_execution_contract(scan)
    execution = config.get("execution") if isinstance(config.get("execution"), dict) else {}
    approval_required_tools = _dedupe_strings(
        [
            str(item).strip().lower()
            for item in list(
                execution_contract.get("approval_required_tools")
                or execution.get("approval_required_tools")
                or []
            )
        ]
    )
    if not approval_required_tools:
        raise ValueError("This scan profile does not expose approval-gated tools.")

    approved_live_tools = _dedupe_strings(
        [str(item).strip().lower() for item in list(config.get("approved_live_tools") or [])]
    )
    allowed_live_tools = _dedupe_strings(
        [str(item).strip().lower() for item in list(execution.get("allowed_live_tools") or [])]
    )

    tool_logs_payload = await get_scan_tool_logs(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    ) or {"logs": []}
    tool_logs = list(tool_logs_payload.get("logs") or [])
    latest_logs_by_tool: dict[str, dict[str, Any]] = {}
    for entry in reversed(tool_logs):
        tool_name = str(entry.get("tool") or "").strip().lower()
        if tool_name and tool_name not in latest_logs_by_tool:
            latest_logs_by_tool[tool_name] = entry

    target_result = await session.execute(
        text(
            """
            SELECT target
            FROM assets
            WHERE id = :asset_id AND tenant_id = :tenant_id
            """
        ),
        {"asset_id": str(scan.asset_id), "tenant_id": str(tenant_id)},
    )
    asset_target = str(target_result.scalar_one_or_none() or "").strip()

    reruns: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for tool_name in normalized_tools:
        if tool_name in approved_live_tools:
            results.append(
                {
                    "tool": tool_name,
                    "disposition": "already_approved",
                    "message": "This tool is already approved for this scan.",
                }
            )
            continue
        if tool_name not in approval_required_tools:
            results.append(
                {
                    "tool": tool_name,
                    "disposition": "skipped",
                    "message": "This tool is not approval-gated in the current scan profile.",
                }
            )
            continue

        approved_live_tools.append(tool_name)
        if tool_name not in allowed_live_tools:
            allowed_live_tools.append(tool_name)

        source_log = latest_logs_by_tool.get(tool_name)
        if source_log is None:
            results.append(
                {
                    "tool": tool_name,
                    "disposition": "approved",
                    "message": "Tool approved for this scan. It will run if future planner/runtime steps request it.",
                }
            )
            continue

        source_node_id = str(source_log.get("node_id") or "").strip()
        if not source_node_id:
            results.append(
                {
                    "tool": tool_name,
                    "disposition": "approved",
                    "message": "Tool approved, but there is no blocked node to requeue yet.",
                }
            )
            continue

        source_node_result = await session.execute(
            text(
                """
                SELECT n.id, n.dag_id, n.phase_id, n.tool, n.worker_family, n.input_refs, n.config
                FROM scan_nodes n
                JOIN scan_dags d ON d.id = n.dag_id
                WHERE n.id = :node_id
                  AND d.scan_id = :scan_id
                  AND n.tenant_id = :tenant_id
                """
            ),
            {
                "node_id": source_node_id,
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
            },
        )
        source_node = source_node_result.mappings().first()
        if source_node is None:
            results.append(
                {
                    "tool": tool_name,
                    "disposition": "approved",
                    "message": "Tool approved, but the blocked node could not be found for requeue.",
                }
            )
            continue

        rerun_config = deepcopy(source_node.get("config") or config)
        if not isinstance(rerun_config, dict):
            rerun_config = {}
        rerun_execution = (
            rerun_config.get("execution") if isinstance(rerun_config.get("execution"), dict) else {}
        )
        rerun_execution["allowed_live_tools"] = _dedupe_strings(
            [*allowed_live_tools, *[str(item).strip().lower() for item in list(rerun_execution.get("allowed_live_tools") or [])]]
        )
        rerun_execution["approval_required_tools"] = _dedupe_strings(
            [*approval_required_tools, *[str(item).strip().lower() for item in list(rerun_execution.get("approval_required_tools") or [])]]
        )
        rerun_config["execution"] = rerun_execution
        rerun_config["approved_live_tools"] = list(approved_live_tools)

        new_node_id = uuid.uuid4()
        new_job_id = uuid.uuid4()
        phase_number = int(source_log.get("phase_number") or 0)
        timeout_seconds = int(
            rerun_config.get("timeout_seconds")
            or ((source_node.get("config") or {}).get("timeout_seconds") if isinstance(source_node.get("config"), dict) else 0)
            or 600
        )

        await session.execute(
            text(
                """
                INSERT INTO scan_jobs (
                    id, scan_id, tenant_id, phase, tool, status,
                    priority, retry_count, max_retries, timeout_seconds
                )
                VALUES (
                    :id, :scan_id, :tenant_id, :phase, :tool, 'queued',
                    :priority, 0, :max_retries, :timeout_seconds
                )
                """
            ),
            {
                "id": str(new_job_id),
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "phase": phase_number,
                "tool": tool_name,
                "priority": str(scan.priority),
                "max_retries": int(rerun_config.get("max_retries", 2) or 2),
                "timeout_seconds": timeout_seconds,
            },
        )
        await session.execute(
            text(
                """
                INSERT INTO scan_nodes (
                    id, dag_id, phase_id, job_id, tenant_id, tool, worker_family,
                    status, is_dynamic, input_refs, config
                )
                VALUES (
                    :id, :dag_id, :phase_id, :job_id, :tenant_id, :tool, :worker_family,
                    'ready', true, CAST(:input_refs AS jsonb), CAST(:config AS jsonb)
                )
                """
            ),
            {
                "id": str(new_node_id),
                "dag_id": str(source_node["dag_id"]),
                "phase_id": str(source_node["phase_id"]),
                "job_id": str(new_job_id),
                "tenant_id": str(tenant_id),
                "tool": tool_name,
                "worker_family": str(source_node["worker_family"]),
                "input_refs": json.dumps(source_node.get("input_refs") or {}),
                "config": json.dumps(rerun_config, default=str),
            },
        )

        reruns.append(
            {
                "tool": tool_name,
                "node_id": new_node_id,
                "job_id": new_job_id,
                "dag_id": uuid.UUID(str(source_node["dag_id"])),
                "phase_number": phase_number,
                "worker_family": str(source_node["worker_family"]),
                "target": asset_target,
                "config": rerun_config,
                "input_refs": source_node.get("input_refs") or {},
            }
        )
        results.append(
            {
                "tool": tool_name,
                "disposition": "approved",
                "message": "Tool approved. Requeueing the blocked tool job now.",
                "node_id": new_node_id,
                "job_id": new_job_id,
            }
        )

    execution["allowed_live_tools"] = list(allowed_live_tools)
    config["execution"] = execution
    config["approved_live_tools"] = list(approved_live_tools)
    scan.config = config
    await session.commit()

    published_at = datetime.now(timezone.utc)
    for rerun in reruns:
        try:
            payload = {
                "job_id": str(rerun["job_id"]),
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "node_id": str(rerun["node_id"]),
                "dag_id": str(rerun["dag_id"]),
                "tool": rerun["tool"],
                "worker_family": rerun["worker_family"],
                "target": rerun["target"],
                "config": json.dumps(rerun["config"], default=str),
                "input_refs": json.dumps(rerun["input_refs"], default=str),
                "dispatched_at": published_at.isoformat(),
                "scheduled_at": published_at.isoformat(),
            }
            await stream_publisher.xadd(
                f"pentra:stream:worker:{rerun['worker_family']}",
                {"data": json.dumps(payload, default=str)},
            )
            await session.execute(
                text(
                    """
                    UPDATE scan_jobs
                    SET status = 'scheduled',
                        scheduled_at = COALESCE(scheduled_at, :scheduled_at)
                    WHERE id = :job_id
                    """
                ),
                {"job_id": str(rerun["job_id"]), "scheduled_at": published_at},
            )
            await session.execute(
                text(
                    """
                    UPDATE scan_nodes
                    SET status = 'scheduled'
                    WHERE id = :node_id
                    """
                ),
                {"node_id": str(rerun["node_id"])},
            )
            for result in results:
                if str(result.get("job_id") or "") == str(rerun["job_id"]):
                    result["disposition"] = "requeued"
                    result["message"] = "Tool approved and a fresh job was queued for execution."
                    break
        except Exception as exc:
            logger.warning(
                "Failed to publish approved tool rerun for scan %s tool %s: %s",
                scan_id,
                rerun["tool"],
                exc,
            )
            await session.execute(
                text(
                    """
                    UPDATE scan_jobs
                    SET error_message = :message
                    WHERE id = :job_id
                    """
                ),
                {
                    "job_id": str(rerun["job_id"]),
                    "message": f"Dispatch failed after approval: {exc}"[:500],
                },
            )
            for result in results:
                if str(result.get("job_id") or "") == str(rerun["job_id"]):
                    result["disposition"] = "error"
                    result["message"] = "Tool was approved, but dispatch failed. Retry approval once the worker path is healthy."
                    break

    await session.commit()
    return {
        "scan_id": scan_id,
        "approved_tools": list(approved_live_tools),
        "generated_at": datetime.now(timezone.utc),
        "results": results,
    }


async def list_findings(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Finding], int]:
    """List findings for a scan (paginated)."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return [], 0

    base_filter = Finding.scan_id == scan.id

    stmt = (
        select(Finding)
        .where(base_filter)
        .order_by(Finding.created_at.desc())
    )
    result = await session.execute(stmt)
    findings = _build_user_facing_findings(list(result.scalars().all()))
    total = len(findings)
    offset = (page - 1) * page_size
    return findings[offset : offset + page_size], total


async def list_artifact_summaries(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Return artifact summary rows for a scan."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return []

    stmt = (
        select(ScanArtifact)
        .where(ScanArtifact.scan_id == scan.id, ScanArtifact.tenant_id == tenant_id)
        .order_by(ScanArtifact.created_at.asc())
    )
    result = await session.execute(stmt)
    artifacts = list(result.scalars().all())

    summaries: list[dict] = []
    for artifact in artifacts:
        metadata = artifact.metadata_ or {}
        summary = metadata.get("summary", {}) if isinstance(metadata, dict) else {}
        severity_counts = {}
        if isinstance(summary, dict):
            severity_counts = summary.get("severity_counts", {}) or metadata.get("severity_counts", {})

        summaries.append(
            {
                "id": artifact.id,
                "scan_id": artifact.scan_id,
                "node_id": artifact.node_id,
                "artifact_type": artifact.artifact_type,
                "tool": metadata.get("tool") if isinstance(metadata, dict) else None,
                "storage_ref": artifact.storage_ref,
                "content_type": artifact.content_type,
                "size_bytes": artifact.size_bytes,
                "checksum": artifact.checksum,
                "item_count": int(metadata.get("item_count", 0)) if isinstance(metadata, dict) else 0,
                "finding_count": int(metadata.get("finding_count", 0)) if isinstance(metadata, dict) else 0,
                "evidence_count": int(metadata.get("evidence_count", 0)) if isinstance(metadata, dict) else 0,
                "severity_counts": severity_counts,
                "summary": summary if isinstance(summary, dict) else {},
                "execution_mode": _artifact_execution_mode(artifact.artifact_type, metadata),
                "execution_provenance": _artifact_execution_provenance(artifact.artifact_type, metadata),
                "execution_reason": _artifact_execution_reason(metadata),
                "created_at": artifact.created_at,
            }
        )

    return summaries


async def get_attack_graph(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict | None:
    """Return the stored attack graph payload for a scan."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return None

    stmt = (
        select(ScanArtifact)
        .where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.tenant_id == tenant_id,
            ScanArtifact.artifact_type == "attack_graph",
        )
        .order_by(ScanArtifact.created_at.desc())
        .limit(1)
    )
    artifact = (await session.execute(stmt)).scalar_one_or_none()
    if artifact is None:
        return _empty_attack_graph_payload(scan)

    payload = read_json_artifact(artifact.storage_ref)
    if isinstance(payload, dict):
        nodes = payload.get("nodes", {})
        payload["nodes"] = list(nodes.values()) if isinstance(nodes, dict) else nodes
        return payload

    metadata = artifact.metadata_ or {}
    return {
        "scan_id": scan_id,
        "tenant_id": artifact.tenant_id,
        "built_at": metadata.get("built_at"),
        "node_count": metadata.get("node_count", 0),
        "edge_count": metadata.get("edge_count", 0),
        "path_summary": metadata.get("path_summary", {}),
        "scoring_summary": metadata.get("scoring_summary", {}),
        "nodes": [],
        "edges": [],
    }


async def get_scan_timeline(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Build a timeline from scan, job, and artifact state."""
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.jobs), selectinload(Scan.artifacts))
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return []

    events: list[dict] = [
        {
            "id": f"scan:{scan.id}:created",
            "timestamp": scan.created_at,
            "event_type": "system",
            "title": "Scan created",
            "details": f"Scan type: {scan.scan_type}",
            "status": scan.status,
            "phase": None,
            "tool": None,
            "job_id": None,
            "node_id": None,
            "artifact_ref": None,
        }
    ]

    if scan.started_at:
        events.append(
            {
                "id": f"scan:{scan.id}:started",
                "timestamp": scan.started_at,
                "event_type": "system",
                "title": "Scan started",
                "details": "Pipeline entered execution.",
                "status": scan.status,
                "phase": None,
                "tool": None,
                "job_id": None,
                "node_id": None,
                "artifact_ref": None,
            }
        )

    try:
        jobs = await list_scan_jobs(scan_id=scan_id, tenant_id=tenant_id, session=session) or []
    except Exception:
        logger.debug("Falling back to empty job list for field-validation assessment %s", scan_id, exc_info=True)
        jobs = []
    for job in jobs:
        job_reason = _artifact_execution_reason(job)
        detail_parts = [f"Phase {job['phase']} · retries {job['retry_count']}"]
        if job_reason:
            detail_parts.append(str(job_reason).replace("_", " "))
        events.append(
            {
                "id": f"job:{job['id']}",
                "timestamp": job["completed_at"] or job["started_at"] or job["created_at"],
                "event_type": _timeline_event_type(int(job["phase"])),
                "title": f"{job['tool']} {job['status']}",
                "details": " · ".join(detail_parts),
                "status": job["status"],
                "phase": int(job["phase"]),
                "tool": job["tool"],
                "job_id": job["id"],
                "node_id": None,
                "artifact_ref": job.get("output_ref"),
            }
        )

    for artifact in sorted(scan.artifacts, key=lambda value: value.created_at):
        metadata = artifact.metadata_ or {}
        events.append(
            {
                "id": f"artifact:{artifact.id}",
                "timestamp": artifact.created_at,
                "event_type": "artifact",
                "title": f"{artifact.artifact_type} stored",
                "details": _artifact_timeline_details(artifact.artifact_type, metadata),
                "status": None,
                "phase": None,
                "tool": metadata.get("tool") if isinstance(metadata, dict) else None,
                "job_id": None,
                "node_id": artifact.node_id,
                "artifact_ref": artifact.storage_ref,
            }
        )

    if scan.completed_at:
        events.append(
            {
                "id": f"scan:{scan.id}:completed",
                "timestamp": scan.completed_at,
                "event_type": "system",
                "title": f"Scan {scan.status}",
                "details": f"Progress reached {scan.progress}%.",
                "status": scan.status,
                "phase": None,
                "tool": None,
                "job_id": None,
                "node_id": None,
                "artifact_ref": None,
            }
        )

    return sorted(events, key=lambda event: event["timestamp"])


async def get_scan_planner_context(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict | None:
    """Return persisted planner/advisory runtime context for frontend inspection."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return None

    planner_effect_artifact = await _latest_artifact_by_type(
        scan_id=scan_id,
        tenant_id=tenant_id,
        artifact_type="planner_effect",
        session=session,
    )
    planner_effect = _read_artifact_payload(planner_effect_artifact)
    capability_advisory_artifacts = await _latest_capability_advisories(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    capability_advisories = []
    for artifact in capability_advisory_artifacts:
        payload = _read_artifact_payload(artifact)
        if isinstance(payload, dict):
            capability_advisories.append(
                payload.get("response") if isinstance(payload.get("response"), dict) else payload
            )

    target_model_summary = {}
    if isinstance(planner_effect, dict):
        target_model_summary = dict(planner_effect.get("target_model_summary") or {})
    if not target_model_summary and capability_advisory_artifacts:
        advisory_payload = _read_artifact_payload(capability_advisory_artifacts[0])
        if isinstance(advisory_payload, dict):
            target_model_summary = dict(advisory_payload.get("target_model_summary") or {})

    advisory_artifact_refs = list(target_model_summary.get("advisory_artifact_refs") or [])
    if not advisory_artifact_refs:
        advisory_artifact_refs = [
            {
                "pack_key": str((artifact.metadata_ or {}).get("pack_key") or ""),
                "storage_ref": str(artifact.storage_ref or ""),
            }
            for artifact in capability_advisory_artifacts
        ]

    strategic_plan = (
        planner_effect.get("strategic_plan")
        if isinstance(planner_effect, dict)
        else None
    )
    tactical_plan = (
        planner_effect.get("tactical_plan")
        if isinstance(planner_effect, dict)
        else None
    )
    planner_decision = None
    if isinstance(strategic_plan, dict):
        planner_decision = str(strategic_plan.get("decision") or "").strip() or None
    if planner_decision is None and planner_effect_artifact is not None:
        metadata = planner_effect_artifact.metadata_ or {}
        planner_decision = str(metadata.get("planner_decision") or "").strip() or None

    return {
        "scan_id": scan_id,
        "target_profile_hypotheses": list(target_model_summary.get("target_profile_hypotheses") or []),
        "capability_pressures": list(target_model_summary.get("capability_pressures") or []),
        "advisory_artifact_refs": advisory_artifact_refs,
        "planner_decision": planner_decision,
        "strategic_plan": strategic_plan,
        "tactical_plan": tactical_plan,
        "planner_effect": planner_effect if isinstance(planner_effect, dict) else None,
        "capability_advisories": capability_advisories,
    }


def _agent_fallback_status(payload: dict[str, Any], *, provider: str | None = None) -> str:
    resolved_provider = str(provider or payload.get("provider") or "").strip().lower()
    if resolved_provider == "heuristic":
        return "deterministic"
    if str(payload.get("error") or "").strip():
        return "error"
    if bool(payload.get("fallback_used")) or str(payload.get("status") or "").strip() == "fallback":
        return "fallback"
    if resolved_provider:
        return "healthy"
    return "unknown"


def _agent_transcript_summary(*, artifact_type: str, payload: dict[str, Any]) -> str:
    if artifact_type == "capability_advisory":
        response = payload.get("response") if isinstance(payload.get("response"), dict) else payload
        focus_items = list(response.get("focus_items") or []) if isinstance(response, dict) else []
        focus_text = ""
        if focus_items:
            first = focus_items[0]
            if isinstance(first, dict):
                focus_text = str(first.get("route_group") or first.get("reason") or "").strip()
        pack_key = str(response.get("pack_key") or payload.get("pack_key") or "").strip()
        if focus_text:
            return f"{pack_key or 'capability_advisory'} focus: {focus_text}"
        if pack_key:
            return f"{pack_key} advisory updated"
        return "Capability advisory updated"
    if artifact_type == "planner_effect":
        strategic_plan = payload.get("strategic_plan")
        if isinstance(strategic_plan, dict):
            objective = str(strategic_plan.get("objective") or "").strip()
            decision = str(strategic_plan.get("decision") or "").strip()
            if objective:
                return objective
            if decision:
                return decision
        return "Planner effect persisted"
    if artifact_type == "ai_strategy":
        recommendation = payload.get("recommendation")
        if isinstance(recommendation, dict):
            decision = str(recommendation.get("phase_decision") or "").strip()
            if decision:
                return f"AI strategy decision: {decision}"
        return "AI strategy updated"
    if artifact_type == "ai_reasoning":
        report = payload.get("report")
        if isinstance(report, dict):
            draft_summary = str(report.get("draft_summary") or "").strip()
            if draft_summary:
                return draft_summary
        return "AI reasoning updated"
    return artifact_type.replace("_", " ")


def _timeline_transcript_summary(event: dict[str, Any]) -> str:
    title = str(event.get("title") or "").strip()
    details = str(event.get("details") or "").strip()
    return f"{title}: {details}" if title and details else title or details or "Timeline event"


def _canonical_command_from_execution_log(execution_log: dict[str, Any] | None) -> dict[str, Any]:
    payload = execution_log if isinstance(execution_log, dict) else {}
    canonical = payload.get("canonical_command")
    if isinstance(canonical, dict):
        return {
            "argv": list(canonical.get("argv") or payload.get("command") or []),
            "display_command": str(
                canonical.get("display_command") or payload.get("display_command") or ""
            ),
            "tool_binary": canonical.get("tool_binary"),
            "container_image": canonical.get("container_image"),
            "entrypoint": list(canonical.get("entrypoint") or []),
            "working_dir": canonical.get("working_dir"),
            "channel": canonical.get("channel") or "unknown",
            "execution_class": canonical.get("execution_class") or payload.get("execution_class"),
            "policy_state": canonical.get("policy_state") or payload.get("policy_state"),
        }

    command = list(payload.get("command") or [])
    return {
        "argv": command,
        "display_command": str(payload.get("display_command") or " ".join(command)),
        "tool_binary": command[0] if command else None,
        "container_image": None,
        "entrypoint": [],
        "working_dir": None,
        "channel": "unknown",
        "execution_class": payload.get("execution_class"),
        "policy_state": payload.get("policy_state"),
    }


async def get_scan_agent_transcript(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict[str, Any] | None:
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return None

    artifact_stmt = (
        select(ScanArtifact)
        .where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.tenant_id == tenant_id,
            ScanArtifact.artifact_type.in_(
                ["capability_advisory", "planner_effect", "ai_strategy", "ai_reasoning"]
            ),
        )
        .order_by(ScanArtifact.created_at.asc(), ScanArtifact.id.asc())
    )
    artifacts = list((await session.execute(artifact_stmt)).scalars().all())
    timeline = await get_scan_timeline(scan_id=scan_id, tenant_id=tenant_id, session=session)

    entries: list[dict[str, Any]] = []
    for artifact in artifacts:
        payload = _read_artifact_payload(artifact)
        metadata = artifact.metadata_ or {}
        transcript_payload = (
            payload.get("response")
            if artifact.artifact_type == "capability_advisory"
            and isinstance(payload, dict)
            and isinstance(payload.get("response"), dict)
            else payload
        )
        if not isinstance(transcript_payload, (dict, list)):
            transcript_payload = {}
        pack_key = None
        provider = None
        model = None
        transport = None
        if isinstance(transcript_payload, dict):
            pack_key = str(transcript_payload.get("pack_key") or metadata.get("pack_key") or "").strip() or None
            provider = str(transcript_payload.get("provider") or metadata.get("provider") or "").strip() or None
            model = str(transcript_payload.get("model") or metadata.get("model") or "").strip() or None
            transport = str(
                transcript_payload.get("transport") or metadata.get("transport") or ""
            ).strip() or None
        entries.append(
            {
                "id": str(artifact.id),
                "timestamp": artifact.created_at,
                "kind": artifact.artifact_type,
                "pack_key": pack_key,
                "provider": provider,
                "model": model,
                "transport": transport,
                "fallback_status": _agent_fallback_status(
                    transcript_payload if isinstance(transcript_payload, dict) else {},
                    provider=provider,
                ),
                "summary": _agent_transcript_summary(
                    artifact_type=artifact.artifact_type,
                    payload=payload if isinstance(payload, dict) else {},
                ),
                "raw_payload": transcript_payload,
                "artifact_ref": artifact.storage_ref,
            }
        )

    for event in timeline:
        entries.append(
            {
                "id": f"timeline:{event['id']}",
                "timestamp": event["timestamp"],
                "kind": "timeline_event",
                "pack_key": None,
                "provider": None,
                "model": None,
                "fallback_status": "unknown",
                "summary": _timeline_transcript_summary(event),
                "raw_payload": event,
                "artifact_ref": event.get("artifact_ref"),
            }
        )

    entries.sort(key=lambda item: (item["timestamp"], item["id"]))
    return {
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc),
        "entries": entries,
    }


async def get_scan_tool_logs(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict[str, Any] | None:
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return None
    execution_contract = _scan_execution_contract(scan)

    result = await session.execute(
        text(
            """
            SELECT
                n.id AS node_id,
                n.tool,
                n.worker_family,
                n.status,
                n.output_summary,
                p.phase_number,
                p.name AS phase_name,
                j.id AS job_id,
                j.status AS job_status,
                j.output_ref,
                j.started_at,
                j.completed_at,
                j.error_message
            FROM scan_nodes n
            JOIN scan_phases p ON p.id = n.phase_id
            JOIN scan_dags d ON d.id = n.dag_id
            LEFT JOIN scan_jobs j ON j.id = n.job_id
            WHERE d.scan_id = :scan_id
            ORDER BY p.phase_number ASC, COALESCE(j.completed_at, j.started_at, n.created_at) ASC, n.tool ASC
            """
        ),
        {"scan_id": str(scan_id)},
    )

    logs: list[dict[str, Any]] = []
    for row in result.mappings().all():
        output_summary = row.get("output_summary") or {}
        if not isinstance(output_summary, dict):
            output_summary = {}
        execution_log = output_summary.get("execution_log") or {}
        if not isinstance(execution_log, dict):
            execution_log = {}
        refs = _execution_log_storage_refs(
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_id=row["node_id"],
            tool_name=str(row["tool"] or ""),
        )
        command_artifact_ref = (
            str(execution_log.get("command_artifact_ref") or "").strip()
            or refs["command_artifact_ref"]
        )
        live_command_payload = read_json_artifact(command_artifact_ref)
        session_artifact_ref = (
            str(execution_log.get("session_artifact_ref") or "").strip()
            or refs["session_artifact_ref"]
        )
        live_session_payload = read_json_artifact(session_artifact_ref)
        stdout_ref = (
            str(execution_log.get("full_stdout_artifact_ref") or "").strip()
            or refs["full_stdout_artifact_ref"]
        )
        stderr_ref = (
            str(execution_log.get("full_stderr_artifact_ref") or "").strip()
            or refs["full_stderr_artifact_ref"]
        )
        live_stdout = read_text_artifact(stdout_ref) or ""
        live_stderr = read_text_artifact(stderr_ref) or ""
        canonical_command = _canonical_command_from_execution_log(execution_log)
        if isinstance(live_command_payload, dict):
            canonical_command = _canonical_command_from_execution_log(
                live_command_payload.get("canonical_command") or canonical_command
            )
        exit_code = execution_log.get("exit_code")
        if exit_code is None and isinstance(live_session_payload, dict):
            exit_code = live_session_payload.get("exit_code")
        execution_mode, execution_provenance, execution_reason = _normalize_execution_truth(
            tool_name=str(row["tool"] or ""),
            execution_mode=output_summary.get("execution_mode"),
            execution_provenance=output_summary.get("execution_provenance"),
            execution_reason=output_summary.get("execution_reason"),
        )
        configured_execution = (
            (_scan_config_dict(scan).get("execution") or {})
            if isinstance(_scan_config_dict(scan).get("execution"), dict)
            else {}
        )
        if not execution_mode:
            execution_mode = str(configured_execution.get("mode") or "unknown")
        if not execution_provenance and (
            isinstance(live_session_payload, dict)
            or isinstance(live_command_payload, dict)
        ):
            execution_provenance = "live"
        execution_class = _normalize_execution_class(
            tool_name=str(row["tool"] or ""),
            execution_class=execution_log.get("execution_class", output_summary.get("execution_class")),
        )
        status_value = (
            row.get("job_status")
            or row["status"]
            or (
                live_session_payload.get("status")
                if isinstance(live_session_payload, dict)
                else None
            )
        )
        runtime_stage = _derive_runtime_stage(
            status=str(status_value or "").strip() or None,
            runtime_stage=(
                str(execution_log.get("runtime_stage") or "").strip()
                or (
                    str(live_session_payload.get("runtime_stage") or "").strip()
                    if isinstance(live_session_payload, dict)
                    else ""
                )
                or None
            ),
            has_command=bool(
                execution_log.get("display_command")
                or (
                    live_command_payload.get("display_command")
                    if isinstance(live_command_payload, dict)
                    else ""
                )
                or canonical_command.get("display_command")
                or list(execution_log.get("command") or [])
            ),
            has_output=bool(live_stdout or live_stderr),
        )
        last_chunk_at = (
            (
                live_session_payload.get("last_chunk_at")
                if isinstance(live_session_payload, dict)
                else None
            )
            or execution_log.get("last_chunk_at")
            or row.get("completed_at")
            or row.get("started_at")
        )
        stream_complete = (
            bool(live_session_payload.get("stream_complete"))
            if isinstance(live_session_payload, dict) and "stream_complete" in live_session_payload
            else bool(execution_log.get("stream_complete"))
            if "stream_complete" in execution_log
            else runtime_stage in {"completed", "failed", "blocked", "cancelled"}
        )
        policy_state = classify_tool_policy_state(
            tool_name=str(row["tool"] or ""),
            execution_contract=execution_contract,
            scan_config=_scan_config_dict(scan),
            execution_provenance=execution_provenance,
            execution_reason=execution_reason,
        )
        logs.append(
            {
                "node_id": row["node_id"],
                "tool": row["tool"],
                "worker_family": row["worker_family"],
                "phase_number": int(row["phase_number"]),
                "phase_name": row["phase_name"],
                "status": status_value,
                "job_id": row.get("job_id"),
                "job_status": row.get("job_status"),
                "started_at": row.get("started_at")
                or (
                    live_session_payload.get("started_at")
                    if isinstance(live_session_payload, dict)
                    else None
                ),
                "completed_at": row.get("completed_at")
                or (
                    live_session_payload.get("completed_at")
                    if isinstance(live_session_payload, dict)
                    else None
                ),
                "duration_ms": int(execution_log.get("duration_ms", output_summary.get("duration_ms", 0)) or 0),
                "execution_mode": execution_mode or "unknown",
                "execution_provenance": execution_provenance or "unknown",
                "execution_reason": execution_reason,
                "execution_class": execution_class,
                "policy_state": policy_state,
                "runtime_stage": runtime_stage,
                "last_chunk_at": last_chunk_at,
                "stream_complete": stream_complete,
                "error_message": row.get("error_message"),
                "item_count": int(output_summary.get("item_count", 0) or 0),
                "finding_count": int(output_summary.get("finding_count", 0) or 0),
                "storage_ref": row.get("output_ref"),
                "command": list(
                    execution_log.get("command")
                    or (
                        live_command_payload.get("command")
                        if isinstance(live_command_payload, dict)
                        else []
                    )
                    or []
                ),
                "display_command": str(
                    execution_log.get("display_command")
                    or (
                        live_command_payload.get("display_command")
                        if isinstance(live_command_payload, dict)
                        else ""
                    )
                    or canonical_command.get("display_command")
                    or ""
                ),
                "tool_binary": canonical_command.get("tool_binary"),
                "container_image": canonical_command.get("container_image"),
                "entrypoint": list(canonical_command.get("entrypoint") or []),
                "working_dir": canonical_command.get("working_dir"),
                "canonical_command": canonical_command,
                "stdout_preview": str(execution_log.get("stdout_preview") or live_stdout[-5_000:]),
                "stderr_preview": str(execution_log.get("stderr_preview") or live_stderr[-2_000:]),
                "exit_code": exit_code,
                "full_stdout_artifact_ref": stdout_ref if live_stdout or execution_log.get("full_stdout_artifact_ref") else None,
                "full_stderr_artifact_ref": stderr_ref if live_stderr or execution_log.get("full_stderr_artifact_ref") else None,
                "command_artifact_ref": command_artifact_ref if isinstance(live_command_payload, dict) or execution_log.get("command_artifact_ref") else None,
                "session_artifact_ref": session_artifact_ref if isinstance(live_session_payload, dict) or execution_log.get("session_artifact_ref") else None,
            }
        )

    return {"scan_id": scan_id, "total": len(logs), "logs": logs}


def _chunk_text_frames(
    *,
    text: str,
    channel: str,
    artifact_ref: str | None,
    start_seq: int,
    timestamp: datetime | None,
) -> tuple[list[dict[str, Any]], int]:
    frames: list[dict[str, Any]] = []
    next_seq = start_seq
    if not text:
        return frames, next_seq
    for start in range(0, len(text), 4000):
        frames.append(
            {
                "channel": channel,
                "chunk_seq": next_seq,
                "chunk_text": text[start : start + 4000],
                "timestamp": timestamp,
                "artifact_ref": artifact_ref,
            }
        )
        next_seq += 1
    return frames, next_seq


def _derive_runtime_stage(
    *,
    status: str | None,
    runtime_stage: str | None,
    has_command: bool,
    has_output: bool,
) -> str | None:
    normalized_runtime_stage = str(runtime_stage or "").strip().lower()
    if normalized_runtime_stage:
        return normalized_runtime_stage

    normalized_status = str(status or "").strip().lower()
    if normalized_status in {"completed", "failed", "blocked", "cancelled"}:
        return normalized_status
    if normalized_status in {"queued", "pending", "scheduled", "assigned"}:
        return "queued"
    if normalized_status == "running":
        if has_output:
            return "streaming"
        if has_command:
            return "command_resolved"
        return "container_starting"
    return None


def _execution_log_storage_refs(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    node_id: uuid.UUID,
    tool_name: str,
) -> dict[str, str]:
    base_ref = f"artifacts/{tenant_id}/{scan_id}/{node_id}/execution_logs/{tool_name}"
    return {
        "command_artifact_ref": f"{base_ref}_command.json",
        "full_stdout_artifact_ref": f"{base_ref}_stdout.txt",
        "full_stderr_artifact_ref": f"{base_ref}_stderr.txt",
        "session_artifact_ref": f"{base_ref}_session.json",
    }


async def get_scan_job_session(
    *,
    scan_id: uuid.UUID,
    job_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict[str, Any] | None:
    logs = await get_scan_tool_logs(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if logs is None:
        return None

    entry = next(
        (item for item in list(logs.get("logs") or []) if str(item.get("job_id") or "") == str(job_id)),
        None,
    )
    if entry is None:
        return None

    frames: list[dict[str, Any]] = []
    session_artifact_ref = str(entry.get("session_artifact_ref") or "").strip() or None
    payload_runtime_stage = None
    payload_last_chunk_at = None
    payload_stream_complete = None
    if session_artifact_ref:
        payload = read_json_artifact(session_artifact_ref)
        if isinstance(payload, dict) and isinstance(payload.get("frames"), list):
            for item in payload.get("frames") or []:
                if isinstance(item, dict):
                    frames.append(
                        {
                            "channel": str(item.get("channel") or "system"),
                            "chunk_seq": int(item.get("chunk_seq") or len(frames)),
                            "chunk_text": str(item.get("chunk_text") or ""),
                            "timestamp": item.get("timestamp")
                            or entry.get("completed_at")
                            or entry.get("started_at"),
                            "artifact_ref": str(item.get("artifact_ref") or "").strip() or None,
                        }
                    )
            payload_runtime_stage = str(payload.get("runtime_stage") or "").strip() or None
            payload_last_chunk_at = payload.get("last_chunk_at")
            payload_stream_complete = (
                bool(payload.get("stream_complete"))
                if "stream_complete" in payload
                else None
            )

    if not frames:
        next_seq = 0
        command_text = ""
        canonical_command = _canonical_command_from_execution_log(entry.get("canonical_command") or {})
        command_artifact_ref = str(entry.get("command_artifact_ref") or "").strip() or None
        if command_artifact_ref:
            payload = read_json_artifact(command_artifact_ref)
            if isinstance(payload, dict):
                artifact_command = payload.get("canonical_command")
                if isinstance(artifact_command, dict):
                    canonical_command = _canonical_command_from_execution_log(artifact_command)
                command_text = str(
                    payload.get("display_command")
                    or canonical_command.get("display_command")
                    or ""
                ).strip()
        if not command_text:
            command_text = str(
                entry.get("display_command")
                or canonical_command.get("display_command")
                or " ".join(list(entry.get("command") or []))
            ).strip()
        if command_text:
            frames.append(
                {
                    "channel": "command",
                    "chunk_seq": next_seq,
                    "chunk_text": command_text,
                    "timestamp": entry.get("started_at"),
                    "artifact_ref": command_artifact_ref,
                }
            )
            next_seq += 1

        stdout_text = ""
        stdout_ref = str(entry.get("full_stdout_artifact_ref") or "").strip() or None
        if stdout_ref:
            stdout_text = read_text_artifact(stdout_ref) or ""
        if not stdout_text:
            stdout_text = str(entry.get("stdout_preview") or "")
        stdout_frames, next_seq = _chunk_text_frames(
            text=stdout_text,
            channel="stdout",
            artifact_ref=stdout_ref,
            start_seq=next_seq,
            timestamp=entry.get("completed_at") or entry.get("started_at"),
        )
        frames.extend(stdout_frames)

        stderr_text = ""
        stderr_ref = str(entry.get("full_stderr_artifact_ref") or "").strip() or None
        if stderr_ref:
            stderr_text = read_text_artifact(stderr_ref) or ""
        if not stderr_text:
            stderr_text = str(entry.get("stderr_preview") or "")
        stderr_frames, next_seq = _chunk_text_frames(
            text=stderr_text,
            channel="stderr",
            artifact_ref=stderr_ref,
            start_seq=next_seq,
            timestamp=entry.get("completed_at") or entry.get("started_at"),
        )
        frames.extend(stderr_frames)

    frames.sort(key=lambda item: (int(item.get("chunk_seq") or 0), str(item.get("channel") or "")))
    runtime_stage = _derive_runtime_stage(
        status=str(entry.get("status") or "").strip() or None,
        runtime_stage=payload_runtime_stage or str(entry.get("runtime_stage") or "").strip() or None,
        has_command=bool(
            entry.get("display_command")
            or entry.get("canonical_command")
            or list(entry.get("command") or [])
        ),
        has_output=any(
            frame.get("channel") in {"stdout", "stderr"} and str(frame.get("chunk_text") or "")
            for frame in frames
        ),
    )
    last_chunk_at = (
        payload_last_chunk_at
        or entry.get("last_chunk_at")
        or entry.get("completed_at")
        or entry.get("started_at")
    )
    stream_complete = (
        payload_stream_complete
        if payload_stream_complete is not None
        else bool(entry.get("stream_complete"))
        if entry.get("stream_complete") is not None
        else runtime_stage in {"completed", "failed", "blocked", "cancelled"}
    )
    return {
        "scan_id": scan_id,
        "job_id": job_id,
        "node_id": entry.get("node_id"),
        "tool": entry.get("tool"),
        "status": entry.get("status"),
        "policy_state": entry.get("policy_state"),
        "execution_provenance": entry.get("execution_provenance"),
        "execution_reason": entry.get("execution_reason"),
        "execution_class": entry.get("execution_class"),
        "runtime_stage": runtime_stage,
        "last_chunk_at": last_chunk_at,
        "stream_complete": stream_complete,
        "started_at": entry.get("started_at"),
        "completed_at": entry.get("completed_at"),
        "exit_code": entry.get("exit_code"),
        "command": list(entry.get("command") or []),
        "display_command": entry.get("display_command") or "",
        "tool_binary": entry.get("tool_binary"),
        "container_image": entry.get("container_image"),
        "entrypoint": list(entry.get("entrypoint") or []),
        "working_dir": entry.get("working_dir"),
        "canonical_command": entry.get("canonical_command"),
        "command_artifact_ref": entry.get("command_artifact_ref"),
        "full_stdout_artifact_ref": entry.get("full_stdout_artifact_ref"),
        "full_stderr_artifact_ref": entry.get("full_stderr_artifact_ref"),
        "session_artifact_ref": session_artifact_ref,
        "frames": frames,
    }


async def get_scan_tool_log_content(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    storage_ref: str,
    session: AsyncSession,
) -> dict[str, Any] | None:
    logs = await get_scan_tool_logs(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if logs is None:
        return None

    allowed_refs = {
        str(ref).strip()
        for entry in list(logs.get("logs") or [])
        for ref in (
            entry.get("full_stdout_artifact_ref"),
            entry.get("full_stderr_artifact_ref"),
            entry.get("command_artifact_ref"),
        )
        if str(ref).strip()
    }
    if storage_ref not in allowed_refs:
        return None

    if storage_ref.endswith("_command.json"):
        payload = read_json_artifact(storage_ref)
        if isinstance(payload, dict):
            rendered = str(payload.get("display_command") or "").strip()
            content = rendered or json.dumps(payload, indent=2, default=str)
        else:
            content = ""
        content_type = "command"
    else:
        content = read_text_artifact(storage_ref) or ""
        content_type = "stderr" if storage_ref.endswith("_stderr.txt") else "stdout"

    return {
        "scan_id": scan_id,
        "storage_ref": storage_ref,
        "content_type": content_type,
        "content": content,
    }


async def get_scan_field_validation_assessment(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict[str, Any] | None:
    """Return a frontend-visible field-validation assessment for one scan."""
    context = await _load_report_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if context is None:
        return None

    planner_context = await get_scan_planner_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    try:
        jobs = await list_scan_jobs(scan_id=scan_id, tenant_id=tenant_id, session=session) or []
    except Exception:
        logger.debug(
            "Falling back to empty job list for field-validation assessment %s",
            scan_id,
            exc_info=True,
        )
        jobs = []
    return _build_field_validation_assessment(
        scan=context["scan"],
        context=context,
        planner_context=planner_context or {},
        jobs=jobs,
    )


async def get_field_validation_summary(
    *,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    limit: int = 10,
) -> dict[str, Any]:
    """Return a field-validation-only readiness summary separate from benchmarks."""
    stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.asset))
        .order_by(Scan.created_at.desc())
        .limit(max(limit * 4, 20))
    )
    scans = list((await session.execute(stmt)).scalars().all())

    items: list[dict[str, Any]] = []
    by_state: dict[str, int] = {}
    for scan in scans:
        if _scan_profile_variant(scan) != "field_validation":
            continue
        context = await _load_report_context(
            scan_id=scan.id,
            tenant_id=tenant_id,
            session=session,
        )
        if context is None:
            continue
        planner_context = await get_scan_planner_context(
            scan_id=scan.id,
            tenant_id=tenant_id,
            session=session,
        )
        try:
            jobs = await list_scan_jobs(scan_id=scan.id, tenant_id=tenant_id, session=session) or []
        except Exception:
            logger.debug("Falling back to empty job list for field-validation summary %s", scan.id, exc_info=True)
            jobs = []
        assessment = _build_field_validation_assessment(
            scan=scan,
            context=context,
            planner_context=planner_context or {},
            jobs=jobs,
        )
        state = str(assessment.get("assessment_state") or "no_findings")
        by_state[state] = by_state.get(state, 0) + 1
        verification_outcomes = assessment.get("verification_outcomes") or {}
        items.append(
            {
                "scan_id": scan.id,
                "asset_name": assessment.get("asset_name"),
                "target": assessment.get("target") or "",
                "status": assessment.get("status") or "",
                "target_profile_guess": assessment.get("target_profile_guess"),
                "selected_capability_packs": list(assessment.get("selected_capability_packs") or []),
                "verified": int(verification_outcomes.get("verified", 0) or 0),
                "reproduced": int(verification_outcomes.get("reproduced", 0) or 0),
                "detected": int(verification_outcomes.get("detected", 0) or 0),
                "needs_evidence": int(verification_outcomes.get("needs_evidence", 0) or 0),
                "assessment_state": state,
                "benchmark_inputs_disabled_confirmed": bool(
                    assessment.get("benchmark_inputs_disabled_confirmed")
                ),
                "generated_at": assessment.get("generated_at"),
            }
        )
        if len(items) >= limit:
            break

    return {
        "generated_at": datetime.now(timezone.utc),
        "total_scans": len(items),
        "by_state": by_state,
        "items": items,
    }


async def list_evidence_references(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Extract evidence references from persisted findings."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return []

    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.created_at.desc())
    )
    findings = list((await session.execute(stmt)).scalars().all())
    return _build_evidence_references(findings)


async def _latest_artifact_by_type(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    artifact_type: str,
    session: AsyncSession,
) -> ScanArtifact | None:
    stmt = (
        select(ScanArtifact)
        .where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.tenant_id == tenant_id,
            ScanArtifact.artifact_type == artifact_type,
        )
        .order_by(ScanArtifact.created_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _latest_capability_advisories(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[ScanArtifact]:
    stmt = (
        select(ScanArtifact)
        .where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.tenant_id == tenant_id,
            ScanArtifact.artifact_type == "capability_advisory",
        )
        .order_by(ScanArtifact.created_at.desc())
    )
    artifacts = list((await session.execute(stmt)).scalars().all())
    latest_by_pack: dict[str, ScanArtifact] = {}
    for artifact in artifacts:
        pack_key = str((artifact.metadata_ or {}).get("pack_key") or "").strip()
        if not pack_key or pack_key in latest_by_pack:
            continue
        latest_by_pack[pack_key] = artifact
    return list(latest_by_pack.values())


def _read_artifact_payload(artifact: ScanArtifact | None) -> dict[str, Any]:
    if artifact is None:
        return {}
    try:
        payload = read_json_artifact(artifact.storage_ref)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        logger.warning("Could not read artifact payload for %s", artifact.storage_ref, exc_info=True)
        return {}


async def get_scan_report(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict | None:
    """Build a buyer-ready report response from persisted findings and graph data."""
    context = await _load_report_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if context is None:
        return None

    scan = context["scan"]
    findings = context["findings"]
    severity_counts = context["severity_counts"]
    verification_counts = context["verification_counts"]
    asset_summary = _build_asset_summary(scan)
    evidence = _build_evidence_references(findings)
    top_findings = [_finding_snapshot(finding) for finding in findings[:5]]
    finding_groups = _build_finding_groups(findings)
    remediation_plan = _build_remediation_plan(findings)
    compliance = _build_compliance_mappings(findings)
    narrative = _build_attack_narrative(
        scan=scan,
        graph=context["attack_graph"],
        findings=findings,
        remediation_plan=remediation_plan,
    )
    comparison = context["comparison"]
    executive_summary = _build_executive_summary(
        asset_summary["target"],
        severity_counts,
        verification_counts,
    )

    report = {
        "scan_id": scan.id,
        "report_id": f"scan-report:{scan.id}",
        "generated_at": datetime.now(timezone.utc),
        "executive_summary": executive_summary,
        "severity_counts": severity_counts,
        "verification_counts": verification_counts,
        "verification_summary": context["verification_summary"],
        "verification_pipeline": context["verification_pipeline"],
        "execution_summary": context["execution_summary"],
        "vulnerability_count": len(findings),
        "evidence_count": len(evidence),
        "asset": asset_summary,
        "narrative": narrative,
        "compliance": compliance,
        "finding_groups": finding_groups,
        "remediation_plan": remediation_plan,
        "comparison": comparison,
        "retest": _build_retest_summary(scan, comparison),
        "export_formats": list(_DEFAULT_EXPORT_FORMATS),
        "top_findings": top_findings,
    }
    report["markdown"] = _build_report_markdown(report)
    return report


async def get_scan_comparison(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    baseline_scan_id: uuid.UUID | None = None,
) -> dict | None:
    """Compare a scan against an explicit or inferred completed baseline."""
    context = await _load_report_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
        baseline_scan_id=baseline_scan_id,
    )
    if context is None:
        return None
    return context["comparison"]


async def export_scan_report(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    export_format: str,
    session: AsyncSession,
) -> tuple[str, str, str] | None:
    """Export a scan report in markdown, json, csv, or html form."""
    report = await get_scan_report(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if report is None:
        return None

    target_slug = _slugify(str(report.get("asset", {}).get("target") or scan_id))
    scan_slug = str(scan_id)

    if export_format == "json":
        return (
            json.dumps(report, indent=2, default=_json_default),
            "application/json",
            f"pentra-report-{target_slug}-{scan_slug}.json",
        )

    if export_format == "csv":
        return (
            _build_report_csv(report),
            "text/csv; charset=utf-8",
            f"pentra-report-{target_slug}-{scan_slug}.csv",
        )

    if export_format == "html":
        return (
            _build_report_html(report),
            "text/html; charset=utf-8",
            f"pentra-report-{target_slug}-{scan_slug}.html",
        )

    return (
        str(report["markdown"]),
        "text/markdown; charset=utf-8",
        f"pentra-report-{target_slug}-{scan_slug}.md",
    )


async def deliver_scan_report_notification(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    channel: str,
    destination_url: str,
    top_findings_limit: int,
    include_markdown: bool,
    include_html: bool,
    custom_headers: dict[str, str] | None,
    authorization_header: str | None,
    session: AsyncSession,
) -> dict[str, Any] | None:
    """Deliver a scan report summary to a webhook-style destination."""
    report = await get_scan_report(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if report is None:
        return None

    delivered_at = datetime.now(timezone.utc)
    if channel == "slack":
        payload = _build_slack_notification_payload(
            report=report,
            delivered_at=delivered_at,
            top_findings_limit=top_findings_limit,
        )
        payload_kind = "slack_webhook"
    else:
        payload = _build_webhook_notification_payload(
            report=report,
            delivered_at=delivered_at,
            top_findings_limit=top_findings_limit,
            include_markdown=include_markdown,
            include_html=include_html,
        )
        payload_kind = "report_summary"

    try:
        status_code = await _post_json_payload(
            destination_url=destination_url,
            payload=payload,
            custom_headers=custom_headers,
            authorization_header=authorization_header,
        )
    except (
        httpx.TimeoutException,
        httpx.TransportError,
        httpx.HTTPStatusError,
    ) as exc:
        raise RuntimeError(f"Notification delivery failed: {exc}") from exc

    top_findings = report.get("top_findings") or []
    return {
        "scan_id": report["scan_id"],
        "channel": channel,
        "delivered_at": delivered_at,
        "destination_host": _destination_host(destination_url),
        "payload_kind": payload_kind,
        "status_code": status_code,
        "summary": report.get("executive_summary") or "",
        "severity_counts": report.get("severity_counts") or {},
        "verification_counts": report.get("verification_counts") or {},
        "top_finding_count": min(len(top_findings), top_findings_limit),
    }


async def export_scan_issues(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    provider: str,
    mode: str,
    minimum_severity: str,
    verified_only: bool,
    max_issues: int,
    destination_url: str | None,
    base_url: str | None,
    repository: str | None,
    project_key: str | None,
    custom_headers: dict[str, str] | None,
    authorization_header: str | None,
    session: AsyncSession,
) -> dict[str, Any] | None:
    """Preview or deliver provider-shaped issue payloads for selected findings."""
    context = await _load_report_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if context is None:
        return None

    report = await get_scan_report(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if report is None:
        return None

    selected_findings = _select_findings_for_issue_export(
        findings=context["findings"],
        minimum_severity=minimum_severity,
        verified_only=verified_only,
        max_issues=max_issues,
    )
    resolved_destination_url = _resolve_issue_destination_url(
        provider=provider,
        destination_url=destination_url,
        base_url=base_url,
        repository=repository,
    )
    generated_at = datetime.now(timezone.utc)
    tickets: list[dict[str, Any]] = []
    delivered_count = 0

    for finding in selected_findings:
        snapshot = _finding_snapshot(finding)
        labels = _issue_labels(snapshot)
        if provider == "jira":
            payload = _build_jira_issue_payload(
                report=report,
                finding_snapshot=snapshot,
                labels=labels,
                project_key=project_key or "PENTRA",
            )
        else:
            payload = _build_github_issue_payload(
                report=report,
                finding_snapshot=snapshot,
                labels=labels,
            )

        status_code: int | None = None
        delivery_status = "preview"
        if mode == "deliver" and resolved_destination_url is not None:
            try:
                status_code = await _post_json_payload(
                    destination_url=resolved_destination_url,
                    payload=payload,
                    custom_headers=custom_headers,
                    authorization_header=authorization_header,
                    extra_headers=_issue_delivery_headers(provider),
                )
            except (
                httpx.TimeoutException,
                httpx.TransportError,
                httpx.HTTPStatusError,
            ) as exc:
                raise RuntimeError(f"Issue delivery failed: {exc}") from exc
            delivery_status = "delivered"
            delivered_count += 1

        tickets.append(
            {
                "finding_id": finding.id,
                "fingerprint": finding.fingerprint,
                "title": str(payload.get("title") or payload.get("fields", {}).get("summary") or finding.title),
                "target": snapshot["target"],
                "severity": snapshot["severity"],
                "verification_state": snapshot["verification_state"],
                "labels": labels,
                "payload": payload,
                "delivery_status": delivery_status,
                "status_code": status_code,
            }
        )

    return {
        "scan_id": scan_id,
        "provider": provider,
        "mode": mode,
        "generated_at": generated_at,
        "destination_host": (
            _destination_host(resolved_destination_url)
            if resolved_destination_url is not None
            else None
        ),
        "selected_count": len(selected_findings),
        "delivered_count": delivered_count,
        "applied_filters": {
            "minimum_severity": minimum_severity,
            "verified_only": verified_only,
            "max_issues": max_issues,
        },
        "tickets": tickets,
    }


async def _load_report_context(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    baseline_scan_id: uuid.UUID | None = None,
) -> dict[str, Any] | None:
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.asset).selectinload(Asset.project),
        )
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return None

    raw_findings = list(scan.findings)
    findings = _build_user_facing_findings(raw_findings)
    pipeline_findings = _build_user_facing_findings(raw_findings, include_rejected=True)
    severity_counts = _count_severity(findings)
    verification_counts = _count_verification(findings)
    attack_graph = await get_attack_graph(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    baseline_scan = await _select_baseline_scan(
        scan=scan,
        tenant_id=tenant_id,
        session=session,
        baseline_scan_id=baseline_scan_id,
    )
    comparison = _build_scan_comparison(
        current_scan=scan,
        current_findings=findings,
        baseline_scan=baseline_scan,
    )
    verification_summary = _build_verification_summary(
        scan=scan,
        findings=findings,
    )
    verification_pipeline = _build_verification_pipeline_summary(
        scan=scan,
        findings=pipeline_findings,
    )

    return {
        "scan": scan,
        "findings": findings,
        "severity_counts": severity_counts,
        "verification_counts": verification_counts,
        "verification_summary": verification_summary,
        "verification_pipeline": verification_pipeline,
        "execution_summary": _execution_summary_from_scan(scan),
        "attack_graph": attack_graph,
        "baseline_scan": baseline_scan,
        "comparison": comparison,
    }


def _sort_findings_for_report(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -_truth_rank(_truth_state_for_finding(finding)),
            -_verification_rank(_verification_state_for_finding(finding)),
            -_severity_rank(str(finding.severity)),
            -int(finding.confidence or 0),
            finding.created_at,
        ),
    )


def _build_user_facing_findings(
    findings: list[Finding],
    *,
    include_rejected: bool = False,
) -> list[Finding]:
    if not findings:
        return []

    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(_finding_display_signature(finding), []).append(finding)

    canonical: list[Finding] = []
    for group in grouped.values():
        merged = _merge_finding_group(group)
        truth_state = _truth_state_for_finding(merged)
        if not include_rejected and (
            getattr(merged, "is_false_positive", False)
            or truth_state in {"rejected", "expired"}
        ):
            continue
        canonical.append(merged)

    return _sort_findings_for_report(canonical)


def _finding_display_signature(finding: Finding) -> str:
    evidence = finding.evidence or {}
    metadata = evidence.get("metadata") or {} if isinstance(evidence, dict) else {}
    verification_context = metadata.get("verification_context") or {} if isinstance(metadata, dict) else {}

    source_fingerprint = str(verification_context.get("finding_fingerprint") or "").strip().lower()
    if source_fingerprint:
        return f"fingerprint:{source_fingerprint}"

    vulnerability_type = (_finding_vulnerability_type(finding) or "unclassified").strip().lower()
    route_group = str(_finding_route_group(finding) or "").strip().lower()
    if vulnerability_type and route_group:
        return f"route:{vulnerability_type}:{route_group}"

    target = str(_finding_target(finding) or "").strip().lower()
    if vulnerability_type and target:
        return f"target:{vulnerability_type}:{target}"

    source_title = str(verification_context.get("finding_title") or "").strip().lower()
    if source_title:
        return f"title:{source_title}"

    return _finding_comparison_key(finding)


def _finding_context_rank(finding: Finding) -> tuple[int, int, int, int]:
    evidence = finding.evidence or {}
    metadata = evidence.get("metadata") or {} if isinstance(evidence, dict) else {}
    negative_verifications = metadata.get("negative_verifications") if isinstance(metadata, dict) else None
    return (
        1 if _finding_target(finding) != finding.title else 0,
        1 if _finding_route_group(finding) else 0,
        1 if isinstance(evidence, dict) and any(evidence.get(key) for key in ("request", "response", "payload")) else 0,
        len(negative_verifications) if isinstance(negative_verifications, list) else 0,
    )


def _finding_strength_rank(finding: Finding) -> tuple[int, int, int, int, int]:
    return (
        _truth_rank(_truth_state_for_finding(finding)),
        _verification_rank(_verification_state_for_finding(finding)),
        _severity_rank(str(finding.severity)),
        int(getattr(finding, "confidence", 0) or 0),
        1 if str(getattr(finding, "source_type", "")) == "exploit_verify" else 0,
    )


def _merge_finding_group(findings: list[Finding]) -> Finding:
    anchor = max(
        findings,
        key=lambda finding: (
            _finding_context_rank(finding),
            _finding_strength_rank(finding),
        ),
    )
    strongest = max(
        findings,
        key=lambda finding: (
            _finding_strength_rank(finding),
            _finding_context_rank(finding),
        ),
    )

    merged = Finding()
    merged.id = anchor.id
    merged.scan_id = anchor.scan_id
    merged.scan_job_id = strongest.scan_job_id or anchor.scan_job_id
    merged.source_type = strongest.source_type or anchor.source_type
    merged.title = _merged_finding_title(anchor, strongest)
    merged.severity = (
        strongest.severity
        if _severity_rank(str(strongest.severity)) >= _severity_rank(str(anchor.severity))
        else anchor.severity
    )
    merged.confidence = max(int(anchor.confidence or 0), int(strongest.confidence or 0))
    merged.cve_id = strongest.cve_id or anchor.cve_id
    merged.cvss_score = strongest.cvss_score if strongest.cvss_score is not None else anchor.cvss_score
    merged.description = anchor.description or strongest.description
    merged.evidence = _merge_finding_evidence(anchor, strongest, findings)
    merged.remediation = strongest.remediation or anchor.remediation
    merged.tool_source = strongest.tool_source or anchor.tool_source
    merged.is_false_positive = bool(anchor.is_false_positive or strongest.is_false_positive)
    merged.fp_probability = _max_optional_int(anchor.fp_probability, strongest.fp_probability)
    merged.fingerprint = anchor.fingerprint or strongest.fingerprint or _finding_display_signature(anchor)
    merged.created_at = min(
        finding.created_at for finding in findings if getattr(finding, "created_at", None) is not None
    )
    return merged


def _merged_finding_title(anchor: Finding, strongest: Finding) -> str:
    vulnerability_type = _finding_vulnerability_type(strongest) or _finding_vulnerability_type(anchor)
    truth_state = _truth_state_for_finding(strongest)
    verification_state = _verification_state_for_finding(strongest)
    strongest_title = str(strongest.title or "").strip()
    anchor_title = str(anchor.title or "").strip()

    if vulnerability_type == "stack_trace_exposure":
        if verification_state == "verified" or truth_state == "verified":
            return "Verified stack trace exposure"
        if truth_state in {"reproduced", "suspected"}:
            return "Suspected stack trace exposure"
        return "Detected stack trace exposure"

    if strongest_title.startswith("Verified "):
        return strongest_title
    if anchor_title.startswith("Verified "):
        return anchor_title
    if anchor_title and not anchor_title.lower().startswith("error:"):
        return anchor_title
    if strongest_title:
        return strongest_title
    if vulnerability_type:
        prefix = "Verified" if truth_state == "verified" else "Detected"
        return f"{prefix} {vulnerability_type.replace('_', ' ')}"
    return anchor_title or strongest_title or "Finding"


def _merge_finding_evidence(anchor: Finding, strongest: Finding, group: list[Finding]) -> dict[str, Any] | None:
    merged = deepcopy(anchor.evidence or {})
    if not isinstance(merged, dict):
        merged = {}

    strongest_evidence = deepcopy(strongest.evidence or {})
    if not isinstance(strongest_evidence, dict):
        strongest_evidence = {}

    for key in ("endpoint", "target", "request", "response", "payload", "proof", "storage_ref"):
        if merged.get(key) in (None, "", []):
            value = strongest_evidence.get(key)
            if value not in (None, "", []):
                merged[key] = value

    classification = deepcopy(merged.get("classification") or {})
    if not isinstance(classification, dict):
        classification = {}
    strongest_classification = deepcopy(strongest_evidence.get("classification") or {})
    if not isinstance(strongest_classification, dict):
        strongest_classification = {}
    classification.update({key: value for key, value in strongest_classification.items() if value not in (None, "")})
    merged["classification"] = classification

    metadata = deepcopy(merged.get("metadata") or {})
    if not isinstance(metadata, dict):
        metadata = {}
    strongest_metadata = deepcopy(strongest_evidence.get("metadata") or {})
    if not isinstance(strongest_metadata, dict):
        strongest_metadata = {}
    metadata.update({key: value for key, value in strongest_metadata.items() if value not in (None, "")})
    metadata["related_finding_ids"] = list(
        dict.fromkeys(str(finding.id) for finding in group if getattr(finding, "id", None))
    )
    metadata["related_finding_titles"] = list(
        dict.fromkeys(str(finding.title) for finding in group if getattr(finding, "title", None))
    )
    metadata["duplicate_count"] = len(group)
    merged["metadata"] = metadata
    merged["references"] = _merge_evidence_references_from_findings(group)
    return merged


def _merge_evidence_references_from_findings(group: list[Finding]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for finding in group:
        evidence = finding.evidence or {}
        if not isinstance(evidence, dict):
            continue
        references = evidence.get("references") or []
        if not isinstance(references, list):
            continue
        for index, reference in enumerate(references):
            if not isinstance(reference, dict):
                continue
            key = str(reference.get("id") or reference.get("storage_ref") or f"{finding.id}:{index}")
            if key not in deduped:
                deduped[key] = deepcopy(reference)
    return list(deduped.values())


def _max_optional_int(*values: Any) -> int | None:
    normalized: list[int] = []
    for value in values:
        if value is None:
            continue
        try:
            normalized.append(int(value))
        except (TypeError, ValueError):
            continue
    if not normalized:
        return None
    return max(normalized)


def _count_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[str(finding.severity)] = counts.get(str(finding.severity), 0) + 1
    return counts


def _count_verification(findings: list[Finding]) -> dict[str, int]:
    counts = {"verified": 0, "suspected": 0, "detected": 0}
    for finding in findings:
        state = _verification_state_for_finding(finding)
        counts[state] = counts.get(state, 0) + 1
    return counts


def _scan_profile_id(scan: Scan) -> str | None:
    config = _scan_config_dict(scan)
    if not isinstance(config, dict):
        return None

    profile_id = config.get("profile_id")
    if profile_id:
        return str(profile_id)

    profile = config.get("profile") or {}
    if isinstance(profile, dict) and profile.get("id"):
        return str(profile["id"])
    return None


def _scan_profile_variant(scan: Scan) -> str:
    profile_id = _scan_profile_id(scan)
    if profile_id == FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID:
        return "field_validation"
    config = _scan_config_dict(scan)
    if isinstance(config, dict):
        profile = config.get("profile") or {}
        if isinstance(profile, dict):
            variant = str(profile.get("variant") or "").strip()
            if variant:
                return variant
    return "standard"


def _scan_execution_contract(scan: Scan) -> dict[str, Any]:
    config = _scan_config_dict(scan)
    if not isinstance(config, dict):
        return {}
    contract = config.get("execution_contract")
    return dict(contract) if isinstance(contract, dict) else {}


def _scan_config_dict(scan: Scan | Any) -> dict[str, Any]:
    config = getattr(scan, "config", None) or {}
    return config if isinstance(config, dict) else {}


def _field_validation_operating_mode(scan: Scan, *, benchmark_inputs_enabled: bool) -> str:
    if _scan_profile_variant(scan) == "field_validation":
        return "field_validation"
    if benchmark_inputs_enabled:
        return "benchmark"
    return "standard"


def _verification_share(verified: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(verified / total, 3)


def _build_verification_summary(
    *,
    scan: Scan,
    findings: list[Finding],
) -> dict[str, Any]:
    by_type: dict[str, dict[str, Any]] = {}

    overall = {
        "total_findings": len(findings),
        "verified": 0,
        "suspected": 0,
        "detected": 0,
        "verified_share": 0.0,
    }

    for finding in findings:
        vulnerability_type = _finding_vulnerability_type(finding) or "unclassified"
        verification_state = _verification_state_for_finding(finding)
        group = by_type.setdefault(
            vulnerability_type,
            {
                "vulnerability_type": vulnerability_type,
                "total_findings": 0,
                "verified": 0,
                "suspected": 0,
                "detected": 0,
                "highest_severity": "info",
                "verified_share": 0.0,
            },
        )

        group["total_findings"] += 1
        group[verification_state] += 1
        group["highest_severity"] = _highest_severity(
            {group["highest_severity"]: 1, str(finding.severity): 1}
        )

        overall[verification_state] += 1

    for group in by_type.values():
        group["verified_share"] = _verification_share(
            int(group["verified"]),
            int(group["total_findings"]),
        )

    overall["verified_share"] = _verification_share(
        int(overall["verified"]),
        int(overall["total_findings"]),
    )

    ordered = sorted(
        by_type.values(),
        key=lambda item: (
            -int(item["verified"]),
            -_severity_rank(str(item["highest_severity"])),
            str(item["vulnerability_type"]),
        ),
    )

    return {
        "profile_id": _scan_profile_id(scan),
        "profile_variant": _scan_profile_variant(scan),
        "scan_type": str(scan.scan_type),
        "overall": overall,
        "by_type": ordered,
    }


def _build_verification_pipeline_summary(
    *,
    scan: Scan,
    findings: list[Finding],
) -> dict[str, Any]:
    by_type: dict[str, dict[str, Any]] = {}
    queue_items: list[dict[str, Any]] = []
    overall = {
        "total_findings": len(findings),
        "verified": 0,
        "reproduced": 0,
        "queued": 0,
        "needs_evidence": 0,
        "rejected": 0,
        "expired": 0,
        "verified_share": 0.0,
        "proof_ready_share": 0.0,
    }

    for finding in findings:
        vulnerability_type = _finding_vulnerability_type(finding) or "unclassified"
        pipeline_state = _verification_pipeline_state_for_finding(finding)
        truth_summary = _truth_summary_for_finding(finding)

        group = by_type.setdefault(
            vulnerability_type,
            {
                "vulnerability_type": vulnerability_type,
                "total_findings": 0,
                "verified": 0,
                "reproduced": 0,
                "queued": 0,
                "needs_evidence": 0,
                "rejected": 0,
                "expired": 0,
                "highest_severity": "info",
                "verified_share": 0.0,
                "proof_ready_share": 0.0,
            },
        )

        group["total_findings"] += 1
        group[pipeline_state] += 1
        group["highest_severity"] = _highest_severity(
            {group["highest_severity"]: 1, str(finding.severity): 1}
        )
        overall[pipeline_state] += 1

        if pipeline_state in {"queued", "needs_evidence", "reproduced"}:
            queue_items.append(
                {
                    "finding_id": str(finding.id),
                    "title": finding.title,
                    "vulnerability_type": vulnerability_type,
                    "target": _finding_target(finding),
                    "route_group": _finding_route_group(finding),
                    "severity": str(finding.severity),
                    "verification_state": _verification_state_for_finding(finding),
                    "truth_state": _truth_state_for_finding(finding),
                    "queue_state": pipeline_state,
                    "readiness_reason": _verification_pipeline_reason(pipeline_state, finding),
                    "required_actions": _verification_pipeline_actions_for_finding(finding, pipeline_state),
                    "provenance_complete": bool(truth_summary.get("provenance_complete")),
                    "replayable": bool(truth_summary.get("replayable")),
                    "evidence_reference_count": int(truth_summary.get("evidence_reference_count") or 0),
                    "raw_evidence_present": bool(truth_summary.get("raw_evidence_present")),
                    "scan_job_bound": bool(truth_summary.get("scan_job_bound")),
                }
            )

    for group in by_type.values():
        total_findings = int(group["total_findings"])
        verified = int(group["verified"])
        proof_ready = verified + int(group["reproduced"])
        group["verified_share"] = _verification_share(verified, total_findings)
        group["proof_ready_share"] = _verification_share(proof_ready, total_findings)

    overall["verified_share"] = _verification_share(
        int(overall["verified"]),
        int(overall["total_findings"]),
    )
    overall["proof_ready_share"] = _verification_share(
        int(overall["verified"]) + int(overall["reproduced"]),
        int(overall["total_findings"]),
    )

    ordered_types = sorted(
        by_type.values(),
        key=lambda item: (
            -int(item["verified"]),
            -int(item["reproduced"]),
            -int(item["queued"]),
            -_severity_rank(str(item["highest_severity"])),
            str(item["vulnerability_type"]),
        ),
    )
    queue_items.sort(
        key=lambda item: (
            -_verification_pipeline_rank(str(item.get("queue_state") or "")),
            -_severity_rank(str(item.get("severity") or "info")),
            str(item.get("title") or ""),
        )
    )

    return {
        "profile_id": _scan_profile_id(scan),
        "profile_variant": _scan_profile_variant(scan),
        "scan_type": str(scan.scan_type),
        "overall": overall,
        "by_type": ordered_types,
        "queue": queue_items[:10],
    }


def _build_field_validation_assessment(
    *,
    scan: Scan,
    context: dict[str, Any],
    planner_context: dict[str, Any],
    jobs: list[dict[str, Any]],
) -> dict[str, Any]:
    verification_summary = context.get("verification_summary") or {}
    verification_pipeline = context.get("verification_pipeline") or {}
    overall = verification_pipeline.get("overall") or {}
    queue_items = list(verification_pipeline.get("queue") or [])
    execution_contract = _scan_execution_contract(scan)
    benchmark_inputs_enabled = bool(
        execution_contract.get("benchmark_inputs_enabled")
        or (scan.config or {}).get("benchmark_inputs_enabled")
    )
    target_profile_hypotheses = list(planner_context.get("target_profile_hypotheses") or [])
    target_profile_guess = next(
        (
            str(item.get("key") or "").strip()
            for item in target_profile_hypotheses
            if str(item.get("key") or "").strip()
        ),
        None,
    )
    capability_pressures = sorted(
        list(planner_context.get("capability_pressures") or []),
        key=lambda item: float(item.get("pressure_score") or 0.0),
        reverse=True,
    )
    selected_capability_packs = _dedupe_strings(
        [str(item.get("pack_key") or "") for item in capability_pressures]
    )
    configured_execution = (
        (scan.config or {}).get("execution")
        if isinstance((scan.config or {}).get("execution"), dict)
        else {}
    )
    configured_allowed_live_tools = _dedupe_strings(
        [str(item).strip() for item in list(configured_execution.get("allowed_live_tools") or [])]
    )
    configured_approval_required = _dedupe_strings(
        [str(item).strip() for item in list(configured_execution.get("approval_required_tools") or [])]
    )
    execution_contract_live_tools = _dedupe_strings(
        [str(item).strip() for item in list(execution_contract.get("live_tools") or [])]
    )
    execution_contract_approval_required = _dedupe_strings(
        [str(item).strip() for item in list(execution_contract.get("approval_required_tools") or [])]
    )
    approval_required_tools = execution_contract_approval_required or configured_approval_required
    approved_live_tools = [
        tool for tool in configured_allowed_live_tools if tool in set(approval_required_tools)
    ]
    approval_pending_tools = [
        tool for tool in approval_required_tools if tool not in set(approved_live_tools)
    ]
    tool_policy_states = [
        {"tool": tool, "policy_state": "auto_live"}
        for tool in execution_contract_live_tools
        if tool not in set(approved_live_tools)
    ] + [
        {"tool": tool, "policy_state": "approved"}
        for tool in approved_live_tools
    ] + [
        {"tool": tool, "policy_state": "approval_required"}
        for tool in approval_pending_tools
    ] + [
        {"tool": tool, "policy_state": "derived"}
        for tool in _dedupe_strings(list(execution_contract.get("derived_tools") or []))
    ] + [
        {"tool": tool, "policy_state": "unsupported"}
        for tool in _dedupe_strings(list(execution_contract.get("unsupported_tools") or []))
    ]
    blocked_tools = _dedupe_dicts(
        [
            {
                "tool": str(job.get("tool") or ""),
                "reason": str(job.get("execution_reason") or ""),
                "provenance": str(job.get("execution_provenance") or ""),
                "policy_state": str(job.get("policy_state") or "blocked"),
            }
            for job in jobs
            if str(job.get("execution_provenance") or "") == "blocked"
            or str(job.get("execution_reason") or "") in {"approval_required", "not_supported", "target_policy_blocked"}
        ],
        key_builder=lambda item: f"{item.get('tool')}::{item.get('reason')}::{item.get('provenance')}",
    )
    capability_advisories = [
        item for item in list(planner_context.get("capability_advisories") or []) if isinstance(item, dict)
    ]
    ai_provider = next(
        (str(item.get("provider") or "").strip() for item in capability_advisories if str(item.get("provider") or "").strip()),
        None,
    )
    ai_model = next(
        (str(item.get("model") or "").strip() for item in capability_advisories if str(item.get("model") or "").strip()),
        None,
    )
    ai_transport = next(
        (
            str(item.get("transport") or "").strip()
            for item in capability_advisories
            if str(item.get("transport") or "").strip()
        ),
        None,
    )
    ai_failure_reason = next(
        (str(item.get("error") or "").strip() for item in capability_advisories if str(item.get("error") or "").strip()),
        None,
    )
    ai_fallback_active = any(
        bool(item.get("fallback_used"))
        or str(item.get("provider") or "").strip() == "heuristic"
        or str(item.get("error") or "").strip()
        for item in capability_advisories
    )
    ai_policy_state = (
        "fallback_active"
        if ai_fallback_active
        else "healthy_primary"
        if capability_advisories
        else "disabled"
    )
    evidence_gaps = _dedupe_strings(
        [
            str(item.get("readiness_reason") or "")
            for item in queue_items
            if str(item.get("queue_state") or "") == "needs_evidence"
        ]
        + [
            str(gap).strip()
            for advisory in capability_advisories
            for gap in list(advisory.get("evidence_gap_priorities") or [])
            if str(gap).strip()
        ]
    )

    assessment_state = _field_validation_assessment_state(overall)
    verification_outcomes = {
        "verified": int(overall.get("verified", 0) or 0),
        "reproduced": int(overall.get("reproduced", 0) or 0),
        "detected": int((verification_summary.get("overall") or {}).get("detected", 0) or 0),
        "needs_evidence": int(overall.get("needs_evidence", 0) or 0),
        "queued": int(overall.get("queued", 0) or 0),
        "rejected": int(overall.get("rejected", 0) or 0),
        "expired": int(overall.get("expired", 0) or 0),
    }
    proof_ready_attempts = (
        verification_outcomes["verified"]
        + verification_outcomes["reproduced"]
        + verification_outcomes["queued"]
    )
    heuristic_only_attempts = verification_outcomes["needs_evidence"]

    return {
        "generated_at": datetime.now(timezone.utc),
        "scan_id": scan.id,
        "asset_id": getattr(scan, "asset_id", None),
        "asset_name": getattr(getattr(scan, "asset", None), "name", None),
        "target": _build_asset_summary(scan).get("target") or "",
        "status": str(scan.status),
        "profile_id": _scan_profile_id(scan),
        "profile_variant": _scan_profile_variant(scan),
        "operating_mode": _field_validation_operating_mode(
            scan,
            benchmark_inputs_enabled=benchmark_inputs_enabled,
        ),
        "benchmark_inputs_enabled": benchmark_inputs_enabled,
        "benchmark_inputs_disabled_confirmed": not benchmark_inputs_enabled,
        "target_profile_guess": target_profile_guess,
        "target_profile_hypotheses": target_profile_hypotheses,
        "selected_capability_packs": selected_capability_packs,
        "approved_live_tools": approved_live_tools,
        "approval_required_tools": approval_required_tools,
        "approval_pending_tools": approval_pending_tools,
        "tool_policy_states": tool_policy_states,
        "blocked_tools": blocked_tools,
        "proof_ready_attempts": proof_ready_attempts,
        "heuristic_only_attempts": heuristic_only_attempts,
        "verification_outcomes": verification_outcomes,
        "evidence_gaps": evidence_gaps[:8],
        "ai_policy_state": ai_policy_state,
        "ai_provider": ai_provider,
        "ai_model": ai_model,
        "ai_transport": ai_transport,
        "ai_fallback_active": ai_fallback_active,
        "ai_failure_reason": ai_failure_reason,
        "assessment_state": assessment_state,
        "summary": _field_validation_summary_text(
            assessment_state=assessment_state,
            target_profile_guess=target_profile_guess,
            selected_capability_packs=selected_capability_packs,
            benchmark_inputs_enabled=benchmark_inputs_enabled,
        ),
    }


def _field_validation_assessment_state(overall: dict[str, Any]) -> str:
    verified = int(overall.get("verified", 0) or 0)
    reproduced = int(overall.get("reproduced", 0) or 0)
    needs_evidence = int(overall.get("needs_evidence", 0) or 0)
    queued = int(overall.get("queued", 0) or 0)
    total = int(overall.get("total_findings", 0) or 0)

    if verified > 0:
        return "verified"
    if reproduced > 0:
        return "reproduced"
    if needs_evidence > 0 or queued > 0:
        return "needs_evidence"
    if total > 0:
        return "detected"
    return "no_findings"


def _field_validation_summary_text(
    *,
    assessment_state: str,
    target_profile_guess: str | None,
    selected_capability_packs: list[str],
    benchmark_inputs_enabled: bool,
) -> str:
    profile_label = target_profile_guess or "unclassified_target"
    pack_text = ", ".join(selected_capability_packs[:3]) if selected_capability_packs else "no prioritized packs"
    benchmark_text = (
        "benchmark inputs still enabled"
        if benchmark_inputs_enabled
        else "benchmark inputs disabled"
    )
    return (
        f"Field validation is currently {assessment_state} on {profile_label}; "
        f"active pack pressure: {pack_text}; {benchmark_text}."
    )


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _dedupe_dicts(
    values: list[dict[str, Any]],
    *,
    key_builder,
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    ordered: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        key = str(key_builder(value) or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    return ordered


def _execution_summary_from_scan(scan: Scan) -> dict[str, int]:
    summary = scan.result_summary or {}
    if not isinstance(summary, dict):
        return {"live": 0, "simulated": 0, "blocked": 0, "inferred": 0, "derived": 0}
    execution_summary = summary.get("execution_summary") or {}
    if not isinstance(execution_summary, dict):
        return {"live": 0, "simulated": 0, "blocked": 0, "inferred": 0, "derived": 0}
    return {
        "live": int(execution_summary.get("live", 0) or 0),
        "simulated": int(execution_summary.get("simulated", 0) or 0),
        "blocked": int(execution_summary.get("blocked", 0) or 0),
        "inferred": int(execution_summary.get("inferred", 0) or 0),
        "derived": int(execution_summary.get("derived", 0) or 0),
    }


def _normalize_execution_truth(
    *,
    tool_name: str | None,
    execution_mode: Any,
    execution_provenance: Any,
    execution_reason: Any,
) -> tuple[str | None, str | None, str | None]:
    tool = str(tool_name or "").strip().lower()
    mode = str(execution_mode).strip().lower() or None if execution_mode is not None else None
    provenance = (
        str(execution_provenance).strip().lower() or None
        if execution_provenance is not None
        else None
    )
    reason = (
        str(execution_reason).strip().lower() or None
        if execution_reason is not None
        else None
    )

    if (
        tool in _DERIVED_EXECUTION_TOOLS
        and provenance == "blocked"
        and reason == "not_supported"
    ):
        return ("derived", "derived", "derived_phase")

    return (mode, provenance, reason)


def _artifact_execution_provenance(artifact_type: str, metadata: dict[str, Any] | None) -> str | None:
    if artifact_type in {"attack_graph", "report", "ai_reasoning"}:
        return "inferred"
    if not isinstance(metadata, dict):
        return None
    _mode, provenance, _reason = _normalize_execution_truth(
        tool_name=metadata.get("tool"),
        execution_mode=metadata.get("execution_mode"),
        execution_provenance=metadata.get("execution_provenance"),
        execution_reason=metadata.get("execution_reason"),
    )
    return provenance


def _artifact_execution_mode(artifact_type: str, metadata: dict[str, Any] | None) -> str | None:
    if artifact_type in {"attack_graph", "report", "ai_reasoning"}:
        return "derived"
    if not isinstance(metadata, dict):
        return None
    mode, _provenance, _reason = _normalize_execution_truth(
        tool_name=metadata.get("tool"),
        execution_mode=metadata.get("execution_mode"),
        execution_provenance=metadata.get("execution_provenance"),
        execution_reason=metadata.get("execution_reason"),
    )
    return mode


def _artifact_execution_reason(metadata: dict[str, Any] | None) -> str | None:
    if not isinstance(metadata, dict):
        return None
    _mode, _provenance, reason = _normalize_execution_truth(
        tool_name=metadata.get("tool"),
        execution_mode=metadata.get("execution_mode"),
        execution_provenance=metadata.get("execution_provenance"),
        execution_reason=metadata.get("execution_reason"),
    )
    return reason


def _normalize_execution_class(
    *,
    tool_name: str | None,
    execution_class: Any,
) -> str:
    normalized = (
        str(execution_class).strip().lower()
        if execution_class is not None
        else ""
    )
    if normalized in {"external_tool", "pentra_native"}:
        return normalized
    return classify_tool_execution(tool_name)


def _build_asset_summary(scan: Scan) -> dict[str, Any]:
    asset = scan.asset
    if asset is None:
        return {
            "id": str(scan.asset_id),
            "name": f"Asset {str(scan.asset_id)[:8]}",
            "target": str(scan.asset_id),
            "asset_type": "unknown",
            "project_name": None,
        }

    project = getattr(asset, "project", None)
    return {
        "id": str(asset.id),
        "name": asset.name,
        "target": asset.target,
        "asset_type": asset.asset_type,
        "project_id": str(asset.project_id),
        "project_name": getattr(project, "name", None),
        "description": asset.description,
    }


def _finding_target(finding: Finding) -> str:
    evidence = finding.evidence or {}
    if isinstance(evidence, dict):
        endpoint = evidence.get("endpoint")
        if endpoint:
            return str(endpoint)
        target = evidence.get("target")
        if target:
            return str(target)
        metadata = evidence.get("metadata") or {}
        if isinstance(metadata, dict):
            verification_context = metadata.get("verification_context") or {}
            if isinstance(verification_context, dict):
                endpoint = verification_context.get("endpoint") or verification_context.get("request_url")
                if endpoint:
                    return str(endpoint)
    return finding.title


def _finding_route_group(finding: Finding) -> str | None:
    evidence = finding.evidence or {}
    if not isinstance(evidence, dict):
        return None
    classification = evidence.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}
    route_group = classification.get("route_group")
    if route_group:
        return str(route_group)
    metadata = evidence.get("metadata") or {}
    if isinstance(metadata, dict):
        verification_context = metadata.get("verification_context") or {}
        if isinstance(verification_context, dict):
            route_group = verification_context.get("route_group")
            if route_group:
                return str(route_group)
    return str(route_group) if route_group else None


def _finding_vulnerability_type(finding: Finding) -> str | None:
    value = getattr(finding, "vulnerability_type", None)
    return str(value) if value else None


def _finding_snapshot(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": str(finding.severity),
        "confidence": int(finding.confidence or 0),
        "vulnerability_type": _finding_vulnerability_type(finding),
        "target": _finding_target(finding),
        "route_group": _finding_route_group(finding),
        "verification_state": _verification_state_for_finding(finding),
        "verification_confidence": getattr(finding, "verification_confidence", None),
        "truth_state": _truth_state_for_finding(finding),
        "truth_summary": getattr(finding, "truth_summary", None),
        "exploitability": getattr(finding, "exploitability", None),
        "surface": getattr(finding, "surface", None),
        "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
        "description": finding.description,
        "remediation": finding.remediation,
        "tool_source": finding.tool_source,
        "created_at": finding.created_at,
    }


def _build_finding_groups(findings: list[Finding]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}

    for finding in findings:
        surface = getattr(finding, "surface", None) or "web"
        route_group = _finding_route_group(finding)
        target = _finding_target(finding)
        label = route_group or target
        group_key = f"{surface}:{label}"
        snapshot = _finding_snapshot(finding)
        group = groups.setdefault(
            group_key,
            {
                "group_id": group_key,
                "title": label,
                "surface": surface,
                "target": target,
                "route_group": route_group,
                "severity_counts": {key: 0 for key in ("critical", "high", "medium", "low", "info")},
                "verification_counts": {"verified": 0, "suspected": 0, "detected": 0},
                "findings": [],
            },
        )
        group["severity_counts"][snapshot["severity"]] += 1
        group["verification_counts"][snapshot["verification_state"]] += 1
        group["findings"].append(snapshot)

    grouped = list(groups.values())
    for group in grouped:
        group["findings"].sort(
            key=lambda item: (
                -_verification_rank(str(item.get("verification_state") or "detected")),
                -_severity_rank(str(item.get("severity") or "info")),
                -int(item.get("confidence") or 0),
            )
        )

    return sorted(
        grouped,
        key=lambda group: (
            -_severity_rank(_highest_severity(group["severity_counts"])),
            group["title"],
        ),
    )


def _build_remediation_plan(findings: list[Finding]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        vulnerability_type = _finding_vulnerability_type(finding) or "general"
        guidance = _FIX_GUIDANCE_LIBRARY.get(vulnerability_type, {})
        entry = grouped.setdefault(
            vulnerability_type,
            {
                "plan_id": vulnerability_type,
                "title": guidance.get("title") or f"Address {vulnerability_type.replace('_', ' ')} findings",
                "priority": "low",
                "owner_hint": guidance.get("owner_hint") or "Engineering",
                "rationale": "",
                "actions": list(guidance.get("actions") or []),
                "related_finding_ids": [],
                "related_vulnerability_types": [vulnerability_type],
                "related_targets": [],
            },
        )
        snapshot = _finding_snapshot(finding)
        entry["related_finding_ids"].append(snapshot["id"])
        if snapshot["target"] not in entry["related_targets"]:
            entry["related_targets"].append(snapshot["target"])
        entry["priority"] = _higher_priority(
            entry["priority"],
            _priority_from_finding(finding),
        )
        entry["rationale"] = _merge_rationale(
            entry["rationale"],
            _finding_rationale(finding),
        )
        remediation = snapshot.get("remediation")
        if remediation and remediation not in entry["actions"]:
            entry["actions"].append(remediation)

    return sorted(grouped.values(), key=lambda item: _priority_rank(item["priority"]), reverse=True)


def _build_compliance_mappings(findings: list[Finding]) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        vulnerability_type = _finding_vulnerability_type(finding)
        if not vulnerability_type or vulnerability_type in seen:
            continue
        seen.add(vulnerability_type)
        mapping = _COMPLIANCE_LIBRARY.get(vulnerability_type, {})
        mappings.append(
            {
                "vulnerability_type": vulnerability_type,
                "owasp": list(mapping.get("owasp") or []),
                "cwe": list(mapping.get("cwe") or []),
            }
        )
    return mappings


def _build_attack_narrative(
    *,
    scan: Scan,
    graph: dict[str, Any] | None,
    findings: list[Finding],
    remediation_plan: list[dict[str, Any]],
) -> dict[str, Any] | None:
    asset_target = scan.asset.target if scan.asset is not None else str(scan.asset_id)
    graph = graph or {}
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        nodes = []
    path_summary = graph.get("path_summary") if isinstance(graph, dict) else {}
    if not isinstance(path_summary, dict):
        path_summary = {}
    targets_reached = [str(item) for item in path_summary.get("targets_reached", []) if item]

    relevant_nodes = [
        node
        for node in nodes
        if isinstance(node, dict)
        and str(node.get("node_type") or "") in {"entrypoint", "service", "endpoint", "vulnerability", "privilege"}
    ]
    relevant_nodes.sort(key=lambda node: _narrative_node_rank(str(node.get("node_type") or "")))
    steps = []
    for index, node in enumerate(relevant_nodes[:5], start=1):
        node_type = str(node.get("node_type") or "unknown")
        label = str(node.get("label") or "Unnamed node")
        steps.append(
            {
                "step": index,
                "action": _narrative_action(node_type),
                "description": _narrative_description(node_type, label),
                "target": label,
                "risk": _narrative_risk(node_type),
                "artifact_ref": node.get("artifact_ref"),
            }
        )

    if not steps and not findings:
        return None

    if not steps:
        for index, finding in enumerate(findings[:3], start=1):
            snapshot = _finding_snapshot(finding)
            steps.append(
                {
                    "step": index,
                    "action": "exploitation",
                    "description": f"Pentra confirmed {snapshot['title']} on {snapshot['target']}.",
                    "target": snapshot["target"],
                    "risk": snapshot["severity"],
                    "artifact_ref": None,
                }
            )

    total_paths = int(path_summary.get("total_paths", 0) or 0)
    summary = (
        f"Pentra identified {total_paths} attack path(s) across {asset_target}."
        if total_paths
        else f"Pentra assembled a focused attack narrative from persisted findings for {asset_target}."
    )
    impact = _impact_summary_from_targets(targets_reached, findings)
    recommendations = [item["title"] for item in remediation_plan[:3]]
    return {
        "title": f"Attack Path Narrative - {asset_target}",
        "summary": summary,
        "impact": impact,
        "steps": steps,
        "recommendations": recommendations,
        "targets_reached": targets_reached,
    }


async def _select_baseline_scan(
    *,
    scan: Scan,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    baseline_scan_id: uuid.UUID | None = None,
) -> Scan | None:
    explicit_baseline = baseline_scan_id
    config = scan.config or {}
    if explicit_baseline is None and isinstance(config, dict):
        retest_config = config.get("retest") or {}
        if isinstance(retest_config, dict):
            raw_baseline = retest_config.get("baseline_scan_id") or retest_config.get("source_scan_id")
            if raw_baseline:
                try:
                    explicit_baseline = uuid.UUID(str(raw_baseline))
                except (TypeError, ValueError):
                    explicit_baseline = None

    stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.findings), selectinload(Scan.asset).selectinload(Asset.project))
    )
    if explicit_baseline is not None:
        return (
            await session.execute(stmt.where(Scan.id == explicit_baseline))
        ).scalar_one_or_none()

    comparison_stmt = (
        stmt.where(
            Scan.asset_id == scan.asset_id,
            Scan.id != scan.id,
            Scan.status == "completed",
            Scan.created_at < scan.created_at,
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return (await session.execute(comparison_stmt)).scalar_one_or_none()


def _build_scan_comparison(
    *,
    current_scan: Scan,
    current_findings: list[Finding],
    baseline_scan: Scan | None,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc)
    if baseline_scan is None:
        return {
            "current_scan_id": current_scan.id,
            "baseline_scan_id": None,
            "generated_at": generated_at,
            "baseline_generated_at": None,
            "summary": "No previous completed scan is available for historical comparison yet.",
            "counts": {"new": len(current_findings), "resolved": 0, "persistent": 0, "escalated": 0},
            "severity_delta": _count_severity(current_findings),
            "verification_delta": _count_verification(current_findings),
            "new_findings": [_finding_snapshot(finding) for finding in current_findings[:5]],
            "resolved_findings": [],
            "escalated_findings": [],
        }

    baseline_findings = _sort_findings_for_report(baseline_scan.findings)
    current_by_key = {_finding_comparison_key(item): item for item in current_findings}
    baseline_by_key = {_finding_comparison_key(item): item for item in baseline_findings}

    new_keys = [key for key in current_by_key if key not in baseline_by_key]
    resolved_keys = [key for key in baseline_by_key if key not in current_by_key]
    persistent_keys = [key for key in current_by_key if key in baseline_by_key]
    escalated_keys = [
        key
        for key in persistent_keys
        if _finding_has_escalated(current_by_key[key], baseline_by_key[key])
    ]

    severity_delta = {
        level: _count_severity(current_findings).get(level, 0) - _count_severity(baseline_findings).get(level, 0)
        for level in ("critical", "high", "medium", "low", "info")
    }
    verification_delta = {
        level: _count_verification(current_findings).get(level, 0) - _count_verification(baseline_findings).get(level, 0)
        for level in ("verified", "suspected", "detected")
    }
    summary = (
        f"Compared with the baseline from {baseline_scan.completed_at or baseline_scan.created_at:%b %d, %Y}, "
        f"Pentra found {len(new_keys)} new, {len(resolved_keys)} resolved, and {len(persistent_keys)} persistent findings."
    )

    return {
        "current_scan_id": current_scan.id,
        "baseline_scan_id": baseline_scan.id,
        "generated_at": generated_at,
        "baseline_generated_at": baseline_scan.completed_at or baseline_scan.created_at,
        "summary": summary,
        "counts": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "persistent": len(persistent_keys),
            "escalated": len(escalated_keys),
        },
        "severity_delta": severity_delta,
        "verification_delta": verification_delta,
        "new_findings": [_finding_snapshot(current_by_key[key]) for key in new_keys[:5]],
        "resolved_findings": [_finding_snapshot(baseline_by_key[key]) for key in resolved_keys[:5]],
        "escalated_findings": [_finding_snapshot(current_by_key[key]) for key in escalated_keys[:5]],
    }


def _build_retest_summary(scan: Scan, comparison: dict[str, Any]) -> dict[str, Any]:
    return {
        "eligible": scan.status == "completed",
        "recommended_scan_type": scan.scan_type,
        "recommended_priority": _recommended_retest_priority(scan),
        "baseline_scan_id": str(scan.id),
        "compare_against_scan_id": str(comparison.get("baseline_scan_id")) if comparison.get("baseline_scan_id") else None,
        "launch_endpoint": f"/api/v1/scans/{scan.id}/retest",
    }


def _build_retest_config(
    *,
    source_scan: Scan,
    config_overrides: dict[str, Any],
) -> dict[str, Any]:
    base_config = deepcopy(source_scan.config or {})
    if not isinstance(base_config, dict):
        base_config = {}
    overrides = deepcopy(config_overrides or {})
    if not isinstance(overrides, dict):
        overrides = {}

    base_retest = base_config.get("retest") if isinstance(base_config.get("retest"), dict) else {}
    override_retest = overrides.get("retest") if isinstance(overrides.get("retest"), dict) else {}
    merged = {
        **base_config,
        **{key: value for key, value in overrides.items() if key != "retest"},
    }
    merged["retest"] = {
        **base_retest,
        **override_retest,
        "mode": "buyer_ready_retest",
        "baseline_scan_id": str(source_scan.id),
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "targets": _build_retest_targets(source_scan.findings),
    }
    return merged


def _build_retest_targets(findings: list[Finding]) -> list[dict[str, Any]]:
    targets = []
    for finding in _sort_findings_for_report(findings)[:10]:
        snapshot = _finding_snapshot(finding)
        targets.append(
            {
                "finding_id": snapshot["id"],
                "title": snapshot["title"],
                "vulnerability_type": snapshot["vulnerability_type"],
                "target": snapshot["target"],
                "route_group": snapshot["route_group"],
                "verification_state": snapshot["verification_state"],
            }
        )
    return targets


def _recommended_retest_priority(scan: Scan) -> str:
    summary = scan.result_summary or {}
    severity_counts = summary.get("severity_counts") if isinstance(summary, dict) else {}
    if isinstance(severity_counts, dict):
        if int(severity_counts.get("critical", 0) or 0) > 0:
            return "high"
        if int(severity_counts.get("high", 0) or 0) > 0:
            return "high"
    return str(scan.priority)


def _build_report_csv(report: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "finding_id",
            "title",
            "severity",
            "verification_state",
            "vulnerability_type",
            "target",
            "route_group",
            "exploitability",
            "confidence",
            "remediation",
        ],
    )
    writer.writeheader()

    for group in report.get("finding_groups", []):
        if not isinstance(group, dict):
            continue
        for finding in group.get("findings", []):
            if not isinstance(finding, dict):
                continue
            writer.writerow(
                {
                    "finding_id": finding.get("id"),
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "verification_state": finding.get("verification_state"),
                    "vulnerability_type": finding.get("vulnerability_type"),
                    "target": finding.get("target"),
                    "route_group": finding.get("route_group"),
                    "exploitability": finding.get("exploitability"),
                    "confidence": finding.get("confidence"),
                    "remediation": finding.get("remediation"),
                }
            )

    return output.getvalue()


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, uuid.UUID)):
        return str(value)
    return value


def _slugify(value: str) -> str:
    cleaned = "".join(char.lower() if char.isalnum() else "-" for char in value)
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "scan"


async def _post_json_payload(
    *,
    destination_url: str,
    payload: dict[str, Any],
    custom_headers: dict[str, str] | None,
    authorization_header: str | None,
    extra_headers: dict[str, str] | None = None,
) -> int:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    if authorization_header:
        headers["Authorization"] = authorization_header
    if custom_headers:
        headers.update(custom_headers)

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        response = await client.post(destination_url, json=payload, headers=headers)
        response.raise_for_status()
        return response.status_code


def _destination_host(destination_url: str | None) -> str:
    if not destination_url:
        return "unknown"
    parsed = urlparse(destination_url)
    return parsed.netloc or parsed.path or "unknown"


def _build_webhook_notification_payload(
    *,
    report: dict[str, Any],
    delivered_at: datetime,
    top_findings_limit: int,
    include_markdown: bool,
    include_html: bool,
) -> dict[str, Any]:
    top_findings = list(report.get("top_findings") or [])[:top_findings_limit]
    payload: dict[str, Any] = {
        "event": "scan.report.generated",
        "sent_at": delivered_at.isoformat(),
        "scan_id": str(report.get("scan_id")),
        "report_id": str(report.get("report_id") or ""),
        "asset": report.get("asset") or {},
        "executive_summary": report.get("executive_summary") or "",
        "severity_counts": report.get("severity_counts") or {},
        "verification_counts": report.get("verification_counts") or {},
        "execution_summary": report.get("execution_summary") or {},
        "top_findings": top_findings,
        "comparison": report.get("comparison") or None,
        "retest": report.get("retest") or None,
    }
    if include_markdown:
        payload["report_markdown"] = report.get("markdown") or ""
    if include_html:
        payload["report_html"] = _build_report_html(report)
    return payload


def _build_slack_notification_payload(
    *,
    report: dict[str, Any],
    delivered_at: datetime,
    top_findings_limit: int,
) -> dict[str, Any]:
    asset = report.get("asset") or {}
    severity_counts = report.get("severity_counts") or {}
    verification_counts = report.get("verification_counts") or {}
    top_findings = list(report.get("top_findings") or [])[:top_findings_limit]
    findings_lines = [
        f"- {finding.get('title')} ({str(finding.get('severity') or 'info').upper()}, {str(finding.get('verification_state') or 'detected').upper()})"
        for finding in top_findings
        if isinstance(finding, dict)
    ]
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Pentra report ready for {asset.get('name') or asset.get('target') or report.get('scan_id')}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": str(report.get("executive_summary") or "Pentra generated a scan report."),
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Critical*\n{int(severity_counts.get('critical', 0) or 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*High*\n{int(severity_counts.get('high', 0) or 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Verified*\n{int(verification_counts.get('verified', 0) or 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Generated*\n{delivered_at.strftime('%Y-%m-%d %H:%M UTC')}",
                },
            ],
        },
    ]
    if findings_lines:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top findings*\n" + "\n".join(findings_lines),
                },
            }
        )

    return {
        "text": f"Pentra report ready for {asset.get('target') or report.get('scan_id')}",
        "blocks": blocks,
    }


def _select_findings_for_issue_export(
    *,
    findings: list[Finding],
    minimum_severity: str,
    verified_only: bool,
    max_issues: int,
) -> list[Finding]:
    selected: list[Finding] = []
    minimum_rank = _severity_rank(minimum_severity)
    for finding in _sort_findings_for_report(findings):
        truth_state = _truth_state_for_finding(finding)
        if getattr(finding, "is_false_positive", False) or truth_state in {"rejected", "expired"}:
            continue
        if _severity_rank(str(finding.severity)) < minimum_rank:
            continue
        if verified_only and truth_state != "verified":
            continue
        selected.append(finding)
        if len(selected) >= max_issues:
            break
    return selected


def _issue_labels(snapshot: dict[str, Any]) -> list[str]:
    labels = [
        "pentra",
        f"severity:{snapshot.get('severity') or 'info'}",
        f"verification:{snapshot.get('verification_state') or 'detected'}",
    ]
    vulnerability_type = snapshot.get("vulnerability_type")
    if vulnerability_type:
        labels.append(f"vuln:{_slugify(str(vulnerability_type))}")
    return labels


def _issue_title(report: dict[str, Any], finding_snapshot: dict[str, Any]) -> str:
    asset = report.get("asset") or {}
    severity = str(finding_snapshot.get("severity") or "info").upper()
    title = str(finding_snapshot.get("title") or "Untitled finding")
    asset_name = str(asset.get("name") or asset.get("target") or report.get("scan_id"))
    return f"[{severity}] {title} on {asset_name}"


def _issue_body_markdown(report: dict[str, Any], finding_snapshot: dict[str, Any]) -> str:
    asset = report.get("asset") or {}
    description = finding_snapshot.get("description") or "No description provided."
    remediation = finding_snapshot.get("remediation") or "No remediation guidance captured."
    return "\n".join(
        [
            f"## Pentra Finding: {finding_snapshot.get('title')}",
            "",
            f"- Asset: {asset.get('name') or asset.get('target') or report.get('scan_id')}",
            f"- Target: {finding_snapshot.get('target')}",
            f"- Severity: {finding_snapshot.get('severity')}",
            f"- Verification: {finding_snapshot.get('verification_state')}",
            f"- Tool Source: {finding_snapshot.get('tool_source')}",
            f"- Scan ID: {report.get('scan_id')}",
            "",
            "### Why this matters",
            "",
            str(description),
            "",
            "### Recommended remediation",
            "",
            str(remediation),
            "",
            "### Pentra executive summary",
            "",
            str(report.get("executive_summary") or ""),
        ]
    )


def _github_issue_target_url(repository: str) -> str:
    return f"https://api.github.com/repos/{repository}/issues"


def _build_github_issue_payload(
    *,
    report: dict[str, Any],
    finding_snapshot: dict[str, Any],
    labels: list[str],
) -> dict[str, Any]:
    return {
        "title": _issue_title(report, finding_snapshot),
        "body": _issue_body_markdown(report, finding_snapshot),
        "labels": labels,
    }


def _jira_text_document(text_value: str) -> dict[str, Any]:
    content: list[dict[str, Any]] = []
    for chunk in [part.strip() for part in text_value.split("\n\n") if part.strip()]:
        lines = [line.strip() for line in chunk.splitlines() if line.strip()]
        bullet_lines = [line[2:].strip() for line in lines if line.startswith("- ")]
        if bullet_lines and len(bullet_lines) == len(lines):
            content.append(
                {
                    "type": "bulletList",
                    "content": [
                        {
                            "type": "listItem",
                            "content": [
                                {
                                    "type": "paragraph",
                                    "content": [{"type": "text", "text": bullet_line}],
                                }
                            ],
                        }
                        for bullet_line in bullet_lines
                    ],
                }
            )
            continue
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": " ".join(lines)}],
            }
        )
    return {"type": "doc", "version": 1, "content": content}


def _build_jira_issue_payload(
    *,
    report: dict[str, Any],
    finding_snapshot: dict[str, Any],
    labels: list[str],
    project_key: str,
) -> dict[str, Any]:
    description = _issue_body_markdown(report, finding_snapshot)
    return {
        "fields": {
            "project": {"key": project_key},
            "summary": _issue_title(report, finding_snapshot),
            "issuetype": {"name": "Bug"},
            "labels": labels,
            "description": _jira_text_document(description),
        }
    }


def _resolve_issue_destination_url(
    *,
    provider: str,
    destination_url: str | None,
    base_url: str | None,
    repository: str | None,
) -> str | None:
    if destination_url:
        return destination_url
    if provider == "github" and repository:
        return _github_issue_target_url(repository)
    if provider == "jira" and base_url:
        return f"{base_url.rstrip('/')}/rest/api/3/issue"
    return None


def _issue_delivery_headers(provider: str) -> dict[str, str]:
    if provider == "github":
        return {"Accept": "application/vnd.github+json"}
    return {"Accept": "application/json"}


def _finding_comparison_key(finding: Finding) -> str:
    vulnerability_type = _finding_vulnerability_type(finding) or finding.title.lower()
    route_group = _finding_route_group(finding) or _finding_target(finding)
    return f"{vulnerability_type}:{route_group}".lower()


def _finding_has_escalated(current: Finding, baseline: Finding) -> bool:
    if _severity_rank(str(current.severity)) > _severity_rank(str(baseline.severity)):
        return True
    return _verification_rank(_verification_state_for_finding(current)) > _verification_rank(
        _verification_state_for_finding(baseline)
    )


def _priority_from_finding(finding: Finding) -> str:
    if _verification_state_for_finding(finding) == "verified" and str(finding.severity) in {"critical", "high"}:
        return "immediate"
    if str(finding.severity) in {"critical", "high"}:
        return "high"
    if str(finding.severity) == "medium":
        return "medium"
    return "low"


def _priority_rank(priority: str) -> int:
    return {"immediate": 4, "high": 3, "medium": 2, "low": 1}.get(priority, 0)


def _higher_priority(left: str, right: str) -> str:
    return left if _priority_rank(left) >= _priority_rank(right) else right


def _finding_rationale(finding: Finding) -> str:
    vulnerability_type = (_finding_vulnerability_type(finding) or "finding").replace("_", " ")
    target = _finding_target(finding)
    verification = _verification_state_for_finding(finding)
    return f"{str(finding.severity).capitalize()} {verification} {vulnerability_type} affecting {target}."


def _merge_rationale(existing: str, candidate: str) -> str:
    if not existing:
        return candidate
    if candidate and candidate not in existing:
        return f"{existing} {candidate}"
    return existing


def _highest_severity(severity_counts: dict[str, int]) -> str:
    for level in ("critical", "high", "medium", "low", "info"):
        if int(severity_counts.get(level, 0) or 0) > 0:
            return level
    return "info"


def _narrative_node_rank(node_type: str) -> int:
    return {
        "entrypoint": 0,
        "service": 1,
        "endpoint": 2,
        "vulnerability": 3,
        "privilege": 4,
    }.get(node_type, 5)


def _narrative_action(node_type: str) -> str:
    return {
        "entrypoint": "discovery",
        "service": "enumeration",
        "endpoint": "enumeration",
        "vulnerability": "exploitation",
        "privilege": "impact",
    }.get(node_type, "analysis")


def _narrative_description(node_type: str, label: str) -> str:
    return {
        "entrypoint": f"The attack path begins from {label}.",
        "service": f"Pentra identified an exposed service surface at {label}.",
        "endpoint": f"Pentra traversed the reachable application endpoint {label}.",
        "vulnerability": f"Pentra connected offensive evidence to the vulnerability node {label}.",
        "privilege": f"The path can terminate in the privileged state {label}.",
    }.get(node_type, f"Pentra analyzed {label}.")


def _narrative_risk(node_type: str) -> str:
    return {
        "entrypoint": "medium",
        "service": "medium",
        "endpoint": "medium",
        "vulnerability": "high",
        "privilege": "critical",
    }.get(node_type, "low")


def _impact_summary_from_targets(targets_reached: list[str], findings: list[Finding]) -> str:
    if "shell_access" in targets_reached:
        return "Attack paths show a route to shell-level access if the identified weaknesses remain exploitable."
    if "database_access" in targets_reached:
        return "Attack paths show reachable database access and sensitive data exposure risk."
    if any(_finding_vulnerability_type(finding) == "auth_bypass" for finding in findings):
        return "Broken access control creates a credible path to privileged workflow abuse."
    if any(_finding_vulnerability_type(finding) == "idor" for finding in findings):
        return "Object-level authorization gaps allow sensitive records to be reached without the correct principal."
    return "The offensive graph shows exploitable web and API weaknesses that engineering should remediate in priority order."


def _timeline_event_type(phase: int) -> str:
    if phase <= 1:
        return "recon"
    if phase <= 3:
        return "vuln"
    if phase == 4:
        return "exploit"
    if phase == 5:
        return "analysis"
    return "report"


def _artifact_timeline_details(artifact_type: str, metadata: dict | None) -> str:
    metadata = metadata or {}
    item_count = int(metadata.get("item_count", 0) or 0)
    finding_count = int(metadata.get("finding_count", 0) or 0)
    evidence_count = int(metadata.get("evidence_count", 0) or 0)
    provenance = _artifact_execution_provenance(artifact_type, metadata)
    parts = [artifact_type, f"items {item_count}", f"findings {finding_count}", f"evidence {evidence_count}"]
    if provenance:
        parts.append(f"truth {provenance}")
    return " · ".join(parts)


def _empty_attack_graph_payload(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.id,
        "tenant_id": scan.tenant_id,
        "built_at": None,
        "node_count": 0,
        "edge_count": 0,
        "path_summary": {
            "total_paths": 0,
            "targets_reached": [],
            "shortest_path": 0,
        },
        "scoring_summary": {},
        "nodes": [],
        "edges": [],
    }


def _build_evidence_references(findings: list[Finding]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        evidence = finding.evidence or {}
        if not isinstance(evidence, dict):
            continue

        target = str(
            evidence.get("endpoint")
            or evidence.get("target")
            or "unknown"
        )
        storage_ref = evidence.get("storage_ref")
        raw_signatures: set[str] = set()

        for evidence_type in ("request", "response", "payload", "exploit_result"):
            content = evidence.get(evidence_type)
            if not content:
                continue

            candidate = {
                "id": f"{finding.id}:{evidence_type}",
                "finding_id": finding.id,
                "finding_title": finding.title,
                "severity": finding.severity,
                "tool_source": finding.tool_source,
                "evidence_type": evidence_type,
                "label": f"{finding.title} · {evidence_type.replace('_', ' ')}",
                "target": target,
                "content_preview": str(content)[:240],
                "content": str(content),
                "storage_ref": storage_ref,
                "metadata": {},
            }
            signature = _evidence_signature(candidate)
            raw_signatures.add(signature)
            _upsert_evidence_reference(deduped, signature, candidate)

        references = evidence.get("references", [])
        if not isinstance(references, list):
            continue

        for index, reference in enumerate(references):
            if isinstance(reference, dict):
                evidence_type = str(reference.get("evidence_type", "reference"))
                preview = str(reference.get("content_preview", ""))
                reference_id = reference.get("id") or f"{finding.id}:reference:{index}"
                reference_storage_ref = reference.get("storage_ref") or storage_ref
                label = reference.get("label", finding.title)
            else:
                evidence_type = "reference"
                preview = str(reference)
                reference_id = f"{finding.id}:reference:{index}"
                reference_storage_ref = storage_ref
                label = f"{finding.title} · reference"

            candidate = {
                "id": reference_id,
                "finding_id": finding.id,
                "finding_title": finding.title,
                "severity": finding.severity,
                "tool_source": finding.tool_source,
                "evidence_type": evidence_type,
                "label": label,
                "target": target,
                "content_preview": preview,
                "content": None,
                "storage_ref": reference_storage_ref,
                "metadata": {},
            }
            signature = _evidence_signature(candidate)
            if evidence_type != "reference" and signature in raw_signatures:
                continue
            _upsert_evidence_reference(deduped, signature, candidate)

    return sorted(
        deduped.values(),
        key=lambda item: (
            -_severity_rank(str(item.get("severity", "info"))),
            -_evidence_rank(str(item.get("evidence_type", "reference"))),
            str(item.get("finding_title", "")),
            str(item.get("label", "")),
        ),
    )


def _evidence_signature(item: dict[str, Any]) -> str:
    storage_ref = str(item.get("storage_ref") or "")
    base_storage_ref = storage_ref.split("#", 1)[0]
    content = str(item.get("content") or item.get("content_preview") or "").strip()
    return "|".join(
        [
            str(item.get("evidence_type", "reference")),
            str(item.get("target", "")),
            base_storage_ref,
            content[:240],
        ]
    )


def _upsert_evidence_reference(
    deduped: dict[str, dict[str, Any]],
    signature: str,
    candidate: dict[str, Any],
) -> None:
    existing = deduped.get(signature)
    candidate = {
        **candidate,
        "metadata": {
            **candidate.get("metadata", {}),
            "related_findings": [candidate.get("finding_title")] if candidate.get("finding_title") else [],
            "duplicate_count": 1,
        },
    }

    if existing is None:
        deduped[signature] = candidate
        return

    _merge_related_finding(existing, candidate.get("finding_title"))
    existing["metadata"]["duplicate_count"] = int(existing["metadata"].get("duplicate_count", 1)) + 1

    if _evidence_preference(candidate) > _evidence_preference(existing):
        candidate["metadata"] = existing["metadata"]
        deduped[signature] = candidate


def _merge_related_finding(item: dict[str, Any], finding_title: str | None) -> None:
    if not finding_title:
        return
    metadata = item.setdefault("metadata", {})
    related = metadata.setdefault("related_findings", [])
    if finding_title not in related:
        related.append(finding_title)


def _evidence_preference(item: dict[str, Any]) -> tuple[int, int, int]:
    return (
        1 if item.get("content") else 0,
        _severity_rank(str(item.get("severity", "info"))),
        _evidence_rank(str(item.get("evidence_type", "reference"))),
    )


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(severity, 0)


def _evidence_rank(evidence_type: str) -> int:
    return {
        "exploit_result": 5,
        "response": 4,
        "request": 3,
        "payload": 2,
        "reference": 1,
    }.get(evidence_type, 0)


def _verification_state_for_finding(finding: Finding) -> str:
    state = getattr(finding, "verification_state", None)
    if state in {"verified", "suspected", "detected"}:
        return str(state)
    if finding.source_type == "exploit_verify":
        return "verified"
    if finding.source_type == "ai_analysis":
        return "suspected"
    return "detected"


def _truth_state_for_finding(finding: Finding) -> str:
    state = getattr(finding, "truth_state", None)
    if state in {"observed", "suspected", "reproduced", "verified", "rejected", "expired"}:
        return str(state)

    verification_state = _verification_state_for_finding(finding)
    if getattr(finding, "is_false_positive", False):
        return "rejected"
    if verification_state == "verified":
        return "verified"
    if verification_state == "suspected":
        return "suspected"
    return "observed"


def _verification_rank(state: str) -> int:
    return {
        "verified": 3,
        "suspected": 2,
        "detected": 1,
    }.get(state, 0)


def _truth_rank(state: str) -> int:
    return {
        "verified": 6,
        "reproduced": 5,
        "suspected": 4,
        "observed": 3,
        "expired": 2,
        "rejected": 1,
    }.get(state, 0)


def _verification_pipeline_state_for_finding(finding: Finding) -> str:
    truth_state = _truth_state_for_finding(finding)
    if truth_state in {"verified", "reproduced", "rejected", "expired"}:
        return truth_state

    summary = _truth_summary_for_finding(finding)
    provenance_complete = bool(summary.get("provenance_complete"))
    evidence_reference_count = int(summary.get("evidence_reference_count") or 0)
    raw_evidence_present = bool(summary.get("raw_evidence_present"))
    scan_job_bound = bool(summary.get("scan_job_bound"))

    if provenance_complete and scan_job_bound and (evidence_reference_count > 0 or raw_evidence_present):
        return "queued"
    return "needs_evidence"


def _verification_pipeline_rank(state: str) -> int:
    return {
        "verified": 6,
        "reproduced": 5,
        "queued": 4,
        "needs_evidence": 3,
        "expired": 2,
        "rejected": 1,
    }.get(state, 0)


def _truth_summary_for_finding(finding: Finding) -> dict[str, Any]:
    summary = getattr(finding, "truth_summary", None)
    return dict(summary) if isinstance(summary, dict) else {}


def _verification_pipeline_reason(state: str, finding: Finding) -> str:
    if state == "verified":
        return "Replayable proof is present and the finding is promotion-eligible."
    if state == "reproduced":
        return "Verification exists, but replayable proof or provenance is still incomplete."
    if state == "queued":
        return "Evidence is sufficient to enqueue bounded verification."
    if state == "needs_evidence":
        return "Additional provenance or proof material is required before verification."
    if state == "rejected":
        return "This record is excluded from trusted output until contradictory proof appears."
    if state == "expired":
        return "Verification evidence is stale and should be refreshed before promotion."
    return f"Verification state is currently {state}."


def _verification_pipeline_actions_for_finding(finding: Finding, state: str) -> list[str]:
    summary = _truth_summary_for_finding(finding)
    actions: list[str] = []

    if state == "reproduced":
        if not bool(summary.get("replayable")):
            actions.append("Attach replay instructions or persisted verifier proof before promotion.")
        if not bool(summary.get("provenance_complete")):
            actions.append("Complete provenance metadata for the reproduced proof.")
    elif state == "queued":
        actions.append("Run bounded verification against the persisted target context.")
        if not bool(summary.get("replayable")):
            actions.append("Capture replayable verifier output when the verification run completes.")
    elif state == "needs_evidence":
        if not bool(summary.get("provenance_complete")):
            actions.append("Attach source, target, and persisted evidence provenance.")
        if int(summary.get("evidence_reference_count") or 0) == 0 and not bool(summary.get("raw_evidence_present")):
            actions.append("Persist request, response, or payload proof material.")
        if not bool(summary.get("scan_job_bound")):
            actions.append("Link the producing scan job before verification.")
        if not bool(summary.get("replayable")):
            actions.append("Capture replayable verification context for follow-up work.")
    elif state == "expired":
        actions.append("Re-run bounded verification to refresh proof.")
    elif state == "rejected":
        actions.append("Keep excluded unless contradictory replayable proof is captured.")

    deduped: list[str] = []
    seen: set[str] = set()
    for action in actions:
        normalized = str(action).strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(normalized)
    return deduped


def _build_executive_summary(
    asset_target: str,
    severity_counts: dict[str, int],
    verification_counts: dict[str, int],
) -> str:
    total = sum(severity_counts.values())
    if total == 0:
        return f"Autonomous assessment of {asset_target} completed with no persisted findings."

    parts = [f"Autonomous assessment of {asset_target} identified {total} persisted findings"]
    if severity_counts["critical"]:
        parts.append(f"{severity_counts['critical']} critical")
    if severity_counts["high"]:
        parts.append(f"{severity_counts['high']} high")
    if severity_counts["medium"]:
        parts.append(f"{severity_counts['medium']} medium")
    if verification_counts.get("verified"):
        parts.append(f"{verification_counts['verified']} verified")
    if verification_counts.get("suspected"):
        parts.append(f"{verification_counts['suspected']} suspected")
    return ", ".join(parts) + "."


def _build_report_html(report: dict[str, Any]) -> str:
    asset = report.get("asset", {}) if isinstance(report, dict) else {}
    comparison = report.get("comparison") or {}
    narrative = report.get("narrative") or {}
    remediation_plan = report.get("remediation_plan") or []
    top_findings = report.get("top_findings") or []
    severity_counts = report.get("severity_counts") or {}
    verification_counts = report.get("verification_counts") or {}
    verification_summary = report.get("verification_summary") or {}
    verification_pipeline = report.get("verification_pipeline") or {}
    execution_summary = report.get("execution_summary") or {}

    def metric_card(label: str, value: Any, accent: str) -> str:
        return (
            "<div class='metric-card'>"
            f"<div class='metric-label'>{html_escape(label)}</div>"
            f"<div class='metric-value' style='color:{accent}'>{html_escape(str(value))}</div>"
            "</div>"
        )

    remediation_items = "".join(
        (
            "<section class='panel'>"
            f"<h3>{html_escape(str(item.get('title') or 'Remediation item'))}</h3>"
            f"<p><strong>Priority:</strong> {html_escape(str(item.get('priority') or 'low'))}</p>"
            f"<p><strong>Owner:</strong> {html_escape(str(item.get('owner_hint') or 'Engineering'))}</p>"
            f"<p>{html_escape(str(item.get('rationale') or ''))}</p>"
            "<ul>"
            + "".join(
                f"<li>{html_escape(str(action))}</li>"
                for action in (item.get("actions") or [])
            )
            + "</ul>"
            "</section>"
        )
        for item in remediation_plan
        if isinstance(item, dict)
    ) or "<section class='panel'><p>No remediation plan items were generated.</p></section>"

    top_finding_items = "".join(
        (
            "<section class='panel finding'>"
            f"<h3>{html_escape(str(finding.get('title') or 'Untitled finding'))}</h3>"
            f"<p><strong>Severity:</strong> {html_escape(str(finding.get('severity') or 'info'))}</p>"
            f"<p><strong>Verification:</strong> {html_escape(str(finding.get('verification_state') or 'detected'))}</p>"
            f"<p><strong>Target:</strong> {html_escape(str(finding.get('target') or 'unknown'))}</p>"
            f"<p>{html_escape(str(finding.get('description') or 'No description provided.'))}</p>"
            "</section>"
        )
        for finding in top_findings
        if isinstance(finding, dict)
    ) or "<section class='panel'><p>No persisted findings were available.</p></section>"

    attack_steps = ""
    steps = narrative.get("steps") or []
    if isinstance(steps, list) and steps:
        attack_steps = (
            "<ol class='steps'>"
            + "".join(
                (
                    "<li>"
                    f"<strong>{html_escape(str(step.get('action') or 'step'))}</strong> - "
                    f"{html_escape(str(step.get('description') or ''))}"
                    f"<div class='step-meta'>Target: {html_escape(str(step.get('target') or 'unknown'))} | "
                    f"Risk: {html_escape(str(step.get('risk') or 'low'))}</div>"
                    "</li>"
                )
                for step in steps
                if isinstance(step, dict)
            )
            + "</ol>"
        )

    comparison_html = (
        "<section class='panel'>"
        f"<h3>Historical Comparison</h3><p>{html_escape(str(comparison.get('summary') or 'No historical comparison available.'))}</p>"
        "<div class='stats-row'>"
        f"{metric_card('New', (comparison.get('counts') or {}).get('new', 0), '#b45309')}"
        f"{metric_card('Resolved', (comparison.get('counts') or {}).get('resolved', 0), '#047857')}"
        f"{metric_card('Persistent', (comparison.get('counts') or {}).get('persistent', 0), '#1f2937')}"
        f"{metric_card('Escalated', (comparison.get('counts') or {}).get('escalated', 0), '#b91c1c')}"
        "</div>"
        "</section>"
    )

    pipeline_overall = verification_pipeline.get("overall") or {}
    pipeline_queue = verification_pipeline.get("queue") or []
    pipeline_html = (
        "<section class='panel'>"
        "<h3>Verification Pipeline</h3>"
        "<div class='stats-row'>"
        f"{metric_card('Verified', pipeline_overall.get('verified', 0), '#047857')}"
        f"{metric_card('Reproduced', pipeline_overall.get('reproduced', 0), '#1d4ed8')}"
        f"{metric_card('Queued', pipeline_overall.get('queued', 0), '#7c3aed')}"
        f"{metric_card('Needs Evidence', pipeline_overall.get('needs_evidence', 0), '#b45309')}"
        "</div>"
    )
    if pipeline_queue:
        pipeline_html += (
            "<div class='stack' style='margin-top:18px;'>"
            + "".join(
                (
                    "<section class='panel'>"
                    f"<h3>{html_escape(str(item.get('title') or 'Queued verification item'))}</h3>"
                    f"<p><strong>State:</strong> {html_escape(str(item.get('queue_state') or 'queued'))}</p>"
                    f"<p><strong>Reason:</strong> {html_escape(str(item.get('readiness_reason') or ''))}</p>"
                    + (
                        "<ul>"
                        + "".join(
                            f"<li>{html_escape(str(action))}</li>"
                            for action in (item.get("required_actions") or [])
                        )
                        + "</ul>"
                    )
                    + "</section>"
                )
                for item in pipeline_queue[:5]
                if isinstance(item, dict)
            )
            + "</div>"
        )
    else:
        pipeline_html += "<p>No verification queue items are pending.</p>"
    pipeline_html += "</section>"

    return f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Pentra Report - {html_escape(str(asset.get("target") or report.get("scan_id") or "scan"))}</title>
    <style>
      :root {{
        color-scheme: light;
        --bg: #f3f4f6;
        --panel: #ffffff;
        --border: #d1d5db;
        --ink: #111827;
        --muted: #4b5563;
        --accent: #b91c1c;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        background: linear-gradient(180deg, #fff7ed 0%, var(--bg) 18%, #eef2ff 100%);
        color: var(--ink);
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        line-height: 1.5;
      }}
      .page {{
        max-width: 1120px;
        margin: 0 auto;
        padding: 40px 20px 64px;
      }}
      .hero {{
        background: radial-gradient(circle at top right, #fecaca 0%, #ffffff 45%, #eff6ff 100%);
        border: 1px solid var(--border);
        border-radius: 24px;
        padding: 28px;
        box-shadow: 0 24px 80px rgba(15, 23, 42, 0.08);
      }}
      .eyebrow {{
        color: var(--accent);
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }}
      h1, h2, h3 {{ margin: 0 0 10px; }}
      h1 {{ font-size: 36px; line-height: 1.1; }}
      h2 {{ font-size: 24px; margin-top: 32px; }}
      h3 {{ font-size: 18px; }}
      p {{ margin: 0 0 12px; color: var(--muted); }}
      .meta {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-top: 20px;
      }}
      .panel, .metric-card {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 18px;
      }}
      .stats-row {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 12px;
        margin-top: 18px;
      }}
      .metric-label {{
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
      }}
      .metric-value {{
        font-size: 28px;
        font-weight: 700;
        margin-top: 8px;
      }}
      .grid {{
        display: grid;
        grid-template-columns: 1.2fr 0.8fr;
        gap: 18px;
        margin-top: 24px;
      }}
      .stack {{
        display: grid;
        gap: 16px;
      }}
      .finding {{
        border-left: 4px solid var(--accent);
      }}
      ul, ol {{
        margin: 12px 0 0 20px;
        color: var(--muted);
      }}
      .steps li {{
        margin-bottom: 12px;
      }}
      .step-meta {{
        color: var(--muted);
        font-size: 13px;
        margin-top: 4px;
      }}
      @media (max-width: 860px) {{
        .grid {{
          grid-template-columns: 1fr;
        }}
        h1 {{
          font-size: 28px;
        }}
      }}
    </style>
  </head>
  <body>
    <main class="page">
      <section class="hero">
        <div class="eyebrow">Pentra Offensive Validation Report</div>
        <h1>{html_escape(str(asset.get("name") or asset.get("target") or report.get("scan_id") or "Scan Report"))}</h1>
        <p>{html_escape(str(report.get("executive_summary") or ""))}</p>
        <div class="meta">
          <div class="panel"><strong>Target</strong><p>{html_escape(str(asset.get("target") or "unknown"))}</p></div>
          <div class="panel"><strong>Project</strong><p>{html_escape(str(asset.get("project_name") or "Unassigned"))}</p></div>
          <div class="panel"><strong>Asset Type</strong><p>{html_escape(str(asset.get("asset_type") or "unknown"))}</p></div>
          <div class="panel"><strong>Generated</strong><p>{html_escape(str(report.get("generated_at") or ""))}</p></div>
        </div>
      </section>

      <section class="stats-row">
        {metric_card("Critical", severity_counts.get("critical", 0), "#b91c1c")}
        {metric_card("High", severity_counts.get("high", 0), "#c2410c")}
        {metric_card("Verified", verification_counts.get("verified", 0), "#047857")}
        {metric_card("Evidence", report.get("evidence_count", 0), "#1d4ed8")}
        {metric_card("Live", execution_summary.get("live", 0), "#047857")}
        {metric_card("Derived", execution_summary.get("derived", 0), "#6d28d9")}
        {metric_card("Blocked", execution_summary.get("blocked", 0), "#b91c1c")}
      </section>

      <section class="grid">
        <div class="stack">
          <section class="panel">
            <h2>Attack Narrative</h2>
            <p>{html_escape(str(narrative.get("summary") or "Pentra assembled a report from persisted findings and attack graph evidence."))}</p>
            <p>{html_escape(str(narrative.get("impact") or ""))}</p>
            {attack_steps}
          </section>
          {pipeline_html}
          {comparison_html}
          <section>
            <h2>Remediation Plan</h2>
            <div class="stack">{remediation_items}</div>
          </section>
        </div>
        <div class="stack">
          <section>
            <h2>Top Findings</h2>
            <div class="stack">{top_finding_items}</div>
          </section>
        </div>
      </section>
    </main>
  </body>
</html>"""


def _build_report_markdown(report: dict[str, Any]) -> str:
    asset = report.get("asset", {}) if isinstance(report, dict) else {}
    asset_target = str(asset.get("target") or report.get("scan_id") or "unknown")
    executive_summary = str(report.get("executive_summary") or "")
    severity_counts = report.get("severity_counts") or {}
    verification_counts = report.get("verification_counts") or {}
    verification_summary = report.get("verification_summary") or {}
    verification_pipeline = report.get("verification_pipeline") or {}
    execution_summary = report.get("execution_summary") or {}
    top_findings = report.get("top_findings") or []
    comparison = report.get("comparison") or {}
    narrative = report.get("narrative") or {}
    remediation_plan = report.get("remediation_plan") or []
    finding_groups = report.get("finding_groups") or []

    lines = [
        f"# Pentra Report - {asset_target}",
        "",
        "## Asset Summary",
        "",
        f"- Asset: {asset.get('name') or 'Unknown Asset'}",
        f"- Project: {asset.get('project_name') or 'Unassigned'}",
        f"- Asset Type: {asset.get('asset_type') or 'unknown'}",
        "",
        "## Executive Summary",
        "",
        executive_summary,
        "",
        "## Severity Summary",
        "",
        f"- Critical: {severity_counts.get('critical', 0)}",
        f"- High: {severity_counts.get('high', 0)}",
        f"- Medium: {severity_counts.get('medium', 0)}",
        f"- Low: {severity_counts.get('low', 0)}",
        f"- Info: {severity_counts.get('info', 0)}",
        "",
        "## Verification Summary",
        "",
        f"- Verified: {verification_counts.get('verified', 0)}",
        f"- Suspected: {verification_counts.get('suspected', 0)}",
        f"- Detected: {verification_counts.get('detected', 0)}",
        "",
        "## Verification Coverage",
        "",
        f"- Profile: {verification_summary.get('profile_id') or 'unknown'}",
        f"- Verified Share: {int(round(float((verification_summary.get('overall') or {}).get('verified_share', 0.0)) * 100))}%",
        "",
        "## Verification Pipeline",
        "",
        f"- Verified: {(verification_pipeline.get('overall') or {}).get('verified', 0)}",
        f"- Reproduced: {(verification_pipeline.get('overall') or {}).get('reproduced', 0)}",
        f"- Queued: {(verification_pipeline.get('overall') or {}).get('queued', 0)}",
        f"- Needs Evidence: {(verification_pipeline.get('overall') or {}).get('needs_evidence', 0)}",
        f"- Rejected: {(verification_pipeline.get('overall') or {}).get('rejected', 0)}",
        f"- Expired: {(verification_pipeline.get('overall') or {}).get('expired', 0)}",
        f"- Proof-Ready Share: {int(round(float((verification_pipeline.get('overall') or {}).get('proof_ready_share', 0.0)) * 100))}%",
        "",
        "## Execution Truth",
        "",
        f"- Live Artifacts: {execution_summary.get('live', 0)}",
        f"- Simulated Artifacts: {execution_summary.get('simulated', 0)}",
        f"- Derived Artifacts: {execution_summary.get('derived', 0)}",
        f"- Blocked Artifacts: {execution_summary.get('blocked', 0)}",
        f"- Inferred Artifacts: {execution_summary.get('inferred', 0)}",
        "",
        "## Historical Comparison",
        "",
        str(comparison.get("summary") or "No historical comparison available."),
        "",
    ]

    if comparison:
        counts = comparison.get("counts") or {}
        lines.extend(
            [
                f"- New Findings: {counts.get('new', 0)}",
                f"- Resolved Findings: {counts.get('resolved', 0)}",
                f"- Persistent Findings: {counts.get('persistent', 0)}",
                f"- Escalated Findings: {counts.get('escalated', 0)}",
                "",
            ]
        )

    if narrative:
        lines.extend(
            [
                "## Attack Path Narrative",
                "",
                str(narrative.get("summary") or ""),
                "",
            ]
        )
        if narrative.get("impact"):
            lines.extend(["### Impact", "", str(narrative.get("impact")), ""])
        steps = narrative.get("steps") or []
        if isinstance(steps, list) and steps:
            lines.extend(["### Attack Steps", ""])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                lines.append(
                    f"- Step {step.get('step')}: {step.get('description')} [{step.get('risk', 'low')}]"
                )
            lines.append("")

    verification_by_type = verification_summary.get("by_type") or []
    if verification_by_type:
        lines.extend(["## Verification Coverage by Type", ""])
        for entry in verification_by_type:
            if not isinstance(entry, dict):
                continue
            lines.append(
                "- "
                f"{entry.get('vulnerability_type')}: "
                f"{entry.get('verified', 0)}/{entry.get('total_findings', 0)} verified "
                f"({int(round(float(entry.get('verified_share', 0.0)) * 100))}%)"
            )
        lines.append("")

    verification_queue = verification_pipeline.get("queue") or []
    if verification_queue:
        lines.extend(["## Verification Queue", ""])
        for item in verification_queue:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- [{item.get('queue_state')}] {item.get('title')} - {item.get('readiness_reason')}"
            )
            for action in item.get("required_actions") or []:
                lines.append(f"  Required: {action}")
        lines.append("")

    lines.extend(["## Remediation Plan", ""])
    if not remediation_plan:
        lines.append("No remediation plan items were generated.")
    else:
        for item in remediation_plan:
            if not isinstance(item, dict):
                continue
            lines.extend(
                [
                    f"### {item.get('title')}",
                    f"Priority: {item.get('priority')}",
                    f"Owner Hint: {item.get('owner_hint')}",
                    item.get("rationale") or "",
                    "",
                ]
            )
            for action in item.get("actions") or []:
                lines.append(f"- {action}")
            lines.append("")

    lines.extend(["## Grouped Findings", ""])
    if not finding_groups:
        lines.append("No grouped findings were available.")
    else:
        for group in finding_groups:
            if not isinstance(group, dict):
                continue
            lines.extend(
                [
                    f"### {group.get('title')}",
                    f"Surface: {group.get('surface') or 'web'}",
                    "",
                ]
            )
            for finding in group.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                verification_state = str(finding.get("verification_state") or "detected").capitalize()
                lines.extend(
                    [
                        f"- {finding.get('title')} ({finding.get('severity')}, {verification_state})",
                        f"  Target: {finding.get('target')}",
                    ]
                )
            lines.append("")

    lines.extend(["## Top Findings", ""])
    if not top_findings:
        lines.append("No persisted findings were available.")
    else:
        for finding in top_findings:
            verification_state = str(finding.get("verification_state") or "detected").capitalize()
            verification_confidence = finding.get("verification_confidence")
            verification_line = f"Verification: {verification_state}"
            if verification_confidence is not None:
                verification_line += f" ({verification_confidence}%)"
            lines.extend(
                [
                    f"### {finding['title']}",
                    f"Severity: {finding['severity']}",
                    verification_line,
                    finding.get("description") or "No description provided.",
                    "",
                ]
            )

    return "\n".join(lines)
