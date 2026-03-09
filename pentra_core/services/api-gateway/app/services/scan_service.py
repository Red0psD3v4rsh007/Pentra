"""Scan service — scan lifecycle management, quota enforcement, event publishing.

Framework-agnostic: accepts plain arguments, returns ORM objects.
No FastAPI Request dependency.

**MOD-04 compatibility**: This service creates only the ``Scan`` record
and publishes ``scan.created`` to Redis Streams.  All DAG planning and
``ScanJob`` creation is delegated to the orchestrator service.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.events.stream_publisher import StreamPublisher
from pentra_common.schemas import SCAN_TERMINAL_STATES

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.tenant import TenantQuota

logger = logging.getLogger(__name__)


# ── Public service functions ─────────────────────────────────────────


async def create_scan(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    asset_id: uuid.UUID,
    scan_type: str,
    priority: str,
    config: dict | None,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Create a scan with quota validation and event publishing.

    1. Validate asset exists and belongs to tenant
    2. Check tenant quota (concurrent + daily limits)
    3. Create Scan record
    4. Increment quota counters
    5. Publish ``scan.created`` event to Redis Stream (XADD)

    All DAG planning and ScanJob creation is handled by the orchestrator
    after it consumes the ``scan.created`` event.
    """
    # 1 — validate asset
    asset = await session.get(Asset, asset_id)
    if asset is None or not asset.is_active:
        raise ValueError("Asset not found or inactive")

    if str(asset.tenant_id) != str(tenant_id):
        raise ValueError("Asset does not belong to this tenant")

    # 2 — check quota
    quota_stmt = select(TenantQuota).where(TenantQuota.tenant_id == tenant_id)
    quota = (await session.execute(quota_stmt)).scalar_one_or_none()

    if quota:
        if quota.active_scans >= quota.max_concurrent_scans:
            raise ValueError(
                f"Concurrent scan limit reached ({quota.max_concurrent_scans})"
            )
        if quota.scans_today >= quota.max_daily_scans:
            raise ValueError(
                f"Daily scan limit reached ({quota.max_daily_scans})"
            )

    # 3 — create scan record
    scan = Scan(
        tenant_id=tenant_id,
        asset_id=asset_id,
        created_by=created_by,
        scan_type=scan_type,
        priority=priority,
        config=config or {},
        status="queued",
        progress=0,
    )
    session.add(scan)
    await session.flush()

    # 4 — increment quota counters
    if quota:
        quota.active_scans += 1
        quota.scans_today += 1
        await session.flush()

    # 5 — publish scan.created event to Redis Stream
    await stream_publisher.publish_scan_created(
        scan_id=scan.id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        project_id=asset.project_id,
        scan_type=scan_type,
        priority=priority,
        target=asset.target,
        asset_type=asset.asset_type,
        config=config or {},
        created_by=created_by,
    )

    logger.info(
        "Scan created: scan_id=%s tenant=%s type=%s priority=%s",
        scan.id, tenant_id, scan_type, priority,
    )

    return scan


async def list_scans(
    *,
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
    *, scan_id: uuid.UUID, session: AsyncSession
) -> Scan | None:
    """Fetch a scan by ID."""
    return await session.get(Scan, scan_id)


async def cancel_scan(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Cancel a running scan — publish cancellation to Redis Stream.

    Sets status to ``cancelled`` and publishes ``scan.status_changed``
    so the orchestrator can gracefully stop dispatching jobs.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise ValueError("Scan not found")

    # Verify it's not already in a terminal state
    if scan.status in {s.value for s in SCAN_TERMINAL_STATES}:
        raise ValueError(f"Scan is already in terminal state: {scan.status}")

    old_status = scan.status
    scan.status = "cancelled"
    scan.error_message = "Cancelled by user"
    scan.completed_at = datetime.now(timezone.utc)
    await session.flush()

    # Decrement active scans quota
    quota_stmt = select(TenantQuota).where(TenantQuota.tenant_id == tenant_id)
    quota = (await session.execute(quota_stmt)).scalar_one_or_none()
    if quota and quota.active_scans > 0:
        quota.active_scans -= 1
        await session.flush()

    # Publish status change event to Redis Stream
    await stream_publisher.publish_scan_status_changed(
        scan_id=scan.id,
        tenant_id=tenant_id,
        old_status=old_status,
        new_status="cancelled",
    )

    return scan


async def list_findings(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Finding], int]:
    """List findings for a scan (paginated)."""
    base_filter = Finding.scan_id == scan_id

    count_stmt = select(func.count()).select_from(Finding).where(base_filter)
    total = (await session.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = (
        select(Finding)
        .where(base_filter)
        .order_by(Finding.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all()), total
