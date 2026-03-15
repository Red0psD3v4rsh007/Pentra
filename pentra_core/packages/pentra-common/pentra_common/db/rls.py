"""Row-Level Security (RLS) helpers for PostgreSQL tenant isolation.

Before every tenant-scoped query the application must call
:func:`set_tenant_context` to set the PostgreSQL session variable
``app.tenant_id``.  The RLS policies reference this variable via
``current_setting('app.tenant_id')``.

This is defence layer L2 in the 5-layer isolation model defined in
MOD-01.5 (W-15).
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def set_tenant_context(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Set ``app.tenant_id`` as a LOCAL session variable.

    ``SET LOCAL`` scopes the variable to the current transaction,
    so it is automatically cleared on commit/rollback.

    Args:
        session: Active async SQLAlchemy session.
        tenant_id: UUID of the tenant for the current request.
    """
    await session.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )


async def clear_tenant_context(session: AsyncSession) -> None:
    """Reset the tenant context — used in admin/system operations."""
    await session.execute(text("RESET app.tenant_id"))
