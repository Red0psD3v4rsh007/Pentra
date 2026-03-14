"""Development seed data for local testing.

Inserts minimal records needed for API validation:
  - Tenant (dev org)
  - TenantQuota
  - Role (owner — if not seeded by migration)
  - User (dev user)
  - Project
  - Asset

Run with:
    cd pentra_core
    PYTHONPATH="services/api-gateway:packages/pentra-common" python3 scripts/seed_dev_data.py
"""

from __future__ import annotations

import asyncio
import sys
import os

# Ensure import paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "services", "api-gateway"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "pentra-common"))

from sqlalchemy import text, select
from pentra_common.db.session import async_session_factory, async_engine

# UUIDs matching the dev-mode bypass in deps.py
TENANT_ID  = "22222222-2222-2222-2222-222222222222"
USER_ID    = "11111111-1111-1111-1111-111111111111"
PROJECT_ID = "33333333-3333-3333-3333-333333333333"
ASSET_ID   = "44444444-4444-4444-4444-444444444444"


async def seed() -> None:
    async with async_session_factory() as session:
        # Disable RLS for seeding (we're the superuser/app user)
        await session.execute(text(
            f"SET LOCAL app.tenant_id = '{TENANT_ID}'"
        ))

        # ── Tenant ──────────────────────────────────────────────
        exists = await session.execute(
            text("SELECT 1 FROM tenants WHERE id = :id"),
            {"id": TENANT_ID},
        )
        if not exists.scalar():
            await session.execute(text("""
                INSERT INTO tenants (id, name, slug, tier)
                VALUES (:id, 'Dev Organization', 'dev-org', 'pro')
            """), {"id": TENANT_ID})
            print(f"✓ Tenant created: {TENANT_ID}")
        else:
            print(f"· Tenant exists: {TENANT_ID}")

        # ── TenantQuota ─────────────────────────────────────────
        exists = await session.execute(
            text("SELECT 1 FROM tenant_quotas WHERE tenant_id = :tid"),
            {"tid": TENANT_ID},
        )
        if not exists.scalar():
            await session.execute(text("""
                INSERT INTO tenant_quotas (
                    tenant_id, max_concurrent_scans, max_daily_scans,
                    max_assets, max_projects
                ) VALUES (:tid, 10, 100, 50, 20)
            """), {"tid": TENANT_ID})
            print(f"✓ TenantQuota created")
        else:
            print(f"· TenantQuota exists")

        # ── User ────────────────────────────────────────────────
        exists = await session.execute(
            text("SELECT 1 FROM users WHERE id = :id"),
            {"id": USER_ID},
        )
        if not exists.scalar():
            await session.execute(text("""
                INSERT INTO users (id, tenant_id, email, full_name, is_active)
                VALUES (:id, :tid, 'dev@pentra.local', 'Dev User', true)
            """), {"id": USER_ID, "tid": TENANT_ID})
            print(f"✓ User created: {USER_ID}")
        else:
            print(f"· User exists: {USER_ID}")

        # ── Assign owner role ───────────────────────────────────
        role = await session.execute(
            text("SELECT id FROM roles WHERE name = 'owner' LIMIT 1")
        )
        role_id = role.scalar()
        if role_id:
            exists = await session.execute(
                text("SELECT 1 FROM user_roles WHERE user_id = :uid AND role_id = :rid"),
                {"uid": USER_ID, "rid": str(role_id)},
            )
            if not exists.scalar():
                await session.execute(text("""
                    INSERT INTO user_roles (user_id, role_id, tenant_id)
                    VALUES (:uid, :rid, :tid)
                """), {"uid": USER_ID, "rid": str(role_id), "tid": TENANT_ID})
                print(f"✓ Owner role assigned")
            else:
                print(f"· Owner role already assigned")

        # ── Project ─────────────────────────────────────────────
        exists = await session.execute(
            text("SELECT 1 FROM projects WHERE id = :id"),
            {"id": PROJECT_ID},
        )
        if not exists.scalar():
            await session.execute(text("""
                INSERT INTO projects (id, tenant_id, name, slug, created_by)
                VALUES (:id, :tid, 'Dev Project', 'dev-project', :uid)
            """), {"id": PROJECT_ID, "tid": TENANT_ID, "uid": USER_ID})
            print(f"✓ Project created: {PROJECT_ID}")
        else:
            print(f"· Project exists: {PROJECT_ID}")

        # ── Asset ───────────────────────────────────────────────
        exists = await session.execute(
            text("SELECT 1 FROM assets WHERE id = :id"),
            {"id": ASSET_ID},
        )
        if not exists.scalar():
            await session.execute(text("""
                INSERT INTO assets (
                    id, tenant_id, project_id, created_by,
                    name, asset_type, target, is_verified
                ) VALUES (
                    :id, :tid, :pid, :uid,
                    'Dev Web App', 'web_app', 'example.com', true
                )
            """), {
                "id": ASSET_ID, "tid": TENANT_ID,
                "pid": PROJECT_ID, "uid": USER_ID,
            })
            print(f"✓ Asset created: {ASSET_ID}")
        else:
            print(f"· Asset exists: {ASSET_ID}")

        await session.commit()
        print("\n✅ Seed data ready. Dev asset ID for scan creation:")
        print(f"   asset_id = {ASSET_ID}")


async def main():
    try:
        await seed()
    finally:
        await async_engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
