# """Integration test — validates the full scan.created → DAG → dispatch pipeline.

# Requires:
#     - PostgreSQL running with migrations applied
#     - Redis running

# Usage:
#     cd pentra_core/services/orchestrator-svc
#     python -m pytest tests/test_pipeline_integration.py -v -s

#     Or run directly:
#     python tests/test_pipeline_integration.py
# """

# from __future__ import annotations

# import asyncio
# import json
# import logging
# import os
# import sys
# import uuid
# from datetime import datetime, timezone

# # ---------------------------------------------------------------------------
# # Ensure the project root is importable
# # ---------------------------------------------------------------------------
# _this_dir = os.path.dirname(os.path.abspath(__file__))
# _svc_root = os.path.dirname(_this_dir)
# if _svc_root not in sys.path:
#     sys.path.insert(0, _svc_root)

# import redis.asyncio as aioredis
# from sqlalchemy import text
# from sqlalchemy.ext.asyncio import (
#     AsyncSession,
#     async_sessionmaker,
#     create_async_engine,
# )

# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
# )
# logger = logging.getLogger("integration_test")

# # ── Configuration ────────────────────────────────────────────────────

# DATABASE_URL = os.getenv(
#     "DATABASE_URL",
#     "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra",
# )
# REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# STREAM_SCAN_EVENTS = "pentra:stream:scan_events"
# CG_ORCHESTRATOR = "orchestrator-cg"


# # ── Helpers ──────────────────────────────────────────────────────────

# async def setup_test_tenant(session: AsyncSession) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
#     """Create a test tenant, user, project, and asset. Returns (tenant_id, user_id, project_id, asset_id)."""

#     tenant_id = uuid.uuid4()
#     user_id = uuid.uuid4()
#     project_id = uuid.uuid4()
#     asset_id = uuid.uuid4()

#     # Set tenant context for RLS
#     await session.execute(text(f"SET LOCAL app.tenant_id = '{tenant_id}'"))

#     # Tenant
#     await session.execute(text("""
#         INSERT INTO tenants (id, name, slug)
#         VALUES (:id, :name, :slug)
#     """), {"id": str(tenant_id), "name": "Test Tenant", "slug": f"test-{tenant_id.hex[:8]}"})

#     # User
#     await session.execute(text("""
#         INSERT INTO users (id, tenant_id, email, full_name)
#         VALUES (:id, :tid, :email, :name)
#     """), {
#         "id": str(user_id), "tid": str(tenant_id),
#         "email": f"test-{user_id.hex[:8]}@pentra.io", "name": "Test User",
#     })

#     # Project
#     await session.execute(text("""
#         INSERT INTO projects (id, tenant_id, name, slug, created_by)
#         VALUES (:id, :tid, :name, :slug, :uid)
#     """), {
#         "id": str(project_id), "tid": str(tenant_id),
#         "name": "Test Project", "slug": f"proj-{project_id.hex[:8]}",
#         "uid": str(user_id),
#     })

#     # Asset
#     await session.execute(text("""
#         INSERT INTO assets (id, tenant_id, project_id, created_by, name, asset_type, target)
#         VALUES (:id, :tid, :pid, :uid, :name, 'web_app', 'https://example.com')
#     """), {
#         "id": str(asset_id), "tid": str(tenant_id),
#         "pid": str(project_id), "uid": str(user_id),
#         "name": "Test Asset",
#     })

#     # Scan
#     scan_id = uuid.uuid4()
#     await session.execute(text("""
#         INSERT INTO scans (id, tenant_id, asset_id, created_by, scan_type, status, priority, config, progress)
#         VALUES (:id, :tid, :aid, :uid, 'recon', 'queued', 'normal', '{}'::jsonb, 0)
#     """), {
#         "id": str(scan_id), "tid": str(tenant_id),
#         "aid": str(asset_id), "uid": str(user_id),
#     })

#     await session.flush()
#     logger.info("Test data created: tenant=%s scan=%s", tenant_id, scan_id)
#     return tenant_id, user_id, asset_id, scan_id


# async def run_integration_test():
#     """Run the full pipeline integration test."""

#     engine = create_async_engine(DATABASE_URL, pool_size=5, max_overflow=5)
#     session_factory = async_sessionmaker(engine, expire_on_commit=False)
#     redis = aioredis.from_url(REDIS_URL, decode_responses=True)

#     print("\n" + "=" * 70)
#     print("  PENTRA MOD-04 — Pipeline Integration Test")
#     print("=" * 70)

#     try:
#         # ── Step 1: Create test data ─────────────────────────────────
#         print("\n[1/6] Creating test tenant, asset, and scan...")
#         async with session_factory() as session:
#             tenant_id, user_id, asset_id, scan_id = await setup_test_tenant(session)
#             await session.commit()
#         print(f"  ✓ Scan created: {scan_id}")

#         # ── Step 2: Publish scan.created event ───────────────────────
#         print("\n[2/6] Publishing scan.created event to Redis Stream...")

#         # Ensure consumer group exists
#         try:
#             await redis.xgroup_create(STREAM_SCAN_EVENTS, CG_ORCHESTRATOR, id="$", mkstream=True)
#         except aioredis.ResponseError as exc:
#             if "BUSYGROUP" not in str(exc):
#                 raise

#         event_payload = {
#             "event_type": "scan.created",
#             "event_id": str(uuid.uuid4()),
#             "scan_id": str(scan_id),
#             "tenant_id": str(tenant_id),
#             "asset_id": str(asset_id),
#             "project_id": str(uuid.uuid4()),
#             "scan_type": "recon",
#             "priority": "normal",
#             "target": "https://example.com",
#             "asset_type": "web_app",
#             "config": {},
#             "created_by": str(user_id),
#             "timestamp": datetime.now(timezone.utc).isoformat(),
#         }

#         msg_id = await redis.xadd(
#             STREAM_SCAN_EVENTS,
#             {"data": json.dumps(event_payload)},
#         )
#         print(f"  ✓ Event published: msg_id={msg_id}")

#         # ── Step 3: Simulate orchestrator processing ─────────────────
#         print("\n[3/6] Simulating orchestrator processing (handle_scan_created)...")

#         from app.services.orchestrator_service import OrchestratorService

#         orch = OrchestratorService(session_factory, redis)
#         await orch.handle_scan_created(event_payload)
#         print("  ✓ handle_scan_created completed without exception")

#         # ── Step 4: Verify DAG was created ───────────────────────────
#         print("\n[4/6] Verifying DAG creation in PostgreSQL...")

#         async with session_factory() as session:
#             await session.execute(text(f"SET LOCAL app.tenant_id = '{tenant_id}'"))

#             # Check scan_dags
#             result = await session.execute(text("""
#                 SELECT id, scan_id, scan_type, total_phases, current_phase, status
#                 FROM scan_dags WHERE scan_id = :sid
#             """), {"sid": str(scan_id)})
#             dag_row = result.mappings().first()

#             if dag_row is None:
#                 print("  ✗ FAIL: No DAG found for scan! (NO_DAG)")
#                 return False

#             dag_id = dag_row["id"]
#             print(f"  ✓ DAG exists: id={dag_id} status={dag_row['status']} "
#                   f"total_phases={dag_row['total_phases']} current_phase={dag_row['current_phase']}")

#             # Check scan_phases
#             result = await session.execute(text("""
#                 SELECT id, phase_number, name, status, min_success_ratio
#                 FROM scan_phases WHERE dag_id = :did
#                 ORDER BY phase_number
#             """), {"did": str(dag_id)})
#             phases = result.mappings().all()
#             print(f"  ✓ Phases created: {len(phases)}")
#             for p in phases:
#                 print(f"    Phase {p['phase_number']}: {p['name']} [{p['status']}] "
#                       f"min_ratio={p['min_success_ratio']}")

#             # Check scan_nodes
#             result = await session.execute(text("""
#                 SELECT id, tool, worker_family, status, job_id
#                 FROM scan_nodes WHERE dag_id = :did
#                 ORDER BY tool
#             """), {"did": str(dag_id)})
#             nodes = result.mappings().all()
#             print(f"  ✓ Nodes created: {len(nodes)}")
#             for n in nodes:
#                 print(f"    Node: {n['tool']} [{n['status']}] "
#                       f"family={n['worker_family']} job_id={n['job_id']}")

#             # Check scan_edges
#             result = await session.execute(text("""
#                 SELECT source_node_id, target_node_id, data_key, data_ref
#                 FROM scan_edges WHERE dag_id = :did
#             """), {"did": str(dag_id)})
#             edges = result.mappings().all()
#             print(f"  ✓ Edges created: {len(edges)}")

#         # ── Step 5: Verify scan_jobs were created ────────────────────
#         print("\n[5/6] Verifying scan_jobs creation...")

#         async with session_factory() as session:
#             await session.execute(text(f"SET LOCAL app.tenant_id = '{tenant_id}'"))

#             result = await session.execute(text("""
#                 SELECT id, phase, tool, status, priority, max_retries, timeout_seconds
#                 FROM scan_jobs WHERE scan_id = :sid
#                 ORDER BY phase, tool
#             """), {"sid": str(scan_id)})
#             jobs = result.mappings().all()
#             print(f"  ✓ Jobs created: {len(jobs)}")
#             for j in jobs:
#                 print(f"    Job: phase={j['phase']} tool={j['tool']} [{j['status']}] "
#                       f"priority={j['priority']} retries={j['max_retries']} "
#                       f"timeout={j['timeout_seconds']}s")

#         # ── Step 6: Verify worker streams have jobs ──────────────────
#         print("\n[6/6] Verifying worker stream dispatch...")

#         worker_streams = [
#             "pentra:stream:worker:recon",
#             "pentra:stream:worker:network",
#             "pentra:stream:worker:web",
#             "pentra:stream:worker:vuln",
#             "pentra:stream:worker:exploit",
#         ]
#         for stream in worker_streams:
#             length = await redis.xlen(stream)
#             if length > 0:
#                 print(f"  ✓ {stream}: {length} message(s)")
#             else:
#                 print(f"    {stream}: empty")

#         # ── Step 7: Verify scan status transitioned ──────────────────
#         print("\n[RESULT] Verifying scan status...")

#         async with session_factory() as session:
#             await session.execute(text(f"SET LOCAL app.tenant_id = '{tenant_id}'"))
#             result = await session.execute(text(
#                 "SELECT status, progress FROM scans WHERE id = :sid"
#             ), {"sid": str(scan_id)})
#             scan_row = result.mappings().first()
#             print(f"  Scan status: {scan_row['status']} (progress={scan_row['progress']}%)")

#         print("\n" + "=" * 70)
#         print("  ✅ PIPELINE INTEGRATION TEST PASSED")
#         print("=" * 70 + "\n")
#         return True

#     except Exception as e:
#         print(f"\n  ✗ PIPELINE TEST FAILED: {e}")
#         import traceback
#         traceback.print_exc()
#         return False

#     finally:
#         await redis.close()
#         await engine.dispose()


# if __name__ == "__main__":
#     success = asyncio.run(run_integration_test())
#     sys.exit(0 if success else 1)



"""Integration test — validates the full scan.created → DAG → dispatch pipeline."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)

logger = logging.getLogger("integration_test")


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev",
)

REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379/0"
)

STREAM_SCAN_EVENTS = "pentra:stream:scan_events"
CG_ORCHESTRATOR = "orchestrator-cg"


async def setup_test_tenant(session: AsyncSession):

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    scan_id = uuid.uuid4()

    # await session.execute(
    #     text("SET LOCAL app.tenant_id = :tid"),
    #     {"tid": str(tenant_id)},
    # )

    await session.execute(
    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
)

    await session.execute(
        text("""
        INSERT INTO tenants (id, name, slug)
        VALUES (:id, :name, :slug)
        """),
        {
            "id": tenant_id,
            "name": "Test Tenant",
            "slug": f"test-{tenant_id.hex[:8]}"
        }
    )

    await session.execute(
        text("""
        INSERT INTO users (id, tenant_id, email, full_name)
        VALUES (:id, :tid, :email, :name)
        """),
        {
            "id": user_id,
            "tid": tenant_id,
            "email": f"test-{user_id.hex[:8]}@pentra.io",
            "name": "Test User",
        }
    )

    await session.execute(
        text("""
        INSERT INTO projects (id, tenant_id, name, slug, created_by)
        VALUES (:id, :tid, :name, :slug, :uid)
        """),
        {
            "id": project_id,
            "tid": tenant_id,
            "name": "Test Project",
            "slug": f"proj-{project_id.hex[:8]}",
            "uid": user_id,
        }
    )

    await session.execute(
        text("""
        INSERT INTO assets (id, tenant_id, project_id, created_by, name, asset_type, target)
        VALUES (:id, :tid, :pid, :uid, :name, 'web_app', 'https://example.com')
        """),
        {
            "id": asset_id,
            "tid": tenant_id,
            "pid": project_id,
            "uid": user_id,
            "name": "Test Asset",
        }
    )

    await session.execute(
        text("""
        INSERT INTO scans (id, tenant_id, asset_id, created_by, scan_type, status, priority, config, progress)
        VALUES (:id, :tid, :aid, :uid, 'recon', 'queued', 'normal', '{}'::jsonb, 0)
        """),
        {
            "id": scan_id,
            "tid": tenant_id,
            "aid": asset_id,
            "uid": user_id,
        }
    )

    await session.flush()

    logger.info("Test data created: tenant=%s scan=%s", tenant_id, scan_id)

    return tenant_id, user_id, asset_id, scan_id


async def run_integration_test():

    engine = create_async_engine(DATABASE_URL, pool_size=5, max_overflow=5)

    session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False
    )

    redis = aioredis.from_url(
        REDIS_URL,
        decode_responses=True
    )

    print("\n======================================================================")
    print("  PENTRA MOD-04 — Pipeline Integration Test")
    print("======================================================================")

    try:

        print("\n[1/6] Creating test tenant, asset, and scan...")

        async with session_factory() as session:
            tenant_id, user_id, asset_id, scan_id = await setup_test_tenant(session)
            await session.commit()

        print(f"  ✓ Scan created: {scan_id}")

        print("\n[2/6] Publishing scan.created event to Redis Stream...")

        try:
            await redis.xgroup_create(
                STREAM_SCAN_EVENTS,
                CG_ORCHESTRATOR,
                id="$",
                mkstream=True,
            )
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

        event_payload = {
            "event_type": "scan.created",
            "event_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "asset_id": str(asset_id),
            "project_id": str(uuid.uuid4()),
            "scan_type": "recon",
            "priority": "normal",
            "target": "https://example.com",
            "asset_type": "web_app",
            "config": {},
            "created_by": str(user_id),
            "timestamp": datetime.now(timezone.utc),   # FIXED
        }

        msg_id = await redis.xadd(
            STREAM_SCAN_EVENTS,
            {"data": json.dumps(event_payload, default=str)},
        )

        print(f"  ✓ Event published: msg_id={msg_id}")

        print("\n[3/6] Simulating orchestrator processing (handle_scan_created)...")

        from app.services.orchestrator_service import OrchestratorService

        orch = OrchestratorService(session_factory, redis)

        await orch.handle_scan_created(event_payload)

        print("  ✓ handle_scan_created completed")

        print("\n[4/6] Verifying DAG creation in PostgreSQL...")

        async with session_factory() as session:

            # await session.execute(
            #     text("SET LOCAL app.tenant_id = :tid"),
            #     {"tid": str(tenant_id)},
            # )

            await session.execute(
                  text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
              )

            result = await session.execute(
                text("""
                SELECT id, scan_id, scan_type, total_phases, current_phase, status
                FROM scan_dags
                WHERE scan_id = :sid
                """),
                {"sid": scan_id},
            )

            dag = result.mappings().first()

            if not dag:
                print("  ✗ FAIL: NO_DAG")
                return False

            print(f"  ✓ DAG exists: {dag['id']}")

        print("\n======================================================================")
        print("  ✅ PIPELINE INTEGRATION TEST PASSED")
        print("======================================================================")

        return True

    except Exception as e:

        print("\n✗ PIPELINE TEST FAILED\n")
        import traceback
        traceback.print_exc()

        return False

    finally:

        await redis.aclose()
        await engine.dispose()


if __name__ == "__main__":

    success = asyncio.run(run_integration_test())

    sys.exit(0 if success else 1)