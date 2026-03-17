"""Retention cleanup — delete expired artifacts from disk and database.

Complements ``retention.py`` which stamps ``expires_at`` metadata on
artifacts at creation time.  This module performs the actual cleanup:

1. Query ``scan_artifacts`` where ``metadata->>'expires_at'`` < now
2. Delete the corresponding files from local disk (``storage_ref``)
3. Delete the database rows
4. Return a summary of cleaned artifacts

Usage from CLI::

    python -m pentra_common.storage.retention_cleanup

Or via the wrapper script::

    pentra_core/scripts/local/run_retention_cleanup.sh
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.db.session import async_session_factory

logger = logging.getLogger(__name__)


async def find_expired_artifacts(session: AsyncSession) -> list[dict[str, Any]]:
    """Return artifacts whose retention window has passed."""
    now = datetime.now(timezone.utc).isoformat()
    result = await session.execute(
        sa_text(
            """
            SELECT id, scan_id, storage_ref, artifact_type,
                   metadata->>'expires_at' AS expires_at
            FROM scan_artifacts
            WHERE metadata->>'expires_at' IS NOT NULL
              AND metadata->>'expires_at' < :now
            ORDER BY metadata->>'expires_at' ASC
            LIMIT 500
            """
        ),
        {"now": now},
    )
    rows = result.mappings().all()
    return [dict(row) for row in rows]


def delete_artifact_file(storage_ref: str | None) -> bool:
    """Delete the local artifact file if it exists.

    Returns True if the file was removed or did not exist.
    Returns False if deletion failed.
    """
    if not storage_ref:
        return True

    path = Path(storage_ref)
    if not path.exists():
        logger.debug("Artifact file already absent: %s", storage_ref)
        return True

    try:
        path.unlink()
        logger.info("Deleted artifact file: %s", storage_ref)
        return True
    except OSError as exc:
        logger.warning("Failed to delete artifact file %s: %s", storage_ref, exc)
        return False


async def delete_artifact_rows(
    session: AsyncSession,
    artifact_ids: list[str],
) -> int:
    """Delete artifact rows from the database by ID."""
    if not artifact_ids:
        return 0

    # Use parameterized ANY() for safe batch delete
    result = await session.execute(
        sa_text(
            "DELETE FROM scan_artifacts WHERE id = ANY(:ids)"
        ),
        {"ids": artifact_ids},
    )
    return result.rowcount or 0


async def run_cleanup(
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the retention cleanup cycle.

    Returns a summary dict with counts of processed, deleted, and failed artifacts.
    """
    summary: dict[str, Any] = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "expired_found": 0,
        "files_deleted": 0,
        "files_failed": 0,
        "rows_deleted": 0,
    }

    async with async_session_factory() as session:
        try:
            expired = await find_expired_artifacts(session)
            summary["expired_found"] = len(expired)

            if not expired:
                logger.info("No expired artifacts found")
                return summary

            logger.info("Found %d expired artifacts", len(expired))

            if dry_run:
                for artifact in expired:
                    logger.info(
                        "  [dry-run] Would delete: id=%s type=%s ref=%s expires=%s",
                        artifact["id"],
                        artifact["artifact_type"],
                        artifact["storage_ref"],
                        artifact["expires_at"],
                    )
                return summary

            # Delete files first, then rows
            ids_to_delete: list[str] = []
            for artifact in expired:
                ok = delete_artifact_file(artifact.get("storage_ref"))
                if ok:
                    summary["files_deleted"] += 1
                    ids_to_delete.append(str(artifact["id"]))
                else:
                    summary["files_failed"] += 1

            if ids_to_delete:
                deleted = await delete_artifact_rows(session, ids_to_delete)
                summary["rows_deleted"] = deleted
                await session.commit()

            logger.info(
                "Retention cleanup complete: %d expired, %d files deleted, %d rows deleted, %d failed",
                summary["expired_found"],
                summary["files_deleted"],
                summary["rows_deleted"],
                summary["files_failed"],
            )

        except Exception:
            await session.rollback()
            logger.exception("Retention cleanup failed")
            raise

    return summary


async def _main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Pentra artifact retention cleanup")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List expired artifacts without deleting them",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    summary = await run_cleanup(dry_run=args.dry_run)
    print(f"\nRetention cleanup summary: {summary}")


if __name__ == "__main__":
    asyncio.run(_main())
