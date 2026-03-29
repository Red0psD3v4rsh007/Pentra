"""Background launcher for one-shot scheduled scans."""

from __future__ import annotations

import asyncio
import logging
import os

from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from pentra_common.events.stream_publisher import StreamPublisher

from app.services import scan_service

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = int(
    os.getenv("PENTRA_SCHEDULED_SCAN_POLL_SECONDS", "30")
)
BATCH_LIMIT = int(os.getenv("PENTRA_SCHEDULED_SCAN_BATCH_LIMIT", "10"))
ENABLED = os.getenv("PENTRA_SCHEDULED_SCAN_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
}


class ScheduledScanLauncher:
    """Starts due scheduled scans using the same API lifecycle contract."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        stream_publisher: StreamPublisher,
    ) -> None:
        self._session_factory = session_factory
        self._stream_publisher = stream_publisher
        self._running = False

    async def start(self) -> None:
        if not ENABLED:
            logger.info("ScheduledScanLauncher disabled via config")
            return

        self._running = True
        logger.info(
            "ScheduledScanLauncher started: poll=%ds batch_limit=%d",
            POLL_INTERVAL_SECONDS,
            BATCH_LIMIT,
        )
        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("ScheduledScanLauncher tick failed")

            try:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                break

        logger.info("ScheduledScanLauncher stopped")

    def stop(self) -> None:
        self._running = False

    async def _tick(self) -> list[str]:
        async with self._session_factory() as session:
            activated = await scan_service.activate_due_scheduled_scans(
                stream_publisher=self._stream_publisher,
                session=session,
                limit=BATCH_LIMIT,
            )
        if activated:
            logger.info(
                "Activated %d scheduled scan(s): %s",
                len(activated),
                ", ".join(str(scan_id) for scan_id in activated),
            )
        return [str(scan_id) for scan_id in activated]
