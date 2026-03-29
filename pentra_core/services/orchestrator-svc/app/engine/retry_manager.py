"""Retry manager — handles job-level retry logic with exponential backoff.

Determines whether a failed node should be retried based on:
  - Current retry count vs max_retries
  - Error type (some errors are not retryable)
  - Exponential backoff delay
"""

from __future__ import annotations

__classification__ = "runtime_hot_path"

import asyncio
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Errors that should NOT be retried
_NON_RETRYABLE_ERRORS = frozenset({
    "SCOPE_VIOLATION",
    "AUTH_FAILURE",
    "INVALID_TARGET",
    "QUOTA_EXCEEDED",
    "LICENCE_EXPIRED",
    "WATCHDOG_TIMEOUT",
    "DEAD_LETTERED",
    "UNKNOWN_TOOL",
})

_NON_RETRYABLE_TOOL_ERRORS = frozenset({
    ("dalfox", "TIMEOUT"),
    ("cors_scanner", "EXIT_1"),
})

# Base backoff in seconds (will be multiplied by 2^retry_count)
_BASE_BACKOFF_SECONDS = 5
_MAX_BACKOFF_SECONDS = 120


class RetryManager:
    """Manages retry decisions and backoff scheduling."""

    def should_retry(
        self,
        *,
        retry_count: int,
        max_retries: int,
        error_code: str,
        tool_name: str | None = None,
    ) -> bool:
        """Determine if a failed job should be retried.

        Returns True if retry is appropriate.
        """
        normalized_tool = str(tool_name or "").strip().lower()
        if (normalized_tool, error_code) in _NON_RETRYABLE_TOOL_ERRORS:
            logger.info(
                "Non-retryable tool failure: tool=%s error=%s (retry_count=%d)",
                normalized_tool,
                error_code,
                retry_count,
            )
            return False

        if error_code in _NON_RETRYABLE_ERRORS:
            logger.info(
                "Non-retryable error: %s (retry_count=%d)",
                error_code, retry_count,
            )
            return False

        if retry_count >= max_retries:
            logger.info(
                "Max retries reached: %d/%d",
                retry_count, max_retries,
            )
            return False

        return True

    def get_backoff_seconds(self, retry_count: int) -> float:
        """Calculate exponential backoff delay for a retry.

        Uses 2^retry_count * base, capped at max.
        """
        delay = min(
            _BASE_BACKOFF_SECONDS * (2 ** retry_count),
            _MAX_BACKOFF_SECONDS,
        )
        return float(delay)

    async def wait_for_backoff(self, retry_count: int) -> None:
        """Sleep for the appropriate backoff duration."""
        delay = self.get_backoff_seconds(retry_count)
        logger.info("Backoff: waiting %.1fs before retry #%d", delay, retry_count + 1)
        await asyncio.sleep(delay)
