"""Git clone runner — clones GitHub repos for Grey/White Box testing.

Used by Grey Box and White Box scan methodologies to fetch source code
for SAST analysis (semgrep, trufflehog, dependency audits).

Source is cloned to ``/tmp/pentra/repos/{scan_id}/`` and mounted
into tool containers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_REPOS_BASE = "/tmp/pentra/repos"
_CLONE_TIMEOUT = 120  # seconds


@dataclass
class CloneResult:
    """Result of a git clone operation."""
    success: bool
    repo_path: str
    branch: str
    commit_hash: str
    error: str | None = None
    file_count: int = 0
    size_mb: float = 0.0


async def clone_repository(
    *,
    scan_id: uuid.UUID,
    repo_url: str,
    token: str | None = None,
    branch: str = "main",
    depth: int = 1,
) -> CloneResult:
    """Clone a GitHub repository for source code analysis.

    Args:
        scan_id: Scan ID for workspace isolation
        repo_url: Git repository URL (HTTPS)
        token: GitHub personal access token (for private repos)
        branch: Branch to clone (default: main)
        depth: Git clone depth (default: 1 for shallow clone)

    Returns:
        CloneResult with status and repo path
    """
    repo_dir = os.path.join(_REPOS_BASE, str(scan_id))
    os.makedirs(repo_dir, exist_ok=True)

    # Inject auth token into URL for private repos
    auth_url = repo_url
    if token and "github.com" in repo_url:
        auth_url = repo_url.replace(
            "https://github.com",
            f"https://{token}@github.com",
        )

    # Build git clone command
    cmd = [
        "git", "clone",
        "--depth", str(depth),
        "--branch", branch,
        "--single-branch",
        auth_url,
        os.path.join(repo_dir, "src"),
    ]

    try:
        logger.info("Cloning repository for scan %s: %s (branch=%s)", scan_id, repo_url, branch)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",  # Never prompt for auth
            },
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=_CLONE_TIMEOUT
        )

        if process.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="replace").strip()
            logger.error("Git clone failed for scan %s: %s", scan_id, error_msg)
            return CloneResult(
                success=False,
                repo_path="",
                branch=branch,
                commit_hash="",
                error=error_msg,
            )

        src_path = os.path.join(repo_dir, "src")

        # Get commit hash
        commit_hash = await _get_commit_hash(src_path)

        # Count files and size
        file_count = 0
        total_size = 0
        for root, _, files in os.walk(src_path):
            # Skip .git directory
            if ".git" in root:
                continue
            for f in files:
                file_count += 1
                try:
                    total_size += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass

        size_mb = round(total_size / (1024 * 1024), 2)

        logger.info(
            "Repository cloned for scan %s: %d files, %.2f MB, commit %s",
            scan_id, file_count, size_mb, commit_hash[:8] if commit_hash else "?",
        )

        return CloneResult(
            success=True,
            repo_path=src_path,
            branch=branch,
            commit_hash=commit_hash,
            file_count=file_count,
            size_mb=size_mb,
        )

    except asyncio.TimeoutError:
        logger.error("Git clone timed out after %ds for scan %s", _CLONE_TIMEOUT, scan_id)
        return CloneResult(
            success=False,
            repo_path="",
            branch=branch,
            commit_hash="",
            error=f"Clone timed out after {_CLONE_TIMEOUT}s",
        )
    except Exception as exc:
        logger.exception("Git clone error for scan %s", scan_id)
        return CloneResult(
            success=False,
            repo_path="",
            branch=branch,
            commit_hash="",
            error=str(exc),
        )


async def cleanup_repository(scan_id: uuid.UUID) -> None:
    """Remove cloned repository after scan completes."""
    repo_dir = os.path.join(_REPOS_BASE, str(scan_id))
    if os.path.exists(repo_dir):
        try:
            shutil.rmtree(repo_dir)
            logger.info("Cleaned up repository for scan %s", scan_id)
        except Exception:
            logger.warning("Failed to clean up repo dir: %s", repo_dir)


async def _get_commit_hash(repo_path: str) -> str:
    """Get the current HEAD commit hash from a cloned repo."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", repo_path, "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        return stdout.decode().strip()
    except Exception:
        return ""
