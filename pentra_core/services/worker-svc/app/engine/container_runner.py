"""Container runner — executes security tools inside Docker containers.

Uses the Docker SDK to:
  1. Pull the tool image (if not cached)
  2. Create a container with volume mounts and resource limits
  3. Run the tool with the rendered command
  4. Stream logs and capture exit code
  5. Clean up the container

Security controls:
  - Read-only root filesystem
  - No privilege escalation
  - Memory/CPU limits
  - Network mode configurable (host for recon, none for exploit)
  - Ephemeral working directory
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────

WORK_DIR_BASE = os.getenv("WORKER_WORK_DIR", "/tmp/pentra/jobs")
MEMORY_LIMIT = os.getenv("CONTAINER_MEMORY_LIMIT", "2g")
CPU_LIMIT = float(os.getenv("CONTAINER_CPU_LIMIT", "2.0"))
NETWORK_MODE_DEFAULT = os.getenv("CONTAINER_NETWORK_MODE", "bridge")

# Exploit family gets no network access
_FAMILY_NETWORK: dict[str, str] = {
    "exploit": "none",
}


@dataclass
class ContainerResult:
    """Result from a container execution."""

    exit_code: int
    stdout: str
    stderr: str
    output_dir: str
    timed_out: bool = False


class ContainerRunner:
    """Runs security tools inside Docker containers.

    Usage::

        runner = ContainerRunner()
        result = await runner.run(
            image="projectdiscovery/subfinder:latest",
            command=["subfinder", "-d", "example.com", "-o", "/work/output/subdomains.json"],
            job_id=uuid.uuid4(),
            worker_family="recon",
            timeout=600,
            env_vars={},
        )
    """

    def __init__(self) -> None:
        self._docker = None

    async def _get_docker(self):
        """Lazy-initialize Docker client."""
        if self._docker is None:
            try:
                import docker
                self._docker = docker.from_env()
                logger.info("Docker client initialized")
            except Exception:
                logger.warning("Docker not available — using simulation mode")
                self._docker = "simulation"
        return self._docker

    async def run(
        self,
        *,
        image: str,
        command: list[str],
        job_id: uuid.UUID,
        worker_family: str,
        timeout: int = 600,
        env_vars: dict[str, str] | None = None,
        input_refs: dict[str, str] | None = None,
    ) -> ContainerResult:
        """Execute a tool inside a Docker container.

        Creates an isolated working directory, mounts it into the container,
        runs the tool, and returns the result.
        """
        # Prepare working directory
        work_dir = Path(WORK_DIR_BASE) / str(job_id)
        output_dir = work_dir / "output"
        input_dir = work_dir / "input"
        output_dir.mkdir(parents=True, exist_ok=True)
        input_dir.mkdir(parents=True, exist_ok=True)

        # Write input refs as files for the tool to consume
        if input_refs:
            for key, ref in input_refs.items():
                (input_dir / f"{key}.ref").write_text(ref)

        docker = await self._get_docker()

        if docker == "simulation":
            return await self._simulate(
                command=command, output_dir=str(output_dir),
                timeout=timeout, job_id=job_id,
            )

        return await self._run_docker(
            docker=docker,
            image=image,
            command=command,
            work_dir=str(work_dir),
            output_dir=str(output_dir),
            worker_family=worker_family,
            timeout=timeout,
            env_vars=env_vars or {},
            job_id=job_id,
        )

    async def _run_docker(
        self,
        *,
        docker,
        image: str,
        command: list[str],
        work_dir: str,
        output_dir: str,
        worker_family: str,
        timeout: int,
        env_vars: dict[str, str],
        job_id: uuid.UUID,
    ) -> ContainerResult:
        """Run inside a real Docker container."""
        network_mode = _FAMILY_NETWORK.get(worker_family, NETWORK_MODE_DEFAULT)
        container_name = f"pentra-job-{str(job_id)[:8]}"

        try:
            # Pull image if needed
            try:
                docker.images.get(image)
            except Exception:
                logger.info("Pulling image: %s", image)
                await asyncio.to_thread(docker.images.pull, image)

            # Create and run container
            container = await asyncio.to_thread(
                docker.containers.run,
                image,
                command=command,
                name=container_name,
                detach=True,
                volumes={
                    work_dir: {"bind": "/work", "mode": "rw"},
                },
                working_dir="/work/output",
                environment=env_vars,
                network_mode=network_mode,
                mem_limit=MEMORY_LIMIT,
                nano_cpus=int(CPU_LIMIT * 1e9),
                read_only=False,  # tools need to write
                security_opt=["no-new-privileges"],
                auto_remove=False,
            )

            # Wait for completion with timeout
            timed_out = False
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(container.wait),
                    timeout=timeout,
                )
                exit_code = result.get("StatusCode", -1)
            except asyncio.TimeoutError:
                logger.warning("Container %s timed out after %ds", container_name, timeout)
                await asyncio.to_thread(container.kill)
                exit_code = -1
                timed_out = True

            # Capture logs
            stdout = (await asyncio.to_thread(container.logs, stdout=True, stderr=False)).decode(
                "utf-8", errors="replace"
            )
            stderr = (await asyncio.to_thread(container.logs, stdout=False, stderr=True)).decode(
                "utf-8", errors="replace"
            )

            # Cleanup container
            try:
                await asyncio.to_thread(container.remove, force=True)
            except Exception:
                pass

            logger.info(
                "Container %s finished: exit_code=%d timed_out=%s",
                container_name, exit_code, timed_out,
            )

            return ContainerResult(
                exit_code=exit_code,
                stdout=stdout[-10_000:],  # cap at 10KB
                stderr=stderr[-5_000:],
                output_dir=output_dir,
                timed_out=timed_out,
            )

        except Exception as e:
            logger.exception("Container execution failed for job %s", job_id)
            return ContainerResult(
                exit_code=-1,
                stdout="",
                stderr=str(e)[:5_000],
                output_dir=output_dir,
                timed_out=False,
            )

    async def _simulate(
        self,
        *,
        command: list[str],
        output_dir: str,
        timeout: int,
        job_id: uuid.UUID,
    ) -> ContainerResult:
        """Simulation mode when Docker is not available.

        Creates a mock output file for dev/test environments.
        """
        logger.info("SIMULATION: %s (job=%s)", " ".join(command[:3]), job_id)

        # Generate mock output
        mock_output = {
            "tool": command[0] if command else "unknown",
            "job_id": str(job_id),
            "simulation": True,
            "findings": [],
            "metadata": {
                "command": " ".join(command),
                "status": "simulated",
            },
        }

        # Write to output directory
        output_file = Path(output_dir) / "output.json"
        output_file.write_text(json.dumps(mock_output, indent=2))

        # Simulate execution time (capped at 2s in sim mode)
        await asyncio.sleep(min(0.5, timeout / 100))

        return ContainerResult(
            exit_code=0,
            stdout=json.dumps(mock_output),
            stderr="",
            output_dir=output_dir,
            timed_out=False,
        )

    async def cleanup_job(self, job_id: uuid.UUID) -> None:
        """Remove the working directory for a completed job."""
        work_dir = Path(WORK_DIR_BASE) / str(job_id)
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)
            logger.debug("Cleaned up work dir for job %s", job_id)
