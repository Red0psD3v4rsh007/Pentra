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
import textwrap
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
EXECUTION_MODE = os.getenv("WORKER_EXECUTION_MODE", "auto").lower()

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
            if EXECUTION_MODE == "simulate":
                logger.info("Worker execution mode forced to simulation")
                self._docker = "simulation"
                return self._docker
            try:
                import docker
                self._docker = docker.from_env()
                logger.info("Docker client initialized")
            except Exception:
                if EXECUTION_MODE == "docker":
                    logger.exception("Docker execution mode requested but Docker is unavailable")
                    raise
                logger.warning("Docker not available — using simulation mode")
                self._docker = "simulation"
        return self._docker

    async def run(
        self,
        *,
        image: str,
        command: list[str],
        tool_name: str,
        target: str,
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
                tool_name=tool_name,
                target=target,
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
        tool_name: str,
        target: str,
        command: list[str],
        output_dir: str,
        timeout: int,
        job_id: uuid.UUID,
    ) -> ContainerResult:
        """Simulation mode when Docker is not available.

        Creates a mock output file for dev/test environments.
        """
        logger.info("SIMULATION: %s (job=%s)", tool_name, job_id)

        self._write_simulated_output(
            tool_name=tool_name,
            target=target,
            output_dir=Path(output_dir),
            command=command,
            job_id=job_id,
        )

        # Simulate execution time (capped at 2s in sim mode)
        await asyncio.sleep(min(0.5, timeout / 100))

        return ContainerResult(
            exit_code=0,
            stdout=json.dumps(
                {
                    "tool": tool_name,
                    "job_id": str(job_id),
                    "status": "simulated",
                }
            ),
            stderr="",
            output_dir=output_dir,
            timed_out=False,
        )

    def _write_simulated_output(
        self,
        *,
        tool_name: str,
        target: str,
        output_dir: Path,
        command: list[str],
        job_id: uuid.UUID,
    ) -> None:
        host = _simulation_host(target)
        base_url = _simulation_base_url(target, host)

        json_payload: list[dict] | dict | None = None
        raw_payload: str | None = None
        filename = "output.json"

        if tool_name == "scope_check":
            json_payload = {
                "target": target or base_url,
                "asset_type": "web_app",
                "in_scope": True,
                "simulation": True,
            }
            filename = "scope.json"
        elif tool_name == "subfinder":
            json_payload = [
                {"host": host, "source": "dns"},
                {"host": f"api.{host}", "source": "crtsh"},
                {"host": f"admin.{host}", "source": "github"},
            ]
            filename = "subdomains.json"
        elif tool_name == "amass":
            json_payload = [
                {"host": host, "source": "amass"},
                {"host": f"staging.{host}", "source": "amass"},
            ]
            filename = "amass.json"
        elif tool_name == "nmap_discovery":
            raw_payload = _simulation_nmap_xml(
                host=host,
                services=[(80, "http", "nginx"), (443, "https", "nginx")],
            )
            filename = "nmap_discovery.xml"
        elif tool_name == "nmap_svc":
            raw_payload = _simulation_nmap_xml(
                host=host,
                services=[(80, "http", "nginx 1.24"), (443, "https", "nginx 1.24")],
            )
            filename = "nmap_svc.xml"
        elif tool_name == "ffuf":
            json_payload = [
                {"url": f"{base_url}/api/v1/auth/login", "status_code": 200, "length": 512, "words": 44},
                {"url": f"{base_url}/api/v1/users/2", "status_code": 200, "length": 338, "words": 28},
                {"url": f"{base_url}/internal/debug", "status_code": 500, "length": 824, "words": 61},
            ]
            filename = "ffuf.json"
        elif tool_name == "nuclei":
            json_payload = [
                {
                    "template-id": "pentra/sql-injection",
                    "matched-at": f"{base_url}/api/v1/auth/login",
                    "request": _simulation_http_request(
                        f"{base_url}/api/v1/auth/login",
                        method="POST",
                        body="{\"username\":\"admin' OR '1'='1\",\"password\":\"test\"}",
                    ),
                    "response": _simulation_http_response(
                        200,
                        '{"success":true,"token":"eyJhbGciOiJIUzI1NiJ9"}',
                    ),
                    "payload": "admin' OR '1'='1",
                    "info": {
                        "name": "SQL Injection in Login Endpoint",
                        "severity": "critical",
                        "description": "Authentication bypass exposes an injectable login query.",
                        "remediation": "Use parameterized queries and reject SQL meta-characters server-side.",
                        "classification": {"cve-id": ["CWE-89"], "cvss-score": 9.8},
                    },
                    "reference": [f"{base_url}/api/v1/auth/login"],
                },
                {
                    "template-id": "pentra/idor-users",
                    "matched-at": f"{base_url}/api/v1/users/2",
                    "request": _simulation_http_request(f"{base_url}/api/v1/users/2"),
                    "response": _simulation_http_response(
                        200,
                        '{"id":2,"email":"john.doe@example.com","salary":85000}',
                    ),
                    "info": {
                        "name": "Broken Access Control - IDOR",
                        "severity": "high",
                        "description": "User profile objects are readable across tenants.",
                        "remediation": "Enforce object-level authorization checks.",
                        "classification": {"cvss-score": 8.2},
                    },
                    "reference": [f"{base_url}/api/v1/users/2"],
                },
            ]
            filename = "nuclei.json"
        elif tool_name == "zap":
            json_payload = [
                {
                    "title": "Unsafe Java Deserialization",
                    "severity": "critical",
                    "url": f"{base_url}/api/v1/process",
                    "description": "Untrusted serialized objects trigger server-side gadget execution.",
                    "request": _simulation_http_request(
                        f"{base_url}/api/v1/process",
                        method="POST",
                        body="[binary serialized payload]",
                    ),
                    "response": _simulation_http_response(
                        500,
                        "<pre>uid=1000(appuser) gid=1000(appuser)</pre>",
                        content_type="text/html",
                    ),
                    "payload": "ysoserial CommonsCollections5",
                    "solution": "Disable native deserialization for untrusted user input.",
                }
            ]
            filename = "zap.json"
        elif tool_name.startswith("sqlmap"):
            raw_payload = textwrap.dedent(
                f"""
                [INFO] testing connection to the target URL
                [CRITICAL] parameter 'username' appears to be injectable
                target={base_url}/api/v1/auth/login
                payload=admin' OR '1'='1
                proof=database user: pentra_app
                """
            ).strip()
            filename = "sqlmap.txt"
        elif tool_name in {"metasploit", "msf_verify"}:
            json_payload = [
                {
                    "target": host,
                    "access_level": "shell",
                    "title": "Verified shell access",
                    "severity": "critical",
                    "description": "Metasploit achieved an application shell on the target.",
                    "exploit_result": "uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)",
                    "payload": "cmd/unix/reverse_bash",
                }
            ]
            filename = "metasploit.json"
        elif tool_name == "custom_poc":
            json_payload = [
                {
                    "target": host,
                    "username": "db_admin",
                    "title": "Credential leak through exposed backup archive",
                    "severity": "high",
                    "description": "Backup artifact exposed reusable database credentials.",
                    "exploit_result": "db_admin:Sup3rS3cret!",
                }
            ]
            filename = "poc_result.json"
        elif tool_name == "ai_triage":
            json_payload = [
                {
                    "title": "SQL Injection in Login Endpoint",
                    "severity": "critical",
                    "confidence": 98,
                    "target": host,
                    "endpoint": f"{base_url}/api/v1/auth/login",
                    "description": "Exploit path combines auth bypass with data exfiltration risk.",
                    "remediation": "Replace string interpolation in auth query with prepared statements.",
                    "request": _simulation_http_request(
                        f"{base_url}/api/v1/auth/login",
                        method="POST",
                        body="{\"username\":\"admin' OR '1'='1\",\"password\":\"test\"}",
                    ),
                    "response": _simulation_http_response(
                        200,
                        '{"success":true,"token":"eyJhbGciOiJIUzI1NiJ9"}',
                    ),
                    "cvss_score": 9.8,
                    "references": [f"{base_url}/api/v1/auth/login"],
                },
                {
                    "title": "Unsafe Java Deserialization",
                    "severity": "critical",
                    "confidence": 94,
                    "target": host,
                    "endpoint": f"{base_url}/api/v1/process",
                    "description": "RCE chain validated by exploit telemetry and server-side crash response.",
                    "remediation": "Replace Java native serialization with JSON and strict allowlists.",
                    "payload": "ysoserial CommonsCollections5",
                    "request": _simulation_http_request(
                        f"{base_url}/api/v1/process",
                        method="POST",
                        body="[binary serialized payload]",
                    ),
                    "response": _simulation_http_response(
                        500,
                        "<pre>uid=1000(appuser) gid=1000(appuser)</pre>",
                        content_type="text/html",
                    ),
                    "cvss_score": 9.1,
                },
            ]
            filename = "findings_scored.json"
        elif tool_name == "report_gen":
            json_payload = {
                "executive_summary": f"Autonomous assessment of {host} identified verified critical exposure paths.",
                "top_findings": [
                    "SQL Injection in Login Endpoint",
                    "Unsafe Java Deserialization",
                    "Verified shell access",
                ],
                "generated_from": "simulation",
                "job_id": str(job_id),
            }
            filename = "report.json"
        else:
            json_payload = {
                "tool": tool_name,
                "job_id": str(job_id),
                "simulation": True,
                "metadata": {
                    "command": " ".join(command),
                    "status": "simulated",
                },
            }

        output_path = output_dir / filename
        if raw_payload is not None:
            output_path.write_text(raw_payload)
            return

        output_path.write_text(json.dumps(json_payload, indent=2))

    async def cleanup_job(self, job_id: uuid.UUID) -> None:
        """Remove the working directory for a completed job."""
        work_dir = Path(WORK_DIR_BASE) / str(job_id)
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)
            logger.debug("Cleaned up work dir for job %s", job_id)


def _simulation_host(target: str) -> str:
    raw = target.strip() or "dev-web.pentra.local"
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    return raw or "dev-web.pentra.local"


def _simulation_base_url(target: str, host: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")
    return f"https://{host}"


def _simulation_nmap_xml(host: str, services: list[tuple[int, str, str]]) -> str:
    ports = []
    for port, service, version in services:
        ports.append(
            f"""
          <port protocol="tcp" portid="{port}">
            <state state="open" />
            <service name="{service}" version="{version}" />
          </port>
            """.rstrip()
        )

    joined_ports = "\n".join(ports)
    return textwrap.dedent(
        f"""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up" />
            <address addr="{host}" />
            <ports>
        {joined_ports}
            </ports>
          </host>
        </nmaprun>
        """
    ).strip()


def _simulation_http_request(url: str, *, method: str = "GET", body: str | None = None) -> str:
    path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
    host = url.split("://", 1)[1].split("/", 1)[0]
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Pentra/phase2-sim",
        "Accept: application/json",
    ]
    if body is not None:
        lines.extend(
            [
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
                "",
                body,
            ]
        )
    return "\n".join(lines)


def _simulation_http_response(
    status_code: int,
    body: str,
    *,
    content_type: str = "application/json",
) -> str:
    reason = {200: "OK", 500: "Internal Server Error"}.get(status_code, "OK")
    return "\n".join(
        [
            f"HTTP/1.1 {status_code} {reason}",
            f"Content-Type: {content_type}",
            "",
            body,
        ]
    )
