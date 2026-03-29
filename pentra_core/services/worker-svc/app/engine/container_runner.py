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
import ipaddress
import json
import logging
import os
import textwrap
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from app.engine.web_interaction_runner import WebInteractionRunner
from app.engine.tool_command_registry import (
    TOOL_CATALOG,
    ToolExecutionLog,
    build_comprehensive_nuclei_templates,
    get_tool,
)
from app.tools.tool_registry import get_tools_for_family
from pentra_common.execution_truth import classify_tool_execution

import time as _time

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────

WORK_DIR_BASE = os.getenv("WORKER_WORK_DIR", "/tmp/pentra/jobs")
MEMORY_LIMIT = os.getenv("CONTAINER_MEMORY_LIMIT", "2g")
CPU_LIMIT = float(os.getenv("CONTAINER_CPU_LIMIT", "2.0"))
NETWORK_MODE_DEFAULT = os.getenv("CONTAINER_NETWORK_MODE", "bridge")
EXECUTION_MODE = os.getenv("WORKER_EXECUTION_MODE", "hybrid").lower()
LIVE_EXECUTION_TOOLS = frozenset(
    tool.strip()
    for tool in os.getenv(
        "WORKER_LIVE_TOOLS",
        "scope_check,subfinder,amass,nmap_discovery,nmap_svc,httpx_probe,ffuf,nuclei,zap,"
        "sqlmap,sqlmap_verify,custom_poc,web_interact,dalfox,graphql_cop,jwt_tool,"
        "cors_scanner,nikto,header_audit_tool,git_clone,semgrep,trufflehog,"
        "dependency_audit,api_spec_parser",
    ).split(",")
    if tool.strip()
)
LIVE_TARGET_POLICY = os.getenv("WORKER_LIVE_TARGET_POLICY", "local_only").lower()
MAX_LIVE_TIMEOUT = int(os.getenv("WORKER_LIVE_MAX_TIMEOUT_SECONDS", "900"))
PREWARM_ENABLED = os.getenv("WORKER_PREWARM_IMAGES", "true").strip().lower() not in {
    "0",
    "false",
    "no",
}
PREWARM_MAX_CONCURRENCY = int(os.getenv("WORKER_PREWARM_MAX_CONCURRENCY", "2"))
_PREWARM_EXCLUDED_TOOLS = frozenset(
    {"scope_check", "custom_poc", "web_interact", "ai_triage", "report_gen"}
)

# Exploit family gets no network access
_FAMILY_NETWORK: dict[str, str] = {
    "exploit": "none",
}
_DEFAULT_HTTP_PROBE_PATHS = ["/", "/login", "/graphql", "/openapi.json", "/swagger.json"]
_DEFAULT_CONTENT_PATHS = [
    "login",
    "api",
    "graphql",
    "openapi.json",
    "swagger.json",
    "swagger",
    "admin",
    ".well-known/security.txt",
]
_MODE_DEMO_SIMULATED = "demo_simulated"
_MODE_CONTROLLED_LIVE_LOCAL = "controlled_live_local"
_MODE_CONTROLLED_LIVE_SCOPED = "controlled_live_scoped"
_MODE_CONTROLLED_LIVE_EXTERNAL = "controlled_live_external"


@dataclass
class ContainerResult:
    """Result from a container execution."""

    exit_code: int
    stdout: str
    stderr: str
    output_dir: str
    timed_out: bool = False
    execution_mode: str = _MODE_CONTROLLED_LIVE_LOCAL
    execution_provenance: str = "live"
    execution_reason: str | None = None
    execution_class: str = "external_tool"


@dataclass(frozen=True)
class ExecutionDecision:
    mode: str
    provenance: str
    reason: str | None = None

    @property
    def live(self) -> bool:
        return self.provenance == "live"


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
        self._web_runner = WebInteractionRunner()

    def planned_prewarm_images(self, *, worker_family: str) -> list[str]:
        """Return unique family-scoped Docker images worth warming on startup."""
        images: list[str] = []
        seen: set[str] = set()
        for tool in get_tools_for_family(worker_family):
            if tool.name not in LIVE_EXECUTION_TOOLS:
                continue
            if tool.name in _PREWARM_EXCLUDED_TOOLS:
                continue
            if tool.image in seen:
                continue
            seen.add(tool.image)
            images.append(tool.image)
        return images

    async def prewarm_images(
        self,
        *,
        worker_family: str,
    ) -> dict[str, dict[str, str]]:
        """Best-effort image prewarming for the worker family."""
        images = self.planned_prewarm_images(worker_family=worker_family)
        if not PREWARM_ENABLED or not images:
            return {}

        try:
            docker = await self._get_docker(
                execution_mode=_normalize_execution_mode(EXECUTION_MODE)
            )
        except RuntimeError as exc:
            return {
                image: {"status": "failed", "detail": str(exc)}
                for image in images
            }

        if docker == "simulation":
            return {
                image: {"status": "skipped", "detail": "demo_simulated_mode"}
                for image in images
            }

        semaphore = asyncio.Semaphore(max(PREWARM_MAX_CONCURRENCY, 1))

        async def _prewarm_image(image: str) -> tuple[str, dict[str, str]]:
            async with semaphore:
                try:
                    await asyncio.to_thread(docker.images.get, image)
                    logger.info("Prewarm image cached: %s", image)
                    return image, {"status": "cached", "detail": "already_present"}
                except Exception:
                    try:
                        logger.info("Prewarm pulling image: %s", image)
                        await asyncio.to_thread(docker.images.pull, image)
                        return image, {"status": "pulled", "detail": "pulled_on_startup"}
                    except Exception as exc:
                        logger.warning("Prewarm failed for %s: %s", image, exc)
                        return image, {"status": "failed", "detail": str(exc)}

        results = await asyncio.gather(*[_prewarm_image(image) for image in images])
        return {image: result for image, result in results}

    async def _get_docker(self, *, execution_mode: str):
        """Lazy-initialize Docker client."""
        if execution_mode == _MODE_DEMO_SIMULATED:
            logger.info("Worker execution mode forced to demo simulation")
            return "simulation"

        if self._docker == "simulation":
            self._docker = None

        if self._docker is None:
            try:
                import docker
                self._docker = docker.from_env()
                logger.info("Docker client initialized")
            except Exception:
                logger.exception("Docker is unavailable for execution mode %s", execution_mode)
                raise RuntimeError(f"Docker unavailable for execution mode {execution_mode}") from None
        return self._docker

    async def run(
        self,
        *,
        image: str,
        command: list[str],
        working_dir: str | None,
        entrypoint: list[str] | None,
        tool_name: str,
        target: str,
        job_id: uuid.UUID,
        worker_family: str,
        timeout: int = 600,
        env_vars: dict[str, str] | None = None,
        input_refs: dict[str, str] | None = None,
        scan_config: dict[str, object] | None = None,
        on_output_chunk: Callable[[str, str], Awaitable[None]] | None = None,
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

            # Resolve .ref files → actual data files (JSON/TXT)
            try:
                from app.engine.artifact_resolver import ArtifactResolver
                resolver = ArtifactResolver()
                await resolver.resolve_input_refs(input_dir)
            except Exception:
                logger.warning(
                    "Failed to resolve input refs for job %s — tools may miss upstream data",
                    job_id,
                )

        scan_config = scan_config or {}
        (work_dir / "config.json").write_text(json.dumps(scan_config, indent=2, default=str))
        self._prepare_runtime_inputs(
            tool_name=tool_name,
            target=target,
            input_dir=input_dir,
            scan_config=scan_config,
        )

        decision = self._resolve_execution_decision(
            tool_name=tool_name,
            target=target,
            scan_config=scan_config,
        )
        if decision.provenance == "blocked":
            return self._blocked(
                tool_name=tool_name,
                output_dir=str(output_dir),
                reason=str(decision.reason or "not_supported"),
                execution_mode=decision.mode,
                job_id=job_id,
            )

        if decision.provenance == "simulated":
            return await self._simulate(
                tool_name=tool_name,
                target=target,
                command=command, output_dir=str(output_dir),
                timeout=timeout, job_id=job_id,
                execution_mode=decision.mode,
                reason=decision.reason,
            )

        if tool_name == "scope_check":
            return await self._run_scope_check(
                target=target,
                output_dir=str(output_dir),
                job_id=job_id,
                scan_config=scan_config,
                execution_mode=decision.mode,
            )

        if tool_name == "custom_poc":
            return await self._run_custom_poc_verifier(
                target=target,
                output_dir=str(output_dir),
                job_id=job_id,
                scan_config=scan_config,
                execution_mode=decision.mode,
            )

        if tool_name == "web_interact":
            return await self._run_web_interact(
                target=target,
                output_dir=str(output_dir),
                job_id=job_id,
                scan_config=scan_config,
                execution_mode=decision.mode,
            )

        if tool_name == "dalfox":
            dalfox_targets = _read_nonempty_lines(input_dir / "dalfox_urls.txt")
            if not dalfox_targets:
                (output_dir / "dalfox.json").write_text("[]\n")
                return ContainerResult(
                    exit_code=0,
                    stdout="Skipped dalfox: no high-signal reflected-XSS candidates.\n",
                    stderr="",
                    output_dir=str(output_dir),
                    timed_out=False,
                    execution_mode=decision.mode,
                    execution_provenance="live",
                    execution_reason="no_candidate_targets",
                    execution_class=classify_tool_execution(tool_name),
                )

        docker = await self._get_docker(execution_mode=decision.mode)
        if docker == "simulation":
            return await self._simulate(
                tool_name=tool_name,
                target=target,
                command=command, output_dir=str(output_dir),
                timeout=timeout, job_id=job_id,
                execution_mode=decision.mode,
                reason="demo_simulated_mode",
            )

        return await self._run_docker(
            docker=docker,
            image=image,
            command=command,
            working_dir=working_dir,
            entrypoint=entrypoint,
            work_dir=str(work_dir),
            output_dir=str(output_dir),
            worker_family=worker_family,
            timeout=min(timeout, MAX_LIVE_TIMEOUT),
            env_vars=env_vars or {},
            job_id=job_id,
            target=target,
            execution_mode=decision.mode,
            tool_name=tool_name,
            scan_config=scan_config,
            on_output_chunk=on_output_chunk,
        )

    async def _run_docker(
        self,
        *,
        docker,
        image: str,
        command: list[str],
        working_dir: str | None,
        entrypoint: list[str] | None,
        work_dir: str,
        output_dir: str,
        worker_family: str,
        timeout: int,
        env_vars: dict[str, str],
        job_id: uuid.UUID,
        target: str,
        execution_mode: str,
        tool_name: str = "",
        scan_config: dict[str, object] | None = None,
        on_output_chunk: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> ContainerResult:
        """Run inside a real Docker container."""
        network_mode = self._resolve_network_mode(
            worker_family=worker_family,
            target=target,
            live_execution=True,
        )
        container_name = f"pentra-job-{str(job_id)[:8]}"

        try:
            # Pull image if needed
            try:
                docker.images.get(image)
            except Exception:
                logger.info("Pulling image: %s", image)
                await asyncio.to_thread(docker.images.pull, image)

            # Reclaim stale container names left behind by interrupted runs.
            try:
                existing = await asyncio.to_thread(docker.containers.get, container_name)
            except Exception:
                existing = None
            if existing is not None:
                logger.warning("Removing stale container before reuse: %s", container_name)
                try:
                    await asyncio.to_thread(existing.remove, force=True)
                except Exception:
                    logger.warning(
                        "Failed to remove stale container %s before execution",
                        container_name,
                        exc_info=True,
                    )

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
                working_dir=working_dir or "/work/output",
                entrypoint=entrypoint,
                environment=env_vars,
                network_mode=network_mode,
                mem_limit=MEMORY_LIMIT,
                nano_cpus=int(CPU_LIMIT * 1e9),
                read_only=False,  # tools need to write
                security_opt=["no-new-privileges"],
                auto_remove=False,
            )

            stdout = ""
            stderr = ""
            timed_out = False
            exit_code = -1
            started_at = _time.monotonic()

            while True:
                current_stdout = (
                    await asyncio.to_thread(container.logs, stdout=True, stderr=False)
                ).decode("utf-8", errors="replace")
                current_stderr = (
                    await asyncio.to_thread(container.logs, stdout=False, stderr=True)
                ).decode("utf-8", errors="replace")

                stdout_delta = (
                    current_stdout[len(stdout) :]
                    if current_stdout.startswith(stdout)
                    else current_stdout
                )
                stderr_delta = (
                    current_stderr[len(stderr) :]
                    if current_stderr.startswith(stderr)
                    else current_stderr
                )
                stdout = current_stdout
                stderr = current_stderr

                if on_output_chunk is not None:
                    if stdout_delta:
                        await on_output_chunk("stdout", stdout_delta)
                    if stderr_delta:
                        await on_output_chunk("stderr", stderr_delta)

                await asyncio.to_thread(container.reload)
                state = container.attrs.get("State") if isinstance(container.attrs, dict) else {}
                state = state if isinstance(state, dict) else {}
                status = str(state.get("Status") or "").strip().lower()
                if status in {"exited", "dead"}:
                    exit_code = int(state.get("ExitCode", -1) or -1)
                    break

                if _time.monotonic() - started_at >= timeout:
                    logger.warning("Container %s timed out after %ds", container_name, timeout)
                    await asyncio.to_thread(container.kill)
                    exit_code = -1
                    timed_out = True
                    break

                await asyncio.sleep(0.5)

            final_stdout = (
                await asyncio.to_thread(container.logs, stdout=True, stderr=False)
            ).decode("utf-8", errors="replace")
            final_stderr = (
                await asyncio.to_thread(container.logs, stdout=False, stderr=True)
            ).decode("utf-8", errors="replace")
            if final_stdout.startswith(stdout):
                stdout_delta = final_stdout[len(stdout) :]
            else:
                stdout_delta = final_stdout
            if final_stderr.startswith(stderr):
                stderr_delta = final_stderr[len(stderr) :]
            else:
                stderr_delta = final_stderr
            stdout = final_stdout
            stderr = final_stderr
            if on_output_chunk is not None:
                if stdout_delta:
                    await on_output_chunk("stdout", stdout_delta)
                if stderr_delta:
                    await on_output_chunk("stderr", stderr_delta)

            self._write_container_logs(output_dir=output_dir, stdout=stdout, stderr=stderr)
            if tool_name == "graphql_cop":
                self._materialize_graphql_cop_output(output_dir=output_dir, stdout=stdout)

            # Cleanup container
            try:
                await asyncio.to_thread(container.remove, force=True)
            except Exception:
                pass

            logger.info(
                "Container %s finished: exit_code=%d timed_out=%s",
                container_name, exit_code, timed_out,
            )

            # Write FULL stdout/stderr to files before truncating for event payload
            stdout_file = Path(str(output_dir)) / "stdout.txt"
            stderr_file = Path(str(output_dir)) / "stderr.txt"
            if stdout:
                stdout_file.write_text(stdout)
            if stderr:
                stderr_file.write_text(stderr)

            return ContainerResult(
                exit_code=exit_code,
                stdout=stdout[-50_000:],  # 50KB for event payload (was 10KB)
                stderr=stderr[-10_000:],
                output_dir=output_dir,
                timed_out=timed_out,
                execution_mode=execution_mode,
                execution_provenance="live",
                execution_class=classify_tool_execution(tool_name),
            )

        except Exception as e:
            logger.exception("Container execution failed for job %s", job_id)
            return ContainerResult(
                exit_code=-1,
                stdout="",
                stderr=str(e)[:5_000],
                output_dir=output_dir,
                timed_out=False,
                execution_mode=execution_mode,
                execution_provenance="live",
                execution_reason="container_execution_error",
                execution_class=classify_tool_execution(tool_name),
            )

    def _write_execution_log(
        self,
        *,
        output_dir: str,
        tool_name: str,
        phase: str,
        command: list[str],
        stdout: str,
        stderr: str,
        exit_code: int,
        duration: float,
    ) -> None:
        """Append a tool execution log entry for terminal panel visibility."""
        log_path = Path(output_dir) / "tool_execution_log.json"
        logs: list[dict] = []
        if log_path.exists():
            try:
                logs = json.loads(log_path.read_text())
            except (json.JSONDecodeError, OSError):
                logs = []

        entry = ToolExecutionLog(
            tool_id=tool_name,
            phase=phase,
            command=command,
            stdout=stdout[-5_000:],
            stderr=stderr[-2_000:],
            exit_code=exit_code,
            duration_seconds=round(duration, 2),
            timestamp=_time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            description=f"{tool_name} — {phase}",
        )
        logs.append(entry.to_dict())
        log_path.write_text(json.dumps(logs, indent=2, default=str))

    def _resolve_execution_decision(
        self,
        *,
        tool_name: str,
        target: str,
        scan_config: dict[str, object],
    ) -> ExecutionDecision:
        mode = self._execution_mode(scan_config)
        if mode == _MODE_DEMO_SIMULATED:
            return ExecutionDecision(
                mode=mode,
                provenance="simulated",
                reason="demo_simulated_mode",
            )

        allowed_tools = self._allowed_live_tools(scan_config)
        if tool_name not in allowed_tools:
            logger.info("Tool %s not in live allowlist; blocking live execution", tool_name)
            reason = "not_supported"
            if tool_name in self._approval_required_tools(scan_config):
                reason = "approval_required"
            return ExecutionDecision(
                mode=mode,
                provenance="blocked",
                reason=reason,
            )

        if not self._target_allowed_for_live(target=target, scan_config=scan_config, mode=mode):
            logger.info("Target %s blocked by live target policy", target)
            return ExecutionDecision(
                mode=mode,
                provenance="blocked",
                reason="target_policy_blocked",
            )

        return ExecutionDecision(mode=mode, provenance="live")

    def resolve_execution_decision(
        self,
        *,
        tool_name: str,
        target: str,
        scan_config: dict[str, object],
    ) -> ExecutionDecision:
        """Expose runtime execution planning without duplicating worker policy logic."""
        return self._resolve_execution_decision(
            tool_name=tool_name,
            target=target,
            scan_config=scan_config,
        )

    def _execution_mode(self, scan_config: dict[str, object]) -> str:
        execution = scan_config.get("execution", {})
        if isinstance(execution, dict) and execution.get("mode"):
            return _normalize_execution_mode(str(execution["mode"]))
        return _normalize_execution_mode(EXECUTION_MODE)

    def _build_command_context(self, scan_config: dict[str, object]) -> dict[str, str]:
        """Build context variables for command template rendering."""
        cmd_ctx = scan_config.get("command_context", {})
        if not isinstance(cmd_ctx, dict):
            cmd_ctx = {}
        targeting = scan_config.get("targeting", {})
        if not isinstance(targeting, dict):
            targeting = {}
        selected = scan_config.get("selected_checks", {})
        if not isinstance(selected, dict):
            selected = {}
        rate_limits = scan_config.get("rate_limits", {})
        if not isinstance(rate_limits, dict):
            rate_limits = {}
        sqlmap_cfg = selected.get("sqlmap", {})
        if not isinstance(sqlmap_cfg, dict):
            sqlmap_cfg = {}

        return {
            "base_url": str(cmd_ctx.get("base_url") or targeting.get("base_url") or ""),
            "target_host": str(cmd_ctx.get("target_host") or targeting.get("host") or ""),
            "scope_domain": str(cmd_ctx.get("scope_host") or targeting.get("scope_domain") or ""),
            "nuclei_tags": str(cmd_ctx.get("nuclei_tags") or "exposure,misconfig,sqli,xss,rce,lfi,ssrf"),
            "nuclei_rate_limit": str(rate_limits.get("nuclei_requests_per_minute", 35)),
            "ffuf_rate_limit": str(rate_limits.get("ffuf_requests_per_minute", 60)),
            "sqlmap_threads": str(rate_limits.get("sqlmap_threads", 1)),
            "sqlmap_path": str(sqlmap_cfg.get("path", "/")),
        }

    def _allowed_live_tools(self, scan_config: dict[str, object]) -> set[str]:
        execution = scan_config.get("execution", {})
        if not isinstance(execution, dict):
            return set(LIVE_EXECUTION_TOOLS)

        configured = execution.get("allowed_live_tools", [])
        if not isinstance(configured, list):
            return set(LIVE_EXECUTION_TOOLS)

        allowed = {str(tool).strip() for tool in configured if str(tool).strip()}
        return allowed or set(LIVE_EXECUTION_TOOLS)

    def _approval_required_tools(self, scan_config: dict[str, object]) -> set[str]:
        execution = scan_config.get("execution", {})
        if not isinstance(execution, dict):
            return set()

        configured = execution.get("approval_required_tools", [])
        if not isinstance(configured, list):
            return set()

        return {str(tool).strip() for tool in configured if str(tool).strip()}

    def _target_allowed_for_live(
        self,
        *,
        target: str,
        scan_config: dict[str, object],
        mode: str | None = None,
    ) -> bool:
        mode = _normalize_execution_mode(mode or self._execution_mode(scan_config))
        execution = scan_config.get("execution", {})
        if mode == _MODE_CONTROLLED_LIVE_LOCAL:
            policy = "local_only"
        elif mode == _MODE_CONTROLLED_LIVE_SCOPED:
            policy = "in_scope"
        else:
            policy = LIVE_TARGET_POLICY
        if isinstance(execution, dict) and execution.get("target_policy"):
            policy = str(execution["target_policy"]).strip().lower()

        host = _host_from_target(target)
        if policy == "local_only":
            return _is_local_host(host)

        if policy == "in_scope" or policy == "external_authorized":
            return _host_in_scope(host=host, scan_config=scan_config)

        return True

    def _prepare_runtime_inputs(
        self,
        *,
        tool_name: str,
        target: str,
        input_dir: Path,
        scan_config: dict[str, object],
    ) -> None:
        base_url = _base_url_from_target(target)
        selected_checks = scan_config.get("selected_checks", {})
        if not isinstance(selected_checks, dict):
            selected_checks = {}

        if tool_name == "httpx_probe":
            http_probe_paths = selected_checks.get("http_probe_paths", _DEFAULT_HTTP_PROBE_PATHS)
            paths = [
                _join_url(base_url, str(path))
                for path in http_probe_paths
                if str(path).strip()
            ]
            (input_dir / "httpx_targets.txt").write_text("\n".join(paths) + "\n")

        if tool_name == "ffuf":
            content_paths = selected_checks.get("content_paths", _DEFAULT_CONTENT_PATHS)
            entries = [
                _normalize_wordlist_entry(str(path))
                for path in content_paths
                if str(path).strip()
            ]
            bounded_entries = entries[:20]
            (input_dir / "ffuf_wordlist.txt").write_text("\n".join(bounded_entries) + "\n")

        if tool_name == "dalfox":
            dalfox_targets = _build_dalfox_targets(
                base_url=base_url,
                input_dir=input_dir,
                selected_checks=selected_checks,
            )
            (input_dir / "dalfox_urls.txt").write_text("\n".join(dalfox_targets) + "\n")

        if tool_name == "nuclei":
            templates_dir = input_dir / "nuclei-templates"
            templates_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "nuclei_targets.txt").write_text(f"{base_url}\n")

            templates = (
                _build_local_validation_nuclei_templates()
                if _is_local_host(_host_from_target(target))
                else _build_scoped_nuclei_templates()
            )
            for filename, content in templates.items():
                (templates_dir / filename).write_text(content)

    async def _run_scope_check(
        self,
        *,
        target: str,
        output_dir: str,
        job_id: uuid.UUID,
        scan_config: dict[str, object],
        execution_mode: str,
    ) -> ContainerResult:
        targeting = scan_config.get("targeting", {})
        if not isinstance(targeting, dict):
            targeting = {}
        execution = scan_config.get("execution", {})
        if not isinstance(execution, dict):
            execution = {}
        payload = {
            "target": target,
            "asset_type": str(targeting.get("asset_type") or "web_app"),
            "in_scope": self._target_allowed_for_live(
                target=target,
                scan_config=scan_config,
                mode=execution_mode,
            ),
            "target_policy": str(
                execution.get("target_policy")
                or ("local_only" if execution_mode == _MODE_CONTROLLED_LIVE_LOCAL else "in_scope")
            ),
        }
        output_path = Path(output_dir) / "scope.json"
        output_path.write_text(json.dumps(payload, indent=2))
        return ContainerResult(
            exit_code=0,
            stdout=json.dumps({"tool": "scope_check", "job_id": str(job_id), "status": "completed"}),
            stderr="",
            output_dir=output_dir,
            timed_out=False,
            execution_mode=execution_mode,
            execution_provenance="live",
            execution_class=classify_tool_execution("scope_check"),
        )

    async def _run_custom_poc_verifier(
        self,
        *,
        target: str,
        output_dir: str,
        job_id: uuid.UUID,
        scan_config: dict[str, object],
        execution_mode: str,
    ) -> ContainerResult:
        workflow_mutation = str(scan_config.get("workflow_mutation") or "").strip().lower()
        if workflow_mutation:
            return await self._run_workflow_mutation_probe(
                target=target,
                output_dir=output_dir,
                job_id=job_id,
                scan_config=scan_config,
                execution_mode=execution_mode,
            )

        verification_context = scan_config.get("verification_context", {})
        if not isinstance(verification_context, dict):
            verification_context = {}

        verify_type = str(verification_context.get("verify_type") or "custom_poc").strip().lower()
        if verify_type not in {
            "idor_read",
            "sensitive_config_exposure",
            "sensitive_data_exposure",
            "stack_trace_exposure",
            "xss_reflect",
            "xss_browser",
        }:
            logger.info("custom_poc verify_type=%s is not supported for live mode", verify_type)
            return self._blocked(
                tool_name="custom_poc",
                output_dir=output_dir,
                reason="not_supported",
                execution_mode=execution_mode,
                job_id=job_id,
            )

        request_url = str(
            verification_context.get("request_url")
            or verification_context.get("endpoint")
            or target
        ).strip()
        headers = {
            "User-Agent": "Pentra-Custom-POC/phase4",
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
            "X-Pentra-Verification": verify_type,
        }

        try:
            if verify_type == "xss_browser":
                payload = await self._run_browser_xss_verifier(
                    request_url=request_url,
                    verification_context=verification_context,
                    output_dir=output_dir,
                )
            else:
                response = await asyncio.to_thread(
                    self._fetch_http_response,
                    request_url,
                    headers,
                )
                payload = self._build_custom_poc_verification_payload(
                    verify_type=verify_type,
                    request_url=request_url,
                    response=response,
                    verification_context=verification_context,
                )
        except (HTTPError, URLError) as exc:
            logger.warning("custom_poc verification failed for %s: %s", request_url, exc)
            payload = []
        except Exception as exc:
            logger.warning("browser-backed custom_poc verification failed for %s: %s", request_url, exc)
            payload = []

        output_path = Path(output_dir) / "poc_result.json"
        output_path.write_text(json.dumps(payload, indent=2))

        return ContainerResult(
            exit_code=0,
            stdout=json.dumps({"tool": "custom_poc", "job_id": str(job_id), "status": "verified"}),
            stderr="",
            output_dir=output_dir,
            timed_out=False,
            execution_mode=execution_mode,
            execution_provenance="live",
            execution_class=classify_tool_execution("custom_poc"),
        )

    async def _run_browser_xss_verifier(
        self,
        *,
        request_url: str,
        verification_context: dict[str, object],
        output_dir: str,
    ) -> list[dict[str, object]]:
        probe_input = {
            "request_url": request_url,
            "verification_context": verification_context,
            "chromium_path": os.getenv("PENTRA_CHROMIUM_PATH", "/usr/bin/chromium"),
        }
        helper_input_path = Path(output_dir) / "xss_browser_input.json"
        helper_output_path = Path(output_dir) / "xss_browser_output.json"
        helper_input_path.write_text(json.dumps(probe_input, indent=2))

        helper_script = Path(__file__).with_name("browser_xss_probe.py")
        helper_python = os.getenv("PENTRA_BROWSER_PYTHON", "python3")
        process = await asyncio.create_subprocess_exec(
            helper_python,
            str(helper_script),
            "--input",
            str(helper_input_path),
            "--output",
            str(helper_output_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={
                **os.environ,
                "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            },
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=45)
        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            stdout_text = stdout.decode("utf-8", errors="replace").strip()
            raise RuntimeError(stderr_text or stdout_text or "browser_xss_probe failed")
        if not helper_output_path.exists():
            return []
        result = json.loads(helper_output_path.read_text())
        return result if isinstance(result, list) else []

    async def _run_web_interact(
        self,
        *,
        target: str,
        output_dir: str,
        job_id: uuid.UUID,
        scan_config: dict[str, object],
        execution_mode: str,
    ) -> ContainerResult:
        payload = await self._web_runner.run_discovery(
            base_url=_base_url_from_target(target),
            scan_config=scan_config,
        )

        output_path = Path(output_dir) / "web_interactions.json"
        output_path.write_text(json.dumps(payload, indent=2))

        return ContainerResult(
            exit_code=0,
            stdout=json.dumps({"tool": "web_interact", "job_id": str(job_id), "status": "completed"}),
            stderr="",
            output_dir=output_dir,
            timed_out=False,
            execution_mode=execution_mode,
            execution_provenance="live",
            execution_class=classify_tool_execution("web_interact"),
        )

    async def _run_workflow_mutation_probe(
        self,
        *,
        target: str,
        output_dir: str,
        job_id: uuid.UUID,
        scan_config: dict[str, object],
        execution_mode: str,
    ) -> ContainerResult:
        payload = await self._web_runner.run_workflow_mutation(
            base_url=_base_url_from_target(target),
            scan_config=scan_config,
            target=target,
        )

        output_path = Path(output_dir) / "poc_result.json"
        output_path.write_text(json.dumps(payload, indent=2))

        return ContainerResult(
            exit_code=0,
            stdout=json.dumps({"tool": "custom_poc", "job_id": str(job_id), "status": "workflow_mutation"}),
            stderr="",
            output_dir=output_dir,
            timed_out=False,
            execution_mode=execution_mode,
            execution_provenance="live",
            execution_class=classify_tool_execution("custom_poc"),
        )

    def _fetch_http_response(self, request_url: str, headers: dict[str, str]) -> dict[str, object]:
        request = Request(request_url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=10) as response:
                body = response.read().decode("utf-8", errors="replace")
                return {
                    "status_code": response.getcode(),
                    "body": body,
                    "content_type": response.headers.get("Content-Type", ""),
                }
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return {
                "status_code": int(exc.code or 0),
                "body": body,
                "content_type": exc.headers.get("Content-Type", ""),
            }

    def _build_custom_poc_verification_payload(
        self,
        *,
        verify_type: str,
        request_url: str,
        response: dict[str, object],
        verification_context: dict[str, object],
    ) -> list[dict[str, object]]:
        status_code = int(response.get("status_code") or 0)
        body = str(response.get("body") or "")
        content_type = str(response.get("content_type") or "")

        if verify_type == "idor_read":
            sensitive_markers = [
                str(marker).strip().lower()
                for marker in verification_context.get("sensitive_markers", ["email", "salary"])
                if str(marker).strip()
            ]
            matched_markers = [marker for marker in sensitive_markers if marker in body.lower()]
            if status_code == 200 and matched_markers:
                return [
                    {
                        "target": request_url,
                        "access_level": "unauthorized_object_read",
                        "title": "Verified IDOR data access",
                        "severity": "high",
                        "confidence": 96,
                        "description": (
                            "Safe verification confirmed unauthorized object access returned "
                            f"sensitive fields: {', '.join(matched_markers)}."
                        ),
                        "request": f"GET {request_url}",
                        "response": f"HTTP/1.1 {status_code}\n\n{body[:4000]}",
                        "exploit_result": (
                            "Unauthorized object read verified with sensitive field exposure: "
                            + ", ".join(matched_markers)
                        ),
                        "surface": "api" if "/api/" in request_url else "web",
                        "route_group": verification_context.get("route_group"),
                        "vulnerability_type": "idor",
                        "verification_state": "verified",
                        "verification_confidence": 96,
                        "exploitability": "high",
                        "exploitability_score": 92,
                    }
                ]
            return []

        if verify_type in {"sensitive_config_exposure", "sensitive_data_exposure"}:
            sensitive_markers = [
                str(marker).strip().lower()
                for marker in verification_context.get(
                    "sensitive_markers",
                    [
                        "config",
                        "baseurl",
                        "showversionnumber",
                        "localbackupenabled",
                        "email",
                        "password",
                        "role",
                        "totpsecret",
                        "deluxetoken",
                        "lastloginip",
                    ],
                )
                if str(marker).strip()
            ]
            lowered_body = body.lower()
            matched_markers = [marker for marker in sensitive_markers if marker in lowered_body]
            if status_code in {200, 401, 403} and matched_markers:
                marker_summary = ", ".join(matched_markers[:5])
                critical_markers = {"password", "totpsecret", "deluxetoken", "lastloginip"}
                exposes_user_records = any(marker in critical_markers for marker in matched_markers) or (
                    "email" in matched_markers and "role" in matched_markers
                )
                unauthorized = status_code in {401, 403}
                title = (
                    "Verified sensitive API data exposure"
                    if exposes_user_records
                    else "Verified exposed application configuration"
                )
                if exposes_user_records and unauthorized:
                    title = "Verified sensitive API data exposure despite authorization response"
                return [
                    {
                        "target": request_url,
                        "access_level": (
                            "unauthorized_data_read"
                            if exposes_user_records and unauthorized
                            else "sensitive_api_read"
                            if exposes_user_records
                            else "public_config_read"
                        ),
                        "title": title,
                        "severity": "critical" if exposes_user_records else "high",
                        "confidence": 96 if exposes_user_records else 94,
                        "description": (
                            "Safe verification confirmed the endpoint returned sensitive "
                            + (
                                "user-account data "
                                if exposes_user_records
                                else "application configuration markers "
                            )
                            + (
                                f"despite HTTP {status_code}: {marker_summary}."
                                if unauthorized
                                else f"{marker_summary}."
                            )
                        ),
                        "request": f"GET {request_url}",
                        "response": (
                            f"HTTP/1.1 {status_code}\nContent-Type: {content_type}\n\n{body[:4000]}"
                        ),
                        "exploit_result": (
                            (
                                "Sensitive API response exposed internal account fields: "
                                if exposes_user_records
                                else "Public configuration response exposed internal markers: "
                            )
                            + marker_summary
                        ),
                        "surface": (
                            "api" if "/api/" in request_url or "/rest/" in request_url else "web"
                        ),
                        "route_group": verification_context.get("route_group"),
                        "vulnerability_type": "sensitive_data_exposure",
                        "verification_state": "verified",
                        "verification_confidence": 96 if exposes_user_records else 94,
                        "exploitability": "high" if exposes_user_records else "medium",
                        "exploitability_score": 90 if exposes_user_records else 76,
                    }
                ]
            return []

        if verify_type == "stack_trace_exposure":
            lowered_body = body.lower()
            stack_trace_markers = [
                marker
                for marker in (
                    "<ul id=\"stacktrace\">",
                    "error: unexpected path:",
                    "error: blocked illegal activity by",
                    "at /juice-shop/build/",
                    "/node_modules/express/lib/router/",
                    "router.process_params",
                    "express ^",
                    "unauthorizederror: no authorization header was found",
                )
                if marker in lowered_body
            ]
            if status_code in {401, 403, 500} and stack_trace_markers:
                marker_summary = ", ".join(stack_trace_markers[:4])
                return [
                    {
                        "target": request_url,
                        "access_level": "verbose_error_page",
                        "title": "Verified stack trace exposure",
                        "severity": "high",
                        "confidence": 94,
                        "description": (
                            "Safe verification confirmed a public verbose error page exposed "
                            f"internal framework details: {marker_summary}."
                        ),
                        "request": f"GET {request_url}",
                        "response": (
                            f"HTTP/1.1 {status_code}\nContent-Type: {content_type}\n\n{body[:4000]}"
                        ),
                        "exploit_result": (
                            "Verbose error response exposed internal stack-trace markers: "
                            + marker_summary
                        ),
                        "surface": (
                            "api" if "/api/" in request_url or "/rest/" in request_url else "web"
                        ),
                        "route_group": verification_context.get("route_group"),
                        "vulnerability_type": "stack_trace_exposure",
                        "verification_state": "verified",
                        "verification_confidence": 94,
                        "exploitability": "medium",
                        "exploitability_score": 66,
                    }
                ]
            return []

        if verify_type == "xss_reflect":
            probe_payload = "<svg id=pentra-xss>"
            probe_url = self._inject_reflection_probe(request_url, payload=probe_payload)
            if probe_url is None or (content_type and "html" not in content_type.lower()):
                return []
            if status_code == 200 and probe_payload.lower() in body.lower():
                return [
                    {
                        "target": probe_url,
                        "access_level": "reflected_script_injection",
                        "title": "Verified reflected XSS",
                        "severity": "high",
                        "confidence": 93,
                        "description": (
                            "Safe verification confirmed unescaped script-tag-like input was "
                            "reflected in an HTML response."
                        ),
                        "request": f"GET {probe_url}",
                        "response": (
                            f"HTTP/1.1 {status_code}\nContent-Type: {content_type}\n\n{body[:4000]}"
                        ),
                        "exploit_result": (
                            "Unescaped HTML reflection confirmed with Pentra marker payload."
                        ),
                        "surface": "web",
                        "route_group": verification_context.get("route_group"),
                        "vulnerability_type": "xss",
                        "verification_state": "verified",
                        "verification_confidence": 93,
                        "exploitability": "high",
                        "exploitability_score": 88,
                    }
                ]
            return []

        return []

    def _inject_reflection_probe(self, request_url: str, *, payload: str) -> str | None:
        parsed = urlparse(request_url)
        query = list(parse_qsl(parsed.query, keep_blank_values=True))
        if not query:
            return None
        key, _ = query[0]
        query[0] = (key, payload)
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _resolve_network_mode(
        self,
        *,
        worker_family: str,
        target: str,
        live_execution: bool,
    ) -> str:
        if worker_family in _FAMILY_NETWORK:
            return _FAMILY_NETWORK[worker_family]

        if live_execution and _is_local_host(_host_from_target(target)):
            return "host"

        return NETWORK_MODE_DEFAULT

    def _write_container_logs(self, *, output_dir: str, stdout: str, stderr: str) -> None:
        output_path = Path(output_dir)
        if stdout.strip():
            (output_path / "_stdout.log").write_text(stdout[-50_000:])
        if stderr.strip():
            (output_path / "_stderr.log").write_text(stderr[-20_000:])

    def _materialize_graphql_cop_output(self, *, output_dir: str, stdout: str) -> None:
        output_path = Path(output_dir)
        if any(output_path.glob("*.json")):
            return

        payload: Any = []
        for line in reversed(stdout.splitlines()):
            candidate = line.strip()
            if not candidate:
                continue
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, list):
                payload = parsed
            elif isinstance(parsed, dict):
                payload = [parsed]
            else:
                payload = []
            break

        (output_path / "graphql_cop.json").write_text(
            json.dumps(payload, indent=2, default=str) + "\n"
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
        execution_mode: str,
        reason: str | None,
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
            execution_mode=execution_mode,
            execution_provenance="simulated",
            execution_reason=reason or "demo_simulated_mode",
            execution_class=classify_tool_execution(tool_name),
        )

    def _blocked(
        self,
        *,
        tool_name: str,
        output_dir: str,
        reason: str,
        execution_mode: str,
        job_id: uuid.UUID,
    ) -> ContainerResult:
        logger.warning(
            "Execution blocked for %s (job=%s mode=%s reason=%s)",
            tool_name,
            job_id,
            execution_mode,
            reason,
        )
        return ContainerResult(
            exit_code=0,
            stdout=json.dumps(
                {
                    "tool": tool_name,
                    "job_id": str(job_id),
                    "status": "blocked",
                    "reason": reason,
                }
            ),
            stderr="",
            output_dir=output_dir,
            timed_out=False,
            execution_mode=execution_mode,
            execution_provenance="blocked",
            execution_reason=reason,
            execution_class=classify_tool_execution(tool_name),
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
                {"host": f"graphql.{host}", "source": "amass"},
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
                services=[(80, "http", "nginx 1.24"), (443, "https", "nginx 1.24"), (8443, "https", "envoy")],
            )
            filename = "nmap_svc.xml"
        elif tool_name == "httpx_probe":
            json_payload = [
                {
                    "url": f"{base_url}",
                    "status_code": 200,
                    "content_length": 18422,
                    "title": "Pentra Demo Portal",
                    "webserver": "nginx",
                    "tech": ["Next.js", "Node.js"],
                },
                {
                    "url": f"{base_url}/graphql",
                    "status_code": 200,
                    "content_length": 612,
                    "title": "GraphQL API",
                    "webserver": "nginx",
                    "tech": ["GraphQL", "Apollo Server"],
                },
                {
                    "url": f"{base_url}/openapi.json",
                    "status_code": 200,
                    "content_length": 2401,
                    "title": "OpenAPI Specification",
                    "webserver": "nginx",
                    "tech": ["OpenAPI", "Swagger UI"],
                },
            ]
            filename = "httpx.json"
        elif tool_name == "web_interact":
            json_payload = {
                "pages": [
                    {
                        "url": f"{base_url}/login",
                        "title": "Pentra Login",
                        "status_code": 200,
                        "session_label": "unauthenticated",
                        "auth_state": "none",
                    },
                    {
                        "url": f"{base_url}/portal/dashboard",
                        "title": "Customer Dashboard",
                        "status_code": 200,
                        "session_label": "john",
                        "auth_state": "authenticated",
                    },
                    {
                        "url": f"{base_url}/portal/checkout/cart",
                        "title": "Checkout Cart",
                        "status_code": 200,
                        "session_label": "john",
                        "auth_state": "authenticated",
                    },
                ],
                "forms": [
                    {
                        "page_url": f"{base_url}/login",
                        "action_url": f"{base_url}/login",
                        "method": "POST",
                        "field_names": ["username", "password", "csrf_token"],
                        "hidden_field_names": ["csrf_token"],
                        "has_csrf": True,
                        "safe_replay": True,
                        "session_label": "unauthenticated",
                    },
                    {
                        "page_url": f"{base_url}/portal/checkout/cart",
                        "action_url": f"{base_url}/portal/checkout/confirm",
                        "method": "POST",
                        "field_names": ["item_id", "quantity", "csrf_token", "pentra_safe_replay"],
                        "hidden_field_names": ["csrf_token", "pentra_safe_replay"],
                        "has_csrf": True,
                        "safe_replay": True,
                        "session_label": "john",
                    },
                ],
                "sessions": [
                    {
                        "session_label": "unauthenticated",
                        "auth_state": "none",
                        "cookie_names": [],
                        "csrf_tokens": [],
                    },
                    {
                        "session_label": "john",
                        "auth_state": "authenticated",
                        "cookie_names": ["pentra_session", "csrf_token"],
                        "csrf_tokens": ["demo-csrf"],
                    },
                ],
                "workflows": [
                    {
                        "source_url": f"{base_url}/login",
                        "target_url": f"{base_url}/portal/dashboard",
                        "action": "login",
                        "requires_auth": False,
                        "session_label": "john",
                    },
                    {
                        "source_url": f"{base_url}/portal/dashboard",
                        "target_url": f"{base_url}/portal/checkout/cart",
                        "action": "navigate",
                        "requires_auth": True,
                        "session_label": "john",
                    },
                    {
                        "source_url": f"{base_url}/portal/checkout/cart",
                        "target_url": f"{base_url}/portal/checkout/confirm",
                        "action": "submit",
                        "requires_auth": True,
                        "session_label": "john",
                    },
                ],
                "replays": [
                    {
                        "request": f"POST {base_url}/login",
                        "target_url": f"{base_url}/login",
                        "session_label": "john",
                        "status_code": 200,
                        "response_preview": "<html><body>Dashboard</body></html>",
                    }
                ],
            }
            filename = "web_interactions.json"
        elif tool_name == "ffuf":
            json_payload = [
                {"url": f"{base_url}/api/v1/auth/login", "status_code": 200, "length": 512, "words": 44},
                {"url": f"{base_url}/api/v1/users/2", "status_code": 200, "length": 338, "words": 28},
                {"url": f"{base_url}/graphql", "status_code": 200, "length": 612, "words": 31},
                {"url": f"{base_url}/openapi.json", "status_code": 200, "length": 2401, "words": 214},
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
                {
                    "template-id": "pentra/openapi-exposure",
                    "matched-at": f"{base_url}/openapi.json",
                    "request": _simulation_http_request(f"{base_url}/openapi.json"),
                    "response": _simulation_http_response(
                        200,
                        '{"openapi":"3.0.3","info":{"title":"Pentra Demo API"}}',
                    ),
                    "info": {
                        "name": "Exposed OpenAPI Schema",
                        "severity": "medium",
                        "description": "Unauthenticated OpenAPI documentation reveals internal API routes.",
                        "remediation": "Require authentication for sensitive API docs or strip internal paths.",
                    },
                    "reference": [f"{base_url}/openapi.json"],
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
                },
                {
                    "title": "GraphQL Introspection Enabled",
                    "severity": "medium",
                    "url": f"{base_url}/graphql",
                    "description": "The production GraphQL endpoint returns the full schema to unauthenticated users.",
                    "request": _simulation_http_request(
                        f"{base_url}/graphql",
                        method="POST",
                        body='{"query":"{ __schema { types { name } } }"}',
                    ),
                    "response": _simulation_http_response(
                        200,
                        '{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}',
                    ),
                    "payload": "__schema introspection query",
                    "solution": "Disable GraphQL introspection or gate it behind trusted operator access.",
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
                    "title": "Broken Access Control - IDOR",
                    "severity": "high",
                    "confidence": 93,
                    "target": host,
                    "endpoint": f"{base_url}/api/v1/users/2",
                    "description": "Object IDs can be enumerated across tenants without authorization checks.",
                    "remediation": "Enforce object-level authorization checks on every user-scoped API request.",
                    "request": _simulation_http_request(f"{base_url}/api/v1/users/2"),
                    "response": _simulation_http_response(
                        200,
                        '{"id":2,"email":"john.doe@example.com","salary":85000}',
                    ),
                    "cvss_score": 8.2,
                    "references": [f"{base_url}/api/v1/users/2"],
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
                "executive_summary": (
                    f"Autonomous External Web + API assessment of {host} identified "
                    "repeatable exploit-backed exposure paths across authentication and API surfaces."
                ),
                "top_findings": [
                    "SQL Injection in Login Endpoint",
                    "Broken Access Control - IDOR",
                    "Unsafe Java Deserialization",
                ],
                "generated_from": "simulation",
                "job_id": str(job_id),
            }
            filename = "report.json"
        elif tool_name == "nikto":
            json_payload = [
                {
                    "title": "Server Header Disclosure",
                    "severity": "info",
                    "url": f"{base_url}/",
                    "description": "Web server reveals version information in HTTP headers.",
                    "finding": f"Server: nginx/1.24.0 at {host}",
                },
                {
                    "title": "Missing X-Content-Type-Options Header",
                    "severity": "low",
                    "url": f"{base_url}/",
                    "description": "The X-Content-Type-Options header is not set, allowing MIME-type sniffing.",
                    "finding": "Header not present: X-Content-Type-Options",
                },
                {
                    "title": "Directory Listing Enabled",
                    "severity": "medium",
                    "url": f"{base_url}/static/",
                    "description": "Directory indexing is enabled on the /static/ path, exposing file listings.",
                    "finding": f"GET {base_url}/static/ returned index listing",
                },
                {
                    "title": "Backup File Detected",
                    "severity": "high",
                    "url": f"{base_url}/db_backup.sql.bak",
                    "description": "A database backup file is publicly accessible.",
                    "finding": f"GET {base_url}/db_backup.sql.bak returned 200 (14302 bytes)",
                },
            ]
            filename = "nikto.json"
        elif tool_name == "cors_check":
            json_payload = [
                {
                    "title": "CORS Misconfiguration — Wildcard Origin Reflected",
                    "severity": "high",
                    "url": f"{base_url}/api/v1/users",
                    "description": (
                        "The server reflects the Origin header in Access-Control-Allow-Origin "
                        "without validation, allowing any domain to read authenticated responses."
                    ),
                    "matched_header": "Access-Control-Allow-Origin: https://evil.pentra.test",
                    "credentials_allowed": True,
                },
                {
                    "title": "CORS — Credentials Allowed with Reflected Origin",
                    "severity": "high",
                    "url": f"{base_url}/graphql",
                    "description": (
                        "Access-Control-Allow-Credentials is true while reflecting arbitrary origins."
                    ),
                    "matched_header": "Access-Control-Allow-Credentials: true",
                    "credentials_allowed": True,
                },
            ]
            filename = "cors_check.json"
        elif tool_name == "header_audit":
            json_payload = [
                {
                    "title": "Missing Content-Security-Policy Header",
                    "severity": "medium",
                    "url": f"{base_url}/",
                    "description": "No CSP header is set, increasing XSS exploit surface.",
                    "missing_header": "Content-Security-Policy",
                },
                {
                    "title": "Missing Strict-Transport-Security Header",
                    "severity": "medium",
                    "url": f"{base_url}/",
                    "description": "HSTS is not enforced, exposing users to protocol downgrade attacks.",
                    "missing_header": "Strict-Transport-Security",
                },
                {
                    "title": "X-Frame-Options Not Set",
                    "severity": "low",
                    "url": f"{base_url}/",
                    "description": "Missing X-Frame-Options allows clickjacking on authenticated pages.",
                    "missing_header": "X-Frame-Options",
                },
                {
                    "title": "Referrer-Policy Not Set",
                    "severity": "low",
                    "url": f"{base_url}/",
                    "description": "No Referrer-Policy header, default browser behavior may leak URLs.",
                    "missing_header": "Referrer-Policy",
                },
            ]
            filename = "header_audit.json"
        elif tool_name == "tech_detect":
            json_payload = [
                {
                    "url": f"{base_url}",
                    "technologies": ["Next.js", "React", "Node.js", "nginx"],
                    "web_server": "nginx/1.24.0",
                    "status_code": 200,
                    "title": "Pentra Demo Portal",
                },
                {
                    "url": f"{base_url}/graphql",
                    "technologies": ["GraphQL", "Apollo Server", "Node.js"],
                    "web_server": "nginx/1.24.0",
                    "status_code": 200,
                    "title": "GraphQL API",
                },
                {
                    "url": f"{base_url}/api/v1",
                    "technologies": ["FastAPI", "Python", "Uvicorn"],
                    "web_server": "uvicorn",
                    "status_code": 200,
                    "title": "Pentra API v1",
                },
            ]
            filename = "tech_detect.json"
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


def _simulation_http_request(
    url: str,
    *,
    method: str = "GET",
    body: str | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
    host = url.split("://", 1)[1].split("/", 1)[0]
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Pentra/phase2-sim",
        "X-Pentra-Profile: external_web_api_v1",
        "Accept: application/json",
    ]
    if headers:
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
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


def _host_from_target(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return parsed.hostname or raw.split("/", 1)[0]


def _base_url_from_target(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path.split("/", 1)[0]
    path_prefix = (parsed.path or "").rstrip("/")
    return f"{scheme}://{netloc}{path_prefix}".rstrip("/")


def _build_dalfox_targets(
    *,
    base_url: str,
    input_dir: Path,
    selected_checks: dict[str, object],
) -> list[str]:
    dalfox_config = selected_checks.get("dalfox", {})
    if not isinstance(dalfox_config, dict):
        dalfox_config = {}

    max_targets = _bounded_int(
        dalfox_config.get("max_targets"),
        default=4,
        minimum=1,
        maximum=12,
    )
    allow_path_only = bool(dalfox_config.get("allow_path_only"))

    targets: set[str] = set()

    endpoints_path = input_dir / "endpoints.json"
    if endpoints_path.exists():
        try:
            payload = json.loads(endpoints_path.read_text())
        except (json.JSONDecodeError, OSError):
            payload = []
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url") or "").strip()
                if url:
                    targets.add(url)

    for collection_key in ("http_probe_paths", "content_paths"):
        values = selected_checks.get(collection_key, [])
        if not isinstance(values, list):
            continue
        for value in values:
            raw_value = str(value or "").strip()
            if not raw_value:
                continue
            if raw_value.startswith("http://") or raw_value.startswith("https://"):
                targets.add(raw_value)
            else:
                normalized = _normalize_wordlist_entry(raw_value)
                if normalized:
                    targets.add(_join_url(base_url, normalized))

    for value in _string_list(dalfox_config.get("include_urls")):
        if value.startswith("http://") or value.startswith("https://"):
            targets.add(value)
        else:
            normalized = _normalize_wordlist_entry(value)
            if normalized:
                targets.add(_join_url(base_url, normalized))

    enriched_targets = set(targets)
    for url in list(targets):
        lowered = url.lower()
        if "?" in url:
            continue
        if "search" in lowered:
            separator = "&" if "?" in url else "?"
            enriched_targets.add(f"{url}{separator}q=test")
        if lowered.endswith("/login") or lowered.endswith("/login.php"):
            enriched_targets.add(f"{url}?next=/")

    candidate_targets = {
        target
        for target in enriched_targets
        if _is_dalfox_candidate_target(target, allow_path_only=allow_path_only)
    }
    ranked_targets = sorted(
        (target for target in candidate_targets if target),
        key=lambda target: (-_score_dalfox_target(target), len(target), target),
    )
    return ranked_targets[:max_targets]


def _is_dalfox_candidate_target(target: str, *, allow_path_only: bool = False) -> bool:
    normalized = str(target or "").strip()
    if not normalized:
        return False
    lowered = normalized.lower()
    if "?" in normalized:
        return True
    if not allow_path_only:
        return False
    candidate_markers = (
        "search",
        "query",
        "redirect",
        "return",
        "callback",
        "next",
        "continue",
        "message",
        "comment",
        "feedback",
        "keyword",
    )
    return any(marker in lowered for marker in candidate_markers)


def _score_dalfox_target(target: str) -> int:
    lowered = str(target or "").lower()
    score = 0
    if "?" in lowered:
        score += 100
    if any(marker in lowered for marker in ("q=", "query=", "search", "keyword", "lang=", "redirect=", "next=")):
        score += 40
    if "/rest/products/search" in lowered:
        score += 50
    if any(marker in lowered for marker in ("message", "comment", "feedback", "return", "callback", "continue")):
        score += 20
    return score


def _read_nonempty_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    except OSError:
        return []


def _command_flag_value(command: list[str], *flags: str) -> str:
    for index, part in enumerate(command[:-1]):
        if part in flags:
            return str(command[index + 1]).strip()
    return ""


def _command_headers(command: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    index = 0
    while index < len(command):
        part = str(command[index]).strip()
        if part not in {"-H", "--header"}:
            index += 1
            continue
        if index + 1 >= len(command):
            break
        raw_value = str(command[index + 1]).strip()
        if not raw_value:
            index += 2
            continue
        try:
            parsed = json.loads(raw_value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                headers[str(key)] = str(value)
        elif ":" in raw_value:
            key, value = raw_value.split(":", 1)
            headers[key.strip()] = value.strip()
        index += 2
    return headers


def _graphql_probe_request(
    target_url: str,
    headers: dict[str, str],
    query: str,
) -> dict[str, Any]:
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Pentra-GraphQL-Probe/phase10",
        **headers,
    }
    body = json.dumps({"query": query}).encode("utf-8")
    request = Request(target_url, data=body, headers=request_headers, method="POST")
    try:
        with urlopen(request, timeout=15) as response:
            raw_body = response.read().decode("utf-8", errors="replace")
            status = getattr(response, "status", 200)
            content_type = response.headers.get("Content-Type", "application/json")
    except HTTPError as exc:
        raw_body = exc.read().decode("utf-8", errors="replace")
        status = exc.code
        content_type = exc.headers.get("Content-Type", "application/json") if exc.headers else "application/json"
    except URLError as exc:
        return {
            "status": None,
            "body": "",
            "json": None,
            "content_type": "application/json",
            "error": str(exc),
        }

    parsed_json: Any = None
    try:
        parsed_json = json.loads(raw_body)
    except json.JSONDecodeError:
        parsed_json = None

    return {
        "status": status,
        "body": raw_body,
        "json": parsed_json,
        "content_type": content_type,
        "error": None,
    }


def _graphql_response_indicates_endpoint(response: dict[str, Any]) -> bool:
    payload = response.get("json")
    if not isinstance(payload, dict):
        return False
    if isinstance(payload.get("data"), dict):
        return True
    errors = payload.get("errors")
    return isinstance(errors, list) and len(errors) > 0


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _normalize_execution_mode(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"simulate", "simulation", "demo", _MODE_DEMO_SIMULATED}:
        return _MODE_DEMO_SIMULATED
    if normalized in {"docker", "controlled_live_scoped", "live_scoped", _MODE_CONTROLLED_LIVE_SCOPED}:
        return _MODE_CONTROLLED_LIVE_SCOPED
    if normalized in {"hybrid", "controlled_live", "live_local", _MODE_CONTROLLED_LIVE_LOCAL}:
        return _MODE_CONTROLLED_LIVE_LOCAL
    return _MODE_CONTROLLED_LIVE_LOCAL


def _is_local_host(host: str) -> bool:
    normalized = host.strip().lower()
    if not normalized:
        return False
    if normalized in {"localhost", "0.0.0.0"}:
        return True
    try:
        ip = ipaddress.ip_address(normalized)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return normalized.endswith(".localhost")


def _host_in_scope(*, host: str, scan_config: dict[str, object]) -> bool:
    normalized = host.strip().lower()
    scope = scan_config.get("scope", {})
    if not isinstance(scope, dict):
        return True

    allowed_hosts = {
        str(value).strip().lower()
        for value in scope.get("allowed_hosts", [])
        if str(value).strip()
    }
    allowed_domains = {
        str(value).strip().lower()
        for value in scope.get("allowed_domains", [])
        if str(value).strip()
    }
    include_subdomains = bool(scope.get("include_subdomains", True))

    if not allowed_hosts and not allowed_domains:
        return True

    if normalized in allowed_hosts or normalized in allowed_domains:
        return True

    if include_subdomains:
        for domain in allowed_hosts | allowed_domains:
            if domain and normalized.endswith(f".{domain}"):
                return True

    return False


def _join_url(base_url: str, path: str) -> str:
    cleaned = path.strip()
    if not cleaned:
        return base_url
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        return cleaned.rstrip("/")
    if cleaned == "/":
        return base_url
    return f"{base_url.rstrip('/')}/{cleaned.lstrip('/')}"


def _normalize_wordlist_entry(value: str) -> str:
    cleaned = value.strip()
    if not cleaned or cleaned == "/":
        return ""
    return cleaned.lstrip("/")


def _build_scoped_nuclei_templates() -> dict[str, str]:
    return {
        "openapi-exposure.yaml": textwrap.dedent(
            """\
            id: pentra-openapi-exposure
            info:
              name: Exposed OpenAPI Schema
              author: pentra
              severity: medium
              tags: exposure,swagger,api
            http:
              - method: GET
                path:
                  - "{{BaseURL}}/openapi.json"
                matchers:
                  - type: word
                    part: body
                    words:
                      - "\"openapi\""
                    condition: and
            """
        ),
        "graphql-introspection.yaml": textwrap.dedent(
            """\
            id: pentra-graphql-introspection
            info:
              name: GraphQL Introspection Enabled
              author: pentra
              severity: medium
              tags: graphql,api
            http:
              - method: POST
                path:
                  - "{{BaseURL}}/graphql"
                headers:
                  Content-Type: application/json
                body: '{"query":"{ __schema { types { name } } }"}'
                matchers:
                  - type: word
                    part: body
                    words:
                      - "__schema"
                      - "Query"
                    condition: and
            """
        ),
        "swagger-ui.yaml": textwrap.dedent(
            """\
            id: pentra-swagger-ui
            info:
              name: Swagger UI Exposed
              author: pentra
              severity: low
              tags: exposure,swagger,api
            http:
              - method: GET
                path:
                  - "{{BaseURL}}/swagger/index.html"
                  - "{{BaseURL}}/swagger-ui/index.html"
                matchers-condition: or
                matchers:
                  - type: word
                    part: body
                    words:
                      - "Swagger UI"
                  - type: word
                    part: body
                    words:
                      - "swagger-ui"
            """
        ),
    }


def _build_local_validation_nuclei_templates() -> dict[str, str]:
    templates = _build_scoped_nuclei_templates()
    templates.update(
        {
        "idor-users.yaml": textwrap.dedent(
            """\
            id: pentra-idor-users
            info:
              name: Broken Access Control - IDOR
              author: pentra
              severity: high
              tags: idor,api
            http:
              - method: GET
                path:
                  - "{{BaseURL}}/api/v1/users/2"
                matchers:
                  - type: word
                    part: body
                    words:
                      - "\"salary\""
                      - "\"email\""
                    condition: and
            """
        ),
            "sqli-login.yaml": textwrap.dedent(
                """\
                id: pentra-sqli-login
                info:
                  name: SQL Injection in Login Endpoint
                  author: pentra
                  severity: critical
                  tags: sqli,api,auth-bypass
                http:
                  - method: POST
                    path:
                      - "{{BaseURL}}/api/v1/auth/login"
                    headers:
                      Content-Type: application/x-www-form-urlencoded
                    body: "username=admin'%20OR%20'1'='1&password=test"
                    matchers:
                      - type: word
                        part: body
                        words:
                          - "\"token\""
                """
            ),
        }
    )
    return templates
