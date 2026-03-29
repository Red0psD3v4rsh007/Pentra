"""Interactive Terminal — WebSocket PTY for real shell access in scan containers.

Mounted at ``/api/v1/terminal``.

Provides:
  - WebSocket endpoint that attaches to a running Docker container's shell
  - Users can type commands directly and see real-time output (exactly like a real terminal)
  - Support for per-scan containers and ad-hoc tool containers
  - Container lifecycle management (start, attach, detach, stop)

Architecture:
  Browser (xterm.js) ←→ WebSocket ←→ Docker exec (PTY) ←→ Container shell
"""

from __future__ import annotations

import asyncio
from functools import lru_cache
import logging
import json
import os
from pathlib import Path
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.auth.jwt import TokenError, decode_token

from app.deps import CurrentUser, get_db_session, require_roles
from app.security.runtime_auth import build_dev_bypass_user, is_dev_auth_bypass_enabled
from app.services import scan_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["terminal"])

_TERMINAL_ALLOWED_ROLES = frozenset({"owner", "admin", "member"})
_TERMINAL_MANAGER_ROLES = frozenset({"owner", "admin"})


class _WebSocketAuthError(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


# ═══════════════════════════════════════════════════════════════════════
#  Container Shell Manager
# ═══════════════════════════════════════════════════════════════════════

class ContainerShellManager:
    """Manages Docker container shell sessions for interactive terminal access."""

    _SHELL_CANDIDATES = ("/bin/sh", "sh", "/busybox/sh")
    _KEEPALIVE_COMMAND = ["-lc", "while true; do sleep 3600; done"]

    def __init__(self):
        self._active_sessions: dict[str, dict[str, Any]] = {}
        self._docker_client = None

    def _get_docker(self):
        """Lazy Docker client initialization."""
        if self._docker_client is None:
            try:
                import docker
                self._docker_client = docker.from_env()
            except Exception as exc:
                logger.error("Docker client unavailable: %s", exc)
                raise RuntimeError("Docker is not available") from exc
        return self._docker_client

    async def start_tool_container(
        self,
        tool_image: str,
        scan_id: str,
        *,
        tenant_id: str,
        user_id: str,
        work_dir: str = "/work",
    ) -> dict[str, str]:
        """Start a new tool container with an interactive shell."""
        client = self._get_docker()
        container_name = f"pentra-terminal-{scan_id}-{uuid.uuid4().hex[:8]}"

        # Ensure work directory exists
        host_work_dir = f"/tmp/pentra-work/{scan_id}"
        os.makedirs(host_work_dir, exist_ok=True)
        os.makedirs(f"{host_work_dir}/output", exist_ok=True)
        os.makedirs(f"{host_work_dir}/input", exist_ok=True)

        try:
            container, shell_path = self._start_shell_container(
                client=client,
                tool_image=tool_image,
                container_name=container_name,
                host_work_dir=host_work_dir,
                work_dir=work_dir,
            )

            session_id = uuid.uuid4().hex

            self._active_sessions[session_id] = {
                "container_id": container.id,
                "container_name": container_name,
                "scan_id": scan_id,
                "tool_image": tool_image,
                "status": "running",
                "tenant_id": tenant_id,
                "user_id": user_id,
                "shell_path": shell_path,
            }

            return {
                "session_id": session_id,
                "container_id": container.id,
                "container_name": container_name,
                "status": "running",
            }
        except Exception as exc:
            logger.error("Failed to start container: %s", exc)
            raise

    def _start_shell_container(
        self,
        *,
        client: Any,
        tool_image: str,
        container_name: str,
        host_work_dir: str,
        work_dir: str,
    ) -> tuple[Any, str]:
        last_exc: Exception | None = None
        for shell_path in self._SHELL_CANDIDATES:
            try:
                container = client.containers.run(
                    tool_image,
                    command=list(self._KEEPALIVE_COMMAND),
                    entrypoint=shell_path,
                    name=container_name,
                    detach=True,
                    stdin_open=True,
                    tty=True,
                    working_dir=work_dir,
                    mem_limit="2g",
                    cpu_quota=200000,  # 2 CPUs
                    network_mode="bridge",
                    volumes={
                        host_work_dir: {"bind": work_dir, "mode": "rw"},
                    },
                    auto_remove=True,
                )
                return container, shell_path
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "Terminal shell candidate failed for image %s: %s -> %s",
                    tool_image,
                    shell_path,
                    exc,
                )

        detail = f"Failed to start shell container for {tool_image}"
        if last_exc is not None:
            detail = f"{detail}: {last_exc}"
        raise RuntimeError(detail)

    async def attach_to_container(
        self,
        container_id: str,
        *,
        shell_path: str = "/bin/sh",
    ) -> Any:
        """Create an exec instance attached to a running container's shell."""
        client = self._get_docker()
        try:
            container = client.containers.get(container_id)
            exec_instance = client.api.exec_create(
                container.id,
                cmd=shell_path,
                stdin=True,
                tty=True,
                stdout=True,
                stderr=True,
            )
            socket = client.api.exec_start(
                exec_instance["Id"],
                socket=True,
                tty=True,
            )
            return exec_instance, socket
        except Exception as exc:
            logger.error("Failed to attach to container %s: %s", container_id, exc)
            raise

    async def stop_container(self, session_id: str) -> None:
        """Stop and remove a terminal container."""
        session = self._active_sessions.pop(session_id, None)
        if not session:
            return

        client = self._get_docker()
        try:
            container = client.containers.get(session["container_id"])
            container.stop(timeout=5)
        except Exception as exc:
            logger.warning("Failed to stop container: %s", exc)

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._active_sessions.get(session_id)

    def list_sessions(
        self,
        *,
        tenant_id: str,
        scan_id: str | None = None,
        user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        sessions = []
        for sid, data in self._active_sessions.items():
            if data.get("tenant_id") != tenant_id:
                continue
            if scan_id and data.get("scan_id") != scan_id:
                continue
            if user_id and data.get("user_id") != user_id:
                continue
            sessions.append({"session_id": sid, **data})
        return sessions


# Global manager instance
_shell_manager = ContainerShellManager()


def _user_has_terminal_role(user: CurrentUser) -> bool:
    return any(role in _TERMINAL_ALLOWED_ROLES for role in user.roles)


def _user_is_terminal_manager(user: CurrentUser) -> bool:
    return any(role in _TERMINAL_MANAGER_ROLES for role in user.roles)


def _parse_scan_id(scan_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(scan_id).strip())
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="scan_id must be a valid UUID") from exc


async def _require_scan_access(
    *,
    scan_id: uuid.UUID,
    user: CurrentUser,
    session: AsyncSession,
) -> None:
    scan = await scan_service.get_scan(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")


def _user_can_manage_session(user: CurrentUser, session_data: dict[str, Any]) -> bool:
    if str(session_data.get("tenant_id") or "") != str(user.tenant_id):
        return False
    if _user_is_terminal_manager(user):
        return True
    return str(session_data.get("user_id") or "") == str(user.user_id)


def _require_session_access(session_id: str, user: CurrentUser) -> dict[str, Any]:
    session_data = _shell_manager.get_session(session_id)
    if session_data is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if str(session_data.get("tenant_id") or "") != str(user.tenant_id):
        raise HTTPException(status_code=404, detail="Session not found")
    if not _user_can_manage_session(user, session_data):
        raise HTTPException(status_code=403, detail="Not authorized for this terminal session")
    return session_data


@lru_cache(maxsize=1)
def _allowed_terminal_images() -> frozenset[str]:
    specs_dir = Path(__file__).resolve().parents[3] / "worker-svc" / "app" / "tools" / "specs"
    images: set[str] = set()
    try:
        for path in specs_dir.glob("*.yaml"):
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("image:"):
                    image = stripped.split(":", 1)[1].strip()
                    if image:
                        images.add(image)
                    break
    except Exception:
        logger.exception("Failed to load terminal tool image allowlist from %s", specs_dir)
        return frozenset()
    return frozenset(images)


def _validate_terminal_image(tool_image: str) -> None:
    images = _allowed_terminal_images()
    if not images:
        raise HTTPException(status_code=503, detail="Terminal tool registry unavailable")
    if tool_image not in images:
        raise HTTPException(
            status_code=400,
            detail="tool_image must match a registered Pentra tool image",
        )


def _build_current_user_from_token(token: str) -> CurrentUser:
    try:
        payload = decode_token(token)
    except TokenError as exc:
        raise _WebSocketAuthError(4401, "Invalid or expired token") from exc

    if payload.get("type") != "access":
        raise _WebSocketAuthError(4401, "Invalid token type")

    return CurrentUser(
        user_id=uuid.UUID(payload["sub"]),
        tenant_id=uuid.UUID(payload["tid"]),
        email=payload.get("email", ""),
        roles=payload.get("roles", []),
        tier=payload.get("tier", "free"),
    )


def _authenticate_terminal_websocket(websocket: WebSocket) -> CurrentUser:
    auth_header = websocket.headers.get("authorization", "").strip()
    token = websocket.query_params.get("token", "").strip()
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    if token:
        user = _build_current_user_from_token(token)
    elif is_dev_auth_bypass_enabled():
        user = build_dev_bypass_user()
    else:
        raise _WebSocketAuthError(4401, "Missing authentication token")

    if not _user_has_terminal_role(user):
        raise _WebSocketAuthError(4403, "Not authorized for terminal access")
    return user


# ═══════════════════════════════════════════════════════════════════════
#  REST Endpoints — container lifecycle
# ═══════════════════════════════════════════════════════════════════════

@router.post(
    "/sessions",
    summary="Start an interactive terminal session",
    status_code=status.HTTP_201_CREATED,
)
async def create_terminal_session(
    body: dict,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Start a new Docker container with a shell for interactive use.

    Body:
      - ``tool_image``: Docker image to use (e.g., "instrumentisto/nmap:latest")
      - ``scan_id``: Associated scan ID for workspace isolation
    """
    tool_image = str(body.get("tool_image", "")).strip()
    scan_id_raw = str(body.get("scan_id", "")).strip()

    if not tool_image:
        raise HTTPException(status_code=400, detail="tool_image is required")
    if not scan_id_raw:
        raise HTTPException(status_code=400, detail="scan_id is required")

    _validate_terminal_image(tool_image)
    scan_id = _parse_scan_id(scan_id_raw)
    await _require_scan_access(scan_id=scan_id, user=user, session=session)

    try:
        session_info = await _shell_manager.start_tool_container(
            tool_image=tool_image,
            scan_id=str(scan_id),
            tenant_id=str(user.tenant_id),
            user_id=str(user.user_id),
        )
        return session_info
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start container: {exc}")


@router.get(
    "/sessions",
    summary="List active terminal sessions",
)
async def list_terminal_sessions(
    scan_id: str | None = None,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """List all active terminal sessions, optionally filtered by scan."""
    scan_filter: str | None = None
    if scan_id:
        parsed_scan_id = _parse_scan_id(scan_id)
        await _require_scan_access(scan_id=parsed_scan_id, user=user, session=session)
        scan_filter = str(parsed_scan_id)

    visible_sessions = _shell_manager.list_sessions(
        tenant_id=str(user.tenant_id),
        scan_id=scan_filter,
        user_id=None if _user_is_terminal_manager(user) else str(user.user_id),
    )
    return {"total": len(visible_sessions), "sessions": visible_sessions}


@router.delete(
    "/sessions/{session_id}",
    summary="Stop a terminal session",
)
async def stop_terminal_session(
    session_id: str,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
) -> dict[str, str]:
    """Stop and clean up an interactive terminal session."""
    _require_session_access(session_id, user)

    await _shell_manager.stop_container(session_id)
    return {"status": "stopped", "session_id": session_id}


# ═══════════════════════════════════════════════════════════════════════
#  WebSocket — interactive PTY
# ═══════════════════════════════════════════════════════════════════════

@router.websocket("/ws/{session_id}")
async def terminal_websocket(
    websocket: WebSocket,
    session_id: str,
):
    """WebSocket endpoint for interactive terminal access.

    Protocol:
      - Client sends text frames containing user keystrokes/commands
      - Server sends text frames containing terminal output
      - Client can send JSON messages for control:
        ``{"type": "resize", "cols": 120, "rows": 40}``
        ``{"type": "input", "data": "ls -la\\n"}``

    Connect with xterm.js on the frontend for a real terminal experience.
    """
    try:
        user = _authenticate_terminal_websocket(websocket)
        session = _require_session_access(session_id, user)
    except _WebSocketAuthError as exc:
        await websocket.close(code=exc.code, reason=exc.reason)
        return
    except HTTPException as exc:
        ws_code = 4403 if exc.status_code == 403 else 4404
        await websocket.close(code=ws_code, reason=str(exc.detail))
        return

    await websocket.accept()

    try:
        client = _shell_manager._get_docker()
        container = client.containers.get(session["container_id"])

        # Create exec instance with PTY
        exec_instance = client.api.exec_create(
            container.id,
            cmd=session.get("shell_path", "/bin/sh"),
            stdin=True,
            tty=True,
            stdout=True,
            stderr=True,
        )

        # Start exec and get the socket
        sock = client.api.exec_start(
            exec_instance["Id"],
            socket=True,
            tty=True,
        )

        # Get the raw socket for bidirectional I/O
        raw_sock = sock._sock if hasattr(sock, '_sock') else sock

        # Send initial prompt
        await websocket.send_text(
            f"\x1b[1;36mPentra Terminal\x1b[0m — Container: {session['container_name']}\r\n"
            f"\x1b[1;33mImage:\x1b[0m {session['tool_image']}\r\n"
            f"\x1b[1;33mWorkspace:\x1b[0m /work\r\n"
            f"\x1b[90m{'─' * 60}\x1b[0m\r\n"
        )

        # Bidirectional I/O loop
        async def read_from_container():
            """Read output from Docker container and send to WebSocket."""
            loop = asyncio.get_event_loop()
            while True:
                try:
                    data = await loop.run_in_executor(
                        None, lambda: raw_sock.recv(4096)
                    )
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    await websocket.send_text(text)
                except Exception:
                    break

        async def write_to_container():
            """Read input from WebSocket and send to Docker container."""
            loop = asyncio.get_event_loop()
            while True:
                try:
                    message = await websocket.receive_text()

                    # Check for control messages
                    if message.startswith("{"):
                        try:
                            ctrl = json.loads(message)
                            if ctrl.get("type") == "resize":
                                cols = ctrl.get("cols", 120)
                                rows = ctrl.get("rows", 40)
                                client.api.exec_resize(
                                    exec_instance["Id"],
                                    height=rows,
                                    width=cols,
                                )
                                continue
                            if ctrl.get("type") == "input":
                                message = ctrl.get("data", "")
                        except json.JSONDecodeError:
                            pass

                    # Send raw input to container
                    if message:
                        await loop.run_in_executor(
                            None, lambda: raw_sock.sendall(message.encode("utf-8"))
                        )
                except WebSocketDisconnect:
                    break
                except Exception:
                    break

        # Run read and write concurrently
        read_task = asyncio.create_task(read_from_container())
        write_task = asyncio.create_task(write_to_container())

        done, pending = await asyncio.wait(
            [read_task, write_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

    except WebSocketDisconnect:
        logger.info("Terminal WebSocket disconnected: session=%s", session_id)
    except Exception as exc:
        logger.error("Terminal WebSocket error: %s", exc)
        try:
            await websocket.send_text(f"\r\n\x1b[1;31mError: {exc}\x1b[0m\r\n")
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
#  Quick Command Execution (non-interactive)
# ═══════════════════════════════════════════════════════════════════════

@router.post(
    "/exec",
    summary="Execute a single command in a container",
    status_code=status.HTTP_200_OK,
)
async def exec_command(
    body: dict,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
) -> dict[str, Any]:
    """Execute a single command in an existing terminal session.

    Useful for running commands programmatically without full interactive mode.

    Body:
      - ``session_id``: Active session ID
      - ``command``: Command string to execute
      - ``timeout``: Maximum execution time (default 60s)
    """
    session_id = str(body.get("session_id", "")).strip()
    command = str(body.get("command", "")).strip()
    timeout = body.get("timeout", 60)

    if not command:
        raise HTTPException(status_code=400, detail="command is required")

    session = _require_session_access(session_id, user)

    try:
        client = _shell_manager._get_docker()
        container = client.containers.get(session["container_id"])

        exec_result = container.exec_run(
            cmd=[session.get("shell_path", "/bin/sh"), "-lc", command],
            stdout=True,
            stderr=True,
            demux=True,
        )

        stdout = exec_result.output[0].decode("utf-8", errors="replace") if exec_result.output[0] else ""
        stderr = exec_result.output[1].decode("utf-8", errors="replace") if exec_result.output[1] else ""

        return {
            "session_id": session_id,
            "command": command,
            "exit_code": exec_result.exit_code,
            "stdout": stdout,
            "stderr": stderr,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Command execution failed: {exc}")
