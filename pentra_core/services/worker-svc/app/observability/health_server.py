"""Minimal async HTTP health server for worker processes."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any


class WorkerHealthServer:
    """Serve worker health JSON over a lightweight HTTP endpoint."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        snapshot_provider: Callable[[], Awaitable[dict[str, Any]]],
    ) -> None:
        self._host = host
        self._port = port
        self._snapshot_provider = snapshot_provider
        self._server: asyncio.AbstractServer | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            return self._port
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection,
            self._host,
            self._port,
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            if not request_line:
                return

            parts = request_line.decode("utf-8", errors="replace").strip().split()
            method = parts[0] if len(parts) >= 1 else ""
            path = parts[1] if len(parts) >= 2 else ""

            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if not line or line in {b"\r\n", b"\n"}:
                    break

            if method == "GET" and path == "/health":
                payload = await self._snapshot_provider()
                body = json.dumps(payload, indent=2, default=str).encode("utf-8")
                status_line = b"HTTP/1.1 200 OK\r\n"
            else:
                body = json.dumps(
                    {"status": "not_found", "detail": "Only GET /health is supported."}
                ).encode("utf-8")
                status_line = b"HTTP/1.1 404 Not Found\r\n"

            writer.writelines(
                [
                    status_line,
                    b"Content-Type: application/json\r\n",
                    f"Content-Length: {len(body)}\r\n".encode("utf-8"),
                    b"Connection: close\r\n",
                    b"\r\n",
                ]
            )
            writer.write(body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
