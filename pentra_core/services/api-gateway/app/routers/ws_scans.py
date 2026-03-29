"""WebSocket router — real-time scan progress streaming.

Mounted at ``/ws/scans/{scan_id}`` in the API gateway.

Subscribes to Redis Pub/Sub channel ``pentra:pubsub:scan:{scan_id}``
and forwards events to the connected client as JSON messages.

Client protocol:
  - Connect: ``ws://host/ws/scans/{scan_id}?token=<jwt>``
  - Receive: JSON events (scan.progress, scan.phase, scan.node, scan.status, scan.finding)
  - Send: ``{"type": "ping"}`` for keepalive (optional)
  - Close: automatic on scan completion or client disconnect
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.auth.jwt import TokenError, decode_token
from pentra_common.auth.tenant_context import CurrentUser
from pentra_common.db.session import async_session_factory
from pentra_common.schemas import ScanStreamEvent

from app.security.runtime_auth import build_dev_bypass_user, is_dev_auth_bypass_enabled
from app.services import scan_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_CHANNEL_PREFIX = "pentra:pubsub:scan"

# Max time (seconds) a WS connection stays open with no events
_IDLE_TIMEOUT = 600  # 10 minutes


class _WebSocketAuthError(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _parse_scan_id(scan_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(scan_id).strip())
    except (TypeError, ValueError) as exc:
        raise _WebSocketAuthError(4400, "scan_id must be a valid UUID") from exc


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


def _authenticate_scan_websocket(websocket: WebSocket, token: str | None = None) -> CurrentUser:
    auth_header = websocket.headers.get("authorization", "").strip()
    query_token = (token or websocket.query_params.get("token", "")).strip()
    if auth_header.startswith("Bearer "):
        query_token = auth_header[7:].strip()

    if query_token:
        return _build_current_user_from_token(query_token)
    if is_dev_auth_bypass_enabled():
        return build_dev_bypass_user()
    raise _WebSocketAuthError(4401, "Missing authentication token")


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


@router.websocket("/scans/{scan_id}")
async def ws_scan_progress(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(default=""),
):
    """Stream real-time scan events to the frontend via WebSocket.

    The client connects with:
        ws://host/ws/scans/<scan_id>?token=<jwt>

    Events are JSON objects pushed from the orchestrator via Redis Pub/Sub.
    Connection closes when the scan completes/fails or client disconnects.
    """
    redis_client: aioredis.Redis | None = None
    pubsub: aioredis.client.PubSub | None = None
    channel_name = ""

    try:
        user = _authenticate_scan_websocket(websocket, token)
        parsed_scan_id = _parse_scan_id(scan_id)
        async with async_session_factory() as session:
            await _require_scan_access(scan_id=parsed_scan_id, user=user, session=session)

        await websocket.accept()
        channel_name = f"{_CHANNEL_PREFIX}:{parsed_scan_id}"

        # Connect to Redis and subscribe
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(channel_name)

        logger.info(
            "WS connected: scan=%s tenant=%s channel=%s",
            parsed_scan_id,
            user.tenant_id,
            channel_name,
        )

        # Send initial connection confirmation
        await websocket.send_json(
            ScanStreamEvent(
                event_type="ws.connected",
                scan_id=parsed_scan_id,
                message="Subscribed to real-time scan events",
            ).model_dump(mode="json")
        )

        # Main event loop: forward Redis Pub/Sub messages to WebSocket
        while True:
            try:
                # Poll for Redis messages with a short timeout
                message = await asyncio.wait_for(
                    pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    ),
                    timeout=5.0,
                )

                if message and message["type"] == "message":
                    data = message["data"]
                    # Parse and forward
                    try:
                        event = ScanStreamEvent.model_validate(json.loads(data))
                        await websocket.send_json(event.model_dump(mode="json"))

                        # Auto-close on terminal scan events
                        if event.event_type == "scan.status":
                            new_status = event.new_status or ""
                            if new_status in ("completed", "failed", "cancelled"):
                                await websocket.send_json(
                                    ScanStreamEvent(
                                        event_type="ws.closing",
                                        scan_id=parsed_scan_id,
                                        reason=f"Scan {new_status}",
                                    ).model_dump(mode="json")
                                )
                                break
                    except (json.JSONDecodeError, TypeError):
                        # Forward raw string if JSON parse fails
                        await websocket.send_text(str(data))

                # Check for client messages (ping/close)
                try:
                    client_msg = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=0.01,
                    )
                    if client_msg:
                        try:
                            parsed = json.loads(client_msg)
                            if parsed.get("type") == "ping":
                                await websocket.send_json({"type": "pong"})
                        except json.JSONDecodeError:
                            pass
                except asyncio.TimeoutError:
                    pass

            except asyncio.TimeoutError:
                # No message in 5s — send heartbeat
                try:
                    await websocket.send_json(
                        ScanStreamEvent(
                            event_type="ws.heartbeat",
                            scan_id=parsed_scan_id,
                        ).model_dump(mode="json")
                    )
                except Exception:
                    break

    except WebSocketDisconnect:
        logger.info("WS disconnected: scan=%s", scan_id)
    except _WebSocketAuthError as exc:
        await websocket.close(code=exc.code, reason=exc.reason)
    except HTTPException as exc:
        ws_code = 4404 if exc.status_code == 404 else 4403
        await websocket.close(code=ws_code, reason=str(exc.detail))
    except Exception:
        logger.exception("WS error: scan=%s", scan_id)
    finally:
        # Cleanup
        if pubsub:
            try:
                await pubsub.unsubscribe(channel_name)
                await pubsub.close()
            except Exception:
                pass
        if redis_client:
            try:
                await redis_client.close()
            except Exception:
                pass
        logger.info("WS cleanup complete: scan=%s", scan_id)
