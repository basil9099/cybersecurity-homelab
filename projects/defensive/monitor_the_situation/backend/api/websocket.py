"""WebSocket hub for real-time multiplexed updates."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("mts.api.websocket")

router = APIRouter()


class WebSocketHub:
    """Manages WebSocket connections with channel-based subscriptions."""

    def __init__(self) -> None:
        self._clients: dict[WebSocket, set[str]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients[ws] = {"system"}
        logger.info("WebSocket client connected (%d total)", len(self._clients))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.pop(ws, None)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._clients))

    async def subscribe(self, ws: WebSocket, channels: list[str]) -> None:
        async with self._lock:
            if ws in self._clients:
                self._clients[ws].update(channels)

    async def unsubscribe(self, ws: WebSocket, channels: list[str]) -> None:
        async with self._lock:
            if ws in self._clients:
                self._clients[ws] -= set(channels)

    async def broadcast(self, channel: str, data: dict[str, Any]) -> None:
        """Send a message to all clients subscribed to a channel."""
        message = json.dumps({
            "channel": channel,
            "data": data,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        dead: list[WebSocket] = []
        async with self._lock:
            targets = [ws for ws, subs in self._clients.items() if channel in subs]

        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.pop(ws, None)

    async def send_keepalive(self) -> None:
        """Send keepalive to all connected clients."""
        await self.broadcast("system", {
            "type": "keepalive",
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    @property
    def client_count(self) -> int:
        return len(self._clients)


# Module-level hub instance
hub = WebSocketHub()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await hub.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue

            if "subscribe" in msg:
                await hub.subscribe(websocket, msg["subscribe"])
            elif "unsubscribe" in msg:
                await hub.unsubscribe(websocket, msg["unsubscribe"])
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(websocket)
