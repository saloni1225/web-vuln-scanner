from collections import defaultdict

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect


class ScanWebSocketHub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.scan_clients: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, websocket: WebSocket, scan_id: str | None = None) -> None:
        await websocket.accept()
        self.clients.add(websocket)
        if scan_id:
            self.scan_clients[scan_id].add(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str | None = None) -> None:
        self.clients.discard(websocket)
        if scan_id and scan_id in self.scan_clients:
            self.scan_clients[scan_id].discard(websocket)
            if not self.scan_clients[scan_id]:
                self.scan_clients.pop(scan_id, None)
            return
        for key in list(self.scan_clients):
            self.scan_clients[key].discard(websocket)
            if not self.scan_clients[key]:
                self.scan_clients.pop(key, None)

    async def broadcast(self, message: dict[str, object]) -> None:
        for client in list(self.clients):
            try:
                await client.send_json(message)
            except WebSocketDisconnect:
                self.disconnect(client)

    async def broadcast_to_scan(self, scan_id: str, message: dict[str, object]) -> None:
        payload = {"scan_id": scan_id, **message}
        delivered = False
        for client in list(self.scan_clients.get(scan_id, set())):
            try:
                await client.send_json(payload)
                delivered = True
            except WebSocketDisconnect:
                self.disconnect(client, scan_id)
        if not delivered:
            await self.broadcast(payload)


scan_hub = ScanWebSocketHub()
