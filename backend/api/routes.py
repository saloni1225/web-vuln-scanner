import uuid

from fastapi import APIRouter, HTTPException, WebSocket
from starlette.websockets import WebSocketDisconnect

from backend.api.scan_controller import ScanController, ScanRequest
from backend.api.websocket import scan_hub
from backend.api.job_registry import job_registry
from backend.database.db import get_scan, list_scans
from backend.detection.registry import describe_loaded_detectors


router = APIRouter()
controller = ScanController()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@router.post("/scan")
async def scan(request: ScanRequest) -> dict[str, object]:
    scan_id = str(uuid.uuid4())
    job_registry.register(scan_id, str(request.target_url))

    async def emit_progress(event: dict[str, object]) -> None:
        job_registry.update(
            scan_id,
            status=str(event.get("status")) if event.get("status") else None,
            progress=int(event.get("progress")) if event.get("progress") is not None else None,
            message=str(event.get("message")) if event.get("message") else None,
        )
        await scan_hub.broadcast_to_scan(scan_id, event)

    try:
        result = await controller.start_scan(request, scan_id=scan_id, progress_callback=emit_progress)
    except RuntimeError as exc:
        job_registry.update(scan_id, status="failed", progress=100, message=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["report_path"] = controller.create_report(result)
    result["report_url"] = controller.create_report_url(result)
    return result


@router.get("/reports")
async def reports() -> list[dict[str, object]]:
    return list_scans()


@router.get("/detectors")
async def detectors() -> list[dict[str, object]]:
    return describe_loaded_detectors()


@router.get("/scans/active")
async def active_scans() -> list[dict[str, object]]:
    return job_registry.list_jobs()


@router.get("/reports/{scan_id}")
async def report_detail(scan_id: str) -> dict[str, object]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    scan["report_url"] = controller.create_report_url(scan)
    return scan


@router.websocket("/ws/scans")
async def scans_websocket(websocket: WebSocket) -> None:
    await scan_hub.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        scan_hub.disconnect(websocket)


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_websocket(websocket: WebSocket, scan_id: str) -> None:
    await scan_hub.connect(websocket, scan_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        scan_hub.disconnect(websocket, scan_id)
