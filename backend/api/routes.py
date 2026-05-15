import uuid

from fastapi import APIRouter, HTTPException, WebSocket
from starlette.websockets import WebSocketDisconnect

from backend.api.scan_controller import ScanController, ScanRequest
from backend.api.websocket import scan_hub
from backend.api.job_registry import job_registry
from backend.core.recon import build_replay_plan
from backend.core.risk_gate import evaluate_risk_gate
from backend.core.role_analysis import compare_roles
from backend.core.scan_profiles import list_scan_profiles
from backend.database.db import get_scan, list_scans
from backend.database.db import compare_scans
from backend.database.db import get_scan_history
from backend.database.db import save_scan
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
    result["report_paths"] = await controller.create_report_bundle(result)
    result["report_urls"] = controller.create_report_urls(result)
    result["report_url"] = result["report_urls"]["html"]
    result["pdf_report_url"] = result["report_urls"]["pdf"]
    save_scan(result)
    return result


@router.get("/reports")
async def reports() -> list[dict[str, object]]:
    return list_scans()


@router.get("/scans/history")
async def scan_history(limit: int = 25) -> dict[str, object]:
    return get_scan_history(limit=max(1, min(limit, 100)))


@router.get("/detectors")
async def detectors() -> list[dict[str, object]]:
    return describe_loaded_detectors()


@router.get("/plugins/marketplace")
async def plugin_marketplace() -> dict[str, object]:
    detectors = describe_loaded_detectors()
    return {
        "detectors": detectors,
        "install_mode": "local-registry",
        "registry_path": "backend/detection/detectors.json",
        "template_path": "backend/detection/PLUGIN_TEMPLATE.md",
        "guidance": "Add detector classes that inherit BaseDetector, then register module/class metadata here.",
    }


@router.get("/scan-profiles")
async def scan_profiles() -> list[dict[str, object]]:
    return list_scan_profiles()


@router.get("/scans/active")
async def active_scans() -> list[dict[str, object]]:
    return job_registry.list_jobs()


@router.get("/reports/compare/{left_scan_id}/{right_scan_id}")
async def report_compare(left_scan_id: str, right_scan_id: str) -> dict[str, object]:
    comparison = compare_scans(left_scan_id, right_scan_id)
    if comparison is None:
        raise HTTPException(status_code=404, detail="One or both scan reports were not found")
    return comparison


@router.get("/roles/compare/{left_scan_id}/{right_scan_id}")
async def role_compare(left_scan_id: str, right_scan_id: str) -> dict[str, object]:
    comparison = compare_roles(left_scan_id, right_scan_id)
    if comparison is None:
        raise HTTPException(status_code=404, detail="One or both scan reports were not found")
    return comparison


@router.get("/reports/{scan_id}")
async def report_detail(scan_id: str) -> dict[str, object]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    scan["report_urls"] = controller.create_report_urls(scan)
    scan["report_url"] = scan["report_urls"]["html"]
    scan["pdf_report_url"] = scan["report_urls"]["pdf"]
    return scan


@router.get("/replay/{scan_id}/{finding_index}")
async def replay_finding(scan_id: str, finding_index: int) -> dict[str, object]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    findings = list(scan.get("findings", []))
    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = findings[finding_index]
    if not isinstance(finding, dict):
        raise HTTPException(status_code=400, detail="Finding is not replayable")
    return finding.get("replay_plan") or build_replay_plan(finding)


@router.post("/scans/{scan_id}/resume")
async def resume_scan(scan_id: str) -> dict[str, object]:
    previous = get_scan(scan_id)
    if previous is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    resume_state = previous.get("resume_state", {})
    if not isinstance(resume_state, dict) or not resume_state.get("available"):
        raise HTTPException(status_code=400, detail="This scan does not contain a resumable state")
    request = ScanRequest(
        target_url=str(resume_state.get("target_url") or previous.get("target_url")),
        authorization_confirmed=bool(previous.get("safety_controls", {}).get("authorization_confirmed", False)),
        domain_allowlist=list(previous.get("safety_controls", {}).get("domain_allowlist", [])),
        scan_profile=str(resume_state.get("scan_options", {}).get("scan_profile", "deep")),
        detector_names=list(resume_state.get("scan_options", {}).get("detector_names", [])),
    )
    request_scan_options = resume_state.get("scan_options", {})
    if isinstance(request_scan_options, dict):
        request_scan_options["resume_from_scan_id"] = str(resume_state.get("checkpoint_scan_id") or scan_id)
    result = await controller.engine.scan(
        str(request.target_url),
        scan_id=str(uuid.uuid4()),
        auth_context={
            "authorization_confirmed": request.authorization_confirmed,
            "domain_allowlist": request.domain_allowlist or [],
        },
        scan_options=request_scan_options if isinstance(request_scan_options, dict) else {},
    )
    result["risk_gate"] = evaluate_risk_gate(result.get("summary", {}))
    result["report_paths"] = await controller.create_report_bundle(result)
    result["report_urls"] = controller.create_report_urls(result)
    result["report_url"] = result["report_urls"]["html"]
    result["pdf_report_url"] = result["report_urls"]["pdf"]
    save_scan(result)
    return result


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
