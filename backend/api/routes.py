import uuid

from fastapi import APIRouter, HTTPException, Response, WebSocket
from pydantic import BaseModel, Field
from starlette.websockets import WebSocketDisconnect

from backend.api.scan_controller import ScanController, ScanRequest
from backend.api.websocket import scan_hub
from backend.api.job_registry import job_registry
from backend.attack_surface.graph import build_attack_surface_graph, build_drift_timeline, correlate_attack_paths
from backend.api_security.schema import analyze_graphql_schema, parse_openapi_document, parse_postman_collection
from backend.exposure.intelligence import aggregate_exposure, build_exposure_intelligence
from backend.core.recon import build_replay_plan
from backend.core.enterprise_foundation import get_enterprise_foundation
from backend.core.product_capabilities import list_product_capabilities
from backend.core.risk_gate import evaluate_risk_gate
from backend.core.role_analysis import compare_roles
from backend.core.scan_profiles import list_scan_profiles
from backend.lifecycle.workflows import lifecycle_policy
from backend.monitoring.policies import monitoring_overview
from backend.operations.intelligence import build_operations_intelligence
from backend.platform import build_platform_overview
from backend.database.migrations import database_backend_status
from backend.observability.service import observability_status, prometheus_metrics
from backend.queue.orchestrator import build_scan_job, queue_health_snapshot, queue_topology
from backend.workers.scan_worker import worker_heartbeat, worker_pool_status
from backend.database.db import get_scan, list_scans
from backend.database.db import compare_scans
from backend.database.db import add_finding_comment
from backend.database.db import create_api_key
from backend.database.db import create_organization
from backend.database.db import create_workspace
from backend.database.db import get_finding_lifecycle
from backend.database.db import get_scan_history
from backend.database.db import get_tenancy_overview
from backend.database.db import list_audit_logs
from backend.database.db import save_scan
from backend.database.db import update_finding_lifecycle
from backend.detection.registry import describe_loaded_detectors


router = APIRouter()
controller = ScanController()


class FindingLifecycleUpdate(BaseModel):
    state: str
    owner: str = ""
    sla_due_at: str = ""
    actor: str = "local-user"


class FindingCommentCreate(BaseModel):
    body: str
    actor: str = "local-user"


class OrganizationCreate(BaseModel):
    name: str
    plan: str = "team"
    actor: str = "local-user"


class WorkspaceCreate(BaseModel):
    org_id: str
    name: str
    default_allowlist: list[str] = Field(default_factory=list)
    actor: str = "local-user"


class ApiKeyCreate(BaseModel):
    workspace_id: str
    name: str
    scopes: list[str] = Field(default_factory=list)
    actor: str = "local-user"


class ApiSchemaAnalyzeRequest(BaseModel):
    format: str = "openapi"
    document: dict[str, object] | None = None
    schema_text: str = ""


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


@router.get("/product/capabilities")
async def product_capabilities() -> dict[str, object]:
    return list_product_capabilities()


@router.get("/product/enterprise-foundation")
async def enterprise_foundation() -> dict[str, object]:
    return get_enterprise_foundation()


@router.get("/platform/overview")
async def platform_overview() -> dict[str, object]:
    return build_platform_overview(list_scans())


@router.get("/platform/operations")
async def platform_operations() -> dict[str, object]:
    scans = [scan for scan in (get_scan(str(item.get("scan_id"))) for item in list_scans()) if scan]
    return build_operations_intelligence(scans)


@router.get("/platform/queue")
async def platform_queue() -> dict[str, object]:
    return {**queue_topology(), "health": queue_health_snapshot(job_registry.list_jobs())}


@router.get("/platform/workers")
async def platform_workers() -> dict[str, object]:
    return worker_pool_status()


@router.get("/platform/database")
async def platform_database() -> dict[str, object]:
    return database_backend_status()


@router.get("/platform/observability")
async def platform_observability() -> dict[str, object]:
    return observability_status()


@router.get("/metrics")
async def metrics() -> Response:
    return Response(
        prometheus_metrics(list_scans(), queue_health_snapshot(job_registry.list_jobs())),
        media_type="text/plain; version=0.0.4",
    )


@router.get("/scans/{scan_id}/execution-plan")
async def scan_execution_plan(scan_id: str) -> dict[str, object]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    return build_scan_job(scan_id, str(scan.get("target_url", "")), scan.get("scan_options", {}))


@router.post("/workers/{worker_id}/heartbeat")
async def worker_heartbeat_route(worker_id: str, pool: str = "crawl", active_task_count: int = 0) -> dict[str, object]:
    return worker_heartbeat(worker_id, pool, active_task_count)


@router.get("/platform/lifecycle-policy")
async def platform_lifecycle_policy() -> dict[str, object]:
    return lifecycle_policy()


@router.get("/platform/monitoring")
async def platform_monitoring() -> dict[str, object]:
    return monitoring_overview(list_scans())


@router.get("/attack-surface/graph")
async def attack_surface_graph() -> dict[str, object]:
    scans = [scan for scan in (get_scan(str(item.get("scan_id"))) for item in list_scans()) if scan]
    if not scans:
        return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0, "attack_paths": [], "highest_risk_path": None}
    latest = scans[0]
    graph = latest.get("attack_surface_graph")
    if isinstance(graph, dict):
        return graph
    return build_attack_surface_graph(latest)


@router.get("/attack-surface/drift")
async def attack_surface_drift() -> dict[str, object]:
    scans = [scan for scan in (get_scan(str(item.get("scan_id"))) for item in list_scans()) if scan]
    return build_drift_timeline(scans)


@router.get("/attack-paths")
async def attack_paths() -> dict[str, object]:
    scans = [scan for scan in (get_scan(str(item.get("scan_id"))) for item in list_scans()) if scan]
    paths = []
    for scan in scans[:25]:
        graph = scan.get("attack_surface_graph") if isinstance(scan.get("attack_surface_graph"), dict) else build_attack_surface_graph(scan)
        for path in correlate_attack_paths(scan, graph):
            paths.append({**path, "scan_id": scan.get("scan_id"), "target_url": scan.get("target_url")})
    paths = sorted(paths, key=lambda item: int(item.get("risk_score", 0)), reverse=True)
    return {"path_count": len(paths), "paths": paths[:50]}


@router.get("/exposure/overview")
async def exposure_overview() -> dict[str, object]:
    scans = [scan for scan in (get_scan(str(item.get("scan_id"))) for item in list_scans()) if scan]
    return aggregate_exposure(scans)


@router.get("/reports/{scan_id}/exposure")
async def report_exposure(scan_id: str) -> dict[str, object]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    existing = scan.get("exposure_intelligence")
    return existing if isinstance(existing, dict) else build_exposure_intelligence(scan)


@router.post("/api-intelligence/analyze-schema")
async def api_schema_analyze(request: ApiSchemaAnalyzeRequest) -> dict[str, object]:
    requested_format = request.format.lower()
    if requested_format == "openapi":
        if not request.document:
            raise HTTPException(status_code=400, detail="OpenAPI document is required")
        return parse_openapi_document(request.document)
    if requested_format == "postman":
        if not request.document:
            raise HTTPException(status_code=400, detail="Postman collection document is required")
        return parse_postman_collection(request.document)
    if requested_format == "graphql":
        if not request.schema_text.strip():
            raise HTTPException(status_code=400, detail="GraphQL schema text is required")
        return analyze_graphql_schema(request.schema_text)
    raise HTTPException(status_code=400, detail="Unsupported schema format")


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


@router.get("/findings/{scan_id}/{finding_index}/lifecycle")
async def finding_lifecycle(scan_id: str, finding_index: int) -> dict[str, object]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    findings = list(scan.get("findings", []))
    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    return get_finding_lifecycle(scan_id, finding_index)


@router.put("/findings/{scan_id}/{finding_index}/lifecycle")
async def update_lifecycle(scan_id: str, finding_index: int, update: FindingLifecycleUpdate) -> dict[str, object]:
    allowed_states = {"open", "triaged", "assigned", "retesting", "resolved", "closed"}
    if update.state not in allowed_states:
        raise HTTPException(status_code=400, detail="Unsupported lifecycle state")
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    findings = list(scan.get("findings", []))
    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    return update_finding_lifecycle(
        scan_id,
        finding_index,
        state=update.state,
        owner=update.owner,
        sla_due_at=update.sla_due_at,
        actor=update.actor,
    )


@router.post("/findings/{scan_id}/{finding_index}/comments")
async def add_lifecycle_comment(scan_id: str, finding_index: int, comment: FindingCommentCreate) -> dict[str, object]:
    if not comment.body.strip():
        raise HTTPException(status_code=400, detail="Comment body is required")
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    findings = list(scan.get("findings", []))
    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    return add_finding_comment(scan_id, finding_index, body=comment.body.strip(), actor=comment.actor)


@router.get("/audit-logs")
async def audit_logs(limit: int = 100) -> list[dict[str, object]]:
    return list_audit_logs(limit=max(1, min(limit, 500)))


@router.get("/tenancy/overview")
async def tenancy_overview() -> dict[str, object]:
    return get_tenancy_overview()


@router.post("/organizations")
async def organizations(payload: OrganizationCreate) -> dict[str, object]:
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="Organization name is required")
    return create_organization(payload.name.strip(), plan=payload.plan.strip() or "team", actor=payload.actor)


@router.post("/workspaces")
async def workspaces(payload: WorkspaceCreate) -> dict[str, object]:
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="Workspace name is required")
    try:
        return create_workspace(
            payload.org_id,
            payload.name.strip(),
            default_allowlist=payload.default_allowlist,
            actor=payload.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api-keys")
async def api_keys(payload: ApiKeyCreate) -> dict[str, object]:
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="API key name is required")
    try:
        return create_api_key(
            payload.workspace_id,
            payload.name.strip(),
            scopes=payload.scopes or None,
            actor=payload.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


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
