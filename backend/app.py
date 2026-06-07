import os

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.config.logging_config import configure_logging
from backend.config.settings import ROOT_DIR, settings
from backend.database.db import init_db
from backend.security.headers import SecurityHeadersMiddleware
from backend.security.jwt_guard import _verify_jwt, _extract_token


configure_logging()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    # Hide auto-generated docs in production — controlled via settings
    docs_url="/api/docs" if settings.adaptivescan_expose_docs else None,
    redoc_url="/api/redoc" if settings.adaptivescan_expose_docs else None,
    openapi_url="/api/openapi.json" if settings.adaptivescan_expose_docs else None,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
# Strictly restrict allowed origins. Never use ["*"] in a credentialed context.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,   # ["http://localhost:5173", "http://127.0.0.1:5173"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-CSRF-Token",
        "X-AdaptiveScan-Role",
        "X-AdaptiveScan-Actor",
    ],
    expose_headers=["X-Request-Id"],
    max_age=600,
)

# ── Security headers (replaces the old inline secure_headers middleware) ──────
app.add_middleware(SecurityHeadersMiddleware, hsts=settings.adaptivescan_hsts)


# ── Deny-by-Default Auth Middleware ──────────────────────────────────────────
# Routes that do NOT require authentication:
_PUBLIC_PREFIXES = (
    "/api/health",
    "/api/auth/",         # login, register, OTP, CSRF, etc.
    "/api/trust",         # public trust center page
    "/api/onboarding",    # unauthenticated onboarding state
    "/api/docs",          # Swagger (only mounted when expose_docs=True)
    "/api/redoc",
    "/api/openapi.json",
)

_PUBLIC_EXACT = frozenset({
    "/",
    "/api/health",
    "/api/auth/architecture",
    "/api/trust",
    "/api/onboarding",
})


@app.middleware("http")
async def enforce_authentication(request: Request, call_next):
    """
    Deny-by-Default: every /api/* route requires a valid JWT
    unless explicitly allowlisted in _PUBLIC_PREFIXES or _PUBLIC_EXACT.
    """
    path = request.url.path

    # Skip non-API paths (static files, root, etc.)
    if not path.startswith("/api"):
        return await call_next(request)

    # Skip preflight CORS OPTIONS requests
    if request.method == "OPTIONS":
        return await call_next(request)

    # Check public routes
    if path in _PUBLIC_EXACT:
        return await call_next(request)
    for prefix in _PUBLIC_PREFIXES:
        if path.startswith(prefix):
            return await call_next(request)

    # Enforce JWT for everything else
    token = _extract_token(request)
    if not token:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": "not_authenticated",
                "message": "Authentication required. Please log in.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        _verify_jwt(token)
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": "invalid_token",
                "message": "Your session has expired or is invalid. Please log in again.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    return await call_next(request)


app.include_router(router, prefix="/api")
app.mount(
    "/exports",
    StaticFiles(directory=ROOT_DIR / "backend" / "reports" / "exports"),
    name="exports",
)


@app.on_event("startup")
async def startup() -> None:
    init_db()

    # Seed default admin user if it doesn't exist
    from backend.database.db import get_auth_user_by_email, create_organization, create_workspace, create_auth_user
    from backend.auth.saas_auth import password_hash
    import uuid

    if not get_auth_user_by_email("test@test.com"):
        org = create_organization("Default Admin Org", plan="enterprise", actor="system")
        create_workspace(org["org_id"], "Default Workspace", default_allowlist=[], actor="system")
        create_auth_user(
            user_id=str(uuid.uuid4()),
            org_id=str(org["org_id"]),
            email="test@test.com",
            first_name="Admin",
            last_name="User",
            company_name="Default Admin Org",
            role="owner",
            password_hash_value=password_hash("Test@1234"),
            mfa_enabled=False,
        )


@app.get("/docs", include_in_schema=False)
async def redirect_docs():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/api/docs")


@app.get("/redoc", include_in_schema=False)
async def redirect_redoc():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/api/redoc")


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": settings.app_name, "status": "ok"}
