import os

from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.config.logging_config import configure_logging
from backend.config.settings import ROOT_DIR, settings
from backend.database.db import init_db, get_connection
from backend.security.headers import SecurityHeadersMiddleware
from backend.security.jwt_guard import _verify_jwt, _extract_token
from backend.security.csrf import enforce_csrf


configure_logging()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed startup validation:
    # Reject weak, missing, or fallback JWT secrets in production mode.
    jwt_secret = settings.adaptivescan_jwt_secret
    dev_fallback = "adaptivescan-local-development-secret"
    is_dev = settings.execution_mode == "local-dev"

    if not jwt_secret or jwt_secret == dev_fallback or len(jwt_secret) < 32:
        if not is_dev:
            raise RuntimeError(
                "FATAL ERROR: ADAPTIVESCAN_JWT_SECRET is missing, weak, or set to the fallback value in production mode! "
                "The application cannot start. Set a secure secret of at least 32 characters in your production environment."
            )

    # Docs validation in production
    if settings.adaptivescan_expose_docs and not is_dev:
        raise RuntimeError("FATAL ERROR: Docs cannot be exposed in production mode.")

    # PostgreSQL connectivity check
    if settings.database_url.startswith("postgresql"):
        try:
            conn = get_connection()
            conn.close()
        except Exception as exc:
            if not is_dev:
                raise RuntimeError(f"FATAL: PostgreSQL database is configured but unavailable in production: {exc}")

    init_db()

    # Seed non-production founder user if enabled
    from backend.auth.saas_auth import seed_founder_user
    seed_founder_user()

    # Seed default admin user only when explicitly enabled via env flag.
    # SECURITY: Never enable ADAPTIVESCAN_SEED_ADMIN=true in production deployments.
    if settings.adaptivescan_seed_admin:
        import uuid
        from backend.auth.saas_auth import password_hash
        from backend.database.db import (
            create_auth_user,
            create_organization,
            create_workspace,
            get_auth_user_by_email,
        )

        seed_email = settings.adaptivescan_seed_email
        seed_password = settings.adaptivescan_seed_password
        if not seed_password:
            import warnings
            warnings.warn(
                "[AdaptiveScan] ADAPTIVESCAN_SEED_ADMIN is true but ADAPTIVESCAN_SEED_PASSWORD is not set. "
                "Skipping seed to avoid insecure default credentials.",
                UserWarning,
                stacklevel=1,
            )
        elif not get_auth_user_by_email(seed_email):
            org = create_organization("Admin Organization", plan="enterprise", actor="system")
            create_workspace(org["org_id"], "Default Workspace", default_allowlist=[], actor="system")
            create_auth_user(
                user_id=str(uuid.uuid4()),
                org_id=str(org["org_id"]),
                email=seed_email,
                first_name="Admin",
                last_name="User",
                company_name="Admin Organization",
                role="owner",
                password_hash_value=password_hash(seed_password),
                mfa_enabled=False,
            )
            import logging
            logging.getLogger("adaptivescan").info("[startup] Seeded admin user: %s", seed_email)

    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    # Hide auto-generated docs in production — controlled via settings
    docs_url="/api/docs" if settings.adaptivescan_expose_docs else None,
    redoc_url="/api/redoc" if settings.adaptivescan_expose_docs else None,
    openapi_url="/api/openapi.json" if settings.adaptivescan_expose_docs else None,
    lifespan=lifespan,
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
_PUBLIC_PREFIXES = (
    "/api/health",
    "/api/auth/",         # login, register, OTP, CSRF, etc.
    "/api/trust",         # public trust center page
    "/api/onboarding",    # unauthenticated onboarding state
    "/api/docs",          # Swagger (only mounted when expose_docs=True)
    "/api/redoc",
    "/api/openapi.json",
    "/api/ws",            # WebSocket connections authenticate themselves
)

_PUBLIC_EXACT = frozenset({
    "/",
    "/api/health",
    "/api/auth/architecture",
    "/api/trust",
    "/api/onboarding",
})


@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    import uuid
    from backend.utils.correlation import set_correlation_id
    correlation_id = request.headers.get("x-correlation-id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    set_correlation_id(correlation_id)
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response


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
        # Check Cloudflare Access identity validation
        from backend.security.cloudflare import verify_cloudflare_assertion
        cf_email = verify_cloudflare_assertion(request)
        if cf_email:
            from backend.database.db import get_auth_user_by_email
            user = get_auth_user_by_email(cf_email)
            if user:
                # Valid Cloudflare Access identity found; allow request to proceed
                return await call_next(request)

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


app.include_router(router, prefix="/api", dependencies=[Depends(enforce_csrf)])

# ── Exports static files — served under /api/exports so auth middleware applies ─
# WARNING: Do NOT mount this at a path outside /api — it would bypass JWT enforcement.
exports_dir = ROOT_DIR / "backend" / "reports" / "exports"
exports_dir.mkdir(parents=True, exist_ok=True)
app.mount(
    "/api/exports",
    StaticFiles(directory=exports_dir),
    name="exports",
)


# Lifespan replaces old on_event startup logic



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
