import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.config.logging_config import configure_logging
from backend.config.settings import ROOT_DIR, settings
from backend.database.db import init_db
from backend.security.headers import SecurityHeadersMiddleware


configure_logging()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    # Hide auto-generated docs in production — set ADAPTIVESCAN_EXPOSE_DOCS=true to enable
    docs_url="/api/docs" if os.environ.get("ADAPTIVESCAN_EXPOSE_DOCS") else None,
    redoc_url="/api/redoc" if os.environ.get("ADAPTIVESCAN_EXPOSE_DOCS") else None,
    openapi_url="/api/openapi.json" if os.environ.get("ADAPTIVESCAN_EXPOSE_DOCS") else None,
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
hsts_enabled = os.environ.get("ADAPTIVESCAN_HSTS", "false").lower() == "true"
app.add_middleware(SecurityHeadersMiddleware, hsts=hsts_enabled)

app.include_router(router, prefix="/api")
app.mount(
    "/exports",
    StaticFiles(directory=ROOT_DIR / "backend" / "reports" / "exports"),
    name="exports",
)


@app.on_event("startup")
async def startup() -> None:
    init_db()


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": settings.app_name, "status": "ok"}
