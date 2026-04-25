from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.config.logging_config import configure_logging
from backend.config.settings import ROOT_DIR, settings
from backend.database.db import init_db


configure_logging()

app = FastAPI(title=settings.app_name, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")
app.mount("/exports", StaticFiles(directory=ROOT_DIR / "backend" / "reports" / "exports"), name="exports")


@app.on_event("startup")
async def startup() -> None:
    init_db()


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": settings.app_name, "status": "ok"}
