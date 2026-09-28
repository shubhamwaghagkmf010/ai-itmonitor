from fastapi import FastAPI
import os
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.api.v1_router import api_router
import asyncio
from backend.app.services.retention import purge_old_data

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# CORS. A wildcard origin cannot be combined with credentials (browsers reject it), so
# credentials are enabled only when explicit origins are configured via CORS_ORIGINS.
_origins = settings.CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials="*" not in _origins,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {"status": "AI-ITMonitor Pro API Online"}


@app.on_event("startup")
async def _schedule_retention():
    """Run data retention on startup and then once a day."""
    async def loop():
        while True:
            try:
                purge_old_data()
            except Exception as exc:
                print("[retention] error:", exc)
            await asyncio.sleep(24 * 3600)
    asyncio.create_task(loop())


_SELF_HTML = os.path.join(os.path.dirname(__file__), "static", "self_service.html")


@app.get("/self-service", response_class=HTMLResponse)
def self_service_page():
    with open(_SELF_HTML, encoding="utf-8") as f:
        return f.read()
