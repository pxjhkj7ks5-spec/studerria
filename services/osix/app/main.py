from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api.routes import create_router
from app.core.config import load_settings
from app.core.logging import configure_logging
from app.core.security import parse_session_token
from app.db.clickhouse import ClickHouseStore
from app.workers.poller import Poller

configure_logging()
settings = load_settings()
store = ClickHouseStore(settings)
poller = Poller(settings, store)

app = FastAPI(title="OSIX", docs_url=f"{settings.base_path}/docs", openapi_url=f"{settings.base_path}/openapi.json")
dashboard_dir = Path(__file__).resolve().parent / "dashboard"


@app.on_event("startup")
async def startup() -> None:
    settings.raw_snapshot_dir.mkdir(parents=True, exist_ok=True)
    store.initialize()
    store.upsert_sources(settings.default_sources())
    poller.start()


@app.on_event("shutdown")
async def shutdown() -> None:
    await poller.stop()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; img-src 'self' data:; connect-src 'self'",
    )
    return response


app.include_router(create_router(settings, store, poller), prefix=settings.base_path)
app.mount(f"{settings.base_path}/static", StaticFiles(directory=dashboard_dir / "static"), name="osix-static")


@app.head(settings.base_path)
@app.head(f"{settings.base_path}/")
async def dashboard_head() -> Response:
    return Response(status_code=200)


@app.get(settings.base_path, response_class=HTMLResponse)
@app.get(f"{settings.base_path}/", response_class=HTMLResponse)
async def dashboard(request: Request) -> FileResponse:
    if settings.dashboard_auth_required and not _has_dashboard_session(request):
        return FileResponse(dashboard_dir / "login.html")
    return FileResponse(dashboard_dir / "index.html")


def _has_dashboard_session(request: Request) -> bool:
    token = request.cookies.get(settings.admin_cookie_name)
    return parse_session_token(token or "", settings.jwt_secret) is not None if settings.jwt_secret else False
