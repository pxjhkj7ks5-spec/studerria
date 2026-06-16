from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.core.config import Settings, is_allowlisted_url
from app.core.security import create_session_token, parse_session_token, verify_password
from app.db.clickhouse import ClickHouseStore
from app.workers.poller import Poller


def create_router(settings: Settings, store: ClickHouseStore, poller: Poller) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    def current_claims(request: Request):
        token = request.cookies.get(settings.admin_cookie_name)
        claims = parse_session_token(token or "", settings.jwt_secret) if settings.jwt_secret else None
        if claims is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return claims

    def require_admin(claims=Depends(current_claims)):
        if claims.role != "admin":
            raise HTTPException(status_code=403, detail="Admin role required")
        return claims

    def read_access(request: Request):
        if not settings.dashboard_auth_required:
            return None
        return current_claims(request)

    @router.get("/health/live")
    async def health_live():
        return {"status": "ok"}

    @router.get("/health/ready")
    async def health_ready():
        try:
            store.client.query("SELECT 1")
        except Exception as exc:
            raise HTTPException(status_code=503, detail="ClickHouse unavailable") from exc
        return {"status": "ok"}

    @router.get("/sources")
    async def list_sources(_=Depends(read_access)):
        return {"sources": store.list_sources()}

    @router.get("/metrics/latest")
    async def latest_metrics(dataset: str | None = None, _=Depends(read_access)):
        return {"metrics": store.latest_metrics(dataset)}

    @router.get("/metrics/series")
    async def metric_series(metric: str = "personnel", dataset: str = "general_losses", period: str = "month", start: str | None = None, end: str | None = None, _=Depends(read_access)):
        start_date, end_date = _range_for(period, start, end)
        return {"series": store.metric_series(metric, dataset, start_date, end_date)}

    @router.get("/source-health")
    async def source_health(_=Depends(read_access)):
        return {"health": store.health()}

    @router.get("/parser-errors")
    async def parser_errors(_=Depends(read_access)):
        return {"errors": store.parser_errors()}

    @router.post("/admin/login")
    async def admin_login(
        request: Request,
        response: Response,
    ):
        payload = await request.json()
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if not settings.admin_enabled:
            raise HTTPException(status_code=503, detail="OSIX admin auth is not configured")
        if username != settings.admin_username or not verify_password(password, settings.admin_password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_session_token(username, "admin", settings.jwt_secret, settings.admin_session_ttl_seconds)
        response.set_cookie(
            settings.admin_cookie_name,
            token,
            httponly=True,
            secure=settings.admin_cookie_secure,
            samesite="strict",
            path=settings.base_path,
            max_age=settings.admin_session_ttl_seconds,
        )
        store.insert_audit(username, "admin", "login", "session")
        return {"status": "ok"}

    @router.post("/admin/logout")
    async def admin_logout(response: Response):
        response.delete_cookie(settings.admin_cookie_name, path=settings.base_path)
        return {"status": "ok"}

    @router.get("/admin/session")
    async def admin_session(claims=Depends(current_claims)):
        return {"subject": claims.subject, "role": claims.role, "expires_at": claims.expires_at}

    @router.post("/admin/reingest")
    async def admin_reingest(claims=Depends(require_admin)):
        results = await poller.run_once()
        store.insert_audit(claims.subject, claims.role, "reingest", "all_sources")
        return {"results": [result.__dict__ for result in results]}

    @router.patch("/admin/sources/{source_id}")
    async def admin_update_source(source_id: str, request: Request, claims=Depends(require_admin)):
        payload = await request.json()
        url = payload.get("url")
        enabled = payload.get("enabled")
        if url is not None:
            url = str(url)
            if not is_allowlisted_url(url, settings.allowlisted_prefixes):
                raise HTTPException(status_code=400, detail="Source URL is not allowlisted")
        if enabled is not None and not isinstance(enabled, bool):
            raise HTTPException(status_code=400, detail="enabled must be boolean")
        updated = store.update_source_config(source_id, url, enabled)
        if updated is None:
            raise HTTPException(status_code=404, detail="Source not found")
        store.insert_audit(claims.subject, claims.role, "update_source", source_id)
        return {"source": updated.__dict__}

    return router


def _range_for(period: str, start: str | None, end: str | None) -> tuple[str | None, str | None]:
    today = date.today()
    if period == "all":
        return None, None
    if period == "custom":
        return start, end
    days = {
        "year": 365,
        "3m": 92,
        "month": 31,
        "week": 7,
    }.get(period, 31)
    return (today - timedelta(days=days)).isoformat(), today.isoformat()
