"""Read-only local FastAPI dashboard."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ebpf_ransom_lab.storage import Store


STATIC_DIRECTORY = Path(__file__).with_name("static")


def create_app(database: Path) -> FastAPI:
    store = Store(Path(database))
    store.initialize()
    app = FastAPI(title="eBPF Ransom Lab", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def page(request: Request, limit: int, offset: int) -> None:
        unknown = set(request.query_params) - {"limit", "offset"}
        if unknown:
            raise HTTPException(422, "unknown query parameter")

    @app.get("/api/v1/health")
    def health(request: Request):
        page(request, 0, 0)
        return {"success": True, **store.health()}

    def list_response(items, limit: int, offset: int):
        return {"success": True, "items": items, "pagination": {"limit": limit, "offset": offset}}

    @app.get("/api/v1/runs")
    def runs(request: Request, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        page(request, limit, offset)
        return list_response(store.list_runs(limit=limit, offset=offset), limit, offset)

    @app.get("/api/v1/processes")
    def processes(request: Request, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        page(request, limit, offset)
        return list_response(store.list_processes(limit=limit, offset=offset), limit, offset)

    @app.get("/api/v1/windows")
    def windows(request: Request, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        page(request, limit, offset)
        return list_response(store.list_windows(limit=limit, offset=offset), limit, offset)

    @app.get("/api/v1/alerts")
    def alerts(request: Request, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        page(request, limit, offset)
        return list_response(store.list_alerts(limit=limit, offset=offset), limit, offset)

    @app.get("/api/v1/metrics")
    def metrics(request: Request):
        page(request, 0, 0)
        return {"success": True, **store.metrics()}

    @app.get("/")
    def dashboard():
        return FileResponse(STATIC_DIRECTORY / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIRECTORY), name="static")
    return app
