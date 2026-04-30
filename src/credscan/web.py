"""FastAPI web GUI for credscan."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .config import default_db_path, load_config
from .normalize import NormalizeError, normalize
from .runner import Runner
from .scanners.registry import build_scanners
from .store import Store

TEMPLATE_DIR = Path(__file__).parent / "templates"

log = logging.getLogger(__name__)


def create_app(db_path: Path | None = None) -> FastAPI:
    """Build the FastAPI app.

    `db_path` defaults to the configured location. Pass an override for tests
    or for multi-instance deployments.
    """
    app = FastAPI(title="credscan", version="0.1.0")
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    resolved_db = db_path or default_db_path()

    def _open_store() -> Store:
        return Store(resolved_db)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        with _open_store() as s:
            scans = s.recent_scans(limit=10)
        scanners = build_scanners(load_config())
        scanner_status = [
            {"name": sc.name, "enabled": sc.enabled(), "requires_auth": sc.requires_auth}
            for sc in scanners
        ]
        return templates.TemplateResponse(
            request,
            "index.html",
            {"scans": scans, "scanner_status": scanner_status},
        )

    @app.post("/scan")
    async def run_scan(target: str = Form(...)) -> JSONResponse:
        try:
            t = normalize(target)
        except NormalizeError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

        try:
            cfg = load_config()
            concurrency = cfg.get("app", {}).get("concurrency", 5)
            scanners = build_scanners(cfg)
            with _open_store() as store:
                result = await Runner(scanners, store, concurrency=concurrency).run(t)
        except Exception:  # noqa: BLE001
            log.exception("scan failed")
            return JSONResponse({"error": "scan failed"}, status_code=500)

        return JSONResponse(result.to_public_dict())

    @app.get("/findings")
    async def findings(target: str) -> JSONResponse:
        with _open_store() as store:
            items = store.findings_for(target)
        return JSONResponse({"findings": items})

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
