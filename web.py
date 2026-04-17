"""FastAPI web GUI for credscan."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .config import DEFAULT_DB_PATH, load_config, scanner_config
from .normalize import NormalizeError, normalize
from .runner import Runner
from .scanners.base import Scanner
from .scanners.crtsh import CrtShScanner
from .scanners.dorks import DorkScanner
from .scanners.github_search import GitHubSearchScanner
from .scanners.hibp import HIBPScanner
from .store import Store

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _build_scanners(cfg: dict) -> list[Scanner]:
    return [
        CrtShScanner(scanner_config("crtsh", cfg)),
        GitHubSearchScanner(scanner_config("github_search", cfg)),
        DorkScanner(scanner_config("dorks", cfg)),
        HIBPScanner(scanner_config("hibp", cfg)),
    ]


def create_app() -> FastAPI:
    app = FastAPI(title="credscan", version="0.1.0")
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    db_path = Path(os.environ.get("CREDSCAN_DB", str(DEFAULT_DB_PATH)))

    def _store() -> Store:
        return Store(db_path)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        with _store() as s:
            scans = s.recent_scans(limit=10)
        # Render scanner status
        cfg = load_config()
        scanners = _build_scanners(cfg)
        scanner_status = [
            {
                "name": sc.name,
                "enabled": sc.enabled(),
                "requires_auth": sc.requires_auth,
            }
            for sc in scanners
        ]
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "scans": scans,
                "scanner_status": scanner_status,
            },
        )

    @app.post("/scan")
    async def run_scan(target: str = Form(...)) -> JSONResponse:
        try:
            t = normalize(target)
        except NormalizeError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

        try:
            cfg = load_config()
            scanners = _build_scanners(cfg)
            with _store() as store:
                runner = Runner(scanners, store)
                result = await runner.run(t)
        except Exception as e:  # noqa: BLE001
            import logging
            logging.exception("scan failed")
            return JSONResponse({"error": f"scan failed: {e}"}, status_code=500)

        return JSONResponse(
            {
                "target": result["target"],
                "scan_id": result["scan_id"],
                "scanners_run": result["scanners_run"],
                "findings": [f.model_dump(mode="json") for f in result["findings"]],
            }
        )

    @app.get("/findings")
    async def findings(target: str) -> JSONResponse:
        with _store() as store:
            items = store.findings_for(target)
        return JSONResponse({"findings": items})

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
