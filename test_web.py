"""Basic FastAPI endpoint tests."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from credscan.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(db_path=tmp_path / "test.db")


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_scan_invalid_target_returns_400(client):
    resp = await client.post("/scan", data={"target": "not!!valid"})
    assert resp.status_code == 400
    assert "error" in resp.json()


async def test_scan_valid_target_no_scanners_returns_200(client):
    # No API tokens configured → no scanners enabled → empty findings list.
    resp = await client.post("/scan", data={"target": "example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert data["findings"] == []


async def test_scan_internal_error_returns_generic_message(client):
    async def _boom(self, _target):
        raise RuntimeError("super secret internal detail xyz")

    with patch("credscan.runner.Runner.run", _boom):
        resp = await client.post("/scan", data={"target": "example.com"})

    assert resp.status_code == 500
    body = resp.json()
    assert body["error"] == "scan failed"
    assert "super secret" not in body["error"]
    assert "xyz" not in body["error"]


async def test_findings_empty_for_unknown_target(client):
    resp = await client.get("/findings", params={"target": "domain:example.com"})
    assert resp.status_code == 200
    assert resp.json() == {"findings": []}


async def test_scan_email_target(client):
    resp = await client.post("/scan", data={"target": "user@example.com"})
    assert resp.status_code == 200
    assert "findings" in resp.json()
