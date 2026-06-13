\"\"\"Basic CLI tests.\"\"\"
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from credscan.cli import app

runner = CliRunner()


def test_scan_rejects_invalid_target():
    result = runner.invoke(app, ["scan", "not!!valid"])
    assert result.exit_code == 1
    assert "Invalid input" in result.output


def test_scan_valid_target_no_scanners(tmp_path: Path, monkeypatch):
    # Point config dir at tmp so no real config or DB is touched.
    monkeypatch.setenv("CREDSCAN_CONFIG_DIR", str(tmp_path))
    result = runner.invoke(app, ["scan", "example.com"])
    assert result.exit_code == 0
    assert "No findings" in result.output or "Scanning" in result.output


def test_scan_json_output(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CREDSCAN_CONFIG_DIR", str(tmp_path))
    # Disable default scanners so we get empty findings without hitting public API.
    config_file = tmp_path / "config.toml"
    config_file.write_text("[scanners.crtsh]\nenabled = false\n[scanners.dorks]\nenabled = false\n")
    result = runner.invoke(app, ["scan", "example.com", "--output", "json"])
    assert result.exit_code == 0
    import json
    data = json.loads(result.output)
    assert "findings" in data
    assert data["findings"] == []


def test_history_empty_db(tmp_path: Path):
    db = tmp_path / "findings.db"
    result = runner.invoke(app, ["history", "--db", str(db)])
    assert result.exit_code == 0
    assert "no scans yet" in result.output


def test_history_shows_past_scan(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CREDSCAN_CONFIG_DIR", str(tmp_path))
    # Disable default scanners to avoid hitting external APIs.
    config_file = tmp_path / "config.toml"
    config_file.write_text("[scanners.crtsh]\nenabled = false\n[scanners.dorks]\nenabled = false\n")
    # Run a scan first to populate history.
    runner.invoke(app, ["scan", "example.com"])
    result = runner.invoke(app, ["history", "--db", str(tmp_path / "findings.db")])
    assert result.exit_code == 0
    assert "example.com" in result.output
