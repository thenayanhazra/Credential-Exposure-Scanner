"""Config loader. Reads TOML from ~/.config/credscan/config.toml by default.

All paths are resolved at call time, so environment changes made after import
still take effect (matters for tests and for CLI flags that set env vars).
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any


def config_dir() -> Path:
    """Directory where credscan stores its config and default DB."""
    override = os.environ.get("CREDSCAN_CONFIG_DIR")
    if override:
        return Path(override)
    return Path.home() / ".config" / "credscan"


def default_config_path() -> Path:
    return config_dir() / "config.toml"


def default_db_path() -> Path:
    return config_dir() / "findings.db"


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Return config dict. Missing file is not an error."""
    p = path or default_config_path()
    if not p.exists():
        return {}
    with open(p, "rb") as f:
        return tomllib.load(f)


def scanner_config(name: str, config: dict[str, Any]) -> dict[str, Any]:
    scanners = config.get("scanners", {})
    return scanners.get(name, {}) or {}
