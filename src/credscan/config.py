from __future__ import annotations

import os
try:
    import tomllib
except ImportError:
    import tomli as tomllib
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field


class AppConfigModel(BaseModel):
    concurrency: int = Field(default=5, ge=1)
    db_path: str = Field(default="findings.db")
    scanner_timeout: int = Field(default=120, ge=1)


class GithubSearchConfigModel(BaseModel):
    enabled: bool = True
    token: str = ""
    max_hits: int = Field(default=20, ge=1)


class DorksConfigModel(BaseModel):
    enabled: bool = True
    max_queries: int = Field(default=6, ge=1)


class CrtshConfigModel(BaseModel):
    enabled: bool = True


class HibpConfigModel(BaseModel):
    enabled: bool = False
    api_key: str = ""


class ExactEmailSearchConfigModel(BaseModel):
    enabled: bool = True
    token: str = ""
    max_hits: int = Field(default=10, ge=1)


class LeadFetchConfigModel(BaseModel):
    enabled: bool = True
    token: str = ""
    max_pages: int = Field(default=10, ge=1)


class ScannersConfigModel(BaseModel):
    github_search: GithubSearchConfigModel = Field(default_factory=GithubSearchConfigModel)
    dorks: DorksConfigModel = Field(default_factory=DorksConfigModel)
    crtsh: CrtshConfigModel = Field(default_factory=CrtshConfigModel)
    hibp: HibpConfigModel = Field(default_factory=HibpConfigModel)
    exact_email_search: ExactEmailSearchConfigModel = Field(default_factory=ExactEmailSearchConfigModel)
    lead_fetch: LeadFetchConfigModel = Field(default_factory=LeadFetchConfigModel)


class ConfigModel(BaseModel):
    app: AppConfigModel = Field(default_factory=AppConfigModel)
    scanners: ScannersConfigModel = Field(default_factory=ScannersConfigModel)


def config_dir() -> Path:
    \"\"\"Directory where credscan stores its config and default DB.\"\"\"
    override = os.environ.get("CREDSCAN_CONFIG_DIR")
    if override:
        return Path(override)
    return Path.home() / ".config" / "credscan"


def default_config_path() -> Path:
    return config_dir() / "config.toml"


def default_db_path() -> Path:
    cfg = load_config()
    db_path_str = cfg.get("app", {}).get("db_path")
    if db_path_str:
        p = Path(db_path_str).expanduser()
        if p.is_absolute():
            return p
        return config_dir() / p.name
    return config_dir() / "findings.db"


def load_config(path: Path | None = None) -> dict[str, Any]:
    \"\"\"Return config dict. Missing file is not an error.\"\"\"
    p = path or default_config_path()
    raw = {}
    if p.exists():
        try:
            with open(p, "rb") as f:
                raw = tomllib.load(f)
        except Exception:
            raw = {}
    try:
        validated = ConfigModel.model_validate(raw)
        return validated.model_dump()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Configuration is invalid: %s. Using default configuration.", e)
        return ConfigModel().model_dump()


def scanner_config(name: str, config: dict[str, Any]) -> dict[str, Any]:
    scanners = config.get("scanners", {})
    return scanners.get(name, {}) or {}
