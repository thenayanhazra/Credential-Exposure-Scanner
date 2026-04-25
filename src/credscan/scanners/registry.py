"""Scanner registry. One place that knows every scanner class.

Callers (CLI, web, tests) get their scanner list here instead of duplicating
the `build_scanners` function.
"""
from __future__ import annotations

from typing import Any

from ..config import scanner_config
from .base import Scanner
from .crtsh import CrtShScanner
from .dorks import DorkScanner
from .exact_email_search import ExactEmailSearchScanner
from .github_search import GitHubSearchScanner
from .hibp import HIBPScanner
from .lead_fetch import LeadFetchScanner

# Order here is the order of chip display in the UI and the order scanners
# are offered to the runner (the runner is concurrent, so order is cosmetic).
SCANNER_CLASSES: list[type[Scanner]] = [
    CrtShScanner,
    GitHubSearchScanner,
    ExactEmailSearchScanner,
    LeadFetchScanner,
    DorkScanner,
    HIBPScanner,
]


def build_scanners(cfg: dict[str, Any] | None = None) -> list[Scanner]:
    """Instantiate every registered scanner with its section of the config."""
    cfg = cfg or {}
    return [cls(scanner_config(cls.name, cfg)) for cls in SCANNER_CLASSES]
