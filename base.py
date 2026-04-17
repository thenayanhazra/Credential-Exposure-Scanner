"""Scanner interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from ..models import Finding, Target


class Scanner(ABC):
    """A single data source scanner.

    Subclasses set `name`, optionally set `requires_auth`, and implement
    `supports(target)` and `scan(target)`.
    """

    name: str = "base"
    requires_auth: bool = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def enabled(self) -> bool:
        """Whether this scanner can run given current config.

        Default: always enabled. Override for API-key-gated scanners.
        """
        return True

    @abstractmethod
    def supports(self, target: Target) -> bool:
        """Whether this scanner applies to the given target kind."""

    @abstractmethod
    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        """Yield zero or more findings. Must be an async generator."""
        if False:  # pragma: no cover - satisfies type checker for async iter
            yield  # type: ignore[unreachable]
