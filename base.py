"""Scanner interface.

Every scanner is an async iterator factory: calling `scan(target)` must return
an AsyncIterator[Finding]. In practice subclasses implement `scan` as an
`async def` with `yield` statements, which makes it an async generator — a
valid AsyncIterator. The base class declares the contract without requiring a
dummy body.
"""
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
        raise NotImplementedError

    @abstractmethod
    def scan(self, target: Target) -> AsyncIterator[Finding]:
        """Return an async iterator of findings.

        Subclasses implement this as an `async def` with `yield` statements,
        which creates an async generator (itself an AsyncIterator).
        """
        raise NotImplementedError
