"""Data models for targets, findings, and scan results."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

try:
    from enum import StrEnum
except ImportError:  # pragma: no cover - Python < 3.11
    class StrEnum(str, Enum):
        pass
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TargetKind(StrEnum):
    EMAIL = "email"
    DOMAIN = "domain"


class Target(BaseModel):
    """A normalized scan target."""

    kind: TargetKind
    value: str  # canonical form (lowercased, plus-stripped for emails)
    domain: str  # for emails, the part after @; for domains, the value itself

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.value}"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Sort rank — lower means more urgent. Single source of truth."""
        return _SEVERITY_RANK[self]


# Authoritative severity ordering. SQL and UI code reference this,
# never hardcode their own.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Finding(BaseModel):
    """A single exposure finding emitted by a scanner."""

    source: str
    target: str  # serialized Target (kind:value)
    kind: str  # finding subtype, e.g. "breach", "exposed_aws_key"
    severity: Severity
    title: str
    evidence_url: str | None = None
    evidence_hash: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)

    def dedup_key(self) -> str:
        """Stable key for upsert/dedup."""
        parts = f"{self.source}|{self.target}|{self.kind}|{self.evidence_url or ''}"
        return sha256(parts.encode("utf-8")).hexdigest()


class ScanResult(BaseModel):
    """The outcome of a single scan run. Shared shape for CLI, web, and tests."""

    target: str
    scan_id: int
    scanners_run: list[str]
    findings: list[Finding]

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize for JSON APIs (findings rendered via Pydantic json mode)."""
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "scanners_run": self.scanners_run,
            "findings": [f.model_dump(mode="json") for f in self.findings],
        }
