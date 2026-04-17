"""Data models for targets and findings."""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(UTC)


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


SEVERITY_ORDER = {
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
