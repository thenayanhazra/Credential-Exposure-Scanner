"""Normalize raw user input into a Target."""
from __future__ import annotations

import re

from .models import Target, TargetKind

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


class NormalizeError(ValueError):
    """Raised when an input cannot be parsed as an email or domain."""


def normalize(raw: str) -> Target:
    """Parse a raw string into a Target.

    Accepts:
      - emails: `User+tag@Example.com` -> `user@example.com`
      - domains: `https://example.com/path` -> `example.com`
    Rejects IPs, URLs without a TLD, and anything else.
    """
    if raw is None:
        raise NormalizeError("empty input")
    s = raw.strip().lower()
    if not s:
        raise NormalizeError("empty input")

    if "@" in s:
        if not EMAIL_RE.match(s):
            raise NormalizeError(f"invalid email: {raw!r}")
        local, _, domain = s.rpartition("@")
        local = local.split("+", 1)[0]
        if not local:
            raise NormalizeError(f"invalid email local-part: {raw!r}")
        if not DOMAIN_RE.match(domain):
            raise NormalizeError(f"invalid email domain: {raw!r}")
        return Target(
            kind=TargetKind.EMAIL,
            value=f"{local}@{domain}",
            domain=domain,
        )

    # Try to accept a pasted URL by stripping scheme/path/port
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/", 1)[0]
    s = s.split(":", 1)[0]
    s = s.rstrip(".")

    if not DOMAIN_RE.match(s):
        raise NormalizeError(f"invalid domain: {raw!r}")
    return Target(kind=TargetKind.DOMAIN, value=s, domain=s)
