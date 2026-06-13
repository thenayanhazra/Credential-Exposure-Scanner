\"\"\"Shared GitHub API helpers: headers, URL construction, secret pattern scanning.\"\"\"
from __future__ import annotations

import re
from collections.abc import Iterator

from .. import USER_AGENT
from ..models import Severity

SECRET_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key", Severity.CRITICAL),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "aws_session_key", Severity.HIGH),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_pat", Severity.CRITICAL),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "github_pat_fine", Severity.CRITICAL),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "slack_token", Severity.HIGH),
    (re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"), "openai_key", Severity.HIGH),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "private_key",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"),
        "password_literal",
        Severity.HIGH,
    ),
    (
        re.compile(r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"),
        "api_key_literal",
        Severity.HIGH,
    ),
    (
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9_]{8}/B[A-Z0-9_]{8}/[A-Za-z0-9_]{24}"),
        "slack_webhook",
        Severity.HIGH,
    ),
    (
        re.compile(r"AIza[0-9A-Za-z-_]{35}"),
        "google_api_key",
        Severity.HIGH,
    ),
    (
        re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24}"),
        "stripe_api_key",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"AC[0-9a-fA-F]{32}"),
        "twilio_account_sid",
        Severity.LOW,
    ),
    (
        re.compile(r"(?:postgresql|postgres|mysql|mongodb|mongodb\+srv|redis)://[^:\s]+:[^@\s]+@[^\s]+"),
        "db_connection_string",
        Severity.CRITICAL,
    ),
]

CONTEXT_WINDOW = 240


def api_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }


def raw_url(repo: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"


def find_secrets(
    content: str,
    domain: str | None = None,
) -> Iterator[tuple[str, Severity]]:
    \"\"\"Yield (kind, severity) for each matching secret pattern.

    If domain is given, only yield when the domain string appears within
    CONTEXT_WINDOW characters of the match (reduces false positives for broad
    searches). Omit domain to match any secret regardless of proximity.
    \"\"\"
    lower = content.lower()
    domain_l = domain.lower() if domain else None
    for pat, kind, severity in SECRET_PATTERNS:
        match = pat.search(content)
        if not match:
            continue
        if domain_l is not None:
            start = max(0, match.start() - CONTEXT_WINDOW)
            end = min(len(content), match.end() + CONTEXT_WINDOW)
            if domain_l not in lower[start:end]:
                continue
        yield kind, severity
