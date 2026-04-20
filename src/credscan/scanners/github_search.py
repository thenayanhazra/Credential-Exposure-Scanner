"""GitHub code search scanner.

Searches public code for occurrences of the target domain alongside common
credential patterns. Requires a free personal access token (read-only).
"""
from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator

import httpx

from .. import USER_AGENT
from ..models import Finding, Severity, Target
from .base import Scanner

# Canonical secret patterns. Keep conservative to limit false positives.
SECRET_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key", Severity.CRITICAL),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "aws_session_key", Severity.HIGH),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_pat", Severity.CRITICAL),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "github_pat_fine", Severity.CRITICAL),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "slack_token", Severity.HIGH),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_key", Severity.HIGH),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "private_key", Severity.CRITICAL),
    (re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"), "password_literal", Severity.HIGH),
    (re.compile(r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"), "api_key_literal", Severity.HIGH),
]

CONTEXT_WINDOW = 240  # chars around the match to check for the domain


class GitHubSearchScanner(Scanner):
    name = "github_search"
    requires_auth = True

    API = "https://api.github.com/search/code"

    def _token(self) -> str | None:
        return self.config.get("token") or os.environ.get("GITHUB_TOKEN")

    def enabled(self) -> bool:
        return self._token() is not None

    def supports(self, target: Target) -> bool:
        return True  # domain or email — we search for the domain string

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        token = self._token()
        if not token:
            return

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        query = f'"{target.domain}"'

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            try:
                resp = await client.get(self.API, params={"q": query, "per_page": 30})
            except httpx.RequestError:
                return
            if resp.status_code != 200:
                return
            items = resp.json().get("items", [])

            seen_keys: set[str] = set()
            for item in items:
                repo = item.get("repository", {}).get("full_name")
                path = item.get("path")
                html_url = item.get("html_url", "")
                if not (repo and path):
                    continue

                raw_url = f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"
                try:
                    raw_resp = await client.get(raw_url, timeout=15.0)
                except httpx.RequestError:
                    continue
                if raw_resp.status_code != 200:
                    continue
                content = raw_resp.text
                lower = content.lower()
                domain_l = target.domain.lower()

                for pat, kind, severity in SECRET_PATTERNS:
                    match = pat.search(content)
                    if not match:
                        continue
                    start = max(0, match.start() - CONTEXT_WINDOW)
                    end = min(len(content), match.end() + CONTEXT_WINDOW)
                    if domain_l not in lower[start:end]:
                        continue
                    dedup = f"{repo}|{path}|{kind}"
                    if dedup in seen_keys:
                        continue
                    seen_keys.add(dedup)
                    yield Finding(
                        source=self.name,
                        target=str(target),
                        kind=f"exposed_{kind}",
                        severity=severity,
                        title=f"Possible {kind} exposure in {repo}/{path}",
                        evidence_url=html_url,
                        raw={"repo": repo, "path": path, "pattern": kind},
                    )
