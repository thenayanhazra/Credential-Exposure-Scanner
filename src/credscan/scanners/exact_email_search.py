\"\"\"Exact email address search on GitHub.

Searches public GitHub code for the exact email address string. Findings in
sensitive file paths (e.g. .env, credentials, db.sql) are HIGH; others MEDIUM.
Requires a GitHub personal access token.
\"\"\"
from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator

import httpx

from ..http import get_with_retry
from ..models import Finding, Severity, Target, TargetKind
from ._github import api_headers, raw_url
from .base import Scanner

_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.env|credentials|config|password|secret|db\.sql|dump)"
)


class ExactEmailSearchScanner(Scanner):
    name = "exact_email_search"
    requires_auth = True

    API = "https://api.github.com/search/code"

    def _token(self) -> str | None:
        return self.config.get("token") or os.environ.get("GITHUB_TOKEN")

    def enabled(self) -> bool:
        if not self.config.get("enabled", True):
            return False
        return self._token() is not None

    def supports(self, target: Target) -> bool:
        return target.kind == TargetKind.EMAIL

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        token = self._token()
        if not token:
            return

        per_page = self.config.get("max_hits", 10)
        query = f'"{target.value}"'

        async with httpx.AsyncClient(timeout=30.0, headers=api_headers(token)) as client:
            resp = await get_with_retry(
                client, self.API, params={"q": query, "per_page": per_page}
            )
            if resp is None or resp.status_code != 200:
                return

            items = resp.json().get("items", [])
            seen: set[str] = set()

            for item in items:
                repo = item.get("repository", {}).get("full_name")
                path = item.get("path", "")
                html_url = item.get("html_url", "")
                if not (repo and path):
                    continue

                dedup = f"{repo}|{path}"
                if dedup in seen:
                    continue
                seen.add(dedup)

                raw_resp = await get_with_retry(client, raw_url(repo, path), timeout=15.0)
                if raw_resp is None or raw_resp.status_code != 200:
                    continue

                from hashlib import sha256
                evidence_hash = sha256(raw_resp.text.encode("utf-8")).hexdigest()

                severity = (
                    Severity.HIGH if _SENSITIVE_PATH_RE.search(path) else Severity.MEDIUM
                )
                yield Finding(
                    source=self.name,
                    target=str(target),
                    kind="email_in_public_code",
                    severity=severity,
                    title=f"Email address found in public repo: {repo}/{path}",
                    evidence_url=html_url,
                    evidence_hash=evidence_hash,
                    raw={"repo": repo, "path": path},
                )
