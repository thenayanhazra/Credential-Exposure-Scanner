\"\"\"GitHub code search scanner.

Searches public code for occurrences of the target domain alongside common
credential patterns. Requires a free personal access token (read-only).
\"\"\"
from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx

from ..http import get_with_retry
from ..models import Finding, Target
from ._github import api_headers, find_secrets, raw_url
from .base import Scanner


class GitHubSearchScanner(Scanner):
    name = "github_search"
    requires_auth = True

    API = "https://api.github.com/search/code"

    def _token(self) -> str | None:
        return self.config.get("token") or os.environ.get("GITHUB_TOKEN")

    def enabled(self) -> bool:
        if not self.config.get("enabled", True):
            return False
        return self._token() is not None

    def supports(self, target: Target) -> bool:
        return True  # domain or email — we search for the domain string

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        token = self._token()
        if not token:
            return

        per_page = self.config.get("max_hits", 30)
        query = f'"{target.domain}"'

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
                path = item.get("path")
                html_url = item.get("html_url", "")
                if not (repo and path):
                    continue

                raw_resp = await get_with_retry(client, raw_url(repo, path), timeout=15.0)
                if raw_resp is None or raw_resp.status_code != 200:
                    continue

                from hashlib import sha256
                evidence_hash = sha256(raw_resp.text.encode("utf-8")).hexdigest()

                for kind, severity in find_secrets(raw_resp.text, domain=target.domain):
                    dedup = f"{repo}|{path}|{kind}"
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    yield Finding(
                        source=self.name,
                        target=str(target),
                        kind=f"exposed_{kind}",
                        severity=severity,
                        title=f"Possible {kind} exposure in {repo}/{path}",
                        evidence_url=html_url,
                        evidence_hash=evidence_hash,
                        raw={"repo": repo, "path": path, "pattern": kind},
                    )
