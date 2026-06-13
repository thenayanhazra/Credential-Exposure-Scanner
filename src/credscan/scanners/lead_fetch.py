\"\"\"Lead fetch scanner.

Searches GitHub for the target (domain or email) in credential-dense file types
(.env, .log, .cfg, .ini) and applies SECRET_PATTERNS to the raw file content.

`max_pages` controls how many search result pages (30 items/page) are consumed.
Raw-file fetches are capped at `max_pages * 5` to bound HTTP request volume
(~60 requests at the default of 10 pages).
\"\"\"
from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx

from ..http import get_with_retry
from ..models import Finding, Target
from ._github import api_headers, find_secrets, raw_url
from .base import Scanner

_FILE_FILTER = "extension:env OR extension:log OR extension:cfg OR extension:ini"
_RAW_FETCH_MULTIPLIER = 5


class LeadFetchScanner(Scanner):
    name = "lead_fetch"
    requires_auth = True

    API = "https://api.github.com/search/code"

    def _token(self) -> str | None:
        return self.config.get("token") or os.environ.get("GITHUB_TOKEN")

    def enabled(self) -> bool:
        if not self.config.get("enabled", True):
            return False
        return self._token() is not None

    def supports(self, target: Target) -> bool:
        return True

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        token = self._token()
        if not token:
            return

        max_pages = self.config.get("max_pages", 10)
        max_raw_fetches = max_pages * _RAW_FETCH_MULTIPLIER
        query = f'"{target.value}" {_FILE_FILTER}'

        async with httpx.AsyncClient(timeout=30.0, headers=api_headers(token)) as client:
            items: list[dict] = []
            for page in range(1, max_pages + 1):
                resp = await get_with_retry(
                    client,
                    self.API,
                    params={"q": query, "per_page": 30, "page": page},
                )
                if resp is None or resp.status_code != 200:
                    break
                page_items = resp.json().get("items", [])
                items.extend(page_items)
                if len(page_items) < 30:
                    break

            seen: set[str] = set()
            fetch_count = 0

            for item in items:
                if fetch_count >= max_raw_fetches:
                    break
                repo = item.get("repository", {}).get("full_name")
                path = item.get("path", "")
                html_url = item.get("html_url", "")
                if not (repo and path):
                    continue

                raw_resp = await get_with_retry(client, raw_url(repo, path), timeout=15.0)
                fetch_count += 1
                if raw_resp is None or raw_resp.status_code != 200:
                    continue

                from hashlib import sha256
                evidence_hash = sha256(raw_resp.text.encode("utf-8")).hexdigest()

                # No domain proximity check: the file was found because it
                # matched the target query, so any secret in it is relevant.
                for kind, severity in find_secrets(raw_resp.text):
                    dedup = f"{repo}|{path}|{kind}"
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    yield Finding(
                        source=self.name,
                        target=str(target),
                        kind=f"exposed_{kind}",
                        severity=severity,
                        title=f"Possible {kind} in sensitive file {repo}/{path}",
                        evidence_url=html_url,
                        evidence_hash=evidence_hash,
                        raw={"repo": repo, "path": path, "pattern": kind},
                    )
