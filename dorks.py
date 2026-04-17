"""Search-engine dorks scanner.

Runs a short list of targeted queries against DuckDuckGo's HTML endpoint.
Experimental: DDG is rate-limited and may rewrite markup. Treat hits as
leads to investigate, not confirmed exposures.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator

import httpx

from ..models import Finding, Severity, Target
from .base import Scanner

DORK_TEMPLATES = [
    '"{domain}" filetype:env',
    '"{domain}" filetype:log "password"',
    '"{domain}" site:pastebin.com',
    '"{domain}" site:gist.github.com password',
    '"{domain}" "BEGIN RSA PRIVATE KEY"',
    '"{domain}" "aws_access_key_id"',
    '"{domain}" "DB_PASSWORD"',
]

LINK_RE = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"', re.IGNORECASE)


class DorkScanner(Scanner):
    name = "dorks"
    ENDPOINT = "https://html.duckduckgo.com/html/"

    def supports(self, target: Target) -> bool:
        return True

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
            ),
        }
        async with httpx.AsyncClient(
            timeout=20.0, follow_redirects=True, headers=headers
        ) as client:
            for template in DORK_TEMPLATES:
                query = template.format(domain=target.domain)
                try:
                    resp = await client.get(self.ENDPOINT, params={"q": query})
                except httpx.RequestError:
                    continue
                if resp.status_code != 200:
                    continue
                hits = LINK_RE.findall(resp.text)
                # De-duplicate while preserving order
                seen: set[str] = set()
                unique_hits: list[str] = []
                for h in hits:
                    if h not in seen:
                        seen.add(h)
                        unique_hits.append(h)
                if not unique_hits:
                    continue
                yield Finding(
                    source=self.name,
                    target=str(target),
                    kind="search_hit",
                    severity=Severity.LOW,
                    title=f"Search hits for: {query}",
                    evidence_url=f"https://duckduckgo.com/?q={httpx.QueryParams({'q': query})}",
                    raw={"query": query, "hits": unique_hits[:10]},
                )
