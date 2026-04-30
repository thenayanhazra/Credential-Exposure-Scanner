"""Search-engine dorks scanner.

Runs a short list of targeted queries against DuckDuckGo's HTML endpoint.
Experimental: DDG is rate-limited and may rewrite markup. Treat hits as
leads to investigate, not confirmed exposures.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Callable
from urllib.parse import urlencode

import httpx

from ..http import get_with_retry
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

LINK_RE = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"', re.IGNORECASE
)

# Browser-looking UA; DDG's HTML endpoint 403s on obvious bot UAs.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
)

INTER_QUERY_DELAY = 0.4  # seconds; be polite

_sleep: Callable[[float], object] = asyncio.sleep


class DorkScanner(Scanner):
    name = "dorks"
    ENDPOINT = "https://html.duckduckgo.com/html/"

    def supports(self, target: Target) -> bool:
        return True

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        headers = {"User-Agent": BROWSER_UA}
        max_q = self.config.get("max_queries", len(DORK_TEMPLATES))
        templates_to_run = DORK_TEMPLATES[:min(len(DORK_TEMPLATES), max_q)]
        async with httpx.AsyncClient(
            timeout=20.0, follow_redirects=True, headers=headers
        ) as client:
            for i, template in enumerate(templates_to_run):
                if i > 0:
                    await _sleep(INTER_QUERY_DELAY)
                query = template.format(domain=target.domain)
                resp = await get_with_retry(client, self.ENDPOINT, params={"q": query})
                if resp is None or resp.status_code != 200:
                    continue
                unique_hits = list(dict.fromkeys(LINK_RE.findall(resp.text)))
                if not unique_hits:
                    continue
                yield Finding(
                    source=self.name,
                    target=str(target),
                    kind="search_hit",
                    severity=Severity.LOW,
                    title=f"Search hits for: {query}",
                    evidence_url="https://duckduckgo.com/?" + urlencode({"q": query}),
                    raw={"query": query, "hits": unique_hits[:10]},
                )
