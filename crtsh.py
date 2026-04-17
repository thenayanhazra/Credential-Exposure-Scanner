"""crt.sh scanner: enumerate subdomains from certificate transparency logs."""
from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from .. import USER_AGENT
from ..models import Finding, Severity, Target, TargetKind
from .base import Scanner


class CrtShScanner(Scanner):
    name = "crtsh"
    BASE_URL = "https://crt.sh/"

    def supports(self, target: Target) -> bool:
        return target.kind == TargetKind.DOMAIN

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        params = {"q": f"%.{target.domain}", "output": "json"}
        async with httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            try:
                resp = await client.get(self.BASE_URL, params=params)
            except httpx.RequestError:
                return
            if resp.status_code != 200:
                return
            try:
                entries = resp.json()
            except ValueError:
                return

        subdomains: set[str] = set()
        for entry in entries:
            names = str(entry.get("name_value", "")).split("\n")
            for name in names:
                n = name.strip().lower().lstrip("*.")
                if n and (n == target.domain or n.endswith("." + target.domain)):
                    subdomains.add(n)

        if not subdomains:
            return

        sample = sorted(subdomains)
        yield Finding(
            source=self.name,
            target=str(target),
            kind="subdomain_enumeration",
            severity=Severity.INFO,
            title=f"Found {len(sample)} subdomains via certificate transparency",
            evidence_url=f"https://crt.sh/?q=%25.{target.domain}",
            raw={"count": len(sample), "subdomains": sample[:200]},
        )
