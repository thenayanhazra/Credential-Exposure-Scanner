"""Have I Been Pwned scanner. Requires a paid API key.

Stub included so users can flip it on by setting `[scanners.hibp] api_key = "..."`.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from .. import USER_AGENT
from ..models import Finding, Severity, Target, TargetKind
from .base import Scanner


class HIBPScanner(Scanner):
    name = "hibp"
    requires_auth = True

    API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

    def _api_key(self) -> str | None:
        return self.config.get("api_key")

    def enabled(self) -> bool:
        if not self.config.get("enabled", True):
            return False
        return bool(self._api_key())

    def supports(self, target: Target) -> bool:
        return target.kind == TargetKind.EMAIL

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        key = self._api_key()
        if not key:
            return
        headers = {
            "hibp-api-key": key,
            "User-Agent": USER_AGENT,
        }
        url = self.API.format(account=target.value)
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            try:
                resp = await client.get(url, params={"truncateResponse": "false"})
            except httpx.RequestError:
                return
            if resp.status_code == 404:
                return
            if resp.status_code != 200:
                return
            breaches = resp.json() or []

        for b in breaches:
            classes = b.get("DataClasses", []) or []
            sev = Severity.HIGH if any("Password" in c for c in classes) else Severity.MEDIUM
            name = b.get("Name", "unknown")
            yield Finding(
                source=self.name,
                target=str(target),
                kind="breach",
                severity=sev,
                title=f"Email appears in breach: {name}",
                evidence_url=f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                raw={"breach": b},
            )
