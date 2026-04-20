"""Runner: executes applicable scanners against a target with bounded concurrency."""
from __future__ import annotations

import asyncio
import logging

from .models import Finding, ScanResult, Target
from .scanners.base import Scanner
from .store import Store

log = logging.getLogger(__name__)


class Runner:
    def __init__(
        self,
        scanners: list[Scanner],
        store: Store,
        concurrency: int = 5,
    ) -> None:
        self.scanners = scanners
        self.store = store
        self.sem = asyncio.Semaphore(concurrency)

    def applicable(self, target: Target) -> list[Scanner]:
        return [s for s in self.scanners if s.enabled() and s.supports(target)]

    async def _run_one(self, scanner: Scanner, target: Target) -> list[Finding]:
        """Drive one scanner. Exceptions are caught so one bad scanner can't
        poison the batch."""
        out: list[Finding] = []
        async with self.sem:
            try:
                async for finding in scanner.scan(target):
                    self.store.upsert(finding)
                    out.append(finding)
            except Exception as e:  # noqa: BLE001
                log.warning("scanner %s failed: %s", scanner.name, e)
        return out

    async def run(self, target: Target) -> ScanResult:
        scan_id = self.store.start_scan(str(target))
        applicable = self.applicable(target)

        if not applicable:
            self.store.finish_scan(scan_id, 0, status="no_scanners")
            return ScanResult(
                target=target.value,
                scan_id=scan_id,
                scanners_run=[],
                findings=[],
            )

        # _run_one already swallows per-scanner exceptions, so gather() will
        # never raise from scanner errors. Any exception here is a bug in the
        # runner itself and should propagate.
        batches = await asyncio.gather(*(self._run_one(s, target) for s in applicable))
        findings = [f for batch in batches for f in batch]
        self.store.finish_scan(scan_id, len(findings), status="done")

        return ScanResult(
            target=target.value,
            scan_id=scan_id,
            scanners_run=[s.name for s in applicable],
            findings=findings,
        )
