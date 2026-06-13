\"\"\"Runner: executes applicable scanners against a target with bounded concurrency.\"\"\"
from __future__ import annotations

import asyncio
import sys
if sys.version_info >= (3, 11):
    from asyncio import timeout as async_timeout_ctx
else:
    from async_timeout import timeout as async_timeout_ctx

import logging

from .models import Finding, ScanResult, Target
from .scanners.base import Scanner
from .store import Store

log = logging.getLogger(__name__)


_DEFAULT_SCANNER_TIMEOUT = 120  # seconds


class Runner:
    def __init__(
        self,
        scanners: list[Scanner],
        store: Store,
        concurrency: int = 5,
        scanner_timeout: int = _DEFAULT_SCANNER_TIMEOUT,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")

        self.scanners = scanners
        self.store = store
        self.sem = asyncio.Semaphore(concurrency)
        self.scanner_timeout = scanner_timeout

    def applicable(self, target: Target) -> list[Scanner]:
        return [s for s in self.scanners if s.enabled() and s.supports(target)]

    async def _run_one(self, scanner: Scanner, target: Target, scan_id: int) -> list[Finding]:
        \"\"\"Drive one scanner. Exceptions are caught so one bad scanner can't
        poison the batch.\"\"\"
        out: list[Finding] = []
        run_id = self.store.start_scanner_run(scan_id, scanner.name)
        status = "done"
        error_msg = None
        async with self.sem:
            try:
                async with async_timeout_ctx(self.scanner_timeout):
                    async for finding in scanner.scan(target):
                        out.append(finding)
                self.store.upsert_many(out)
            except (asyncio.TimeoutError, TimeoutError):
                status = "timeout"
                error_msg = f"Timed out after {self.scanner_timeout}s"
                log.warning(
                    "scanner %s timed out after %ds", scanner.name, self.scanner_timeout
                )
            except Exception as e:  # noqa: BLE001
                status = "failed"
                error_msg = str(e)
                log.warning("scanner %s failed: %s", scanner.name, e)
            finally:
                self.store.finish_scanner_run(run_id, len(out), status, error_msg)
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
        batches = await asyncio.gather(*(self._run_one(s, target, scan_id) for s in applicable))
        findings = [f for batch in batches for f in batch]
        self.store.finish_scan(scan_id, len(findings), status="done")

        return ScanResult(
            target=target.value,
            scan_id=scan_id,
            scanners_run=[s.name for s in applicable],
            findings=findings,
        )
