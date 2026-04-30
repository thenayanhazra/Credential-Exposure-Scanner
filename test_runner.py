"""Test the Runner orchestrates scanners correctly."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from credscan.models import Finding, Severity, Target, TargetKind
from credscan.runner import Runner
from credscan.scanners.base import Scanner
from credscan.store import Store


class _FakeScanner(Scanner):
    def __init__(self, name: str, findings: list[Finding], supports: bool = True,
                 enabled: bool = True, raises: bool = False):
        super().__init__()
        self.name = name
        self._findings = findings
        self._supports = supports
        self._enabled = enabled
        self._raises = raises

    def enabled(self) -> bool:
        return self._enabled

    def supports(self, target: Target) -> bool:
        return self._supports

    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        if self._raises:
            raise RuntimeError(f"{self.name} boom")
        for f in self._findings:
            yield f


class _SlowScanner(_FakeScanner):
    async def scan(self, target: Target) -> AsyncIterator[Finding]:
        await asyncio.sleep(0.05)
        if False:
            yield  # pragma: no cover


def _target() -> Target:
    return Target(kind=TargetKind.DOMAIN, value="example.com", domain="example.com")


def _finding(source: str, kind: str = "test") -> Finding:
    return Finding(
        source=source,
        target="domain:example.com",
        kind=kind,
        severity=Severity.MEDIUM,
        title=f"{source} finding",
        evidence_url=f"https://evidence.test/{source}/{kind}",
    )


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    yield s
    s.close()


async def test_runs_applicable_and_aggregates(store):
    s1 = _FakeScanner("s1", [_finding("s1", "a"), _finding("s1", "b")])
    s2 = _FakeScanner("s2", [_finding("s2", "c")])
    runner = Runner([s1, s2], store)
    result = await runner.run(_target())
    assert len(result.findings) == 3
    assert set(result.scanners_run) == {"s1", "s2"}


async def test_skips_disabled(store):
    s1 = _FakeScanner("s1", [_finding("s1")], enabled=False)
    s2 = _FakeScanner("s2", [_finding("s2")])
    runner = Runner([s1, s2], store)
    result = await runner.run(_target())
    assert result.scanners_run == ["s2"]
    assert len(result.findings) == 1


async def test_skips_unsupported(store):
    s1 = _FakeScanner("s1", [_finding("s1")], supports=False)
    s2 = _FakeScanner("s2", [_finding("s2")])
    runner = Runner([s1, s2], store)
    result = await runner.run(_target())
    assert result.scanners_run == ["s2"]


async def test_scanner_exception_does_not_break_others(store):
    s1 = _FakeScanner("bad", [], raises=True)
    s2 = _FakeScanner("good", [_finding("good")])
    runner = Runner([s1, s2], store)
    result = await runner.run(_target())
    assert len(result.findings) == 1
    assert result.findings[0].source == "good"


async def test_findings_persisted(store):
    s = _FakeScanner("s", [_finding("s", "a"), _finding("s", "b")])
    runner = Runner([s], store)
    await runner.run(_target())
    rows = store.findings_for("domain:example.com")
    assert len(rows) == 2


async def test_scan_history_recorded(store):
    s = _FakeScanner("s", [_finding("s")])
    runner = Runner([s], store)
    await runner.run(_target())
    scans = store.recent_scans()
    assert len(scans) == 1
    assert scans[0]["status"] == "done"
    assert scans[0]["finding_count"] == 1


async def test_no_applicable_scanners(store):
    s = _FakeScanner("s", [_finding("s")], supports=False)
    runner = Runner([s], store)
    result = await runner.run(_target())
    assert result.findings == []
    assert result.scanners_run == []
    scans = store.recent_scans()
    assert scans[0]["status"] == "no_scanners"


async def test_scanner_timeout_does_not_break_others(store):
    slow = _SlowScanner("slow", [])
    good = _FakeScanner("good", [_finding("good")])
    runner = Runner([slow, good], store, scanner_timeout_s=0.01)
    result = await runner.run(_target())
    assert len(result.findings) == 1
    assert result.findings[0].source == "good"
