from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _instant_sleep(monkeypatch):
    """Make retry backoff and inter-query delays instant in tests.

    Patches the module-level _sleep references in the two modules that delay,
    rather than the global asyncio.sleep, to avoid interfering with
    pytest-asyncio's internal event-loop scheduling.
    """
    async def _noop(_seconds):
        pass

    monkeypatch.setattr("credscan.http._sleep", _noop)
    monkeypatch.setattr("credscan.scanners.dorks._sleep", _noop)
