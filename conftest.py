from __future__ import annotations

import asyncio

import pytest


@pytest.fixture(autouse=True)
def _instant_sleep(monkeypatch):
    """Make asyncio.sleep a no-op so retry backoff doesn't slow the test suite."""
    async def _noop(_seconds):
        pass

    monkeypatch.setattr(asyncio, "sleep", _noop)
