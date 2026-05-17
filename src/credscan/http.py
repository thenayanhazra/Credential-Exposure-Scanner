"""Shared HTTP utility: GET with exponential backoff on transient errors."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

import httpx

log = logging.getLogger(__name__)

# Module-level reference so tests can patch just this without touching the
# global asyncio.sleep (which pytest-asyncio also uses internally).
_sleep: Callable[[float], object] = asyncio.sleep

_TRANSIENT = frozenset({429, 500, 502, 503, 504})
_BASE_DELAY = 2.0
_MAX_DELAY = 60.0


async def get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 3,
    **kwargs,
) -> httpx.Response | None:
    """GET url, retrying transient failures with exponential backoff.

    Returns the response on success (any status), None after exhausting retries
    or on a network-level error. Callers are responsible for checking the status
    code of the returned response.
    """
    for attempt in range(retries + 1):
        try:
            resp = await client.get(url, **kwargs)
        except (httpx.RequestError, asyncio.TimeoutError) as exc:
            if attempt == retries:
                log.warning("GET %s failed after %d attempt(s): %s", url, retries + 1, exc)
                return None
            await _sleep(min(_BASE_DELAY * (2**attempt), _MAX_DELAY))
            continue

        if resp.status_code not in _TRANSIENT:
            return resp

        if attempt == retries:
            log.warning("GET %s → %d after %d attempt(s)", url, resp.status_code, retries + 1)
            return None

        header = resp.headers.get("Retry-After", "")
        delay = float(header) if header.isdigit() else _BASE_DELAY * (2**attempt)
        delay = min(delay, _MAX_DELAY)
        log.debug("GET %s → %d, retrying in %.1fs", url, resp.status_code, delay)
        await _sleep(delay)

    return None  # unreachable, but satisfies type checkers
