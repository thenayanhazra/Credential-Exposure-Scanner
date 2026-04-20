"""Minimal test stub for respx used in this repository's unit tests.

Provides:
- @respx.mock decorator/context manager
- respx.get(url).mock(return_value=httpx.Response(...))
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable

import httpx


@dataclass
class _Route:
    method: str
    url: str
    response: httpx.Response | None = None

    def mock(self, *, return_value: httpx.Response) -> "_Route":
        self.response = return_value
        _ROUTES[(self.method, self.url)] = self
        return self


_ROUTES: dict[tuple[str, str], _Route] = {}
_ORIG_GET: Callable[..., Any] | None = None


def get(url: str) -> _Route:
    return _Route(method="GET", url=url)


async def _patched_get(self: httpx.AsyncClient, url: str, *args: Any, **kwargs: Any) -> httpx.Response:
    route = _ROUTES.get(("GET", str(url)))
    if route and route.response is not None:
        return route.response
    if _ORIG_GET is None:
        raise RuntimeError("respx mock not initialized")
    return await _ORIG_GET(self, url, *args, **kwargs)


class _Mock:
    def __enter__(self) -> "mock":
        global _ORIG_GET
        _ROUTES.clear()
        _ORIG_GET = httpx.AsyncClient.get
        httpx.AsyncClient.get = _patched_get
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        global _ORIG_GET
        if _ORIG_GET is not None:
            httpx.AsyncClient.get = _ORIG_GET
        _ORIG_GET = None
        _ROUTES.clear()

    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        if hasattr(fn, "__code__") and fn.__code__.co_flags & 0x80:  # coroutine function
            @wraps(fn)
            async def async_wrapped(*args: Any, **kwargs: Any):
                with self:
                    return await fn(*args, **kwargs)

            return async_wrapped

        @wraps(fn)
        def wrapped(*args: Any, **kwargs: Any):
            with self:
                return fn(*args, **kwargs)

        return wrapped


mock = _Mock()
