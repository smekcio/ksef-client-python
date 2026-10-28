"""Bounded response helpers; limits are explicit request arguments."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast

import httpx

from ._async_cleanup import shield_and_drain
from .exceptions import KsefResponseLimitError
from .request_control import current_request_control


class _ClosingAsyncStream(httpx.AsyncByteStream):
    """Protect HTTPX's implicit EOF close as well as context-manager cleanup."""

    def __init__(self, source: httpx.AsyncByteStream) -> None:
        self._source = source

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._source:
            yield chunk

    async def aclose(self) -> None:
        await shield_and_drain(self._source.aclose())


@asynccontextmanager
async def limited_response_stream(
    client: httpx.AsyncClient, **kwargs: Any
) -> AsyncIterator[httpx.Response]:
    manager = client.stream(**kwargs)
    response = await manager.__aenter__()
    try:
        response.stream = _ClosingAsyncStream(cast(httpx.AsyncByteStream, response.stream))
        yield response
    finally:
        exception = sys.exc_info()
        cancellation = exception[1] if isinstance(exception[1], asyncio.CancelledError) else None
        await shield_and_drain(manager.__aexit__(*exception), cancellation=cancellation)


def validate_max_bytes(max_bytes: int) -> None:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")


def check_control() -> None:
    control = current_request_control()
    if control is not None:
        control.check()


def check_headers(response: httpx.Response, max_bytes: int) -> None:
    reason = None
    if 300 <= response.status_code < 400:
        reason = "response_redirect"
    elif response.headers.get("Content-Encoding", "identity").lower().strip() != "identity":
        reason = "response_encoding"
    if reason:
        raise KsefResponseLimitError(limit_bytes=max_bytes, reason_code=reason)
    length = response.headers.get("Content-Length", "")
    if length.isascii() and length.isdigit():
        # Avoid converting an arbitrarily large digit string into an integer.
        significant = length.lstrip("0") or "0"
        if len(significant) > 20 or int(significant) > max_bytes:
            raise KsefResponseLimitError(limit_bytes=max_bytes)


def append_chunk(body: bytearray, chunk: bytes, max_bytes: int) -> None:
    check_control()
    size = len(body) + len(chunk)
    if size > max_bytes:
        raise KsefResponseLimitError(limit_bytes=max_bytes, observed_bytes=size)
    body.extend(chunk)


def identity_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        **{k: v for k, v in headers.items() if k.lower() != "accept-encoding"},
        "Accept-Encoding": "identity",
    }
