"""Per-invocation body policies, isolated from nested auth and concurrent work."""

from __future__ import annotations

import asyncio
import sys
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import Any, cast

import httpx

from ._async_cleanup import shield_and_drain
from .exceptions import KsefResponseLimitError
from .request_control import current_request_control


def _execution() -> tuple[int, object]:
    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    return threading.get_ident(), task


@dataclass(frozen=True)
class BodyPolicy:
    owner: object
    execution: tuple[int, object]
    max_bytes: int
    url: str


PENDING: ContextVar[BodyPolicy | None] = ContextVar("ksef_pending_body", default=None)
FRAME: ContextVar[BodyPolicy | None] = ContextVar("ksef_body_frame", default=None)


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


def policy_for(owner: object) -> BodyPolicy | None:
    policy = FRAME.get()
    return policy if policy and policy.owner is owner and policy.execution == _execution() else None


def make_policy(owner: Any, path: str, max_bytes: int) -> BodyPolicy:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    url = (
        path
        if path.startswith(("https://", "http://"))
        else (owner.api_base_url.rstrip("/") + "/" + path.lstrip("/"))
    )
    return BodyPolicy(owner, _execution(), max_bytes, url)


def _enter(owner: object) -> tuple[Any, Any]:
    policy = PENDING.get()
    if policy and (policy.owner is not owner or policy.execution != _execution()):
        policy = None
    # Consume once. A nested ordinary request must start an ordinary frame.
    return PENDING.set(None), FRAME.set(policy)


def body_frame(function: Any) -> Any:
    if asyncio.iscoroutinefunction(function):

        @wraps(function)
        async def async_call(self: object, *args: Any, **kwargs: Any) -> Any:
            pending, frame = _enter(self)
            try:
                return await function(self, *args, **kwargs)
            finally:
                FRAME.reset(frame)
                PENDING.reset(pending)

        return async_call

    @wraps(function)
    def call(self: object, *args: Any, **kwargs: Any) -> Any:
        pending, frame = _enter(self)
        try:
            return function(self, *args, **kwargs)
        finally:
            FRAME.reset(frame)
            PENDING.reset(pending)

    return call


def check_control() -> None:
    control = current_request_control()
    if control is not None:
        control.check()


def check_headers(response: httpx.Response, policy: BodyPolicy) -> None:
    reason = None
    if 300 <= response.status_code < 400:
        reason = "response_redirect"
    elif response.headers.get("Content-Encoding", "identity").lower().strip() != "identity":
        reason = "response_encoding"
    if reason:
        raise KsefResponseLimitError(limit_bytes=policy.max_bytes, reason_code=reason)
    length = response.headers.get("Content-Length", "")
    if length.isascii() and length.isdigit():
        # Avoid converting an arbitrarily large digit string into an integer.
        significant = length.lstrip("0") or "0"
        if len(significant) > 20 or int(significant) > policy.max_bytes:
            raise KsefResponseLimitError(limit_bytes=policy.max_bytes)


def append_chunk(body: bytearray, chunk: bytes, policy: BodyPolicy) -> None:
    check_control()
    size = len(body) + len(chunk)
    if size > policy.max_bytes:
        raise KsefResponseLimitError(limit_bytes=policy.max_bytes, observed_bytes=size)
    body.extend(chunk)


def identity_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        **{k: v for k, v in headers.items() if k.lower() != "accept-encoding"},
        "Accept-Encoding": "identity",
    }
