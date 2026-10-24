"""Task-local, cooperative controls for budget admission and retry waits."""

from __future__ import annotations

import asyncio
import math
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from .rate_limiting import CancellationSignal, RequestControl

_CURRENT: ContextVar[RequestControl | None] = ContextVar("ksef_request_control", default=None)


class _CancellationGroup(threading.Event):
    def __init__(self, *tokens: CancellationSignal) -> None:
        super().__init__()
        self._tokens = tokens

    def is_set(self) -> bool:
        return any(token.is_set() for token in self._tokens)


def current_request_control() -> RequestControl | None:
    return _CURRENT.get()


def _finite(value: float, name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite number")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError(f"{name} must be a finite number") from None
    if not math.isfinite(result):
        raise ValueError(f"{name} must be a finite number")
    return result


@contextmanager
def request_control(
    *,
    timeout_seconds: float | None = None,
    deadline: float | None = None,
    cancellation: CancellationSignal | None = None,
) -> Iterator[RequestControl]:
    """Bound an operation with a monotonic deadline and/or cooperative cancellation.

    Use a normal ``with`` block in sync or async code. Controls propagate through
    nested SDK calls and asyncio tasks, but not automatically into new threads.
    Nested controls may tighten a parent deadline, never relax it. Cancellation
    interrupts budget/retry waits; it does not undo a request already sent.
    """
    parent = _CURRENT.get()
    deadlines = []
    if timeout_seconds is not None:
        seconds = _finite(timeout_seconds, "timeout_seconds")
        if seconds < 0:
            raise ValueError("timeout_seconds must be non-negative")
        deadlines.append(time.monotonic() + seconds)
    if deadline is not None:
        deadlines.append(_finite(deadline, "deadline"))
    if parent is not None:
        if parent.deadline is not None:
            deadlines.append(parent.deadline)
        if parent.cancellation is not None:
            cancellation = (
                _CancellationGroup(parent.cancellation, cancellation)
                if cancellation is not None
                else parent.cancellation
            )
    control = RequestControl(
        deadline=min(deadlines) if deadlines else None, cancellation=cancellation
    )
    control.check()
    marker = _CURRENT.set(control)
    try:
        yield control
    finally:
        _CURRENT.reset(marker)


def wait_seconds(seconds: float, *, sleep: Callable[[float], None] = time.sleep) -> None:
    control = _CURRENT.get()
    if control is None:
        sleep(seconds)
        return
    end = time.monotonic() + seconds
    while True:
        control.check()
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        deadline_remaining = control.remaining()
        sleep(
            min(
                remaining, 0.05, deadline_remaining if deadline_remaining is not None else remaining
            )
        )


async def wait_seconds_async(
    seconds: float, *, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
) -> None:
    control = _CURRENT.get()
    if control is None:
        await sleep(seconds)
        return
    end = time.monotonic() + seconds
    while True:
        control.check()
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        deadline_remaining = control.remaining()
        await sleep(
            min(
                remaining, 0.05, deadline_remaining if deadline_remaining is not None else remaining
            )
        )
