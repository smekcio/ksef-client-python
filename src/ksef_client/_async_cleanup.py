"""Collect an already-authorized commit or cleanup despite repeated cancellation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from contextlib import suppress
from typing import TypeVar

T = TypeVar("T")


async def shield_and_drain(
    operation: Awaitable[T],
    *,
    cancellation: asyncio.CancelledError | None = None,
) -> T:
    task = asyncio.ensure_future(operation)
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            cancellation = error
        except Exception:
            break
    if cancellation is not None:
        with suppress(BaseException):
            task.result()
        raise cancellation
    return task.result()
