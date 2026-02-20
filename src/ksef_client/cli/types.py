from __future__ import annotations

from typing import Any, TypedDict


class EnvelopeMeta(TypedDict, total=False):
    duration_ms: int
    timestamp: str


class EnvelopeError(TypedDict, total=False):
    code: str
    message: str
    hint: str


class Envelope(TypedDict, total=False):
    ok: bool
    command: str
    profile: str | None
    data: dict[str, Any] | None
    errors: list[EnvelopeError]
    meta: EnvelopeMeta
