from __future__ import annotations

from typing import Any, Protocol


class Renderer(Protocol):
    def info(self, message: str, *, command: str | None = None) -> None: ...

    def success(
        self,
        *,
        command: str,
        profile: str,
        data: dict[str, Any] | None = None,
        message: str | None = None,
    ) -> None: ...

    def error(
        self,
        *,
        command: str,
        profile: str,
        code: str,
        message: str,
        hint: str | None = None,
    ) -> None: ...
