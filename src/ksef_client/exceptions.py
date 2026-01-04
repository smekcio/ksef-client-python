from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class KsefHttpError(Exception):
    status_code: int
    message: str
    response_body: Any | None = None

    def __str__(self) -> str:
        return f"HTTP {self.status_code}: {self.message}"


@dataclass
class KsefRateLimitError(KsefHttpError):
    retry_after: str | None = None


@dataclass
class KsefApiError(KsefHttpError):
    exception_response: dict[str, Any] | None = None
