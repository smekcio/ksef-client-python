from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class KsefHttpError(Exception):
    status_code: int
    message: str
    response_body: Optional[Any] = None

    def __str__(self) -> str:
        return f"HTTP {self.status_code}: {self.message}"


@dataclass
class KsefRateLimitError(KsefHttpError):
    retry_after: Optional[str] = None


@dataclass
class KsefApiError(KsefHttpError):
    exception_response: Optional[dict[str, Any]] = None
