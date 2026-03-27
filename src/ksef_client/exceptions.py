from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeAlias

from .models import (
    ExceptionResponse,
    ForbiddenProblemDetails,
    TooManyRequestsResponse,
    UnauthorizedProblemDetails,
    UnknownApiProblem,
)

ApiProblem: TypeAlias = (
    ExceptionResponse
    | ForbiddenProblemDetails
    | TooManyRequestsResponse
    | UnauthorizedProblemDetails
    | UnknownApiProblem
)


@dataclass
class KsefHttpError(Exception):
    status_code: int
    message: str
    response_body: Any | None = None
    problem: ApiProblem | None = None

    def __str__(self) -> str:
        return f"HTTP {self.status_code}: {self.message}"


@dataclass
class KsefRateLimitError(KsefHttpError):
    retry_after: int | None = None
    retry_after_raw: str | None = None


@dataclass
class KsefApiError(KsefHttpError):
    exception_response: ExceptionResponse | None = None
