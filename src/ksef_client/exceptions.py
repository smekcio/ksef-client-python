from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, TypeAlias

from .models import (
    BadRequestProblemDetails,
    ExceptionResponse,
    ForbiddenProblemDetails,
    GoneProblemDetails,
    TooManyRequestsProblemDetails,
    TooManyRequestsResponse,
    UnauthorizedProblemDetails,
    UnknownApiProblem,
)

ApiProblem: TypeAlias = (
    BadRequestProblemDetails
    | ExceptionResponse
    | ForbiddenProblemDetails
    | GoneProblemDetails
    | TooManyRequestsProblemDetails
    | TooManyRequestsResponse
    | UnauthorizedProblemDetails
    | UnknownApiProblem
)


def _restore_error(
    error_cls: type[KsefHttpError], values: dict[str, Any], args: tuple[Any, ...]
) -> KsefHttpError:
    """Odtwarza wyjątek bez wołania ``__init__`` — dla ``pickle`` i ``copy``.

    Konstruktory SDK wymagają ``status_code`` i ``message`` pozycyjnie, więc samo
    ``args`` nie wystarcza do odtworzenia obiektu (patrz ``KsefHttpError.__reduce__``).
    """
    error = error_cls.__new__(error_cls)
    error.__dict__.update(values)
    error.args = args
    return error


@dataclass
class KsefHttpError(Exception):
    status_code: int
    message: str
    response_body: Any | None = None
    problem: ApiProblem | None = None
    #: Sekundy z nagłówka ``Retry-After`` (już z sufitem) — ``None``, gdy nagłówka nie było.
    #:
    #: ``Retry-After`` dotyczy nie tylko 429: KSeF wysyła go także przy 502/503/504,
    #: a CLI ponawia wszystkie te kody. Pola są ``kw_only``, żeby zachować dotychczasową
    #: kolejność argumentów pozycyjnych w podklasach — ``KsefApiError(400, "msg", body,
    #: problem, exception_response)`` nadal działa.
    retry_after: int | None = field(default=None, kw_only=True)
    #: Surowa wartość nagłówka ``Retry-After`` (liczba sekund albo data HTTP).
    retry_after_raw: str | None = field(default=None, kw_only=True)

    def __str__(self) -> str:
        return f"HTTP {self.status_code}: {self.message}"

    def __reduce__(self) -> tuple[Any, ...]:
        """Odtwarza wyjątek z kompletem pól (``pickle``, ``copy``, ``multiprocessing``).

        Domyślna implementacja ``BaseException.__reduce__`` przekazuje do odtworzenia
        wyłącznie ``self.args``, a konstruktory SDK ustawiają pola słowami kluczowymi —
        ``args`` jest więc puste. ``pickle.loads`` wołał wtedy ``Klasa()`` i kończył się
        ``TypeError: __init__() missing 2 required positional arguments``: błąd
        przenoszony do innego procesu (``ProcessPoolExecutor``) zmieniał się w inny błąd.
        """
        values = {model_field.name: getattr(self, model_field.name) for model_field in fields(self)}
        return (_restore_error, (type(self), values, self.args))


@dataclass
class KsefRateLimitError(KsefHttpError):
    """429 — przekroczony limit tempa.

    ``retry_after``/``retry_after_raw`` dziedziczy z bazy, ale zostają tu argumentami
    pozycyjnymi (tak było przed przeniesieniem pól do ``KsefHttpError``) — nadpisanie
    zmienia wyłącznie sposób przekazywania, nie znaczenie pól.
    """

    retry_after: int | None = None
    retry_after_raw: str | None = None
    exception_response: ExceptionResponse | None = None

    def __post_init__(self) -> None:
        """Uzupełnia ``exception_response``, gdy ``problem`` jest ``ExceptionResponse``.

        KSeF potrafi odpowiedzieć 429 ciałem ``{"exception": ...}`` — tak samo jak przy
        400. Ten sam obiekt problemu należy wtedy do obu pól; wcześniej
        ``exception_response`` zostawało ``None`` mimo wypełnionego ``problem``.
        """
        if self.exception_response is None and isinstance(self.problem, ExceptionResponse):
            self.exception_response = self.problem


@dataclass
class KsefApiError(KsefHttpError):
    exception_response: ExceptionResponse | None = None
