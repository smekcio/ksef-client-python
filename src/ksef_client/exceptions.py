from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum, IntEnum
from typing import Any, ClassVar, TypeAlias
from urllib.parse import urlparse

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


class ErrorCode(str, Enum):
    """Stabilny identyfikator kategorii błędu (kontrakt dla CLI i MCP).

    Wartości są częścią kontraktu publicznego: nie zmieniaj istniejących, nowe
    dodawaj na końcu. ``str`` w dziedziczeniu utrzymuje zgodność z Pythonem 3.10
    (bez ``enum.StrEnum``).
    """

    ERROR = "error"
    HTTP_ERROR = "http_error"
    TRANSPORT_ERROR = "transport_error"
    API_ERROR = "api_error"
    BAD_REQUEST = "bad_request"
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHORIZATION_FAILED = "authorization_failed"
    PERMISSION_ERROR = "permission_error"
    VALIDATION_FAILED = "validation_failed"
    INVOICE_REJECTED = "invoice_rejected"
    INVOICE_NOT_FOUND = "invoice_not_found"
    INVOICE_UNAVAILABLE = "invoice_unavailable"
    UPO_NOT_FOUND = "upo_not_found"
    SESSION_ERROR = "session_error"
    EXPORT_ERROR = "export_error"
    CERTIFICATE_ERROR = "certificate_error"
    COLLECTIVE_IDENTIFIER_ERROR = "collective_identifier_error"
    INVALID_CONTINUATION_TOKEN = "invalid_continuation_token"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    NOT_FOUND = "not_found"
    WORKFLOW_ERROR = "workflow_error"
    AUTHENTICATION_TIMEOUT = "authentication_timeout"
    DOCUMENT_ERROR = "document_error"
    DOCUMENT_VALIDATION_FAILED = "document_validation_failed"
    DOCUMENT_RENDERING_FAILED = "document_rendering_failed"
    VERIFICATION_FAILED = "verification_failed"
    CHECKPOINT_FAILED = "checkpoint_failed"
    PAGINATION_ERROR = "pagination_error"
    INVALID_PAGINATION_CURSOR = "invalid_pagination_cursor"
    INCOMPLETE_PAGINATION = "incomplete_pagination"
    SYNC_ERROR = "sync_error"
    INVALID_SYNC_CHECKPOINT = "invalid_sync_checkpoint"
    SYNC_STATE_ERROR = "sync_state_error"
    SYNC_CONFLICT = "sync_conflict"
    SYNC_DATA_CONFLICT = "sync_data_conflict"
    SYNC_LIMIT_EXCEEDED = "sync_limit_exceeded"
    SYNC_STORE_ERROR = "sync_store_error"
    SYNC_RUN_FAILED = "sync_run_failed"
    RESPONSE_LIMIT_EXCEEDED = "response_limit_exceeded"
    XML_INTEGRITY_ERROR = "xml_integrity_error"
    XML_STORAGE_ERROR = "xml_storage_error"

    def __str__(self) -> str:
        return self.value


class KsefExceptionCode(IntEnum):
    """Kody ``exceptionCode`` z KSeF API 2.9.0 (snapshot OpenAPI).

    Pełny zbiór 50 kodów jest wymuszany testem. Kody spoza enumy pozostają
    dostępne jako ``int`` w :attr:`KsefApiError.exception_codes`.
    """

    INVALID_SIGNATURE_DOCUMENT = 9101
    MISSING_SIGNATURE = 9102
    SIGNATURE_LIMIT_EXCEEDED = 9103
    INVALID_SIGNATURE = 9105
    INVALID_CONTENT = 21001
    INVALID_AUTH_CHALLENGE = 21111
    INVALID_CERTIFICATE = 21115
    INVALID_CONTEXT_IDENTIFIER = 21117
    SESSION_INVOICE_LIMIT_EXCEEDED = 21155
    INVALID_PACKAGE_PART_SIZE = 21157
    PACKAGE_PART_LIMIT_EXCEEDED = 21161
    INVOICE_NOT_FOUND = 21164
    INVOICE_NOT_AVAILABLE = 21165
    TECHNICAL_CORRECTION_UNAVAILABLE = 21166
    CORRECTION_BLOCKED_BY_STATUS = 21167
    SESSION_NOT_FOUND = 21173
    QUERY_RESULT_NOT_FOUND = 21175
    UPO_NOT_FOUND = 21178
    SESSION_STATUS_BLOCKS_OPERATION = 21180
    INVALID_EXPORT_REQUEST = 21181
    EXPORT_LIMIT_EXCEEDED = 21182
    FILTER_RANGE_OUT_OF_BOUNDS = 21183
    SESSION_TEMPORARILY_UNAVAILABLE = 21184
    EMPTY_PACKAGE = 21205
    UPLOAD_OR_FINISH_TIMEOUT = 21208
    INVALID_CHARACTER_ENCODING = 21217
    AUTHORIZATION_MISSING = 21301
    AUTHENTICATION_MISSING = 21304
    DECEASED_PERSON_AUTH_METHOD = 21308
    XML_SCHEMA_VALIDATION_FAILED = 21401
    INVALID_FILE_SIZE = 21402
    INVALID_FILE_HASH = 21403
    INPUT_VALIDATION_FAILED = 21405
    SIGNATURE_AUTH_TYPE_CONFLICT = 21406
    INVALID_CONTINUATION_TOKEN = 21418
    UNKNOWN_OR_REVOKED_KEY = 21470
    CSR_DATA_UNAVAILABLE = 25001
    CERTIFICATE_REQUEST_UNAVAILABLE = 25002
    CSR_DATA_MISMATCH = 25003
    INVALID_CSR = 25004
    CERTIFICATE_REQUEST_NOT_FOUND = 25005
    CERTIFICATE_REQUEST_LIMIT_EXCEEDED = 25006
    CERTIFICATE_LIMIT_EXCEEDED = 25007
    CERTIFICATE_NOT_FOUND = 25008
    CERTIFICATE_ALREADY_REVOKED = 25009
    INVALID_KEY_TYPE_OR_LENGTH = 25010
    INVALID_CSR_SIGNATURE_ALGORITHM = 25011
    TOKEN_PERMISSIONS_EXCEED_OWNER = 26001
    TOKEN_NOT_ALLOWED_FOR_CONTEXT = 26002
    PERMISSION_ALREADY_EXISTS = 30001
    COLLECTIVE_INVOICE_NOT_FOUND = 71001
    COLLECTIVE_INVOICE_LIMIT_EXCEEDED = 71002
    INVOICES_HAVE_DIFFERENT_SELLERS = 71004
    DUPLICATE_KSEF_NUMBER = 71005

    @classmethod
    def from_code(cls, value: int) -> KsefExceptionCode | None:
        """Zwraca znany kod albo ``None`` (nie rzuca dla kodów z przyszłych wersji API)."""
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        try:
            return cls(value)
        except ValueError:
            return None


class ForbiddenReason(str, Enum):
    """Wartości ``reasonCode`` z odpowiedzi 403 (KSeF API 2.9.0)."""

    MISSING_PERMISSIONS = "missing-permissions"
    IP_NOT_ALLOWED = "ip-not-allowed"
    INSUFFICIENT_RESOURCE_ACCESS = "insufficient-resource-access"
    AUTH_METHOD_NOT_ALLOWED = "auth-method-not-allowed"
    SECURITY_SERVICE_BLOCKED = "security-service-blocked"
    CONTEXT_TYPE_NOT_ALLOWED = "context-type-not-allowed"


def _problem_value(problem: Any, name: str, raw_key: str | None = None) -> Any:
    """Czyta pole z modelu albo surowego dictu (snake_case i camelCase)."""
    if problem is None:
        return None
    if isinstance(problem, dict):
        if raw_key is not None and raw_key in problem:
            return problem[raw_key]
        return problem.get(name)
    value = getattr(problem, name, None)
    if value is not None:
        return value
    raw = getattr(problem, "raw", None)
    if isinstance(raw, dict):
        if raw_key is not None and raw_key in raw:
            return raw[raw_key]
        return raw.get(name)
    return None


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def exception_codes(problem: Any | None) -> tuple[int, ...]:
    """Wyciąga kody KSeF z obu formatów błędów (bez wyjątków na złym payloadzie).

    Obsługuje ``errors[].code`` (Problem Details) oraz
    ``exception.exceptionDetailList[].exceptionCode`` (format legacy).
    """
    codes: list[int] = []

    def _add(value: Any) -> None:
        # Kontrakt ``code``/``exceptionCode`` to ``int32``. Odrzucamy ``bool``
        # (podklasa ``int``) oraz ``float`` — ``21304.9`` nie może stać się
        # ``21304``. Tekstową liczbę przyjmujemy, tak jak robi to CLI.
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            code = value
        elif isinstance(value, str):
            try:
                code = int(value)
            except ValueError:
                return
        else:
            return
        if code not in codes:
            codes.append(code)

    for item in _sequence(_problem_value(problem, "errors", "errors")):
        _add(_problem_value(item, "code", "code"))

    exception = _problem_value(problem, "exception", "exception")
    for item in _sequence(
        _problem_value(exception, "exception_detail_list", "exceptionDetailList")
    ):
        _add(_problem_value(item, "exception_code", "exceptionCode"))

    return tuple(codes)


def _problem_details(problem: Any | None) -> tuple[str, ...]:
    details: list[str] = []

    def _add(value: Any) -> None:
        if isinstance(value, str) and value and value not in details:
            details.append(value)

    for item in _sequence(_problem_value(problem, "errors", "errors")):
        _add(_problem_value(item, "description", "description"))
        for extra in _sequence(_problem_value(item, "details", "details")):
            _add(extra)

    exception = _problem_value(problem, "exception", "exception")
    for item in _sequence(
        _problem_value(exception, "exception_detail_list", "exceptionDetailList")
    ):
        _add(_problem_value(item, "exception_description", "exceptionDescription"))
        for extra in _sequence(_problem_value(item, "details", "details")):
            _add(extra)

    if not details:
        # Problem Details (np. 5xx/403) często ma tylko ``detail`` — bez tego
        # ``to_dict()`` gubiłby jedyny czytelny opis błędu.
        _add(_problem_value(problem, "detail", "detail"))

    return tuple(details)


def _problem_trace_id(problem: Any | None) -> str | None:
    value = _problem_value(problem, "trace_id", "traceId")
    return str(value) if isinstance(value, str) and value else None


def _problem_reason_code(problem: Any | None) -> str | None:
    value = _problem_value(problem, "reason_code", "reasonCode")
    return str(value) if isinstance(value, str) and value else None


class KsefError(Exception):
    """Bazowy błąd SDK — wspólny dla HTTP, workflow i przyszłych warstw (PDF, MCP)."""

    code: ClassVar[ErrorCode] = ErrorCode.ERROR

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message

    def __reduce__(self) -> tuple[Any, ...]:
        """Zachowuje atrybuty przy ``pickle``/``copy`` (np. ``status_code``)."""
        return (_restore_workflow_error, (type(self), self.__dict__, self.args))

    def to_dict(self, *, omit_none: bool = False) -> dict[str, Any]:
        """Stały, JSON-owy kontrakt błędu dla CLI/MCP (bez surowego ciała odpowiedzi)."""
        payload: dict[str, Any] = {
            "code": self.code.value,
            "message": self.message,
            "status_code": getattr(self, "status_code", None),
            "retry_after": getattr(self, "retry_after", None),
            "ksef_codes": list(getattr(self, "exception_codes", ())),
            "details": list(getattr(self, "details", ())),
            "reason_code": getattr(self, "reason_code", None),
            "trace_id": getattr(self, "trace_id", None),
        }
        if omit_none:
            return {key: value for key, value in payload.items() if value is not None}
        return payload


class KsefResponseLimitError(KsefError):
    """A bounded response was rejected; deterministic and never retried."""

    code = ErrorCode.RESPONSE_LIMIT_EXCEEDED

    def __init__(
        self,
        *,
        limit_bytes: int,
        observed_bytes: int | None = None,
        reason_code: str = "response_size_limit",
    ) -> None:
        super().__init__("Bounded HTTP response rejected")
        self.limit_bytes = limit_bytes
        self.observed_bytes = observed_bytes
        self.reason_code = reason_code


class KsefSyncError(KsefError):
    code = ErrorCode.SYNC_ERROR

    def __init__(self, reason_code: str = "sync_error") -> None:
        super().__init__("Invoice metadata synchronization failed")
        self.reason_code = reason_code


class KsefInvalidSyncCheckpointError(KsefSyncError):
    code = ErrorCode.INVALID_SYNC_CHECKPOINT


class KsefSyncStateError(KsefSyncError):
    code = ErrorCode.SYNC_STATE_ERROR


class KsefSyncConflictError(KsefSyncError):
    code = ErrorCode.SYNC_CONFLICT


class KsefSyncDataConflictError(KsefSyncError):
    code = ErrorCode.SYNC_DATA_CONFLICT


class KsefSyncLimitError(KsefSyncError):
    code = ErrorCode.SYNC_LIMIT_EXCEEDED

    def __init__(
        self, *, limit_stage: str, limit_bytes: int, observed_bytes: int | None = None
    ) -> None:
        if limit_stage not in {"response_body", "page_snapshot", "checkpoint"}:
            raise ValueError("Invalid sync limit stage")
        super().__init__("sync_limit_exceeded")
        self.limit_stage = limit_stage
        self.limit_bytes = limit_bytes
        self.observed_bytes = observed_bytes


class KsefSyncStoreError(KsefSyncError):
    code = ErrorCode.SYNC_STORE_ERROR

    def __init__(
        self,
        *,
        operation: str,
        commit_outcome: str = "not_started",
        failure_scope: str = "stream",
        original_error: BaseException | None = None,
    ) -> None:
        if (
            operation not in {"load", "commit"}
            or commit_outcome not in {"not_started", "rolled_back", "committed", "unknown"}
            or failure_scope not in {"stream", "store"}
            or operation == "load"
            and commit_outcome != "not_started"
        ):
            raise ValueError("Invalid store error attributes")
        super().__init__("store_failure")
        self.operation = operation
        self.commit_outcome = commit_outcome
        self.failure_scope = failure_scope
        self.original_error = original_error


class KsefSyncRunError(KsefSyncError):
    code = ErrorCode.SYNC_RUN_FAILED

    def __init__(self, report: Any) -> None:
        super().__init__("stream_failures")
        self.report = report


class KsefPaginationError(KsefError):
    """Base error for the opt-in resumable metadata search."""

    code = ErrorCode.PAGINATION_ERROR


class KsefInvalidPaginationCursorError(KsefPaginationError):
    """Invalid or incompatible cursor, rejected before HTTP."""

    code = ErrorCode.INVALID_PAGINATION_CURSOR


class KsefIncompletePaginationError(KsefPaginationError):
    """Cannot prove completeness. last_cursor is private replay state."""

    code = ErrorCode.INCOMPLETE_PAGINATION

    def __init__(self, reason_code: str, *, last_cursor: str) -> None:
        super().__init__(f"Incomplete invoice pagination: {reason_code}")
        self.reason_code = reason_code
        self.last_cursor = last_cursor


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


def _restore_workflow_error(
    error_cls: type[KsefError], values: dict[str, Any], args: tuple[Any, ...]
) -> KsefError:
    """Odtwarza błąd workflow bez wołania ``__init__`` (keyword-only argumenty)."""
    error = error_cls.__new__(error_cls)
    error.__dict__.update(values)
    error.args = args
    return error


@dataclass(repr=False)
class KsefHttpError(KsefError):
    code: ClassVar[ErrorCode] = ErrorCode.HTTP_ERROR
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

    def __repr__(self) -> str:
        """Nie pokazuje ``response_body``/``problem`` — mogą zawierać dane biznesowe.

        Repr trafia do logów częściej niż jawny ``to_dict()``; redakcja jest celowa.
        """
        problem_name = type(self.problem).__name__ if self.problem is not None else None
        return (
            f"{type(self).__name__}(status_code={self.status_code!r}, "
            f"message={self.message!r}, problem={problem_name!r})"
        )

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

    @property
    def exception_codes(self) -> tuple[int, ...]:
        """Wszystkie kody KSeF z odpowiedzi (zachowują kolejność, bez duplikatów)."""
        return exception_codes(self.problem)

    @property
    def known_exception_codes(self) -> tuple[KsefExceptionCode, ...]:
        """Kody rozpoznane przez :class:`KsefExceptionCode` (nowe kody API pomijane)."""
        known: list[KsefExceptionCode] = []
        for code in self.exception_codes:
            member = KsefExceptionCode.from_code(code)
            if member is not None:
                known.append(member)
        return tuple(known)

    @property
    def details(self) -> tuple[str, ...]:
        """Opisy błędów przekazane przez KSeF (bez surowego body)."""
        return _problem_details(self.problem)

    @property
    def reason_code(self) -> str | None:
        """Surowy ``reasonCode`` z 403 (także nieznane wartości)."""
        return _problem_reason_code(self.problem)

    @property
    def forbidden_reason(self) -> ForbiddenReason | None:
        """``reasonCode`` jako enum, gdy wartość jest znana."""
        raw = self.reason_code
        if raw is None:
            return None
        try:
            return ForbiddenReason(raw)
        except ValueError:
            return None

    @property
    def trace_id(self) -> str | None:
        return _problem_trace_id(self.problem)


@dataclass(repr=False)
class KsefRateLimitError(KsefHttpError):
    """429 — przekroczony limit tempa.

    ``retry_after``/``retry_after_raw`` dziedziczy z bazy, ale zostają tu argumentami
    pozycyjnymi (tak było przed przeniesieniem pól do ``KsefHttpError``) — nadpisanie
    zmienia wyłącznie sposób przekazywania, nie znaczenie pól.
    """

    code: ClassVar[ErrorCode] = ErrorCode.RATE_LIMITED
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


@dataclass(repr=False)
class KsefApiError(KsefHttpError):
    code: ClassVar[ErrorCode] = ErrorCode.API_ERROR
    exception_response: ExceptionResponse | None = None


class KsefTransportError(KsefHttpError):
    """Błąd transportu (status ``0``) — żądanie nie dotarło do KSeF."""

    code: ClassVar[ErrorCode] = ErrorCode.TRANSPORT_ERROR


class KsefBadRequestError(KsefApiError):
    """400 bez rozpoznanego kodu KSeF."""

    code: ClassVar[ErrorCode] = ErrorCode.BAD_REQUEST


class KsefAuthenticationError(KsefApiError):
    """401 albo 400 z kodami uwierzytelnienia."""

    code: ClassVar[ErrorCode] = ErrorCode.AUTHENTICATION_FAILED


class KsefAuthorizationError(KsefApiError):
    """403 albo 400/``21301`` — brak uprawnień; ``reason_code`` z 403."""

    code: ClassVar[ErrorCode] = ErrorCode.AUTHORIZATION_FAILED


class KsefPermissionError(KsefApiError):
    """Błędy uprawnień i tokenów (26xxx, 30xxx)."""

    code: ClassVar[ErrorCode] = ErrorCode.PERMISSION_ERROR


class KsefCertificateError(KsefApiError):
    """Błędy certyfikatów i CSR (25xxx)."""

    code: ClassVar[ErrorCode] = ErrorCode.CERTIFICATE_ERROR


class KsefValidationError(KsefApiError):
    """Walidacja wejścia lub kodowania (21001, 21217, 21405)."""

    code: ClassVar[ErrorCode] = ErrorCode.VALIDATION_FAILED


class KsefInvoiceRejectedError(KsefApiError):
    """Faktura odrzucona przez walidację pliku (21401–21403)."""

    code: ClassVar[ErrorCode] = ErrorCode.INVOICE_REJECTED


class KsefInvoiceNotFoundError(KsefApiError):
    """Faktura nie istnieje (21164)."""

    code: ClassVar[ErrorCode] = ErrorCode.INVOICE_NOT_FOUND


class KsefInvoiceUnavailableError(KsefApiError):
    """Faktura jeszcze niedostępna albo zablokowana (21165–21167)."""

    code: ClassVar[ErrorCode] = ErrorCode.INVOICE_UNAVAILABLE


class KsefUpoNotFoundError(KsefApiError):
    """Brak UPO dla podanych kryteriów (21175, 21178)."""

    code: ClassVar[ErrorCode] = ErrorCode.UPO_NOT_FOUND


class KsefSessionError(KsefApiError):
    """Błędy sesji (21155, 21157, 21161, 21173, 21180, 21184, 21205, 21208)."""

    code: ClassVar[ErrorCode] = ErrorCode.SESSION_ERROR


class KsefExportError(KsefApiError):
    """Błędy eksportu (21181–21183)."""

    code: ClassVar[ErrorCode] = ErrorCode.EXPORT_ERROR


class KsefCollectiveIdentifierError(KsefApiError):
    """Błędy identyfikatorów zbiorczych (71xxx)."""

    code: ClassVar[ErrorCode] = ErrorCode.COLLECTIVE_IDENTIFIER_ERROR


class KsefInvalidContinuationTokenError(KsefApiError):
    """Nieprawidłowy token kontynuacji (21418)."""

    code: ClassVar[ErrorCode] = ErrorCode.INVALID_CONTINUATION_TOKEN


class KsefResourceGoneError(KsefApiError):
    """410 bez rozpoznanego kodu zasobu."""

    code: ClassVar[ErrorCode] = ErrorCode.NOT_FOUND


class KsefServerError(KsefApiError):
    """Błąd po stronie KSeF (5xx)."""

    code: ClassVar[ErrorCode] = ErrorCode.SERVER_ERROR


class KsefServiceUnavailableError(KsefServerError):
    """502/503/504 — usługa tymczasowo niedostępna."""

    code: ClassVar[ErrorCode] = ErrorCode.SERVICE_UNAVAILABLE


class KsefWorkflowError(KsefError):
    """Błąd lokalnego workflow (bez odpowiedzi HTTP)."""

    code: ClassVar[ErrorCode] = ErrorCode.WORKFLOW_ERROR

    def __init__(self, message: str, *, details: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.details = details


class KsefAuthenticationFailedError(KsefWorkflowError, RuntimeError):
    """Uwierzytelnienie zakończyło się kodem innym niż sukces."""

    code: ClassVar[ErrorCode] = ErrorCode.AUTHENTICATION_FAILED

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        details: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message, details=details)
        self.status_code = status_code


class KsefAuthenticationTimeoutError(KsefWorkflowError, TimeoutError):
    """Polling uwierzytelnienia przekroczył ``max_attempts``."""

    code: ClassVar[ErrorCode] = ErrorCode.AUTHENTICATION_TIMEOUT

    def __init__(self, message: str, *, max_attempts: int) -> None:
        super().__init__(message)
        self.max_attempts = max_attempts


class KsefDocumentError(KsefError):
    """Bazowy błąd lokalnej warstwy dokumentów (bez odpowiedzi HTTP)."""

    code: ClassVar[ErrorCode] = ErrorCode.DOCUMENT_ERROR

    def __init__(self, *args: Any, details: tuple[str, ...] = ()) -> None:
        # Zachowujemy argumenty ValueError, również pustą krotkę i obiekty inne
        # niż str. Kontrakt JSON wymaga tekstowego opisu pierwszego argumentu.
        super().__init__(str(args[0]) if args else "")
        self.args = args
        self.details = tuple(details)

    def __str__(self) -> str:
        return Exception.__str__(self)


class KsefDocumentValidationError(KsefDocumentError, ValueError):
    """Dokument jest niepoprawny składniowo, semantycznie albo względem XSD."""

    code: ClassVar[ErrorCode] = ErrorCode.DOCUMENT_VALIDATION_FAILED


class KsefRenderingError(KsefDocumentError, RuntimeError):
    """Nie udało się wyrenderować dokumentu (HTML/PDF, brak zależności)."""

    code: ClassVar[ErrorCode] = ErrorCode.DOCUMENT_RENDERING_FAILED


class KsefVerificationError(KsefDocumentError, ValueError):
    """Weryfikacja dokumentu/UPO/hasha nie powiodła się."""

    code: ClassVar[ErrorCode] = ErrorCode.VERIFICATION_FAILED


class KsefCheckpointError(KsefDocumentError, RuntimeError):
    """Nie udało się zapisać lub odczytać checkpointu (eksport/wznawianie)."""

    code: ClassVar[ErrorCode] = ErrorCode.CHECKPOINT_FAILED


_AUTHENTICATION_CODES = frozenset(
    {9101, 9102, 9103, 9105, 21111, 21115, 21117, 21304, 21308, 21406, 21470}
)
_AUTHORIZATION_CODES = frozenset({21301})
_PERMISSION_CODES = frozenset({26001, 26002, 30001})
_CERTIFICATE_CODES = frozenset(range(25001, 25012))
_COLLECTIVE_IDENTIFIER_CODES = frozenset({71001, 71002, 71004, 71005})
_EXPORT_CODES = frozenset({21175, 21181, 21182, 21183})
_SESSION_CODES = frozenset({21155, 21157, 21161, 21173, 21180, 21184, 21205, 21208})
_INVOICE_UNAVAILABLE_CODES = frozenset({21165, 21166, 21167})
_INVOICE_NOT_FOUND_CODES = frozenset({21164})
_UPO_NOT_FOUND_CODES = frozenset({21178})
_INVOICE_REJECTED_CODES = frozenset({21402, 21403})
_VALIDATION_CODES = frozenset({21001, 21217, 21405})
_CONTINUATION_TOKEN_CODES = frozenset({21418})

#: Kolejność ma znaczenie: pierwsza rodzina, do której należy którykolwiek kod,
#: wygrywa. Dzięki temu odpowiedź z kilkoma kodami ma deterministyczną klasę.
_CODE_PRIORITY: tuple[tuple[type[KsefApiError], frozenset[int]], ...] = (
    (KsefAuthenticationError, _AUTHENTICATION_CODES),
    (KsefAuthorizationError, _AUTHORIZATION_CODES),
    (KsefPermissionError, _PERMISSION_CODES),
    (KsefCertificateError, _CERTIFICATE_CODES),
    (KsefCollectiveIdentifierError, _COLLECTIVE_IDENTIFIER_CODES),
    (KsefExportError, _EXPORT_CODES),
    (KsefSessionError, _SESSION_CODES),
    (KsefInvoiceUnavailableError, _INVOICE_UNAVAILABLE_CODES),
    (KsefInvoiceNotFoundError, _INVOICE_NOT_FOUND_CODES),
    (KsefUpoNotFoundError, _UPO_NOT_FOUND_CODES),
    (KsefInvoiceRejectedError, _INVOICE_REJECTED_CODES),
    (KsefValidationError, _VALIDATION_CODES),
    (KsefInvalidContinuationTokenError, _CONTINUATION_TOKEN_CODES),
)


def _class_for_codes(codes: tuple[int, ...]) -> type[KsefApiError] | None:
    for error_cls, group in _CODE_PRIORITY:
        if any(code in group for code in codes):
            return error_cls
    return None


def _normalized_path(path: str) -> str:
    """Normalizuje ścieżkę tak jak warstwa HTTP (leading slash, bez query).

    ``"auth/x"`` i ``"/auth/x"`` prowadzą do tego samego URL, więc muszą też
    dawać tę samą klasyfikację błędu.
    """
    if path.startswith(("http://", "https://")):
        return urlparse(path).path or "/"
    return "/" + path.split("?", 1)[0].lstrip("/")


def _is_auth_path(path: str) -> bool:
    normalized = _normalized_path(path)
    return normalized == "/auth" or normalized.startswith("/auth/")


def _is_invoice_path(path: str) -> bool:
    normalized = _normalized_path(path)
    return "/invoices" in normalized or "/sessions" in normalized


def classify_http_error(
    status_code: int, problem: Any | None, *, path: str = ""
) -> type[KsefHttpError]:
    """Dobiera klasę wyjątku do statusu, payloadu i ścieżki żądania.

    ``path`` jest potrzebny dla kodu ``21401`` (niepoprawny dokument XSD), który
    występuje zarówno przy podpisie XAdES w ``/auth/xades-signature``, jak i przy
    fakturach — bez kontekstu nie da się ich rozróżnić.
    """
    codes = exception_codes(problem)

    if status_code == 0:
        return KsefTransportError
    if status_code == 429:
        return KsefRateLimitError
    if status_code == 401:
        return KsefAuthenticationError
    if status_code == 403:
        return KsefAuthorizationError
    if status_code == 410:
        return _class_for_codes(codes) or KsefResourceGoneError
    if status_code == 400:
        if 21401 in codes:
            if _is_auth_path(path):
                return KsefAuthenticationError
            if _is_invoice_path(path):
                return KsefInvoiceRejectedError
            return KsefValidationError
        return _class_for_codes(codes) or KsefBadRequestError
    if status_code in {502, 503, 504}:
        return KsefServiceUnavailableError
    if status_code >= 500:
        return KsefServerError
    if status_code >= 300:
        # Także 3xx z ciałem JSON było wcześniej ``KsefApiError`` — nie zmieniamy
        # tego kontraktu (builder i tak wybiera ``KsefHttpError`` tylko bez body).
        return KsefApiError
    return KsefHttpError


__all__ = [
    "ApiProblem",
    "ErrorCode",
    "ForbiddenReason",
    "KsefApiError",
    "KsefAuthenticationError",
    "KsefAuthenticationFailedError",
    "KsefAuthenticationTimeoutError",
    "KsefAuthorizationError",
    "KsefBadRequestError",
    "KsefCertificateError",
    "KsefCheckpointError",
    "KsefCollectiveIdentifierError",
    "KsefDocumentError",
    "KsefDocumentValidationError",
    "KsefError",
    "KsefExceptionCode",
    "KsefExportError",
    "KsefHttpError",
    "KsefIncompletePaginationError",
    "KsefInvalidContinuationTokenError",
    "KsefInvalidPaginationCursorError",
    "KsefInvalidSyncCheckpointError",
    "KsefInvoiceNotFoundError",
    "KsefInvoiceRejectedError",
    "KsefInvoiceUnavailableError",
    "KsefPaginationError",
    "KsefPermissionError",
    "KsefRateLimitError",
    "KsefRenderingError",
    "KsefResourceGoneError",
    "KsefResponseLimitError",
    "KsefServerError",
    "KsefServiceUnavailableError",
    "KsefSessionError",
    "KsefSyncConflictError",
    "KsefSyncDataConflictError",
    "KsefSyncError",
    "KsefSyncLimitError",
    "KsefSyncRunError",
    "KsefSyncStateError",
    "KsefSyncStoreError",
    "KsefTransportError",
    "KsefUpoNotFoundError",
    "KsefValidationError",
    "KsefVerificationError",
    "KsefWorkflowError",
    "classify_http_error",
    "exception_codes",
]
