from __future__ import annotations

from enum import IntEnum

from ksef_client.exceptions import ErrorCode, KsefError


class ExitCode(IntEnum):
    SUCCESS = 0
    VALIDATION_ERROR = 2
    AUTH_ERROR = 3
    RETRY_EXHAUSTED = 4
    API_ERROR = 5
    CONFIG_ERROR = 6
    CIRCUIT_OPEN = 7
    IO_ERROR = 8

#: Mapowanie kategorii błędu SDK na kod wyjścia CLI.
#:
#: Nieznane kategorie trafiają do ``API_ERROR`` — CLI nie może zakończyć się
#: sukcesem tylko dlatego, że SDK dodało nowy ``ErrorCode``.
_ERROR_EXIT_CODES: dict[ErrorCode, ExitCode] = {
    ErrorCode.ERROR: ExitCode.API_ERROR,
    ErrorCode.HTTP_ERROR: ExitCode.API_ERROR,
    ErrorCode.TRANSPORT_ERROR: ExitCode.API_ERROR,
    ErrorCode.API_ERROR: ExitCode.API_ERROR,
    ErrorCode.BAD_REQUEST: ExitCode.VALIDATION_ERROR,
    ErrorCode.AUTHENTICATION_FAILED: ExitCode.AUTH_ERROR,
    ErrorCode.AUTHORIZATION_FAILED: ExitCode.AUTH_ERROR,
    ErrorCode.PERMISSION_ERROR: ExitCode.API_ERROR,
    ErrorCode.VALIDATION_FAILED: ExitCode.VALIDATION_ERROR,
    ErrorCode.INVOICE_REJECTED: ExitCode.VALIDATION_ERROR,
    ErrorCode.INVOICE_NOT_FOUND: ExitCode.API_ERROR,
    ErrorCode.INVOICE_UNAVAILABLE: ExitCode.API_ERROR,
    ErrorCode.UPO_NOT_FOUND: ExitCode.API_ERROR,
    ErrorCode.SESSION_ERROR: ExitCode.API_ERROR,
    ErrorCode.EXPORT_ERROR: ExitCode.API_ERROR,
    ErrorCode.CERTIFICATE_ERROR: ExitCode.API_ERROR,
    ErrorCode.COLLECTIVE_IDENTIFIER_ERROR: ExitCode.API_ERROR,
    ErrorCode.INVALID_CONTINUATION_TOKEN: ExitCode.VALIDATION_ERROR,
    ErrorCode.RATE_LIMITED: ExitCode.RETRY_EXHAUSTED,
    ErrorCode.SERVER_ERROR: ExitCode.API_ERROR,
    ErrorCode.SERVICE_UNAVAILABLE: ExitCode.API_ERROR,
    ErrorCode.NOT_FOUND: ExitCode.API_ERROR,
    ErrorCode.WORKFLOW_ERROR: ExitCode.API_ERROR,
    ErrorCode.AUTHENTICATION_TIMEOUT: ExitCode.AUTH_ERROR,
    ErrorCode.DOCUMENT_ERROR: ExitCode.API_ERROR,
    ErrorCode.DOCUMENT_VALIDATION_FAILED: ExitCode.VALIDATION_ERROR,
    ErrorCode.DOCUMENT_RENDERING_FAILED: ExitCode.API_ERROR,
    ErrorCode.VERIFICATION_FAILED: ExitCode.VALIDATION_ERROR,
    ErrorCode.CHECKPOINT_FAILED: ExitCode.IO_ERROR,
    ErrorCode.PAGINATION_ERROR: ExitCode.API_ERROR,
    ErrorCode.INVALID_PAGINATION_CURSOR: ExitCode.VALIDATION_ERROR,
    ErrorCode.INCOMPLETE_PAGINATION: ExitCode.API_ERROR,
    ErrorCode.SYNC_ERROR: ExitCode.API_ERROR,
    ErrorCode.INVALID_SYNC_CHECKPOINT: ExitCode.VALIDATION_ERROR,
    ErrorCode.SYNC_STATE_ERROR: ExitCode.VALIDATION_ERROR,
    ErrorCode.SYNC_CONFLICT: ExitCode.API_ERROR,
    ErrorCode.SYNC_DATA_CONFLICT: ExitCode.API_ERROR,
    ErrorCode.SYNC_LIMIT_EXCEEDED: ExitCode.API_ERROR,
    ErrorCode.SYNC_STORE_ERROR: ExitCode.IO_ERROR,
    ErrorCode.SYNC_RUN_FAILED: ExitCode.API_ERROR,
    ErrorCode.RESPONSE_LIMIT_EXCEEDED: ExitCode.API_ERROR,
    ErrorCode.XML_INTEGRITY_ERROR: ExitCode.VALIDATION_ERROR,
    ErrorCode.XML_STORAGE_ERROR: ExitCode.IO_ERROR,
}


def exit_code_for_error(exc: BaseException) -> ExitCode | None:
    """Zwraca kod wyjścia CLI dla błędu SDK albo ``None`` dla obcego wyjątku."""
    if not isinstance(exc, KsefError):
        return None
    return _ERROR_EXIT_CODES.get(exc.code, ExitCode.API_ERROR)
