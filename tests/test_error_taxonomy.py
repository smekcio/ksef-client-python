from __future__ import annotations

import copy
import json
import pickle
import re
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from ksef_client.cli.exit_codes import ExitCode, exit_code_for_error
from ksef_client.config import KsefClientOptions
from ksef_client.exceptions import (
    ErrorCode,
    ForbiddenReason,
    KsefApiError,
    KsefAuthenticationError,
    KsefAuthenticationFailedError,
    KsefAuthenticationTimeoutError,
    KsefAuthorizationError,
    KsefBadRequestError,
    KsefCertificateError,
    KsefCollectiveIdentifierError,
    KsefError,
    KsefExceptionCode,
    KsefExportError,
    KsefHttpError,
    KsefInvalidContinuationTokenError,
    KsefInvoiceNotFoundError,
    KsefInvoiceRejectedError,
    KsefInvoiceUnavailableError,
    KsefPermissionError,
    KsefRateLimitError,
    KsefResourceGoneError,
    KsefServerError,
    KsefServiceUnavailableError,
    KsefSessionError,
    KsefTransportError,
    KsefUpoNotFoundError,
    KsefValidationError,
    classify_http_error,
    exception_codes,
)
from ksef_client.http import BaseHttpClient
from ksef_client.models import (
    AuthenticationOperationStatusResponse,
    BadRequestProblemDetails,
    ExceptionResponse,
    ForbiddenProblemDetails,
    StatusInfo,
    UnknownApiProblem,
)
from ksef_client.retry import RetryConfig
from ksef_client.services.workflows import AsyncAuthCoordinator, AuthCoordinator


def _legacy_problem(*codes: int, description: str = "Opis błędu") -> ExceptionResponse:
    return ExceptionResponse.from_dict(
        {
            "exception": {
                "exceptionDetailList": [
                    {
                        "exceptionCode": code,
                        "exceptionDescription": description,
                        "details": [f"szczegół {code}"],
                    }
                    for code in codes
                ]
            }
        }
    )


def _bad_request_problem(*codes: int) -> BadRequestProblemDetails:
    return BadRequestProblemDetails.from_dict(
        {
            "detail": "validation failed",
            "errors": [
                {"code": code, "description": f"błąd {code}", "details": ["x"]}
                for code in codes
            ],
            "instance": "/invoices",
            "status": 400,
            "timestamp": "2026-10-23T10:00:00Z",
            "title": "Bad Request",
            "traceId": "trace-1",
        }
    )


def _forbidden_problem(reason: str = "missing-permissions") -> ForbiddenProblemDetails:
    return ForbiddenProblemDetails.from_dict(
        {
            "detail": "brak uprawnień",
            "reasonCode": reason,
            "status": 403,
            "title": "Forbidden",
            "traceId": "trace-2",
        }
    )


class _FakeAuth:
    def __init__(self, code: int, details: list[str] | None = None) -> None:
        self.code = code
        self.details = details

    def get_auth_status(
        self, reference_number: str, authentication_token: str
    ) -> AuthenticationOperationStatusResponse:
        return AuthenticationOperationStatusResponse(
            status=StatusInfo(
                code=self.code,
                description="status",
                details=self.details,
            )
        )


class _FakeAsyncAuth:
    def __init__(self, code: int, details: list[str] | None = None) -> None:
        self.code = code
        self.details = details

    async def get_auth_status(
        self, reference_number: str, authentication_token: str
    ) -> AuthenticationOperationStatusResponse:
        return AuthenticationOperationStatusResponse(
            status=StatusInfo(
                code=self.code,
                description="status",
                details=self.details,
            )
        )


# --- enumy -----------------------------------------------------------------


SNAPSHOT_PATH = (
    Path(__file__).resolve().parents[1] / "specs" / "ksef-openapi.snapshot.json"
)


def _snapshot_exception_codes() -> set[int]:
    """Kody z tabel ``ExceptionCode`` w snapshocie (≥9000 odsiewa inne tabele)."""
    text = SNAPSHOT_PATH.read_text(encoding="utf-8")
    codes = {int(match.group(1)) for match in re.finditer(r"\|\s*(\d{4,5})\s*\|", text)}
    return {code for code in codes if code >= 9000}


def test_exception_code_enum_matches_spec_catalog() -> None:
    assert {member.value for member in KsefExceptionCode} == _snapshot_exception_codes()
    assert KsefExceptionCode.from_code(21405) is KsefExceptionCode.INPUT_VALIDATION_FAILED
    assert KsefExceptionCode.from_code(99999) is None
    assert KsefExceptionCode.from_code(9105) is KsefExceptionCode.INVALID_SIGNATURE


def test_error_codes_and_forbidden_reasons_are_stable() -> None:
    assert {member.value for member in ErrorCode} == {
        "error",
        "http_error",
        "transport_error",
        "api_error",
        "bad_request",
        "authentication_failed",
        "authorization_failed",
        "permission_error",
        "validation_failed",
        "invoice_rejected",
        "invoice_not_found",
        "invoice_unavailable",
        "upo_not_found",
        "session_error",
        "export_error",
        "certificate_error",
        "collective_identifier_error",
        "invalid_continuation_token",
        "rate_limited",
        "server_error",
        "service_unavailable",
        "not_found",
        "workflow_error",
        "authentication_timeout",
    }
    assert {member.value for member in ForbiddenReason} == {
        "missing-permissions",
        "ip-not-allowed",
        "insufficient-resource-access",
        "auth-method-not-allowed",
        "security-service-blocked",
        "context-type-not-allowed",
    }
    assert str(ErrorCode.VALIDATION_FAILED) == "validation_failed"


# --- klasyfikacja ----------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "problem", "expected"),
    [
        (0, None, KsefTransportError),
        (429, None, KsefRateLimitError),
        (401, None, KsefAuthenticationError),
        (403, _forbidden_problem(), KsefAuthorizationError),
        (410, None, KsefResourceGoneError),
        (410, _legacy_problem(21164), KsefInvoiceNotFoundError),
        (400, None, KsefBadRequestError),
        (400, _legacy_problem(21111), KsefAuthenticationError),
        (400, _legacy_problem(21301), KsefAuthorizationError),
        (400, _legacy_problem(30001), KsefPermissionError),
        (400, _legacy_problem(25004), KsefCertificateError),
        (400, _legacy_problem(71001), KsefCollectiveIdentifierError),
        (400, _legacy_problem(21181), KsefExportError),
        (400, _legacy_problem(21155), KsefSessionError),
        (400, _legacy_problem(21165), KsefInvoiceUnavailableError),
        (400, _legacy_problem(21164), KsefInvoiceNotFoundError),
        (400, _legacy_problem(21175), KsefExportError),
        (400, _legacy_problem(21178), KsefUpoNotFoundError),
        (400, _legacy_problem(9105), KsefAuthenticationError),
        (400, _legacy_problem(21401), KsefValidationError),
        (400, _legacy_problem(21405), KsefValidationError),
        (400, _legacy_problem(21418), KsefInvalidContinuationTokenError),
        (400, _legacy_problem(99999), KsefBadRequestError),
        (400, _bad_request_problem(21405), KsefValidationError),
        (500, None, KsefServerError),
        (501, None, KsefServerError),
        (502, None, KsefServiceUnavailableError),
        (503, None, KsefServiceUnavailableError),
        (504, None, KsefServiceUnavailableError),
        (505, None, KsefServerError),
        (499, None, KsefApiError),
        (302, None, KsefApiError),
        (200, None, KsefHttpError),
        (400, UnknownApiProblem(status=400, title="x"), KsefBadRequestError),
    ],
)
def test_classify_http_error(
    status: int, problem: object, expected: type[KsefHttpError]
) -> None:
    assert classify_http_error(status, problem) is expected


def test_21401_classification_depends_on_request_path() -> None:
    problem = _legacy_problem(21401)

    assert (
        classify_http_error(400, problem, path="/auth/xades-signature")
        is KsefAuthenticationError
    )
    assert (
        classify_http_error(400, problem, path="/invoices/ksef/123")
        is KsefInvoiceRejectedError
    )
    assert (
        classify_http_error(400, problem, path="/sessions/online")
        is KsefInvoiceRejectedError
    )
    assert classify_http_error(400, problem) is KsefValidationError


def test_http_error_defaults_to_http_error_code() -> None:
    error = KsefHttpError(500, "boom")

    assert error.code is ErrorCode.HTTP_ERROR
    assert error.to_dict()["code"] == "http_error"


def test_overflowing_error_code_does_not_break_retry() -> None:
    payload = b'{"errors":[{"code": 1e309, "description": "x"}]}'
    response = httpx.Response(
        503,
        content=payload,
        headers={"Content-Type": "application/json"},
    )
    client = BaseHttpClient(
        KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            retry=RetryConfig(max_retries=1),
        )
    )
    request = Mock(return_value=response)

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep"),pytest.raises(KsefHttpError) as excinfo
    ):
        client.request("GET", "/x")

    assert isinstance(excinfo.value, KsefServiceUnavailableError)
    assert request.call_count == 2


def test_classification_precedence_is_deterministic() -> None:
    # certyfikat ma pierwszeństwo przed walidacją
    assert classify_http_error(400, _legacy_problem(21405, 25004)) is KsefCertificateError
    # uwierzytelnienie ma pierwszeństwo przed walidacją
    assert classify_http_error(400, _legacy_problem(21405, 21111)) is KsefAuthenticationError


def test_exception_codes_support_both_payload_formats() -> None:
    assert exception_codes(_legacy_problem(21405, 25004)) == (21405, 25004)
    assert exception_codes(_bad_request_problem(21405)) == (21405,)
    assert exception_codes({"errors": [{"code": 21405}, {"code": 21405}]}) == (21405,)
    assert exception_codes(
        {"exception": {"exceptionDetailList": [{"exceptionCode": 25004}]}}
    ) == (25004,)
    assert exception_codes(None) == ()
    assert exception_codes({"errors": [{"code": "x"}, {"code": True}]}) == ()
    assert exception_codes({"errors": [{"code": float("inf")}]}) == ()


# --- właściwości i to_dict -------------------------------------------------


def test_api_error_properties() -> None:
    error = KsefValidationError(
        status_code=400,
        message="API error",
        problem=_bad_request_problem(21405),
    )

    assert error.exception_codes == (21405,)
    assert error.known_exception_codes == (KsefExceptionCode.INPUT_VALIDATION_FAILED,)
    assert error.details == ("błąd 21405", "x")
    assert error.trace_id == "trace-1"
    assert error.reason_code is None
    assert error.forbidden_reason is None


def test_forbidden_properties_and_unknown_reason() -> None:
    known = KsefAuthorizationError(
        status_code=403,
        message="API error",
        problem=_forbidden_problem("ip-not-allowed"),
    )
    unknown = KsefAuthorizationError(
        status_code=403,
        message="API error",
        problem=_forbidden_problem("future-reason"),
    )

    assert known.reason_code == "ip-not-allowed"
    assert known.forbidden_reason is ForbiddenReason.IP_NOT_ALLOWED
    assert unknown.reason_code == "future-reason"
    assert unknown.forbidden_reason is None


def test_details_from_legacy_exception_payload() -> None:
    error = KsefApiError(
        status_code=400,
        message="API error",
        problem=_legacy_problem(21405, description="Niepoprawne dane"),
    )

    assert error.details == ("Niepoprawne dane", "szczegół 21405")
    assert error.known_exception_codes == (KsefExceptionCode.INPUT_VALIDATION_FAILED,)


def test_every_known_exception_code_has_a_specific_class() -> None:
    for member in KsefExceptionCode:
        error_cls = classify_http_error(400, _legacy_problem(member.value))
        assert error_cls is not KsefBadRequestError, member
        assert error_cls is not KsefApiError, member


def test_repr_never_contains_response_body() -> None:
    secret = "SECRET-TOKEN-123"
    error = KsefValidationError(
        status_code=400,
        message="API error",
        response_body={"accessToken": secret},
    )

    text = repr(error)

    assert secret not in text
    assert "response_body" not in text
    assert "problem=" in text


def test_to_dict_never_contains_response_body() -> None:
    secret = "SECRET-TOKEN-123"
    error = KsefValidationError(
        status_code=400,
        message="API error",
        response_body={"accessToken": secret},
    )

    payload = error.to_dict()

    assert "response_body" not in payload
    assert secret not in json.dumps(payload)


def test_details_fall_back_to_problem_detail() -> None:
    problem = UnknownApiProblem(
        status=500,
        title="Service Unavailable",
        detail="maintenance window",
    )
    error = KsefServerError(
        status_code=500,
        message="API error",
        problem=problem,
    )

    assert error.details == ("maintenance window",)
    assert error.to_dict()["details"] == ["maintenance window"]


def test_to_dict_is_stable_and_json_serializable() -> None:
    error = KsefValidationError(
        status_code=400,
        message="API error",
        problem=_bad_request_problem(21405),
        retry_after=None,
    )

    payload = error.to_dict()

    assert payload == {
        "code": "validation_failed",
        "message": "API error",
        "status_code": 400,
        "retry_after": None,
        "ksef_codes": [21405],
        "details": ["błąd 21405", "x"],
        "reason_code": None,
        "trace_id": "trace-1",
    }
    assert "response_body" not in payload
    assert json.loads(json.dumps(payload)) == payload
    assert set(error.to_dict(omit_none=True)) == {
        "code",
        "message",
        "status_code",
        "ksef_codes",
        "details",
        "trace_id",
    }


def test_to_dict_for_rate_limit_and_workflow_errors() -> None:
    rate_limit = KsefRateLimitError(
        status_code=429,
        message="Too Many Requests",
        problem=_legacy_problem(21418),
        retry_after=30,
        retry_after_raw="30",
    )
    assert rate_limit.to_dict()["code"] == "rate_limited"
    assert rate_limit.to_dict()["retry_after"] == 30
    assert rate_limit.exception_codes == (21418,)
    assert rate_limit.to_dict()["ksef_codes"] == [21418]

    failed = KsefAuthenticationFailedError("auth failed", status_code=400)
    assert failed.to_dict()["code"] == "authentication_failed"
    assert failed.to_dict()["status_code"] == 400

    timeout = KsefAuthenticationTimeoutError("timeout", max_attempts=5)
    assert timeout.to_dict()["code"] == "authentication_timeout"
    assert timeout.max_attempts == 5


# --- serializacja ----------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        KsefTransportError(0, "network"),
        KsefValidationError(400, "API error", problem=_bad_request_problem(21405)),
        KsefAuthorizationError(403, "API error", problem=_forbidden_problem()),
        KsefRateLimitError(429, "Too Many Requests", retry_after=5, retry_after_raw="5"),
        KsefAuthenticationFailedError("auth", status_code=400, details=("x",)),
        KsefAuthenticationTimeoutError("timeout", max_attempts=1),
    ],
)
def test_errors_survive_pickle_and_copy(error: KsefError) -> None:
    restored_errors = (
        pickle.loads(pickle.dumps(error)),
        copy.copy(error),
        copy.deepcopy(error),
    )
    for restored in restored_errors:
        assert type(restored) is type(error)
        assert isinstance(restored, KsefError)
        assert restored.to_dict() == error.to_dict()


# --- workflow auth ---------------------------------------------------------


def test_auth_failure_raises_domain_error() -> None:
    coordinator = AuthCoordinator(_FakeAuth(400, details=["zły token"]))  # type: ignore[arg-type]

    with pytest.raises(KsefAuthenticationFailedError) as excinfo:
        coordinator._poll_auth_status("ref", "token", 0.0, 1)

    error = excinfo.value
    assert isinstance(error, RuntimeError)
    assert isinstance(error, KsefError)
    assert error.status_code == 400
    assert error.details == ("zły token",)
    assert "Authentication failed" in str(error)


def test_auth_timeout_raises_domain_error() -> None:
    coordinator = AuthCoordinator(_FakeAuth(100))  # type: ignore[arg-type]

    with pytest.raises(KsefAuthenticationTimeoutError) as excinfo:
        coordinator._poll_auth_status("ref", "token", 0.0, 1)

    assert isinstance(excinfo.value, TimeoutError)
    assert excinfo.value.max_attempts == 1


def test_async_auth_failure_and_timeout_raise_domain_errors() -> None:
    import asyncio

    async def scenario() -> None:
        failed = AsyncAuthCoordinator(_FakeAsyncAuth(400))  # type: ignore[arg-type]
        with pytest.raises(KsefAuthenticationFailedError) as excinfo:
            await failed._poll_auth_status("ref", "token", 0.0, 1)
        assert excinfo.value.status_code == 400

        timed_out = AsyncAuthCoordinator(_FakeAsyncAuth(100))  # type: ignore[arg-type]
        with pytest.raises(KsefAuthenticationTimeoutError):
            await timed_out._poll_auth_status("ref", "token", 0.0, 1)

    asyncio.run(scenario())


# --- CLI -------------------------------------------------------------------


def test_exit_code_for_error_covers_every_error_code() -> None:
    expected = {
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
    }

    for code, exit_code in expected.items():
        error_cls = type("_Error", (KsefError,), {"code": code})
        error = error_cls("x")
        assert exit_code_for_error(error) is exit_code

    assert exit_code_for_error(ValueError("x")) is None


def test_errors_keep_legacy_base_classes() -> None:
    validation = KsefValidationError(400, "API error")
    service = KsefServiceUnavailableError(503, "API error")
    rate_limit = KsefRateLimitError(429, "Too Many Requests")

    assert isinstance(validation, KsefApiError)
    assert isinstance(validation, KsefHttpError)
    assert isinstance(service, KsefApiError)
    assert isinstance(service, KsefHttpError)
    assert isinstance(rate_limit, KsefHttpError)
    assert not isinstance(rate_limit, KsefApiError)


def test_unexpected_success_status_with_body_stays_http_error() -> None:
    client = BaseHttpClient(
        KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    )
    response = httpx.Response(200, json={"detail": "unexpected"})

    with pytest.raises(KsefHttpError) as excinfo:
        client._raise_for_status(response)

    assert not isinstance(excinfo.value, KsefApiError)
    assert excinfo.value.message == "API error"


def test_redirect_with_json_body_stays_api_error() -> None:
    client = BaseHttpClient(
        KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    )
    response = httpx.Response(302, json={"detail": "redirect"})

    with pytest.raises(KsefApiError) as excinfo:
        client._raise_for_status(response)

    assert excinfo.value.message == "API error"
