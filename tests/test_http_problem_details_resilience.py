"""Odporność warstwy błędów HTTP na odpowiedzi niezgodne z kontraktem.

Kontrakt KSeF oznacza `timestamp` i `traceId` jako wymagane w modelach Problem
Details, ale API ich nie zawsze przysyła. Modele generowane z OpenAPI mają te
pola bez wartości domyślnych, więc bez zabezpieczenia w `http.py` poprawna
odpowiedź 400/429/410 degraduje się do `UnknownApiProblem` i użytkownik traci
typowe `errors[]` oraz `instance`.
"""

from __future__ import annotations

import httpx
import pytest

from ksef_client.config import KsefClientOptions
from ksef_client.http import BaseHttpClient
from ksef_client.models import (
    BadRequestProblemDetails,
    ForbiddenProblemDetails,
    GoneProblemDetails,
    TooManyRequestsProblemDetails,
    UnauthorizedProblemDetails,
    UnknownApiProblem,
)


@pytest.fixture
def client() -> BaseHttpClient:
    return BaseHttpClient(KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl"))


def _problem(client: BaseHttpClient, status: int, payload: dict) -> object:
    response = httpx.Response(status, json=payload)
    with pytest.raises(Exception) as ctx:
        client._raise_for_status(response)
    return getattr(ctx.value, "problem", None)


# --- Poprawne odpowiedzi bez pól oznaczonych w OpenAPI jako wymagane ---


def test_bad_request_without_trace_fields_stays_typed(client: BaseHttpClient) -> None:
    problem = _problem(
        client,
        400,
        {
            "title": "Bad Request",
            "status": 400,
            "detail": "Blad walidacji",
            "errors": [{"code": 21405, "description": "Blad walidacji danych"}],
            "instance": "/sessions/online",
        },
    )
    assert isinstance(problem, BadRequestProblemDetails)
    assert [error.code for error in problem.errors] == [21405]


def test_too_many_requests_without_trace_fields_stays_typed(
    client: BaseHttpClient,
) -> None:
    problem = _problem(
        client,
        429,
        {
            "title": "Too Many Requests",
            "status": 429,
            "detail": "Limit",
            "instance": "/rate-limits",
        },
    )
    assert isinstance(problem, TooManyRequestsProblemDetails)


def test_gone_without_trace_fields_stays_typed(client: BaseHttpClient) -> None:
    problem = _problem(
        client,
        410,
        {
            "title": "Gone",
            "status": 410,
            "detail": "Wygaslo",
            "instance": "/sessions/online/ref",
        },
    )
    assert isinstance(problem, GoneProblemDetails)


def test_unauthorized_without_timestamp_stays_typed(client: BaseHttpClient) -> None:
    problem = _problem(
        client, 401, {"title": "Unauthorized", "status": 401, "detail": "Brak tokena"}
    )
    assert isinstance(problem, UnauthorizedProblemDetails)


def test_forbidden_without_optional_fields_stays_typed(client: BaseHttpClient) -> None:
    problem = _problem(
        client,
        403,
        {"title": "Forbidden", "status": 403, "detail": "Brak uprawnien", "reasonCode": "x"},
    )
    assert isinstance(problem, ForbiddenProblemDetails)


# --- Payloady niezgodne z kontraktem nadal degraduja sie bezpiecznie ---


@pytest.mark.parametrize(
    ("status", "payload"),
    [
        (
            400,
            {
                "title": "B",
                "status": 400,
                "detail": "d",
                "errors": "nie-lista",
                "instance": "/x",
            },
        ),
        (403, {"title": "F", "status": 403, "detail": "d", "reasonCode": ["lista"]}),
        (410, {"title": "G", "status": 410, "detail": "d"}),
        (401, {"title": "U", "status": "oops", "detail": "d"}),
    ],
)
def test_malformed_payload_falls_back_to_unknown_with_raw(
    client: BaseHttpClient, status: int, payload: dict
) -> None:
    problem = _problem(client, status, payload)
    assert isinstance(problem, UnknownApiProblem)
    assert problem.raw == payload


def test_exception_style_response_is_preferred(client: BaseHttpClient) -> None:
    """Styl wyjatkowy nie wymaga uzupelniania pol i nadal dziala."""
    problem = _problem(
        client,
        400,
        {
            "exception": {
                "serviceCode": "00-1E",
                "serviceName": "Sesja",
                "exceptionDetailList": [
                    {"exceptionCode": 21184, "exceptionDescription": "Niedostepna"}
                ],
            }
        },
    )
    assert type(problem).__name__ == "ExceptionResponse"


# --- Brak pol opcjonalnych nie moze degradowac odpowiedzi (KSeF ich nie zawsze wysyla) ---


@pytest.mark.parametrize(
    "payload",
    [
        {"title": "B", "status": 400, "detail": "d", "instance": "/x"},
        {"title": "B", "status": 400, "detail": "d"},
    ],
)
def test_bad_request_without_errors_is_still_typed(
    client: BaseHttpClient, payload: dict
) -> None:
    """KSeF potrafi zwrocic 400 bez `errors`; brak listy nie moze degradowac modelu."""
    problem = _problem(client, 400, payload)
    assert isinstance(problem, BadRequestProblemDetails)
    assert problem.errors == []


def test_bad_request_missing_fields_are_filled_with_correct_types(
    client: BaseHttpClient,
) -> None:
    """Uzupelnione pola musza miec typy zgodne z adnotacjami, nie tylko "jakiekolwiek"."""
    problem = _problem(client, 400, {"title": "B", "status": 400, "detail": "d"})

    assert isinstance(problem, BadRequestProblemDetails)
    assert isinstance(problem.errors, list)
    assert isinstance(problem.instance, str)
    assert isinstance(problem.timestamp, str)
    assert isinstance(problem.trace_id, str)
    # `errors` musi byc iterowalne - zla wartosc zastępcza lamie to na int.
    assert list(problem.errors) == []


def test_bad_request_with_errors_as_string_stays_unknown(client: BaseHttpClient) -> None:
    """Malformed `errors` nie moze byc rozbity na liste znakow i udawac poprawny model."""
    payload = {
        "title": "B",
        "status": 400,
        "detail": "d",
        "errors": "nie-lista",
        "instance": "/x",
    }
    problem = _problem(client, 400, payload)

    assert isinstance(problem, UnknownApiProblem)
    assert problem.raw == payload


def test_neutral_value_matches_annotation_type() -> None:
    """`dict[str, Any]` nie moze byc rozpoznane jako `str` (podlancuch w adnotacji)."""
    from ksef_client.http import _neutral_value

    assert _neutral_value("str") == ""
    assert _neutral_value("int") == 0
    assert _neutral_value("bool") is False
    assert _neutral_value("list[ApiError]") == []
    assert _neutral_value("dict[str, Any]") == {}
    assert _neutral_value("Optional[str]") == ""
    assert _neutral_value("Optional[list[ApiError]]") == []
    assert _neutral_value("str | None") == ""
    # Nieznany typ zagniezdzonego modelu nie jest zgadywany.
    assert _neutral_value("ApiError") is None


@pytest.mark.parametrize(
    ("annotation", "expected"),
    [
        ("Optional[Optional[str]]", ""),
        ("Optional[Optional[int]]", 0),
        ("Optional[Optional[list[ApiError]]]", []),
        ("Optional[str | None]", ""),
        ("Optional[dict[str, str | None]]", {}),
        ("list[str | None]", []),
        ("dict[str, str | None]", {}),
        ("Optional[Optional[Optional[bool]]]", False),
    ],
)
def test_neutral_value_unwraps_nested_optional(annotation: str, expected: object) -> None:
    """Zagnieżdżone `Optional`/`| None` muszą być rozwijane, nie kończyć jako `None`."""
    from ksef_client.http import _neutral_value

    assert _neutral_value(annotation) == expected


def test_neutral_value_terminates_for_unknown_types() -> None:
    """Rozwijanie nie może się zapętlić na nietypowych adnotacjach."""
    from ksef_client.http import _neutral_value

    for annotation in ["None", "Any", "object", "ApiError", "tuple[int, str]", ""]:
        assert _neutral_value(annotation) is None
