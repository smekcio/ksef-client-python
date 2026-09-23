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
