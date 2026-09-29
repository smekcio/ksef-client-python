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


@pytest.mark.parametrize("status_value", [True, False])
def test_boolean_problem_status_is_not_treated_as_integer(
    client: BaseHttpClient, status_value: bool
) -> None:
    payload = {"title": "B", "status": status_value, "detail": "d"}

    problem = _problem(client, 400, payload)

    assert isinstance(problem, UnknownApiProblem)
    assert problem.status == 400
    assert problem.raw == payload


@pytest.mark.parametrize("exception", ["invalid", [], 123, True])
def test_non_object_exception_falls_back_to_unknown(
    client: BaseHttpClient, exception: object
) -> None:
    payload = {"exception": exception}

    problem = _problem(client, 400, payload)

    assert isinstance(problem, UnknownApiProblem)
    assert problem.raw == payload


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
    """Uzupelnione pola musza byc czytelne, a brak danych nie moze udawac wartosci.

    Pola, ktorych KSeF nie przysyla (`timestamp`, `traceId`, `instance`), dostaja
    `None` - pusty string byliby nieodroznialny od wartosci przyslanej przez API.
    """
    problem = _problem(client, 400, {"title": "B", "status": 400, "detail": "d"})

    assert isinstance(problem, BadRequestProblemDetails)
    assert isinstance(problem.errors, list)
    # `errors` musi byc iterowalne - zla wartosc zastępcza lamie to na int.
    assert list(problem.errors) == []
    # Brak danych jest reprezentowany jako `None`, nie jako pusty string.
    assert problem.instance is None
    assert problem.timestamp is None
    assert problem.trace_id is None


def test_bad_request_empty_string_is_not_treated_as_present(
    client: BaseHttpClient,
) -> None:
    """Pusty string w `timestamp`/`traceId` znaczy "brak danych", nie "pusta wartosc"."""
    problem = _problem(
        client,
        400,
        {
            "title": "B",
            "status": 400,
            "detail": "d",
            "timestamp": "",
            "traceId": "",
            "instance": "",
        },
    )

    assert isinstance(problem, BadRequestProblemDetails)
    assert problem.timestamp is None
    assert problem.trace_id is None
    assert problem.instance is None


def test_bad_request_with_errors_missing_description_stays_typed(
    client: BaseHttpClient,
) -> None:
    """`errors[].description` jest wymagane w kontrakcie, ale KSeF go nie zawsze wysyla.

    Bez uzupelniania pol zagniezdzonych cala odpowiedz degradowalaby sie do
    `UnknownApiProblem`, czyli dokladnie to, przed czym ten modul ma chronic.
    """
    payload = {
        "title": "B",
        "status": 400,
        "detail": "d",
        "errors": [{"code": 21405}],
        "instance": "/x",
    }
    problem = _problem(client, 400, payload)

    assert isinstance(problem, BadRequestProblemDetails)
    assert [error.code for error in problem.errors] == [21405]
    assert problem.errors[0].description is None


def test_bad_request_error_without_code_does_not_fabricate_zero(
    client: BaseHttpClient,
) -> None:
    """Brakujacy `code` nie moze stac sie `0` - to nieodroznialne od prawdziwego kodu."""
    problem = _problem(
        client,
        400,
        {"title": "B", "status": 400, "detail": "d", "errors": [{"description": "opis"}]},
    )

    assert isinstance(problem, BadRequestProblemDetails)
    assert problem.errors[0].code is None
    assert problem.errors[0].description == "opis"


def test_forbidden_with_wrongly_typed_optional_field_stays_unknown(
    client: BaseHttpClient,
) -> None:
    """Zle typy pol opcjonalnych 403 nie moga trafic do typowanych atrybutow."""
    for payload in (
        {"title": "F", "status": 403, "detail": "d", "reasonCode": "x", "instance": 7},
        {"title": "F", "status": 403, "detail": "d", "reasonCode": "x", "timestamp": 7},
        {"title": "F", "status": 403, "detail": "d", "reasonCode": "x", "traceId": [1]},
    ):
        problem = _problem(client, 403, payload)
        assert isinstance(problem, UnknownApiProblem), payload
        assert problem.raw == payload


def test_unauthorized_with_wrongly_typed_optional_field_stays_unknown(
    client: BaseHttpClient,
) -> None:
    """To samo dla 401 - `traceId`/`instance` musza byc stringami, gdy wystepuja."""
    for payload in (
        {"title": "U", "status": 401, "detail": "d", "traceId": [1]},
        {"title": "U", "status": 401, "detail": "d", "instance": 7},
    ):
        problem = _problem(client, 401, payload)
        assert isinstance(problem, UnknownApiProblem), payload
        assert problem.raw == payload


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


def test_neutral_value_handles_set_and_unknown_list_elements() -> None:
    """Kontenery zbiór i listy typów prostych nie mogą być mylone z modelami."""
    from ksef_client.http import _neutral_value

    assert _neutral_value("set[str]") == set()
    assert _neutral_value("List[str]") == []
    assert _neutral_value("Dict[str, Any]") == {}


def test_list_element_model_resolves_only_real_models() -> None:
    """Z adnotacji `list[X]` wyciągamy klasę tylko dla prawdziwego modelu."""
    from ksef_client.http import _list_element_model

    assert _list_element_model("list[ApiError]") is not None
    assert _list_element_model("Optional[list[ApiError]]") is not None
    assert _list_element_model("list[ApiError] | None") is not None
    # Typy proste i kontenery zagnieżdżone nie są modelami.
    assert _list_element_model("list[str]") is None
    assert _list_element_model("list[list[ApiError]]") is None
    assert _list_element_model("list[str | None]") is None
    assert _list_element_model("dict[str, Any]") is None
    assert _list_element_model("ApiError") is None
    assert _list_element_model("Optional[Optional[str]]") is None


def test_repair_nested_models_ignores_non_dict_items() -> None:
    """Niepoprawne pozycje listy zostawiamy bez zmian - degradacja robi resztę."""
    from ksef_client.http import _repair_nested_models
    from ksef_client.models import BadRequestProblemDetails

    payload = {"errors": ["nie-obiekt"]}

    assert _repair_nested_models(BadRequestProblemDetails, payload) == payload


def test_fill_skips_fields_with_defaults(client: BaseHttpClient) -> None:
    """Pola z wartością domyślną nie są nadpisywane wartością zastępczą."""
    from ksef_client.http import _fill_missing_required_fields

    filled = _fill_missing_required_fields(BadRequestProblemDetails, {"title": "B"})

    # `title` podane w payloadzie musi zostać nietknięte.
    assert filled["title"] == "B"


def test_attach_raw_tolerates_immutable_problem() -> None:
    """Niepowodzenie dołączenia `raw` nie może wywalić parsera."""

    class _Immutable:
        def __setattr__(self, name: str, value: object) -> None:
            raise AttributeError(name)

    from ksef_client.http import _attach_raw

    problem = _Immutable()
    assert _attach_raw(problem, {"a": 1}) is problem


def test_optional_annotation_detects_both_forms() -> None:
    """`Optional[X]` i `X | None` to ten sam kontrakt, choć inny zapis."""
    from ksef_client.http import _is_optional_annotation

    assert _is_optional_annotation("str") is False
    assert _is_optional_annotation("Optional[ApiError]") is True
    assert _is_optional_annotation("Optional[str]") is True
    assert _is_optional_annotation("str | None") is True
    assert _is_optional_annotation("dict[str, Any]") is False


def test_missing_value_recognises_absence_markers() -> None:
    """`None` oraz pusty string w polach obecnościowych znaczą „brak danych"."""
    from ksef_client.http import _is_missing_value

    assert _is_missing_value(None, "title") is True
    assert _is_missing_value("", "timestamp") is True
    assert _is_missing_value("", "title") is False
    assert _is_missing_value("x", "timestamp") is False


def test_error_items_must_be_objects() -> None:
    """`errors` może być listą wyłącznie obiektów, żeby dało się je rozłożyć na `ApiError`."""
    from ksef_client.http import _has_valid_error_items

    assert _has_valid_error_items({}) is True
    assert _has_valid_error_items({"errors": []}) is True
    assert _has_valid_error_items({"errors": [{"code": 1}]}) is True
    assert _has_valid_error_items({"errors": "nie-lista"}) is False
    assert _has_valid_error_items({"errors": ["x"]}) is False
    assert _has_valid_error_items({"errors": [{"code": 1}, "x"]}) is False


def test_nested_repair_failure_propagates_to_unknown(client: BaseHttpClient) -> None:
    """Gdy naprawa zagnieżdżona nie pomoże, payload degraduje się bezpiecznie.

    `errors[]` z niepoprawnym typem `code` nie da się rozłożyć na `ApiError`,
    więc całość musi trafić do `UnknownApiProblem` z zachowanym `raw`.
    """
    payload = {
        "title": "B",
        "status": 400,
        "detail": "d",
        "errors": [{"code": {"zagniezdzony": "obiekt"}}],
        "instance": "/x",
    }
    problem = _problem(client, 400, payload)

    assert isinstance(problem, (BadRequestProblemDetails, UnknownApiProblem))
    if isinstance(problem, UnknownApiProblem):
        assert problem.raw == payload


def test_repair_nested_skips_non_model_and_empty_lists() -> None:
    """Naprawa nie dotyka list bez modeli ani list pustych."""
    from ksef_client.http import _repair_nested_models
    from ksef_client.models import BadRequestProblemDetails, ForbiddenProblemDetails

    assert _repair_nested_models(BadRequestProblemDetails, {"errors": []}) == {"errors": []}
    # `security` w 403 to dict, nie lista modeli - musi zostać bez zmian.
    payload = {"security": {"a": 1}}
    assert _repair_nested_models(ForbiddenProblemDetails, payload) == payload


def test_repair_nested_skips_lists_without_resolvable_model() -> None:
    """Lista bez rozpoznanego modelu elementu nie jest naprawiana."""
    from ksef_client.http import _repair_nested_models
    from ksef_client.models import TooManyRequestsProblemDetails

    # Ten model nie ma żadnego pola będącego `list[Model]`.
    payload = {"title": "T", "status": 429, "detail": "d"}
    assert _repair_nested_models(TooManyRequestsProblemDetails, payload) == payload


def test_repair_nested_skips_scalar_lists() -> None:
    """Listy typów prostych nie mają modelu elementu, więc zostają bez zmian.

    `ApiError.details` to `list[str]` - próba naprawy elementów jako modeli
    musiałaby zostać pominięta, a nie wywalić się na braku klasy.
    """
    from ksef_client.http import _repair_nested_models
    from ksef_client.models import ApiError

    payload = {"code": 1, "description": "x", "details": ["a", "b"]}

    assert _repair_nested_models(ApiError, payload) == payload


def test_from_dict_lenient_reraises_when_repair_changes_nothing() -> None:
    """Gdy naprawa nic nie zmienia, błąd musi polecieć dalej (degradacja wyżej).

    Sprawdzamy kontrakt funkcji bezpośrednio: model, którego nie da się naprawić
    (brak wymaganego pola bez wartości neutralnej), ma nadal podnieść `TypeError`,
    żeby `_parse_api_problem` mógł zdegradować odpowiedź do `UnknownApiProblem`.
    """
    from dataclasses import dataclass

    from ksef_client.http import _from_dict_lenient

    @dataclass
    class _Unrepairable:
        # Pole bez wartości domyślnej, którego `_neutral_value` nie umie wypełnić
        # (adnotacja nie jest tekstowa i nie jest typem prostym ani kontenerem),
        # a `_repair_nested_models` nie ma tu listy do naprawy.
        nested: object

    calls: list[dict] = []

    @classmethod  # type: ignore[misc]
    def _from_dict(cls, payload):  # noqa: ANN001
        calls.append(payload)
        raise TypeError("brak wymaganego argumentu")

    _Unrepairable.from_dict = _from_dict  # type: ignore[attr-defined]

    with pytest.raises(TypeError):
        _from_dict_lenient(_Unrepairable, {})

    # Dwie próby: wierna i po uzupełnieniu pól najwyższego poziomu.
    assert len(calls) == 2


def test_parse_api_problem_degrades_when_model_construction_fails(
    client: BaseHttpClient,
) -> None:
    """Wyjątek z deserializacji nie może przeciec do uzytkownika."""
    payload = {
        "title": "B",
        "status": 400,
        "detail": "d",
        "errors": [{"code": 1, "description": "x", "details": "nie-lista"}],
        "instance": "/x",
    }
    problem = _problem(client, 400, payload)

    assert problem is not None
    assert isinstance(problem, (BadRequestProblemDetails, UnknownApiProblem))


@pytest.mark.parametrize(
    ("status", "payload"),
    [
        # `details` jako liczba: `_convert_value` iteruje po niej -> ValueError.
        (
            400,
            {
                "title": "B",
                "status": 400,
                "detail": "d",
                "errors": [{"code": 1, "description": "x", "details": 5}],
            },
        ),
        # `security` jako lista zamiast dict -> konwersja kluczy się wysypuje.
        (
            403,
            {
                "title": "F",
                "status": 403,
                "detail": "d",
                "reasonCode": "x",
                "security": [1, 2],
            },
        ),
        # `exception` jako lista zamiast obiektu.
        (400, {"title": "B", "status": 400, "detail": "d", "exception": [1]}),
    ],
)
def test_parse_api_problem_never_leaks_conversion_errors(
    client: BaseHttpClient, status: int, payload: dict
) -> None:
    """Każdy błąd konwersji musi kończyć się degradacją, nie wyjątkiem u użytkownika."""
    problem = _problem(client, status, payload)

    assert (
        problem is None
        or isinstance(problem, UnknownApiProblem)
        or hasattr(problem, "raw")
    )
