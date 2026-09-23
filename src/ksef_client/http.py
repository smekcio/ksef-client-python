from __future__ import annotations

import ipaddress
import math
from dataclasses import MISSING, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import KsefClientOptions
from .exceptions import KsefApiError, KsefHttpError, KsefRateLimitError
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


def _merge_headers(base: dict[str, str], extra: dict[str, str] | None) -> dict[str, str]:
    if not extra:
        return base
    merged = dict(base)
    merged.update(extra)
    return merged


def _is_absolute_http_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def _is_json_content_type(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


def _host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    for allowed in allowed_hosts:
        normalized_allowed = allowed.lower().strip().rstrip(".")
        if not normalized_allowed:
            continue
        if normalized_host == normalized_allowed:
            return True
        try:
            ipaddress.ip_address(normalized_allowed)
            continue
        except ValueError:
            pass
        if normalized_host.endswith("." + normalized_allowed):
            return True
    return False


def _validate_presigned_url_security(options: KsefClientOptions, url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("Rejected insecure presigned URL: host is missing.")

    normalized_host = host.lower().rstrip(".")
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        raise ValueError(
            "Rejected insecure presigned URL: localhost hosts are not allowed "
            "for skip_auth requests."
        )

    if options.strict_presigned_url_validation and parsed.scheme != "https":
        raise ValueError(
            "Rejected insecure presigned URL: https is required for skip_auth requests."
        )

    try:
        host_ip = ipaddress.ip_address(normalized_host)
    except ValueError:
        host_ip = None

    if host_ip is not None:
        if host_ip.is_loopback:
            raise ValueError(
                "Rejected insecure presigned URL: loopback addresses are not allowed "
                "for skip_auth requests."
            )
        if (
            not options.allow_private_network_presigned_urls
            and (host_ip.is_private or host_ip.is_link_local or host_ip.is_reserved)
        ):
            raise ValueError(
                "Rejected insecure presigned URL: private, link-local, and reserved "
                "IP hosts are blocked for skip_auth requests."
            )

    if options.allowed_presigned_hosts and not _host_allowed(
        normalized_host, options.allowed_presigned_hosts
    ):
        raise ValueError(
            "Rejected insecure presigned URL: host is not in allowed_presigned_hosts "
            "for skip_auth requests."
        )


def _handle_system_warning(options: KsefClientOptions, response: httpx.Response) -> None:
    warning = response.headers.get("X-System-Warning")
    if not warning or options.system_warning_handler is None:
        return
    options.system_warning_handler(warning)


def _parse_retry_after(value: str | None) -> int | None:
    if value is None:
        return None
    normalized_value = value.strip()
    if not normalized_value:
        return None
    try:
        return int(normalized_value)
    except ValueError:
        try:
            retry_after_dt = parsedate_to_datetime(normalized_value)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if retry_after_dt.tzinfo is None:
            retry_after_dt = retry_after_dt.replace(tzinfo=timezone.utc)
        delta_seconds = (retry_after_dt - datetime.now(timezone.utc)).total_seconds()
        return max(0, math.ceil(delta_seconds))


def _coerce_problem_status(value: Any, fallback_status: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback_status


def _has_required_types(body: dict[str, Any], expected: dict[str, type]) -> bool:
    """Sprawdza typy pól wymaganych, zanim uznamy payload za dany model Problem Details.

    `OpenApiModel.from_dict` nie waliduje typów, więc bez tej kontroli malformed
    odpowiedź (np. `reasonCode` jako lista zamiast string) zostałaby
    zdeserializowana do modelu szczegółowego i nigdy nie trafiłaby do
    `UnknownApiProblem` — czyli surowy payload zostałby ukryty przed użytkownikiem.
    """
    for key, expected_type in expected.items():
        if key not in body:
            return False
        if not isinstance(body[key], expected_type):
            return False
    return True


def _has_valid_optional_types(body: dict[str, Any], expected: dict[str, type]) -> bool:
    """Sprawdza typy pól **opcjonalnych**: brak pola jest OK, zły typ nie.

    Potrzebne dla pól, których KSeF nie zawsze przysyła, ale które po
    deserializacji trafiają do typowanego atrybutu. Bez tego `errors` podane jako
    string zostałoby zamienione na listę pojedynczych znaków i model wyglądałby
    na poprawny, ukrywając malformed payload.
    """
    for key, expected_type in expected.items():
        if key in body and not isinstance(body[key], expected_type):
            return False
    return True


def _neutral_value(annotation: Any) -> Any:
    """Zwraca wartość neutralną dla typu adnotacji pola.

    Adnotacje w modelach generowanych są **tekstowe** (moduł używa
    `from __future__ import annotations`), więc `field.type` to np. `'list[ApiError]'`,
    a nie obiekt typu. Wcześniejsza wersja sprawdzała `"str" in str(annotation)`,
    co dla `'dict[str, Any]'` dawało fałszywe trafienie i wstawiało `""` w pole
    `status`, kończąc się `AttributeError` przy `from_dict`.

    Rozpoznajemy typ po nazwie bazowej, a dla typów parametryzowanych po nazwie
    kontenera — bez parsowania pełnej składni, bo używamy tego wyłącznie do
    wartości zastępczych.
    """
    text = annotation if isinstance(annotation, str) else str(annotation)
    base = text.strip()

    # `Optional[X]` / `X | None` -> interesuje nas X.
    if base.startswith("Optional[") and base.endswith("]"):
        base = base[len("Optional[") : -1].strip()
    if "|" in base:
        parts = [part.strip() for part in base.split("|")]
        inner = [part for part in parts if part != "None"]
        base = inner[0] if inner else "None"

    if base.startswith("list[") or base.startswith("List["):
        return []
    if base.startswith("dict[") or base.startswith("Dict["):
        return {}
    if base.startswith("set[") or base.startswith("Set["):
        return set()
    if base == "str":
        return ""
    if base == "bool":
        return False
    if base in ("int", "float", "Decimal"):
        return 0
    # Nieznany typ (np. zagnieżdżony model) - pomijamy pole, żeby nie wstawić
    # wartości o typie sprzecznym z adnotacją.
    return None


def _fill_missing_required_fields(model_cls: type, payload: dict[str, Any]) -> dict[str, Any]:
    """Uzupełnia brakujące pola wymagane, żeby `from_dict` nie wywalił się na `TypeError`.

    Kontrakt KSeF oznacza `timestamp` i `traceId` jako wymagane w modelach
    Problem Details, ale API nie przysyła ich w każdej odpowiedzi 400/429/410.
    Modele generowane z OpenAPI mają te pola bez wartości domyślnych, więc
    `from_dict` kończy się `TypeError`, `_parse_api_problem` go połyka i poprawna
    odpowiedź degraduje się do `UnknownApiProblem` — użytkownik traci typowane
    `errors[]` i `instance`.

    Brakujące pola uzupełniamy wartościami neutralnymi **tylko w warstwie odczytu
    odpowiedzi**; pliki generowane pozostają wierne kontraktowi. Pola, których nie
    umiemy wypełnić sensownie (`_neutral_value` zwraca `None`), są pomijane, żeby
    nie wstawiać wartości o złym typie.
    """
    type_map = getattr(model_cls, "__dataclass_fields__", {})
    filled = dict(payload)
    for field_name, model_field in type_map.items():
        json_key = model_field.metadata.get("json_key", field_name)
        if json_key in filled:
            continue
        if model_field.default is not MISSING or model_field.default_factory is not MISSING:
            continue
        neutral = _neutral_value(model_field.type)
        if neutral is not None:
            filled[json_key] = neutral
    return filled


def _from_dict_lenient(model_cls: type, payload: dict[str, Any]) -> Any:
    """Deserializuje payload, tolerując brak pól wymaganych przez kontrakt OpenAPI."""
    try:
        return model_cls.from_dict(payload)  # type: ignore[attr-defined]
    except TypeError:
        return model_cls.from_dict(  # type: ignore[attr-defined]
            _fill_missing_required_fields(model_cls, payload)
        )


# Kontrakt KSeF oznacza `traceId`/`timestamp` jako wymagane w modelach Problem Details,
# ale API ich nie zawsze przysyła. Deserializacja do modelu szczegółowego wywala się
# wtedy na brakującym argumencie i poprawna odpowiedź 400/429/410 degraduje się do
# `UnknownApiProblem`, tracąc typowane `errors[]` i `instance`. Dlatego sprawdzamy
# tylko pola faktycznie potrzebne, a nie całą listę `required` z OpenAPI.
#
# `errors` celowo nie jest wymagane: KSeF potrafi zwrócić 400 bez listy błędów
# szczegółowych, a wymaganie tego pola degradowało poprawny response do
# `UnknownApiProblem`. Brakującą listę uzupełnia `_fill_missing_required_fields`.
_BAD_REQUEST_REQUIRED_TYPES: dict[str, type] = {
    "detail": str,
    "status": int,
    "title": str,
}
# `errors` i `instance` nie są wymagane (KSeF potrafi ich nie przysłać), ale gdy
# występują, muszą mieć właściwy typ — inaczej string trafiłby do `list[ApiError]`.
_BAD_REQUEST_OPTIONAL_TYPES: dict[str, type] = {
    "errors": list,
    "instance": str,
}
_GONE_REQUIRED_TYPES: dict[str, type] = {
    "detail": str,
    "instance": str,
    "status": int,
    "title": str,
}
_TOO_MANY_REQUESTS_REQUIRED_TYPES: dict[str, type] = _GONE_REQUIRED_TYPES
_FORBIDDEN_REQUIRED_TYPES: dict[str, type] = {
    "detail": str,
    "reasonCode": str,
    "status": int,
    "title": str,
}
_UNAUTHORIZED_REQUIRED_TYPES: dict[str, type] = {
    "detail": str,
    "status": int,
    "title": str,
}


def _parse_api_problem(status_code: int, body: Any) -> Any | None:
    if not isinstance(body, dict):
        return None

    try:
        if "exception" in body:
            return ExceptionResponse.from_dict(body)
        if status_code == 400 and _has_required_types(
            body, _BAD_REQUEST_REQUIRED_TYPES
        ) and _has_valid_optional_types(body, _BAD_REQUEST_OPTIONAL_TYPES):
            return _from_dict_lenient(BadRequestProblemDetails, body)
        if status_code == 429:
            if isinstance(body.get("status"), dict):
                return TooManyRequestsResponse.from_dict(body)
            if _has_required_types(body, _TOO_MANY_REQUESTS_REQUIRED_TYPES):
                return _from_dict_lenient(TooManyRequestsProblemDetails, body)
        if status_code == 410 and _has_required_types(body, _GONE_REQUIRED_TYPES):
            return _from_dict_lenient(GoneProblemDetails, body)
        if status_code == 401 and _has_required_types(body, _UNAUTHORIZED_REQUIRED_TYPES):
            return _from_dict_lenient(UnauthorizedProblemDetails, body)
        if status_code == 403 and _has_required_types(body, _FORBIDDEN_REQUIRED_TYPES):
            return _from_dict_lenient(ForbiddenProblemDetails, body)
    except (AttributeError, IndexError, TypeError, ValueError, KeyError):
        # `AttributeError`/`IndexError` mogą pojawić się przy nietypowym payloadzie;
        # bez nich wyjątek przeciekłby do użytkownika zamiast degradacji do UnknownApiProblem.
        pass

    if "status" in body or "title" in body or "detail" in body:
        return UnknownApiProblem(
            status=_coerce_problem_status(body.get("status"), status_code),
            title=str(body.get("title", "API error")),
            detail=str(body["detail"]) if body.get("detail") is not None else None,
            raw=body,
        )
    if body:
        return UnknownApiProblem(
            status=status_code,
            title="API error",
            detail=None,
            raw=body,
        )
    return None


@dataclass
class HttpResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes

    def json(self) -> Any:
        return httpx.Response(self.status_code, headers=self.headers, content=self.content).json()


class BaseHttpClient:
    def __init__(
        self,
        options: KsefClientOptions,
        access_token: str | None = None,
    ) -> None:
        self._options = options
        self._access_token = access_token
        self._client = httpx.Client(
            timeout=options.timeout_seconds,
            verify=options.verify_ssl,
            proxy=options.proxy,
            follow_redirects=options.follow_redirects,
        )

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        url = path
        if not _is_absolute_http_url(url):
            url = self._options.normalized_base_url().rstrip("/") + "/" + path.lstrip("/")
        elif skip_auth:
            _validate_presigned_url_security(self._options, url)

        base_headers = {
            "User-Agent": self._options.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if json is not None:
            base_headers["Content-Type"] = "application/json"

        if not skip_auth:
            token = access_token or self._access_token
            if refresh_token:
                token = refresh_token
            if token:
                base_headers["Authorization"] = f"Bearer {token}"

        base_headers = _merge_headers(base_headers, self._options.custom_headers)
        final_headers = _merge_headers(base_headers, headers)

        response = self._client.request(
            method=method,
            url=url,
            params=params,
            headers=final_headers,
            json=json,
            content=data,
        )
        _handle_system_warning(self._options, response)

        if (
            expected_status
            and response.status_code not in expected_status
            or not expected_status
            and response.status_code >= 400
        ):
            self._raise_for_status(response)

        return HttpResponse(response.status_code, response.headers, response.content)

    def _raise_for_status(self, response: httpx.Response) -> None:
        retry_after = response.headers.get("Retry-After")
        content_type = response.headers.get("Content-Type", "")
        body: Any = None
        if _is_json_content_type(content_type):
            try:
                body = response.json()
            except ValueError:
                body = None

        problem = _parse_api_problem(response.status_code, body)

        if response.status_code == 429:
            raise KsefRateLimitError(
                status_code=response.status_code,
                message="Too Many Requests",
                response_body=body,
                problem=problem,
                retry_after=_parse_retry_after(retry_after),
                retry_after_raw=retry_after,
            )

        if body is not None:
            raise KsefApiError(
                status_code=response.status_code,
                message="API error",
                response_body=body,
                problem=problem,
                exception_response=problem if isinstance(problem, ExceptionResponse) else None,
            )

        raise KsefHttpError(
            status_code=response.status_code,
            message=response.text,
            response_body=None,
            problem=None,
        )


class AsyncBaseHttpClient:
    def __init__(
        self,
        options: KsefClientOptions,
        access_token: str | None = None,
    ) -> None:
        self._options = options
        self._access_token = access_token
        self._client = httpx.AsyncClient(
            timeout=options.timeout_seconds,
            verify=options.verify_ssl,
            proxy=options.proxy,
            follow_redirects=options.follow_redirects,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        url = path
        if not _is_absolute_http_url(url):
            url = self._options.normalized_base_url().rstrip("/") + "/" + path.lstrip("/")
        elif skip_auth:
            _validate_presigned_url_security(self._options, url)

        base_headers = {
            "User-Agent": self._options.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if json is not None:
            base_headers["Content-Type"] = "application/json"

        if not skip_auth:
            token = access_token or self._access_token
            if refresh_token:
                token = refresh_token
            if token:
                base_headers["Authorization"] = f"Bearer {token}"

        base_headers = _merge_headers(base_headers, self._options.custom_headers)
        final_headers = _merge_headers(base_headers, headers)

        response = await self._client.request(
            method=method,
            url=url,
            params=params,
            headers=final_headers,
            json=json,
            content=data,
        )
        _handle_system_warning(self._options, response)

        if (
            expected_status
            and response.status_code not in expected_status
            or not expected_status
            and response.status_code >= 400
        ):
            self._raise_for_status(response)

        return HttpResponse(response.status_code, response.headers, response.content)

    def _raise_for_status(self, response: httpx.Response) -> None:
        retry_after = response.headers.get("Retry-After")
        content_type = response.headers.get("Content-Type", "")
        body: Any = None
        if _is_json_content_type(content_type):
            try:
                body = response.json()
            except ValueError:
                body = None

        problem = _parse_api_problem(response.status_code, body)

        if response.status_code == 429:
            raise KsefRateLimitError(
                status_code=response.status_code,
                message="Too Many Requests",
                response_body=body,
                problem=problem,
                retry_after=_parse_retry_after(retry_after),
                retry_after_raw=retry_after,
            )

        if body is not None:
            raise KsefApiError(
                status_code=response.status_code,
                message="API error",
                response_body=body,
                problem=problem,
                exception_response=problem if isinstance(problem, ExceptionResponse) else None,
            )

        raise KsefHttpError(
            status_code=response.status_code,
            message=response.text,
            response_body=None,
            problem=None,
        )
