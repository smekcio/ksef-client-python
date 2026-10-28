from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import math
import random
import re
import time
from dataclasses import MISSING, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from . import openapi_models as _openapi_models
from ._bounded_http import (
    append_chunk,
    check_control,
    check_headers,
    identity_headers,
    limited_response_stream,
    validate_max_bytes,
)
from ._json_bounds import check_json_structure
from .config import KsefClientOptions
from .exceptions import (
    KsefApiError,
    KsefHttpError,
    KsefRateLimitError,
    KsefTransportError,
    classify_http_error,
)
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
from .rate_limit_routing import canonical_rate_limit_environment, classify_rate_limit_groups
from .rate_limiting import KsefRateLimitWaitTimeout, RateLimitAdmission, RateLimitScope
from .request_control import current_request_control, wait_seconds, wait_seconds_async
from .retry import (
    MAX_RETRY_AFTER_SECONDS,
    RETRYABLE_STATUS_CODES,
    compute_retry_delay_seconds,
    should_retry_request,
)

logger = logging.getLogger(__name__)


def _budget_parameters(
    options: KsefClientOptions, method: str, path: str, *, skip_auth: bool
) -> tuple[RateLimitScope, tuple[str, ...]] | None:
    if options.rate_limit_budget is None:
        return None
    groups = classify_rate_limit_groups(
        method, path, options.normalized_base_url(), skip_auth=skip_auth
    )
    if groups is None:
        return None
    return (
        RateLimitScope(
            environment=canonical_rate_limit_environment(options.normalized_base_url()),
            context_key=options.rate_limit_context_key or "",
            client_ip=options.rate_limit_egress_key,
        ),
        groups,
    )


def _request_url(options: KsefClientOptions, path: str) -> str:
    if _is_absolute_http_url(path):
        return path
    return options.normalized_base_url().rstrip("/") + "/" + path.lstrip("/")


def _wire_timeout(options: KsefClientOptions) -> dict[str, Any]:
    control = current_request_control()
    if control is None:
        return {}
    control.check()
    remaining = control.remaining()
    if remaining is None:
        return {}
    control.check()
    configured = options.timeout_seconds
    return {"timeout": min(configured, remaining) if configured is not None else remaining}


def _budget_retry_after(value: str | None) -> float:
    """Keep the complete server cooldown; individual waits remain cancellable."""
    if value is None or not value.strip():
        return 1.0
    text = value.strip()
    if text.isascii() and text.isdigit():
        seconds = float(text)
    else:
        try:
            until = parsedate_to_datetime(text)
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            seconds = (until - datetime.now(timezone.utc)).total_seconds()
        except (ValueError, TypeError, IndexError, OverflowError):
            return 1.0
    if not math.isfinite(seconds):
        raise KsefRateLimitWaitTimeout("Server cooldown exceeds supported numeric range")
    return max(0.0, seconds)


def _loggable_url(url: str) -> str:
    """Adres do logu diagnostycznego — bez danych dostępowych.

    Pre-signed URL niesie w query podpis i dane dostępowe, więc do logu trafia
    tylko schemat, host, port i ścieżka. Username i hasło z części ``userinfo``
    też są usuwane: ``base_url`` z poświadczeniami nie może wyciec do logu.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return url.split("?", 1)[0].split("#", 1)[0]
    host = parsed.hostname or ""
    if ":" in host:  # IPv6 w nawiasach
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}{parsed.path}"


def _merge_headers(base: dict[str, str], extra: dict[str, str] | None) -> dict[str, str]:
    if not extra:
        return base
    merged = dict(base)
    merged.update(extra)
    return merged


def _without_authorization(headers: dict[str, str]) -> dict[str, str]:
    """Usuwa ``Authorization`` (bez względu na wielkość liter) z nagłówków żądania.

    Przy ``skip_auth=True`` żądanie idzie pod adres pre-signed URL, często na obcy host
    (magazyn plików). Token KSeF podany globalnie w ``custom_headers`` albo w ``headers``
    pojedynczego żądania nie może tam trafić — wcześniej leciał mimo ``skip_auth``.
    """
    return {name: value for name, value in headers.items() if name.lower() != "authorization"}


def _is_absolute_http_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def _is_json_content_type(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


#: Hosty, które wyglądają na adres IP zapisany niekanonicznie (sam licznik, hex,
#: skrócona notacja IPv4). `ipaddress` ich nie parsuje, ale resolvery systemowe
#: potrafią zinterpretować je jako adres — dlatego są odrzucane.
_AMBIGUOUS_NUMERIC_HOST = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\.[0-9]+)*$")


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

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Rejected insecure presigned URL: userinfo is not allowed.")

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

    if host_ip is None and _AMBIGUOUS_NUMERIC_HOST.match(normalized_host):
        # `inet_aton`/glibc rozumieją `2130706433`, `0x7f000001`, `127.1` czy
        # `0177.0.0.1` jako adresy IP, a `ipaddress` ich nie parsuje — host
        # przeszedłby więc obok kontroli loopback/prywatnych adresów.
        raise ValueError(
            "Rejected insecure presigned URL: ambiguous numeric host is not allowed "
            "for skip_auth requests."
        )

    if host_ip is not None:
        # `[::ffff:127.0.0.1]` to technicznie IPv6, którego `is_loopback` jest
        # fałszywe — bez rozwinięcia mapowania reguła loopback dałaby się obejść.
        mapped = getattr(host_ip, "ipv4_mapped", None)
        if mapped is not None:
            host_ip = mapped
        if host_ip.is_loopback:
            raise ValueError(
                "Rejected insecure presigned URL: loopback addresses are not allowed "
                "for skip_auth requests."
            )
        if not options.allow_private_network_presigned_urls and (
            host_ip.is_private or host_ip.is_link_local or host_ip.is_reserved
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


# `MAX_RETRY_AFTER_SECONDS` i `RETRYABLE_STATUS_CODES` mieszkają w `retry.py`
# (wspólne z CLI), a tutaj są importowane i re-eksportowane — istniejące importy
# `from ksef_client.http import MAX_RETRY_AFTER_SECONDS` działają bez zmian.

#: Status dla wyjątków bez odpowiedzi HTTP (błąd transportu, timeout).
#:
#: ``KsefHttpError`` wymaga kodu statusu, a żądanie nie dotarło do serwera, więc nie ma
#: żadnego prawdziwego kodu. ``0`` nie koliduje z kodami HTTP (te zaczynają się od 100),
#: więc wołający odróżni brak odpowiedzi od odpowiedzi 4xx/5xx.
NO_HTTP_STATUS_CODE = 0


def _reject_json_and_data_together(json: dict[str, Any] | None, data: bytes | None) -> None:
    """`json` i `data` wykluczają się — `httpx` cicho wybrałby jedno z nich.

    Wcześniej żądanie z oboma parametrami wysyłało treść `json` (albo `data`,
    zależnie od wersji), więc wołający nie wiedział, co poszło do KSeF.
    """
    if json is not None and data is not None:
        raise ValueError("Pass either json or data, not both")


def _parse_retry_after(value: str | None) -> int | None:
    if value is None:
        return None
    normalized_value = value.strip()
    if not normalized_value:
        return None
    try:
        return max(0, min(int(normalized_value), MAX_RETRY_AFTER_SECONDS))
    except ValueError:
        try:
            retry_after_dt = parsedate_to_datetime(normalized_value)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if retry_after_dt.tzinfo is None:
            retry_after_dt = retry_after_dt.replace(tzinfo=timezone.utc)
        delta_seconds = (retry_after_dt - datetime.now(timezone.utc)).total_seconds()
        return max(0, min(math.ceil(delta_seconds), MAX_RETRY_AFTER_SECONDS))


def _retry_after_fields(response: httpx.Response) -> dict[str, Any]:
    """Pola ``retry_after``/``retry_after_raw`` wyjątku dla statusów ponawialnych.

    KSeF wysyła ``Retry-After`` nie tylko przy 429, ale i przy 502/503/504 (przerwa
    serwisowa, przeciążenie), a CLI ponawia wszystkie te kody. Wcześniej nagłówek był
    czytany wyłącznie dla 429, więc ponowienie po 503 czekało 0,25 s zamiast żądanych
    przez serwer 30 s. Dla pozostałych statusów nie czytamy nagłówka, żeby nie
    sugerować ponowienia tam, gdzie go nie ma.
    """
    if response.status_code not in RETRYABLE_STATUS_CODES:
        return {}
    raw_value = response.headers.get("Retry-After")
    return {"retry_after": _parse_retry_after(raw_value), "retry_after_raw": raw_value}


def _wrap_transport_error(
    exc: httpx.TransportError | httpx.TooManyRedirects, *, method: str, url: str
) -> KsefHttpError:
    """Opakowuje błąd transportu ``httpx`` w wyjątek SDK.

    ``ConnectError``, timeouty i ``RemoteProtocolError`` (oraz ``TooManyRedirects``,
    który nie jest ``TransportError``) uciekały do użytkownika jako surowe wyjątki
    ``httpx``, mimo że biblioteka obiecuje wyjątki ``Ksef*``. Status to
    ``NO_HTTP_STATUS_CODE`` (brak odpowiedzi); surowy oryginał jest wyciszony.
    Komunikat nie zawiera tekstu oryginału; może on nieść podpisane URL-e i sekrety.
    """
    return KsefTransportError(
        status_code=NO_HTTP_STATUS_CODE,
        message=(f"Network error during {method} {_loggable_url(url)}: {type(exc).__name__}"),
    )


def _coerce_problem_status(value: Any, fallback_status: int) -> int:
    # ``bool`` jest podklasą ``int``, ale nie jest poprawnym statusem HTTP.
    # Bez jawnego odrzucenia ``True`` zostałoby zinterpretowane jako status 1.
    if isinstance(value, bool):
        return fallback_status
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
        if expected_type is int and isinstance(body[key], bool):
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

    # `Optional[X]` / `X | None` -> interesuje nas X. Rozwijamy iteracyjnie, bo
    # zdarzają się formy zagnieżdżone (`Optional[Optional[str]]`, `Optional[X | None]`).
    while True:
        stripped = base
        if base.startswith("Optional[") and base.endswith("]"):
            base = base[len("Optional[") : -1].strip()
        if "|" in base:
            parts = [part.strip() for part in base.split("|")]
            inner = [part for part in parts if part != "None"]
            base = inner[0] if inner else "None"
        if base == stripped:
            break

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

    Pola wymagane kontraktu, których API po prostu nie przysyła (``timestamp``,
    ``traceId``, ``instance``), wypełniamy ``None`` — a nie wartością neutralną
    typu. Dzięki temu odbiorca odróżnia „API nie przysłało" od „API przysłało
    pusty string", a ``None`` jest zgodne z adnotacją, bo te pola są opcjonalne
    w modelach Problem Details, mimo że figurują w liście ``required`` OpenAPI.

    Dotyczy to również pól tożsamościowych ``ApiError`` w ``errors[]``: przy braku
    ``description`` wstawiamy ``None`` zamiast ``""``, a przy braku ``code`` —
    ``None`` zamiast ``0``. Fabrykowany kod ``0`` byłby nieodróżnialny od
    prawdziwego kodu błędu KSeF.
    """
    type_map = getattr(model_cls, "__dataclass_fields__", {})
    filled = dict(payload)
    for field_name, model_field in type_map.items():
        json_key = model_field.metadata.get("json_key", field_name)
        if json_key in filled and not _is_missing_value(filled[json_key], json_key):
            continue
        if model_field.default is not MISSING or model_field.default_factory is not MISSING:
            continue
        # Pole opcjonalne w modelu (`Optional[...]`) - brak danych reprezentujemy
        # jako `None`, nie jako pusty string, żeby nie udawać wartości z API.
        # Dotyczy to również pól, które kontrakt oznacza jako wymagane, ale KSeF ich
        # nie przysyła (`timestamp`, `traceId`, `instance`) oraz pól tożsamościowych
        # modeli błędów (`code`, `description`) - patrz `_UNKNOWN_VALUE_KEYS`.
        if (
            _is_optional_annotation(model_field.type)
            or json_key in _ABSENT_AS_EMPTY_KEYS
            or json_key in _UNKNOWN_VALUE_KEYS
        ):
            filled[json_key] = None
            continue
        neutral = _neutral_value(model_field.type)
        if neutral is not None:
            filled[json_key] = neutral
    return filled


def _is_optional_annotation(annotation: Any) -> bool:
    """Czy adnotacja dopuszcza ``None`` (``Optional[X]`` albo ``X | None``)."""
    text = annotation if isinstance(annotation, str) else str(annotation)
    base = text.strip()
    if base.startswith("Optional[") and base.endswith("]"):
        return True
    return any(part.strip() == "None" for part in base.split("|"))


# Pola, które KSeF potrafi przysłać jako pusty string, a które w istocie znaczą
# „brak danych". Tylko dla nich zamieniamy `""` na wartość neutralną; w pozostałych
# polach pusty string jest legalną wartością i nie wolno jej nadpisywać.
_ABSENT_AS_EMPTY_KEYS: frozenset[str] = frozenset({"timestamp", "traceId", "instance"})

# Nazwy typów prostych, które nie są modelami - nie da się z nich zbudować obiektu
# przy naprawie zagnieżdżonych list.
_SCALAR_NAMES: frozenset[str] = frozenset({"str", "int", "float", "bool", "Any"})

# Pola tożsamościowe modeli błędów. Gdy ich brakuje, wstawiamy `None`, a nie
# wartość neutralną typu (`0` / `""`), żeby nie udawać danych z API.
_UNKNOWN_VALUE_KEYS: frozenset[str] = frozenset({"code", "description", "exceptionCode"})


def _is_missing_value(value: Any, json_key: str) -> bool:
    """Czy wartość z payloadu oznacza „pole nieobecne"."""
    if value is None:
        return True
    return value == "" and json_key in _ABSENT_AS_EMPTY_KEYS


def _repair_nested_models(model_cls: type, payload: dict[str, Any]) -> dict[str, Any]:
    """Uzupełnia brakujące pola wymagane we **wnętrznych** modelach listy.

    ``_fill_missing_required_fields`` działa tylko na polach najwyższego poziomu i
    celowo pomija zagnieżdżone modele (nie umie zgadnąć ich wartości). Wystarcza to
    dla ``timestamp``/``traceId``, ale nie dla ``errors[]``: ``errors[].description``
    jest wymagane w kontrakcie, a KSeF potrafi przysłać pozycję z samym ``code``.
    Bez tej naprawy cała odpowiedź 400 degraduje się do ``UnknownApiProblem``,
    czyli dokładnie to, przed czym ten moduł ma chronić.

    Brakujące ``code``/``description`` uzupełniamy ``None``, a nie ``0``/``""``.
    Fabrykowany kod ``0`` byłby nieodróżnialny od prawdziwego, a ``build_problem_hint``
    pokazywałby go użytkownikowi jako realny kod błędu KSeF.
    """
    type_map = getattr(model_cls, "__dataclass_fields__", {})
    repaired = dict(payload)
    for field_name, model_field in type_map.items():
        json_key = model_field.metadata.get("json_key", field_name)
        items = repaired.get(json_key)
        if not isinstance(items, list) or not items:
            continue
        element_cls = _list_element_model(model_field.type)
        if element_cls is None:
            continue
        fixed_items = [
            _fill_missing_required_fields(element_cls, item) if isinstance(item, dict) else item
            for item in items
        ]
        if fixed_items != items:
            repaired[json_key] = fixed_items
    return repaired


def _list_element_model(annotation: Any) -> type | None:
    """Zwraca klasę modelu z adnotacji ``list[X]`` (albo ``None``)."""
    text = annotation if isinstance(annotation, str) else str(annotation)
    base = text.strip()
    while True:
        stripped = base
        if base.startswith("Optional[") and base.endswith("]"):
            base = base[len("Optional[") : -1].strip()
        if "|" in base:
            inner = [part.strip() for part in base.split("|") if part.strip() != "None"]
            base = inner[0] if inner else "None"
        if base == stripped:
            break
    for prefix in ("list[", "List["):
        if base.startswith(prefix) and base.endswith("]"):
            element = base[len(prefix) : -1].strip()
            if "[" in element or "|" in element or element in _SCALAR_NAMES:
                return None
            return _MODEL_REGISTRY.get(element)
    return None


def _from_dict_lenient(model_cls: type, payload: dict[str, Any]) -> Any:
    """Deserializuje payload, tolerując brak pól wymaganych przez kontrakt OpenAPI.

    Najpierw próbujemy wiernie. Dopiero gdy ``from_dict`` zgłosi brakujący argument
    (``TypeError``), uzupełniamy pola najwyższego poziomu, a w drugiej kolejności
    pola wewnątrz list modeli. Drugi krok jest potrzebny, bo ``errors[]`` bywa
    przysyłane bez wymaganego ``description``.
    """
    try:
        return model_cls.from_dict(payload)  # type: ignore[attr-defined]
    except TypeError:
        pass

    filled = _fill_missing_required_fields(model_cls, payload)
    try:
        return model_cls.from_dict(filled)  # type: ignore[attr-defined]
    except TypeError:
        repaired = _repair_nested_models(model_cls, filled)
        if repaired == filled:
            raise
        return model_cls.from_dict(repaired)  # type: ignore[attr-defined]


def _model_registry() -> dict[str, type]:
    """Mapa nazwa modelu -> klasa, do rozwiązywania adnotacji zagnieżdżonych."""
    registry: dict[str, type] = {}
    for name in dir(_openapi_models):
        candidate = getattr(_openapi_models, name)
        if isinstance(candidate, type) and hasattr(candidate, "from_dict"):
            registry[name] = candidate
    return registry


_MODEL_REGISTRY: dict[str, type] = _model_registry()


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
# Pola opcjonalne 401/403 muszą mieć właściwy typ, gdy występują. Bez tego
# `instance: 7` albo `traceId: [1]` trafiały do typowanego atrybutu bez ostrzeżenia,
# bo `_fill_missing_required_fields` pomija pola z wartością domyślną.
_UNAUTHORIZED_OPTIONAL_TYPES: dict[str, type] = {
    "instance": str,
    "traceId": str,
}
_FORBIDDEN_OPTIONAL_TYPES: dict[str, type] = {
    "instance": str,
    "security": dict,
    "timestamp": str,
    "traceId": str,
}
_GONE_OPTIONAL_TYPES: dict[str, type] = {
    "instance": str,
    "traceId": str,
}
_TOO_MANY_REQUESTS_OPTIONAL_TYPES: dict[str, type] = dict(_GONE_OPTIONAL_TYPES)


def _has_valid_error_items(body: dict[str, Any]) -> bool:
    """Sprawdza, czy każdy element ``errors[]`` da się zdeserializować do ``ApiError``.

    ``_has_valid_optional_types`` widzi tylko kontener (``list``), więc
    ``errors=["x"]`` przechodziło i wpisywało goły string w ``list[ApiError]``.
    Wymagamy więc, by każda pozycja była obiektem.
    """
    errors = body.get("errors")
    if errors is None:
        return True
    if not isinstance(errors, list):
        return False
    return all(isinstance(item, dict) for item in errors)


def _attach_raw(problem: Any, body: dict[str, Any]) -> Any:
    """Dołącza surowy payload do obiektu problemu, żeby dało się odczytać kody błędów.

    ``ExceptionResponse`` modeluje wyłącznie ``exception``, więc ``errors[]`` oraz
    ``status``/``title`` z tego samego payloadu przepadają. ``_error_utils`` czyta
    kody właśnie z ``errors[].code`` (jest to bogatsze źródło niż
    ``exceptionDetailList``), a bez zachowanego ``raw`` te kody są nieosiągalne.
    """
    with contextlib.suppress(AttributeError, TypeError):
        object.__setattr__(problem, "raw", body)
    return problem


def _parse_api_problem(status_code: int, body: Any) -> Any | None:
    if not isinstance(body, dict):
        return None

    try:
        if "exception" in body:
            if body["exception"] is None or isinstance(body["exception"], dict):
                return _attach_raw(ExceptionResponse.from_dict(body), body)
            # Obecność wadliwego pola ``exception`` oznacza, że cały payload
            # jest niezgodny z kontraktem. Nie interpretujemy go ponownie jako
            # innego, pozornie poprawnego wariantu Problem Details.
            raise TypeError("exception must be an object or null")
        if (
            status_code == 400
            and _has_required_types(body, _BAD_REQUEST_REQUIRED_TYPES)
            and _has_valid_optional_types(body, _BAD_REQUEST_OPTIONAL_TYPES)
            and _has_valid_error_items(body)
        ):
            return _from_dict_lenient(BadRequestProblemDetails, body)
        if status_code == 429:
            if isinstance(body.get("status"), dict):
                return TooManyRequestsResponse.from_dict(body)
            if _has_required_types(
                body, _TOO_MANY_REQUESTS_REQUIRED_TYPES
            ) and _has_valid_optional_types(body, _TOO_MANY_REQUESTS_OPTIONAL_TYPES):
                return _from_dict_lenient(TooManyRequestsProblemDetails, body)
        if (
            status_code == 410
            and _has_required_types(body, _GONE_REQUIRED_TYPES)
            and _has_valid_optional_types(body, _GONE_OPTIONAL_TYPES)
        ):
            return _from_dict_lenient(GoneProblemDetails, body)
        if (
            status_code == 401
            and _has_required_types(body, _UNAUTHORIZED_REQUIRED_TYPES)
            and _has_valid_optional_types(body, _UNAUTHORIZED_OPTIONAL_TYPES)
        ):
            return _from_dict_lenient(UnauthorizedProblemDetails, body)
        if (
            status_code == 403
            and _has_required_types(body, _FORBIDDEN_REQUIRED_TYPES)
            and _has_valid_optional_types(body, _FORBIDDEN_OPTIONAL_TYPES)
        ):
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


def _build_http_error(
    status_code: int,
    text: str,
    body: Any | None,
    problem: Any | None,
    retry_after_fields: dict[str, Any],
    path: str = "",
) -> KsefHttpError:
    """Buduje wyjątek SDK dla nieoczekiwanego statusu HTTP.

    Zachowuje dotychczasowe ``message`` i pola, ale dobiera klasę z taksonomii.
    """
    if status_code == 429:
        return KsefRateLimitError(
            status_code=status_code,
            message="Too Many Requests",
            response_body=body,
            problem=problem,
            **retry_after_fields,
        )

    if body is None:
        # Brak ciała JSON to najczęściej odpowiedź proxy/pośrednika, a nie kontrakt
        # KSeF — zachowujemy dotychczasową klasę ``KsefHttpError`` (bez ``KsefApiError``),
        # żeby nie zmieniać semantyki istniejących ``except``.
        return KsefHttpError(
            status_code=status_code,
            message=f"HTTP {status_code} error (non-JSON response)",
            response_body=text,
            problem=None,
            **retry_after_fields,
        )

    error_cls = classify_http_error(status_code, problem, path=path)
    if issubclass(error_cls, KsefApiError):
        return error_cls(
            status_code=status_code,
            message="API error",
            response_body=body,
            problem=problem,
            exception_response=problem if isinstance(problem, ExceptionResponse) else None,
            **retry_after_fields,
        )
    return error_cls(
        status_code=status_code,
        message="API error",
        response_body=body,
        problem=problem,
        **retry_after_fields,
    )


@dataclass
class HttpResponse:
    status_code: int
    headers: httpx.Headers = field(repr=False)
    content: bytes = field(repr=False)

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

    @property
    def api_base_url(self) -> str:
        """Read-only effective API target used by this transport."""
        return self._options.normalized_base_url()

    def request_json_limited(
        self, method: str, path: str, *, max_bytes: int, **kwargs: Any
    ) -> HttpResponse:
        validate_max_bytes(max_bytes)
        return self.request(method, path, max_bytes=max_bytes, **kwargs)

    def _received_headers(
        self,
        response: httpx.Response,
        budget_parameters: tuple[RateLimitScope, tuple[str, ...]] | None,
    ) -> None:
        if budget_parameters is not None and response.status_code == 429:
            assert self._options.rate_limit_budget is not None
            self._options.rate_limit_budget.defer(
                *budget_parameters, _budget_retry_after(response.headers.get("Retry-After"))
            )
        _handle_system_warning(self._options, response)

    def _receive_response(
        self, *, budget_parameters: Any, max_bytes: int | None = None, **kwargs: Any
    ) -> httpx.Response:
        if max_bytes is None:
            response = self._client.request(**kwargs)
            self._received_headers(response, budget_parameters)
            return response
        kwargs["headers"] = identity_headers(kwargs["headers"])
        kwargs["follow_redirects"] = False
        check_control()
        with self._client.stream(**kwargs) as response:
            self._received_headers(response, budget_parameters)
            check_headers(response, max_bytes)
            check_control()
            body = bytearray()
            for chunk in response.iter_raw():
                append_chunk(body, chunk, max_bytes)
                check_control()
            check_control()
            return httpx.Response(
                response.status_code, headers=response.headers, content=bytes(body)
            )

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
        max_bytes: int | None = None,
    ) -> HttpResponse:
        """Wykonuje żądanie HTTP, opcjonalnie ponawiając je według ``options.retry``.

        Bez skonfigurowanego ``retry`` zachowanie jest identyczne z wcześniejszym:
        jedno żądanie i wyjątek przy błędzie. Pętla ponawia wyłącznie odpowiedzi
        z ``RETRYABLE_STATUS_CODES`` dla metod z allowlisty (patrz
        :func:`ksef_client.retry.should_retry_request`).

        ``max_bytes=None`` zachowuje zwykły odbiór. Dodatni limit obejmuje każdą
        próbę, wymaga identity encoding i wyłącza przekierowania. Nie przechodzi
        na zagnieżdżone wywołania bez jawnego przekazania argumentu.
        """
        if max_bytes is not None:
            validate_max_bytes(max_bytes)
        # Freeze the limited target before auth, retry or rate-budget waits.
        request_url = _request_url(self._options, path) if max_bytes is not None else None
        config = self._options.retry
        if config is None:
            return self._request_once(
                method,
                path,
                params=params,
                headers=headers,
                json=json,
                data=data,
                access_token=access_token,
                refresh_token=refresh_token,
                skip_auth=skip_auth,
                expected_status=expected_status,
                max_bytes=max_bytes,
                request_url=request_url,
            )

        attempts_limit = config.max_retries + 1
        attempt = 1
        while True:
            try:
                return self._request_once(
                    method,
                    path,
                    params=params,
                    headers=headers,
                    json=json,
                    data=data,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    skip_auth=skip_auth,
                    expected_status=expected_status,
                    max_bytes=max_bytes,
                    request_url=request_url,
                )
            except KsefHttpError as exc:
                if attempt >= attempts_limit or not should_retry_request(
                    method, path, exc.status_code, config
                ):
                    raise
                delay = compute_retry_delay_seconds(
                    attempt,
                    config,
                    retry_after=exc.retry_after_raw,
                    random_value=random.random(),
                )
                logger.debug(
                    "Retry %s %s (attempt %d/%d) in %.2fs after status %d",
                    method,
                    _loggable_url(path),
                    attempt,
                    attempts_limit,
                    delay,
                    exc.status_code,
                )
                wait_seconds(delay, sleep=time.sleep)
                attempt += 1

    def _resolve_request_token(
        self,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> str | None:
        if skip_auth:
            return None
        return refresh_token or access_token or self._access_token

    def _request_token_is_current(
        self,
        token: str | None,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> bool:
        return True

    def _admit_request(
        self,
        method: str,
        path: str,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> tuple[
        str | None, tuple[RateLimitScope, tuple[str, ...]] | None, RateLimitAdmission | None
    ]:
        parameters = _budget_parameters(self._options, method, path, skip_auth=skip_auth)
        while True:
            control = current_request_control()
            if control is not None:
                control.check()
            # A refresh may itself perform HTTP and wait for its own budget.
            # Never hold a business-request admission while refreshing tokens.
            token = self._resolve_request_token(
                access_token=access_token, refresh_token=refresh_token, skip_auth=skip_auth
            )
            if parameters is None:
                return token, None, None
            assert self._options.rate_limit_budget is not None
            admission = self._options.rate_limit_budget.acquire(*parameters, control=control)
            try:
                if self._request_token_is_current(
                    token,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    skip_auth=skip_auth,
                ):
                    return token, parameters, admission
            except BaseException:
                admission.cancel()
                raise
            admission.cancel()

    def _request_once(
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
        max_bytes: int | None = None,
        request_url: str | None = None,
    ) -> HttpResponse:
        _reject_json_and_data_together(json, data)
        url = request_url if request_url is not None else _request_url(self._options, path)
        if skip_auth and _is_absolute_http_url(path):
            _validate_presigned_url_security(self._options, url)

        token, budget_parameters, admission = self._admit_request(
            method,
            path,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
        )
        try:
            base_headers = {
                "User-Agent": self._options.user_agent,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            }
            if json is not None:
                base_headers["Content-Type"] = "application/json"

            if token:
                base_headers["Authorization"] = f"Bearer {token}"

            base_headers = _merge_headers(base_headers, self._options.custom_headers)
            final_headers = _merge_headers(base_headers, headers)
            if skip_auth:
                # Presigned URL idzie na obcy host — token KSeF (także ten z `custom_headers`
                # albo z nagłówków pojedynczego żądania) nie może tam trafić.
                final_headers = _without_authorization(final_headers)

            wire_options = _wire_timeout(self._options)
        except BaseException:
            if admission is not None:
                admission.cancel()
            raise
        if admission is not None:
            admission.commit()
        try:
            response = self._receive_response(
                budget_parameters=budget_parameters,
                max_bytes=max_bytes,
                method=method,
                url=url,
                params=params,
                headers=final_headers,
                json=json,
                content=data,
                # Przy `skip_auth` walidacja bezpieczeństwa dotyczy WYŁĄCZNIE adresu
                # początkowego, a nagłówka `Authorization` i tak nie ma — podążenie za
                # przekierowaniem wykonałoby więc żądanie pod adres wskazany przez
                # serwer (także do sieci wewnętrznej) i zwróciło jego treść jako
                # wynik. Dlatego dla presigned URL przekierowań nie śledzimy
                # niezależnie od `options.follow_redirects`.
                follow_redirects=False if skip_auth else self._options.follow_redirects,
                **wire_options,
            )
        except (httpx.TransportError, httpx.TooManyRedirects) as exc:
            # Błędy sieci i timeouty nie są wyjątkami SDK — opakowujemy je, żeby
            # wołający miał jeden kontrakt błędów (`KsefHttpError`).
            raise _wrap_transport_error(exc, method=method, url=url) from None
        logger.debug("HTTP %s %s -> %s", method, _loggable_url(url), response.status_code)

        if (
            expected_status
            and response.status_code not in expected_status
            or not expected_status
            and response.status_code >= 300
        ):
            # Bez `expected_status` każda odpowiedź spoza 2xx jest błędem —
            # także przekierowanie (3xx). `httpx` nie podąża za przekierowaniami
            # (domyślnie `follow_redirects=False`), więc treścią takiej
            # odpowiedzi jest strona pośrednika albo puste ciało. Przyjmowanie
            # jej jako sukcesu zapisywało PUSTY plik UPO/faktury i raportowało
            # sukces (`upo download` tworzył plik o rozmiarze 0).
            self._raise_for_status(response, path, max_bytes=max_bytes)

        return HttpResponse(response.status_code, response.headers, response.content)

    def _raise_for_status(
        self, response: httpx.Response, path: str = "", *, max_bytes: int | None = None
    ) -> None:
        retry_after_fields = _retry_after_fields(response)
        content_type = response.headers.get("Content-Type", "")
        body: Any = None
        if _is_json_content_type(content_type):
            try:
                if max_bytes is not None:
                    check_json_structure(response.content, max_nodes=500_000, max_depth=32)
                body = response.json()
            except ValueError:
                body = None

        problem = _parse_api_problem(response.status_code, body)
        raise _build_http_error(
            response.status_code,
            response.text,
            body,
            problem,
            retry_after_fields,
            path=path,
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

    @property
    def api_base_url(self) -> str:
        """Read-only effective API target used by this transport."""
        return self._options.normalized_base_url()

    async def request_json_limited(
        self, method: str, path: str, *, max_bytes: int, **kwargs: Any
    ) -> HttpResponse:
        validate_max_bytes(max_bytes)
        return await self.request(method, path, max_bytes=max_bytes, **kwargs)

    def _received_headers(
        self,
        response: httpx.Response,
        budget_parameters: tuple[RateLimitScope, tuple[str, ...]] | None,
    ) -> None:
        if budget_parameters is not None and response.status_code == 429:
            assert self._options.rate_limit_budget is not None
            self._options.rate_limit_budget.defer(
                *budget_parameters, _budget_retry_after(response.headers.get("Retry-After"))
            )
        _handle_system_warning(self._options, response)

    async def _receive_response(
        self, *, budget_parameters: Any, max_bytes: int | None = None, **kwargs: Any
    ) -> httpx.Response:
        if max_bytes is None:
            response = await self._client.request(**kwargs)
            self._received_headers(response, budget_parameters)
            return response
        kwargs["headers"] = identity_headers(kwargs["headers"])
        kwargs["follow_redirects"] = False
        check_control()
        async with limited_response_stream(self._client, **kwargs) as response:
            self._received_headers(response, budget_parameters)
            check_headers(response, max_bytes)
            check_control()
            body = bytearray()
            async for chunk in response.aiter_raw():
                append_chunk(body, chunk, max_bytes)
                check_control()
            check_control()
            return httpx.Response(
                response.status_code, headers=response.headers, content=bytes(body)
            )

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
        max_bytes: int | None = None,
    ) -> HttpResponse:
        """Asynchroniczny odpowiednik :meth:`BaseHttpClient.request`.

        Pętla retry ma identyczną semantykę; różni się wyłącznie ``asyncio.sleep``.
        """
        if max_bytes is not None:
            validate_max_bytes(max_bytes)
        # Freeze the limited target before auth, retry or rate-budget waits.
        request_url = _request_url(self._options, path) if max_bytes is not None else None
        config = self._options.retry
        if config is None:
            return await self._request_once(
                method,
                path,
                params=params,
                headers=headers,
                json=json,
                data=data,
                access_token=access_token,
                refresh_token=refresh_token,
                skip_auth=skip_auth,
                expected_status=expected_status,
                max_bytes=max_bytes,
                request_url=request_url,
            )

        attempts_limit = config.max_retries + 1
        attempt = 1
        while True:
            try:
                return await self._request_once(
                    method,
                    path,
                    params=params,
                    headers=headers,
                    json=json,
                    data=data,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    skip_auth=skip_auth,
                    expected_status=expected_status,
                    max_bytes=max_bytes,
                    request_url=request_url,
                )
            except KsefHttpError as exc:
                if attempt >= attempts_limit or not should_retry_request(
                    method, path, exc.status_code, config
                ):
                    raise
                delay = compute_retry_delay_seconds(
                    attempt,
                    config,
                    retry_after=exc.retry_after_raw,
                    random_value=random.random(),
                )
                logger.debug(
                    "Retry %s %s (attempt %d/%d) in %.2fs after status %d",
                    method,
                    _loggable_url(path),
                    attempt,
                    attempts_limit,
                    delay,
                    exc.status_code,
                )
                await wait_seconds_async(delay, sleep=asyncio.sleep)
                attempt += 1

    async def _resolve_request_token(
        self,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> str | None:
        if skip_auth:
            return None
        return refresh_token or access_token or self._access_token

    async def _request_token_is_current(
        self,
        token: str | None,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> bool:
        return True

    async def _admit_request(
        self,
        method: str,
        path: str,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> tuple[
        str | None, tuple[RateLimitScope, tuple[str, ...]] | None, RateLimitAdmission | None
    ]:
        parameters = _budget_parameters(self._options, method, path, skip_auth=skip_auth)
        while True:
            control = current_request_control()
            if control is not None:
                control.check()
            # A refresh may itself perform HTTP and wait for its own budget.
            # Never hold a business-request admission while refreshing tokens.
            token = await self._resolve_request_token(
                access_token=access_token, refresh_token=refresh_token, skip_auth=skip_auth
            )
            if parameters is None:
                return token, None, None
            assert self._options.rate_limit_budget is not None
            admission = await self._options.rate_limit_budget.acquire_async(
                *parameters, control=control
            )
            try:
                if await self._request_token_is_current(
                    token,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    skip_auth=skip_auth,
                ):
                    return token, parameters, admission
            except BaseException:
                admission.cancel()
                raise
            admission.cancel()

    async def _request_once(
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
        max_bytes: int | None = None,
        request_url: str | None = None,
    ) -> HttpResponse:
        _reject_json_and_data_together(json, data)
        url = request_url if request_url is not None else _request_url(self._options, path)
        if skip_auth and _is_absolute_http_url(path):
            _validate_presigned_url_security(self._options, url)

        token, budget_parameters, admission = await self._admit_request(
            method,
            path,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
        )
        try:
            base_headers = {
                "User-Agent": self._options.user_agent,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            }
            if json is not None:
                base_headers["Content-Type"] = "application/json"

            if token:
                base_headers["Authorization"] = f"Bearer {token}"

            base_headers = _merge_headers(base_headers, self._options.custom_headers)
            final_headers = _merge_headers(base_headers, headers)
            if skip_auth:
                # Patrz `BaseHttpClient.request`: presigned URL idzie na obcy host, więc
                # token KSeF nie może trafić do nagłówków — także z `custom_headers`.
                final_headers = _without_authorization(final_headers)

            wire_options = _wire_timeout(self._options)
        except BaseException:
            if admission is not None:
                admission.cancel()
            raise
        if admission is not None:
            admission.commit()
        try:
            response = await self._receive_response(
                budget_parameters=budget_parameters,
                max_bytes=max_bytes,
                method=method,
                url=url,
                params=params,
                headers=final_headers,
                json=json,
                content=data,
                # Patrz `BaseHttpClient.request`: presigned URL nigdy nie podąża za
                # przekierowaniem, bo walidacja dotyczy tylko adresu początkowego.
                follow_redirects=False if skip_auth else self._options.follow_redirects,
                **wire_options,
            )
        except (httpx.TransportError, httpx.TooManyRedirects) as exc:
            # Patrz `BaseHttpClient.request`: jeden kontrakt błędów także dla sieci.
            raise _wrap_transport_error(exc, method=method, url=url) from None
        logger.debug("HTTP %s %s -> %s", method, _loggable_url(url), response.status_code)

        if (
            expected_status
            and response.status_code not in expected_status
            or not expected_status
            and response.status_code >= 300
        ):
            # Bez `expected_status` każda odpowiedź spoza 2xx jest błędem —
            # także przekierowanie (3xx). `httpx` nie podąża za przekierowaniami
            # (domyślnie `follow_redirects=False`), więc treścią takiej
            # odpowiedzi jest strona pośrednika albo puste ciało. Przyjmowanie
            # jej jako sukcesu zapisywało PUSTY plik UPO/faktury i raportowało
            # sukces (`upo download` tworzył plik o rozmiarze 0).
            self._raise_for_status(response, path, max_bytes=max_bytes)

        return HttpResponse(response.status_code, response.headers, response.content)

    def _raise_for_status(
        self, response: httpx.Response, path: str = "", *, max_bytes: int | None = None
    ) -> None:
        retry_after_fields = _retry_after_fields(response)
        content_type = response.headers.get("Content-Type", "")
        body: Any = None
        if _is_json_content_type(content_type):
            try:
                if max_bytes is not None:
                    check_json_structure(response.content, max_nodes=500_000, max_depth=32)
                body = response.json()
            except ValueError:
                body = None

        problem = _parse_api_problem(response.status_code, body)
        raise _build_http_error(
            response.status_code,
            response.text,
            body,
            problem,
            retry_after_fields,
            path=path,
        )
