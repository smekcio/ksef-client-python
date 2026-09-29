from __future__ import annotations

from typing import Any

from ksef_client.exceptions import KsefApiError, KsefRateLimitError
from ksef_client.utils.naming import to_snake_case

# Podpowiedzi dla kodów błędów wymagających konkretnego działania użytkownika.
_EXCEPTION_CODE_HINTS: dict[int, str] = {
    21155: (
        "Sesja osiągnęła limit liczby faktur. Zamknij sesję i wyślij pozostałe "
        "faktury w nowej sesji."
    ),
    21173: (
        "Nie znaleziono sesji o wskazanym numerze referencyjnym. Sprawdź numer "
        "albo otwórz nową sesję."
    ),
    21180: (
        "Status sesji nie pozwala na wysyłkę faktur. Zamknij sesję i otwórz nową, "
        "aby kontynuować."
    ),
    21184: (
        "Sesja jest tymczasowo niedostępna. Spróbuj ponownie później; jeśli błąd "
        "się utrzymuje, otwórz nową sesję i wyślij pozostałe faktury (KSeF API 2.8.0)."
    ),
    21418: (
        "Token kontynuacji jest nieprawidłowy. Pobierz listę od początku "
        "(bez tokenu kontynuacji)."
    ),
    71004: (
        "Faktury należą do różnych sprzedawców. Identyfikator zbiorczy może "
        "grupować faktury tylko jednego sprzedawcy."
    ),
    71005: (
        "W żądaniu powtórzono numer KSeF. Usuń duplikaty z listy faktur."
    ),
}


def _to_codes(candidates: list[Any]) -> list[int]:
    """Zamienia surowe wartości na unikalne kody, zachowując kolejność.

    Akceptujemy ``int`` oraz zapis tekstowy liczby (API potrafi przysłać kod jako
    string). Odrzucamy ``bool`` — jest podklasą ``int``, więc ``True`` dałoby kod
    ``1`` — oraz ``float``, bo ucinałby część ułamkową. Kontrakt typuje
    ``code``/``exceptionCode`` jako ``int32``.
    """
    codes: list[int] = []
    seen: set[int] = set()
    for value in candidates:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            code = value
        elif isinstance(value, str):
            try:
                code = int(value)
            except ValueError:
                continue
        else:
            continue
        # Błąd wsadowy może zawierać wiele pozycji z tym samym kodem; bez deduplikacji
        # ta sama podpowiedź powtarzałaby się w komunikacie wielokrotnie.
        if code in seen:
            continue
        seen.add(code)
        codes.append(code)
    return codes


def _extract_exception_codes(problem: Any) -> list[int]:
    """Wyciąga kody błędów KSeF z odpowiedzi.

    Obsługuje oba kształty zwracane przez API:

    - styl wyjątkowy: ``exception.exceptionDetailList[].exceptionCode``,
    - styl Problem Details (400/429/410): ``errors[].code``.

    Kolejność źródeł jest hierarchią, ale **rozstrzyganą po wyekstrahowanych
    kodach**, nie po surowej liście kandydatów. ``exceptionCode`` jest w kontrakcie
    opcjonalny, więc obecność ``exceptionDetailList`` bez kodów nie może przesłaniać
    poprawnych kodów z ``errors[]``.
    """
    if problem is None:
        return []

    def _collect_detail_list(items: Any, key: str) -> list[Any]:
        collected: list[Any] = []
        if not isinstance(items, list):
            return collected
        for item in items:
            if isinstance(item, dict):
                collected.append(item.get(key))
            else:
                collected.append(getattr(item, to_snake_case(key), None))
        return collected

    exception = getattr(problem, "exception", None)
    exception_codes: list[Any] = []
    if exception is not None:
        exception_codes = _collect_detail_list(
            getattr(exception, "exception_detail_list", None), "exceptionCode"
        )

    raw = getattr(problem, "raw", None)
    raw_exception_codes: list[Any] = []
    raw_error_codes: list[Any] = []
    if isinstance(raw, dict):
        exception_raw = raw.get("exception")
        if isinstance(exception_raw, dict):
            raw_exception_codes = _collect_detail_list(
                exception_raw.get("exceptionDetailList"), "exceptionCode"
            )
        raw_error_codes = _collect_detail_list(raw.get("errors"), "code")

    typed_error_codes = _collect_detail_list(getattr(problem, "errors", None), "code")

    # `errors[]` jest bogatszym źródłem niż `exceptionDetailList` (unikalne kody
    # per pozycja), więc ma pierwszeństwo. Scalamy oba zbiory, gdy oba niosą kody —
    # wtedy nic nie ginie, a deduplikacja pilnuje powtórzeń.
    primary = _to_codes(typed_error_codes) or _to_codes(raw_error_codes)
    if primary:
        merged = list(primary)
        seen = set(primary)
        # Letni `errors[]` mógł zostać nierozłożony (np. brak `description`),
        # a wtedy kody siedzą wyłącznie w surowym payloadzie.
        for candidates in (exception_codes, raw_exception_codes):
            for code in _to_codes(candidates):
                if code not in seen:
                    seen.add(code)
                    merged.append(code)
        return merged

    combined: list[int] = []
    seen = set()
    for candidates in (exception_codes, raw_exception_codes):
        for code in _to_codes(candidates):
            if code not in seen:
                seen.add(code)
                combined.append(code)
    return combined


def _problem_value(problem: Any, attr_name: str, *, raw_key: str | None = None) -> Any:
    value = getattr(problem, attr_name, None)
    if value is not None:
        return value
    raw = getattr(problem, "raw", None)
    if raw_key and isinstance(raw, dict):
        return raw.get(raw_key)
    return None


def _format_problem_errors(errors: Any) -> str | None:
    if not isinstance(errors, list) or not errors:
        return None

    items: list[str] = []
    for error in errors[:3]:
        code = getattr(error, "code", None)
        description = getattr(error, "description", None)
        details = getattr(error, "details", None)
        parts: list[str] = []
        if code is not None:
            parts.append(str(code))
        if description:
            parts.append(str(description))
        if isinstance(details, list) and details:
            parts.append("; ".join(str(item) for item in details))
        if parts:
            items.append(" - ".join(parts))

    if not items:
        return None
    return " | ".join(items)


def build_problem_hint(problem: Any | None, *, default_hint: str | None) -> str | None:
    if problem is None:
        return default_hint

    parts: list[str] = []

    detail = _problem_value(problem, "detail")
    if detail:
        parts.append(f"Detail: {detail}")

    reason_code = _problem_value(problem, "reason_code", raw_key="reasonCode")
    if reason_code:
        parts.append(f"Reason: {reason_code}")

    rendered_errors = _format_problem_errors(_problem_value(problem, "errors"))
    if rendered_errors:
        parts.append(f"Errors: {rendered_errors}")

    trace_id = _problem_value(problem, "trace_id", raw_key="traceId")
    if trace_id:
        parts.append(f"Trace ID: {trace_id}")

    instance = _problem_value(problem, "instance")
    if instance:
        parts.append(f"Instance: {instance}")

    for code in _extract_exception_codes(problem):
        hint = _EXCEPTION_CODE_HINTS.get(code)
        if hint:
            parts.append(f"[{code}] {hint}")

    if default_hint:
        parts.append(default_hint)

    return "\n".join(parts) if parts else default_hint


def build_api_error_hint(exc: KsefApiError, *, default_hint: str) -> str:
    return build_problem_hint(exc.problem, default_hint=default_hint) or default_hint


def build_rate_limit_hint(exc: KsefRateLimitError, *, default_hint: str) -> str:
    retry_hint = f"Retry-After: {exc.retry_after}" if exc.retry_after else default_hint
    return build_problem_hint(exc.problem, default_hint=retry_hint) or retry_hint
