from __future__ import annotations

from typing import Any

from ksef_client.exceptions import KsefApiError, KsefRateLimitError
from ksef_client.utils.naming import to_snake_case

# Podpowiedzi dla kodów błędów wymagających konkretnego działania użytkownika.
_EXCEPTION_CODE_HINTS: dict[int, str] = {
    21184: (
        "Sesja jest tymczasowo niedostępna. Otwórz nową sesję i kontynuuj wysyłkę "
        "pozostałych faktur (KSeF API 2.8.0)."
    ),
}


def _extract_exception_codes(problem: Any) -> list[int]:
    """Wyciąga kody błędów KSeF z odpowiedzi.

    Obsługuje oba kształty zwracane przez API:

    - styl wyjątkowy: ``exception.exceptionDetailList[].exceptionCode``,
    - styl Problem Details (400/429/410): ``errors[].code``.
    """
    if problem is None:
        return []

    candidates: list[Any] = []

    def _collect_detail_list(items: Any, key: str) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if isinstance(item, dict):
                candidates.append(item.get(key))
            else:
                candidates.append(getattr(item, to_snake_case(key), None))

    exception = getattr(problem, "exception", None)
    if exception is not None:
        _collect_detail_list(
            getattr(exception, "exception_detail_list", None), "exceptionCode"
        )
    if not candidates:
        _collect_detail_list(getattr(problem, "errors", None), "code")

    raw = getattr(problem, "raw", None)
    if isinstance(raw, dict):
        exception_raw = raw.get("exception")
        if isinstance(exception_raw, dict):
            _collect_detail_list(exception_raw.get("exceptionDetailList"), "exceptionCode")
        if not candidates:
            _collect_detail_list(raw.get("errors"), "code")

    codes: list[int] = []
    seen: set[int] = set()
    for value in candidates:
        try:
            code = int(value)
        except (TypeError, ValueError):
            continue
        # Błąd wsadowy może zawierać wiele pozycji z tym samym kodem; bez deduplikacji
        # ta sama podpowiedź powtarzałaby się w komunikacie wielokrotnie.
        if code in seen:
            continue
        seen.add(code)
        codes.append(code)
    return codes


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
