from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..utils.datetime_parsing import try_parse_api_datetime


def _get_value(
    payload: Any,
    attr_name: str,
    json_name: str | None = None,
    default: Any = None,
) -> Any:
    if isinstance(payload, dict):
        return payload.get(json_name or attr_name, default)
    return getattr(payload, attr_name, default)


def _get_invoices(payload: Any) -> list[Any]:
    invoices = _get_value(payload, "invoices", default=None)
    if isinstance(invoices, list):
        return invoices
    if isinstance(payload, dict):
        invoice_list = payload.get("invoiceList")
        if isinstance(invoice_list, list):
            return invoice_list
    return []


def _get_direct_last_permanent_storage_date(payload: Any) -> str | None:
    direct_value = _get_value(payload, "last_permanent_storage_date", "lastPermanentStorageDate")
    if not direct_value:
        return None
    return str(direct_value)


def _permanent_storage_date_sort_key(value: str) -> tuple[datetime, str]:
    """Klucz sortowania po RZECZYWISTYM czasie, nie po zapisie tekstowym.

    Zwracanie ``("", value)`` dla nieparsowalnej wartości (a tak działo się na
    Pythonie 3.10 z 7-cyfrowym ułamkiem) sprawiało, że ``max()`` wybierał
    chronologicznie **starszą** datę, a przy różnych strefach porównanie
    leksykograficzne dawało wynik zależny od zapisu, nie od czasu.
    """
    parsed = try_parse_api_datetime(value)
    if parsed is None:
        return (datetime.min.replace(tzinfo=timezone.utc), value)
    return (parsed, value)


def _get_latest_invoice_permanent_storage_date(payload: Any) -> str | None:
    candidates: list[str] = []
    for invoice in _get_invoices(payload):
        permanent_storage_date = _get_value(
            invoice,
            "permanent_storage_date",
            "permanentStorageDate",
        )
        if permanent_storage_date:
            candidates.append(str(permanent_storage_date))
    if not candidates:
        return None
    return max(candidates, key=_permanent_storage_date_sort_key)


def update_continuation_point(
    continuation_points: dict[str, str | None],
    subject_type: str,
    package: Any,
) -> None:
    """Ustala punkt wznowienia przyrostowego pobierania faktur.

    Kolejność wynika z dokumentacji MF („Przyrostowe pobieranie faktur"): dla
    paczki **obciętej** kontynuujemy od daty OSTATNIEGO REKORDU, który zmieścił
    się w paczce. `permanentStorageHwmDate` to watermark serwera równy końcowi
    zapytanego okna (`dateRange.to`), więc wznowienie od niego pomijałoby
    wszystkie faktury z przedziału między ostatnim rekordem a watermarkiem —
    i nie zostałyby one pobrane NIGDY.

    Wartość `lastPermanentStorageDate` bierzemy, gdy API ją zwróci (nie ma jej
    w kontrakcie OpenAPI, więc nie można na niej polegać), a w przeciwnym razie
    liczymy datę ostatniego rekordu z `invoices[]`.
    """
    hwm_date = _get_value(package, "permanent_storage_hwm_date", "permanentStorageHwmDate")
    is_truncated = bool(_get_value(package, "is_truncated", "isTruncated", False))
    last_permanent_storage_date = _get_direct_last_permanent_storage_date(package)
    fallback_date = _get_latest_invoice_permanent_storage_date(package)

    truncated_resume_point = last_permanent_storage_date or fallback_date
    if is_truncated and truncated_resume_point:
        continuation_points[subject_type] = str(truncated_resume_point)
    elif hwm_date:
        continuation_points[subject_type] = str(hwm_date)
    elif fallback_date:
        continuation_points[subject_type] = fallback_date
    else:
        continuation_points.pop(subject_type, None)


def get_effective_start_date(
    continuation_points: dict[str, str | None],
    subject_type: str,
    window_from: str,
) -> str:
    continuation_point = continuation_points.get(subject_type)
    if continuation_point:
        return continuation_point
    return window_from


def dedupe_by_ksef_number(metadata_summaries: list[Any]) -> dict[str, Any]:
    unique: dict[str, Any] = {}
    seen: set[str] = set()
    for summary in metadata_summaries:
        ksef_number = _get_value(summary, "ksef_number", "ksefNumber") or _get_value(
            summary, "KsefNumber"
        )
        if not ksef_number:
            continue
        key = str(ksef_number).lower()
        if key in seen:
            continue
        seen.add(key)
        unique[str(ksef_number)] = summary
    return unique
