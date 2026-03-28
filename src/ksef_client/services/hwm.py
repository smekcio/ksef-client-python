from __future__ import annotations

from typing import Any


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


def _get_last_permanent_storage_date(payload: Any) -> str | None:
    direct_value = _get_value(
        payload,
        "last_permanent_storage_date",
        "lastPermanentStorageDate",
    )
    if direct_value:
        return str(direct_value)
    for invoice in reversed(_get_invoices(payload)):
        permanent_storage_date = _get_value(
            invoice,
            "permanent_storage_date",
            "permanentStorageDate",
        )
        if permanent_storage_date:
            return str(permanent_storage_date)
    return None


def update_continuation_point(
    continuation_points: dict[str, str | None],
    subject_type: str,
    package: Any,
) -> None:
    is_truncated = bool(_get_value(package, "is_truncated", "isTruncated", False))
    last_permanent_storage_date = _get_last_permanent_storage_date(package)
    hwm_date = _get_value(package, "permanent_storage_hwm_date", "permanentStorageHwmDate")

    if is_truncated and last_permanent_storage_date:
        continuation_points[subject_type] = str(last_permanent_storage_date)
    elif hwm_date:
        continuation_points[subject_type] = str(hwm_date)
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
