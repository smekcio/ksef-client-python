from __future__ import annotations

from typing import Any


def update_continuation_point(
    continuation_points: dict[str, str | None],
    subject_type: str,
    package: dict[str, Any],
) -> None:
    is_truncated = bool(package.get("isTruncated"))
    last_permanent_storage_date = package.get("lastPermanentStorageDate")
    hwm_date = package.get("permanentStorageHwmDate")

    if is_truncated and last_permanent_storage_date:
        continuation_points[subject_type] = last_permanent_storage_date
    elif hwm_date:
        continuation_points[subject_type] = hwm_date
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


def dedupe_by_ksef_number(metadata_summaries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for summary in metadata_summaries:
        ksef_number = summary.get("ksefNumber") or summary.get("KsefNumber")
        if not ksef_number:
            continue
        key = str(ksef_number).lower()
        if key in seen:
            continue
        seen.add(key)
        unique[str(ksef_number)] = summary
    return unique
