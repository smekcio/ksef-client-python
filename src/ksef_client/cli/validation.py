from __future__ import annotations

from datetime import datetime


def require_exactly_one(flags: dict[str, bool], error_message: str) -> None:
    selected = [name for name, is_selected in flags.items() if is_selected]
    if len(selected) != 1:
        raise ValueError(error_message)


def validate_iso_date(value: str) -> str:
    datetime.strptime(value, "%Y-%m-%d")
    return value
