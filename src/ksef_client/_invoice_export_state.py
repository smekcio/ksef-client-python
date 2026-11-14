"""Validated time boundaries for export-based synchronization."""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from ._invoice_export_package import ValidatedInvoicePackage
from .exceptions import KsefDocumentValidationError
from .invoice_search import _date
from .invoice_sync_state import _loads, utc_timestamp
from .operations import OperationState
from .utils.zip_utils import EXPORT_MAX_INVOICES


@dataclass(frozen=True)
class ExportProgress:
    """A stable watermark and a separate inclusive continuation for an open window."""

    since: str
    committed_hwm: str | None = None
    continuation: str | None = None
    window_end: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "since", utc_timestamp(self.since))
        for name in ("committed_hwm", "continuation", "window_end"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, utc_timestamp(value))
        if (self.continuation is None) != (self.window_end is None):
            raise ValueError("An open export continuation needs its original end")
        if self.committed_hwm is not None and _date(self.committed_hwm) < _date(self.since):
            raise ValueError("Export watermark precedes synchronization start")
        if self.window_end is not None and not (
            _date(self.committed_hwm or self.since) <= _date(self.start) <= _date(self.window_end)
        ):
            raise ValueError("Invalid open export window")

    @property
    def start(self) -> str:
        return self.continuation or self.committed_hwm or self.since

    def bounds(self, stop: str | None, *, now: datetime | None = None) -> tuple[str, str] | None:
        start = self.start
        if self.window_end is not None:
            if stop is not None and _date(utc_timestamp(stop)) < _date(self.window_end):
                raise ValueError("Cannot shorten an active export window")
            return start, self.window_end
        end = (
            utc_timestamp(stop)
            if stop is not None
            else utc_timestamp((now if now is not None else datetime.now(timezone.utc)).isoformat())
        )
        end_time = _date(end)
        if end_time <= _date(start):
            return None
        # A UTC midnight on day 100 is within the API's calendar-day bound,
        # independent of fractional-second precision or the original offset.
        first_day = _date(start)[0].replace(hour=0, minute=0, second=0, microsecond=0)
        if (end_time[0] - first_day).days >= 100:
            end = utc_timestamp((first_day + timedelta(days=100)).isoformat())
        return start, end

    def finish(
        self, package: ValidatedInvoicePackage, *, window_end: str, new_at_boundary: int
    ) -> ExportProgress:
        window_end = utc_timestamp(window_end)
        if self.window_end is not None and window_end != self.window_end:
            raise KsefDocumentValidationError("Export window changed during continuation")
        boundary = _date(package.continuation)
        if not _date(self.start) <= boundary <= _date(window_end):
            raise KsefDocumentValidationError("Export boundary is outside the active window")
        if package.truncated:
            if boundary == _date(self.start) and not new_at_boundary:
                raise KsefDocumentValidationError("Truncated export cannot advance")
            return replace(self, continuation=package.continuation, window_end=window_end)
        return replace(self, committed_hwm=package.continuation, continuation=None, window_end=None)


@dataclass(frozen=True)
class ExportCheckpoint:
    progress: ExportProgress
    end: str | None = None
    operation: OperationState | None = field(default=None, repr=False)
    offset: int = 0
    inserted: int = 0
    package_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.end is not None:
            object.__setattr__(self, "end", utc_timestamp(self.end))
            if _date(self.end) < _date(self.progress.start) or self.progress.window_end not in (
                None,
                self.end,
            ):
                raise ValueError("Export checkpoint has inconsistent bounds")
        if self.operation is not None and (self.end is None or self.operation.kind != "export"):
            raise ValueError("Export operation does not belong to an active window")
        if (
            type(self.offset) is not int
            or type(self.inserted) is not int
            or not 0 <= self.inserted <= self.offset <= EXPORT_MAX_INVOICES
            or (self.package_id is None and self.offset)
            or (self.package_id is not None and self.operation is None)
        ):
            raise ValueError("Invalid export import checkpoint")
        if self.package_id is not None and (
            type(self.package_id) is not str
            or len(self.package_id) != 64
            or any(char not in "0123456789abcdef" for char in self.package_id)
        ):
            raise ValueError("Invalid export package fingerprint")

    def encode(self, key: bytes) -> dict[str, Any]:
        return {
            "version": 1,
            "progress": asdict(self.progress),
            "end": self.end,
            "operation": (
                base64.b64encode(self.operation.to_encrypted_bytes(key)).decode("ascii")
                if self.operation is not None
                else None
            ),
            "offset": self.offset,
            "inserted": self.inserted,
            "package_id": self.package_id,
        }

    @classmethod
    def decode(cls, raw: bytes, key: bytes) -> ExportCheckpoint:
        try:
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError
            value = _loads(raw)
            if type(value) is not dict:
                raise ValueError
            version = value.pop("version")
            if type(version) is not int or version != 1:
                raise ValueError
            if value.keys() != {"progress", "end", "operation", "offset", "inserted", "package_id"}:
                raise ValueError
            encrypted = value["operation"]
            value["operation"] = (
                None
                if encrypted is None
                else OperationState.from_encrypted_bytes(
                    base64.b64decode(encrypted, validate=True), key
                )
            )
            value["progress"] = ExportProgress(**value["progress"])
            return cls(**value)
        except (KeyError, TypeError, ValueError, OverflowError, binascii.Error, RecursionError):
            raise KsefDocumentValidationError("Invalid or unreadable export checkpoint") from None
