"""Validated time boundaries for export-based synchronization."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from ._invoice_export_package import ValidatedInvoicePackage
from .exceptions import KsefDocumentValidationError
from .invoice_search import _date
from .invoice_sync_state import utc_timestamp


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
        if _date(end) <= _date(start):
            return None
        # A UTC midnight on day 100 is within the API's calendar-day bound,
        # independent of fractional-second precision or the original offset.
        first_day = _date(start)[0].replace(hour=0, minute=0, second=0, microsecond=0)
        if (_date(end)[0].date() - first_day.date()).days > 100:
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
