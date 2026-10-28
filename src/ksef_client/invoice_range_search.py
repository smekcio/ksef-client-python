"""Restartable metadata searches over inclusive windows of at most 100 UTC days."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

from .exceptions import (
    KsefIncompletePaginationError,
    KsefInvalidPaginationCursorError,
    KsefPaginationError,
)
from .invoice_search import (
    MAX_CURSOR_BYTES,
    InvoiceMetadataObservationPage,
    InvoiceMetadataPage,
    InvoiceMetadataSearchIdentity,
    _date,
    _dump,
    _InvalidMetadataResponse,
    _json_object,
    _MetadataMachine,
    _reject_constant,
    _same_json,
)
from .models import InvoiceMetadata, InvoiceQueryFilters, QueryInvoicesMetadataResponse
from .operations import environment_key
from .pagination import validate_page_size

_STATE_KEYS = {
    "kind",
    "version",
    "environment",
    "context_key",
    "filters",
    "page_size",
    "sort_order",
    "window_days",
    "end",
    "window",
    "child",
    "hwm",
}


def _shift(value: str, days: int) -> str:
    """Move whole UTC days without losing the API's sub-microsecond precision."""
    parsed, remainder = _date(value)
    shifted = parsed + timedelta(days=days)
    stamp = shifted.isoformat(timespec="microseconds")
    if remainder:
        # Decimal('0.12') denotes the digits after the first six fractional digits.
        stamp = stamp[:-6] + format(remainder, "f")[2:] + stamp[-6:]
    return stamp


class _RangeMachine:
    def __init__(
        self,
        filters: dict[str, Any],
        *,
        environment: str,
        context_key: str,
        page_size: int,
        sort_order: str,
        window_days: int,
    ) -> None:
        validate_page_size(page_size)
        if type(window_days) is not int or not 1 <= window_days <= 100:
            raise ValueError("window_days must be an integer from 1 to 100")
        if sort_order not in {"Asc", "Desc"}:
            raise ValueError("sort_order must be Asc or Desc")
        if not isinstance(context_key, str) or not context_key.strip():
            raise ValueError("context_key must be a non-empty application context identifier")
        dr = filters.get("dateRange")
        if type(dr) is not dict:
            raise ValueError("Invoice search requires a dateRange object")
        # Validate the complete shape without applying the single-request limit.
        sample = deepcopy(dr)
        sample["to"] = sample.get("from")
        _MetadataMachine._validate_range(sample)
        if dr.get("to") is not None and _date(dr["to"]) < _date(dr["from"]):
            raise ValueError("Invoice date range must satisfy from <= to")
        self.environment = environment
        self.identity: dict[str, Any] = {
            "kind": "invoice-metadata-range",
            "version": 1,
            "environment": "sha256:" + hashlib.sha256(environment.encode()).hexdigest(),
            "context_key": context_key,
            "filters": deepcopy(filters),
            "page_size": page_size,
            "sort_order": sort_order,
            "window_days": window_days,
        }
        self.ascending = sort_order == "Asc"
        self.restricted = (
            dr["dateType"] == "PermanentStorage"
            and dr.get("restrictToPermanentStorageHwmDate") is True
        )

    def _bounds(self, end: str, index: int) -> tuple[str, str]:
        start = self.identity["filters"]["dateRange"]["from"]
        days = self.identity["window_days"]
        distance = index * days
        try:
            if self.ascending:
                low = start if not index else _shift(start, distance)
                high = min((_shift(low, days), end), key=_date)
            else:
                high = end if not index else _shift(end, -distance)
                low = max((_shift(high, -days), start), key=_date)
        except OverflowError:
            # A final partial window near datetime's supported extremes.
            if self.ascending:
                low = start if not index else _shift(start, distance)
                high = end
            else:
                high = end if not index else _shift(end, -distance)
                low = start
        if _date(low) > _date(high):
            raise ValueError("Invalid window index")
        return low, high

    def child_machine(self, state: dict[str, Any]) -> _MetadataMachine:
        low, high = self._bounds(state["end"], state["window"])
        filters = deepcopy(self.identity["filters"])
        filters["dateRange"].update({"from": low, "to": high})
        return _MetadataMachine(
            filters,
            environment=self.environment,
            context_key=self.identity["context_key"],
            page_size=self.identity["page_size"],
            sort_order=self.identity["sort_order"],
        )

    def load(self, cursor: str | None) -> dict[str, Any]:
        if cursor is None:
            dr = self.identity["filters"]["dateRange"]
            end = dr.get("to") or datetime.now(timezone.utc).isoformat()
            if _date(end) < _date(dr["from"]):
                raise ValueError("Invoice date range must satisfy from <= to")
            state = {**deepcopy(self.identity), "end": end, "window": 0, "hwm": None}
            state["child"] = self.child_machine(state).load(None)
            try:
                _dump(state)
            except KsefInvalidPaginationCursorError:
                raise KsefPaginationError(
                    "Search state exceeds pagination cursor size limit"
                ) from None
            return state
        try:
            if type(cursor) is not str or len(cursor) > MAX_CURSOR_BYTES:
                raise ValueError("Invalid range cursor size or type")
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            state = json.loads(raw, object_pairs_hook=_json_object, parse_constant=_reject_constant)
            self._validate_state(state)
            # Replay uses canonical JSON, whose Unicode escapes may be much
            # larger than the untrusted cursor's original UTF-8 encoding.
            _dump(state)
            return state
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OverflowError,
            RecursionError,
            binascii.Error,
        ):
            raise KsefInvalidPaginationCursorError(
                "Invalid or incompatible range pagination cursor"
            ) from None

    def _validate_state(self, state: Any) -> None:
        if type(state) is not dict or set(state) != _STATE_KEYS:
            raise ValueError("Invalid range cursor structure")
        for key, value in self.identity.items():
            if not _same_json(state[key], value):
                raise ValueError("Incompatible range search")
        if type(state["version"]) is not int or type(state["window"]) is not int:
            raise ValueError("Invalid range counters")
        if not 0 <= state["window"] <= 3_652_058:
            raise ValueError("Invalid range window")
        original = self.identity["filters"]["dateRange"]
        if original.get("to") is not None and state["end"] != original["to"]:
            raise ValueError("Changed range end")
        if _date(state["end"]) < _date(original["from"]):
            raise ValueError("Invalid range end")
        machine = self.child_machine(state)
        machine._validate_state(state["child"])
        if state["hwm"] is not None and (
            not self.restricted or _date(state["hwm"]) > _date(state["end"])
        ):
            raise ValueError("Invalid range HWM")
        child = state["child"]
        if (
            self.restricted
            and state["hwm"] is None
            and (state["window"] or child["hwm"] is not None)
        ):
            raise ValueError("Missing range HWM")
        if self.restricted and self.ascending and state["hwm"] is not None:
            low, high = self._bounds(state["end"], state["window"])
            expected = min((child["hwm"], high), key=_date) if child["hwm"] else low
            if _date(state["hwm"]) != _date(expected):
                raise ValueError("Range HWM does not match the active window")
        if child["last_date"] is not None:
            lower, last, upper = (
                _date(original["from"]),
                _date(child["last_date"]),
                _date(state["end"]),
            )
            # Issue dates have day precision, including queries starting at noon.
            valid = (
                lower[0].date() <= last[0].date() <= upper[0].date()
                if original["dateType"] == "Issue"
                else lower <= last <= upper
            )
            if not valid:
                raise ValueError("Boundary outside complete range")

    def advance(
        self,
        state: dict[str, Any],
        response: QueryInvoicesMetadataResponse,
    ) -> InvoiceMetadataPage:
        replay = _dump(state)
        machine = self.child_machine(state)
        low, high = self._bounds(state["end"], state["window"])
        try:
            page, child = machine.advance_state(state["child"], response)
            new = deepcopy(state)
            new["child"] = child
            if self.restricted:
                hwm = min((page.permanent_storage_hwm_date, high, state["end"]), key=_date)
                if self.ascending or new["hwm"] is None:
                    new["hwm"] = hwm
            finished = page.next_cursor is None
            overall_start = self.identity["filters"]["dateRange"]["from"]
            last_window = (
                _date(high) == _date(state["end"])
                if self.ascending
                else _date(low) == _date(overall_start)
            )
            # HWM clipping must stop the scan at the actual confirmed boundary;
            # jumping to the scheduled end would leave an unqueried gap.
            clipped = self.ascending and _date(child["request"]["dateRange"]["to"]) < _date(high)
            if finished and (last_window or clipped):
                return InvoiceMetadataPage(page.items, None, new["hwm"])
            if finished:
                new["window"] += 1
                next_child = self.child_machine(new).load(None)
                next_child["last_date"] = child["last_date"]
                next_child["seen"] = child["seen"]
                new["child"] = next_child
            next_cursor = _dump(new)
        except KsefIncompletePaginationError as exc:
            raise KsefIncompletePaginationError(exc.reason_code, last_cursor=replay) from None
        except KsefInvalidPaginationCursorError:
            raise KsefIncompletePaginationError("cursor_size_limit", last_cursor=replay) from None
        return InvoiceMetadataPage(page.items, next_cursor, new["hwm"])


def _search_identity(machine: _RangeMachine) -> InvoiceMetadataSearchIdentity:
    identity = machine.identity
    return InvoiceMetadataSearchIdentity(
        environment=environment_key(machine.environment),
        context_key=identity["context_key"],
        query_fingerprint=hashlib.sha256(
            json.dumps(
                identity["filters"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode()
        ).hexdigest(),
        page_size=identity["page_size"],
        window_days=identity["window_days"],
        sort_order=identity["sort_order"],
    )


class InvoiceMetadataRangeSearch:
    """Lazy multi-window search; persist one next_cursor after committing each page."""

    def __init__(
        self,
        machine: _RangeMachine,
        fetch: Callable[..., QueryInvoicesMetadataResponse],
        observation_fetch: Callable[..., QueryInvoicesMetadataResponse] | None = None,
    ) -> None:
        self._machine, self._fetch = machine, fetch
        self._observation_fetch = observation_fetch or fetch

    @property
    def identity(self) -> InvoiceMetadataSearchIdentity:
        return _search_identity(self._machine)

    def validate_cursor(self, cursor: str | None) -> None:
        self._machine.load(cursor)

    def observation_page(self, cursor: str | None = None) -> InvoiceMetadataObservationPage:
        state = self._machine.load(cursor)
        try:
            response = self._observation_fetch(
                InvoiceQueryFilters.from_dict(state["child"]["request"]),
                page_offset=state["child"]["offset"],
                page_size=state["page_size"],
                sort_order=state["sort_order"],
            )
        except _InvalidMetadataResponse:
            raise KsefIncompletePaginationError(
                "invalid_response", last_cursor=_dump(state)
            ) from None
        page = self._machine.advance(state, response)
        return InvoiceMetadataObservationPage(
            tuple(response.invoices), page.next_cursor, page.permanent_storage_hwm_date
        )

    def page(self, cursor: str | None = None) -> InvoiceMetadataPage:
        state = self._machine.load(cursor)
        try:
            response = self._fetch(
                InvoiceQueryFilters.from_dict(state["child"]["request"]),
                page_offset=state["child"]["offset"],
                page_size=state["page_size"],
                sort_order=state["sort_order"],
            )
        except _InvalidMetadataResponse:
            raise KsefIncompletePaginationError(
                "invalid_response", last_cursor=_dump(state)
            ) from None
        return self._machine.advance(state, response)

    def pages(self, cursor: str | None = None) -> Iterator[InvoiceMetadataPage]:
        while True:
            page = self.page(cursor)
            yield page
            cursor = page.next_cursor
            if cursor is None:
                return

    def items(self, cursor: str | None = None) -> Iterator[InvoiceMetadata]:
        for page in self.pages(cursor):
            yield from page.items

    def __iter__(self) -> Iterator[InvoiceMetadata]:
        return self.items()


class AsyncInvoiceMetadataRangeSearch:
    """Async range search using the same window and pagination state machine."""

    def __init__(
        self,
        machine: _RangeMachine,
        fetch: Callable[..., Awaitable[QueryInvoicesMetadataResponse]],
        observation_fetch: Callable[..., Awaitable[QueryInvoicesMetadataResponse]] | None = None,
    ) -> None:
        self._machine, self._fetch = machine, fetch
        self._observation_fetch = observation_fetch or fetch

    @property
    def identity(self) -> InvoiceMetadataSearchIdentity:
        return _search_identity(self._machine)

    def validate_cursor(self, cursor: str | None) -> None:
        self._machine.load(cursor)

    async def observation_page(self, cursor: str | None = None) -> InvoiceMetadataObservationPage:
        state = self._machine.load(cursor)
        try:
            response = await self._observation_fetch(
                InvoiceQueryFilters.from_dict(state["child"]["request"]),
                page_offset=state["child"]["offset"],
                page_size=state["page_size"],
                sort_order=state["sort_order"],
            )
        except _InvalidMetadataResponse:
            raise KsefIncompletePaginationError(
                "invalid_response", last_cursor=_dump(state)
            ) from None
        page = self._machine.advance(state, response)
        return InvoiceMetadataObservationPage(
            tuple(response.invoices), page.next_cursor, page.permanent_storage_hwm_date
        )

    async def page(self, cursor: str | None = None) -> InvoiceMetadataPage:
        state = self._machine.load(cursor)
        try:
            response = await self._fetch(
                InvoiceQueryFilters.from_dict(state["child"]["request"]),
                page_offset=state["child"]["offset"],
                page_size=state["page_size"],
                sort_order=state["sort_order"],
            )
        except _InvalidMetadataResponse:
            raise KsefIncompletePaginationError(
                "invalid_response", last_cursor=_dump(state)
            ) from None
        return self._machine.advance(state, response)

    async def pages(self, cursor: str | None = None) -> AsyncIterator[InvoiceMetadataPage]:
        while True:
            page = await self.page(cursor)
            yield page
            cursor = page.next_cursor
            if cursor is None:
                return

    async def items(self, cursor: str | None = None) -> AsyncIterator[InvoiceMetadata]:
        async for page in self.pages(cursor):
            for item in page.items:
                yield item

    def __aiter__(self) -> AsyncIterator[InvoiceMetadata]:
        return self.items()
