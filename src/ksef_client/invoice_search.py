"""Opt-in metadata search with versioned, restartable, inclusive cursors.

The cursor is untrusted query data, not an authorization token or a snapshot.
Only PermanentStorage searches restricted to KSeF HWM describe a stable set.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, NoReturn

from .exceptions import KsefIncompletePaginationError, KsefInvalidPaginationCursorError
from .models import InvoiceMetadata, InvoiceQueryFilters, QueryInvoicesMetadataResponse
from .pagination import validate_page_size
from .utils.datetime_parsing import parse_api_datetime

MAX_CURSOR_BYTES = 2 * 1024 * 1024
_FIELDS = {
    "Issue": "issue_date",
    "Invoicing": "invoicing_date",
    "PermanentStorage": "permanent_storage_date",
}
_STATE_KEYS = {
    "version",
    "environment",
    "context_key",
    "filters",
    "page_size",
    "sort_order",
    "request",
    "offset",
    "empty",
    "last_date",
    "seen",
    "truncated_boundary",
    "stalled",
    "hwm",
}


def _date(value: str) -> tuple[datetime, Decimal]:
    # Keep the server's sub-microsecond precision when comparing boundaries.
    fraction = re.search(r"\.(\d+)", value)
    remainder = fraction.group(1)[6:] if fraction else ""
    return parse_api_datetime(value), Decimal("0." + (remainder or "0"))


def _dump(state: dict[str, Any]) -> str:
    raw = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=")
    if len(encoded) > MAX_CURSOR_BYTES:
        raise KsefInvalidPaginationCursorError("Pagination cursor exceeds size limit")
    return encoded.decode("ascii")


@dataclass(frozen=True)
class InvoiceMetadataPage:
    """Processed metadata and the next request; None means confirmed end."""

    items: list[InvoiceMetadata]
    next_cursor: str | None = field(repr=False)
    permanent_storage_hwm_date: str | None = None


class _MetadataMachine:
    def __init__(
        self,
        filters: dict[str, Any],
        *,
        environment: str,
        context_key: str,
        page_size: int,
        sort_order: str,
    ) -> None:
        validate_page_size(page_size)
        if sort_order not in {"Asc", "Desc"}:
            raise ValueError("sort_order must be Asc or Desc")
        if not isinstance(context_key, str) or not context_key.strip():
            raise ValueError("context_key must be a non-empty application context identifier")
        self.identity: dict[str, Any] = {
            "version": 1,
            "environment": environment,
            "context_key": context_key,
            "filters": deepcopy(filters),
            "page_size": page_size,
            "sort_order": sort_order,
        }
        self._validate_range(filters["dateRange"], allow_open=True)
        self.date_type = filters["dateRange"]["dateType"]
        self.ascending = sort_order == "Asc"

    @staticmethod
    def _validate_range(dr: dict[str, Any], *, allow_open: bool = False) -> None:
        if set(dr) - {"dateType", "from", "to", "restrictToPermanentStorageHwmDate"}:
            raise ValueError("Invalid date range")
        if dr.get("dateType") not in _FIELDS:
            raise ValueError("Unsupported date type")
        if not isinstance(dr.get("from"), str):
            raise ValueError("Missing range start")
        start = _date(dr["from"])
        end = dr.get("to")
        if end is None and allow_open:
            return
        if not isinstance(end, str):
            raise ValueError("Missing range end")
        finish = _date(end)
        if start > finish or (finish[0].date() - start[0].date()).days > 100:
            raise ValueError("Invalid range: require from <= to and at most 100 UTC days")
        restricted = dr.get("restrictToPermanentStorageHwmDate")
        if restricted is not None and type(restricted) is not bool:
            raise ValueError("Invalid HWM restriction")

    def load(self, cursor: str | None) -> dict[str, Any]:
        if cursor is None:
            request = deepcopy(self.identity["filters"])
            if not request["dateRange"].get("to"):
                request["dateRange"]["to"] = datetime.now(timezone.utc).isoformat()
            self._validate_range(request["dateRange"])
            return {
                **deepcopy(self.identity),
                "request": request,
                "offset": 0,
                "empty": 0,
                "stalled": 0,
                "last_date": None,
                "seen": [],
                "truncated_boundary": None,
                "hwm": None,
            }
        try:
            if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR_BYTES:
                raise ValueError("Cursor size or type")
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            state = json.loads(raw)
            self._validate_state(state)
            return state
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, binascii.Error):
            raise KsefInvalidPaginationCursorError(
                "Invalid or incompatible pagination cursor"
            ) from None

    def _validate_state(self, state: Any) -> None:
        if not isinstance(state, dict) or set(state) != _STATE_KEYS:
            raise ValueError("Invalid cursor structure")
        if type(state["version"]) is not int or state["version"] != 1:
            raise ValueError("Unsupported version")
        for key, value in self.identity.items():
            if state[key] != value or type(state[key]) is not type(value):
                raise ValueError("Incompatible search")
        for key, maximum in (("offset", 999), ("empty", 2), ("stalled", 2)):
            if type(state[key]) is not int or not 0 <= state[key] <= maximum:
                raise ValueError("Invalid counter")
        request = state["request"]
        if not isinstance(request, dict) or set(request) != set(self.identity["filters"]):
            raise ValueError("Invalid request")
        for key, value in self.identity["filters"].items():
            if key != "dateRange" and request[key] != value:
                raise ValueError("Changed filters")
        dr = request["dateRange"]
        self._validate_range(dr)
        original = self.identity["filters"]["dateRange"]
        if dr.get("dateType") != original["dateType"] or dr.get(
            "restrictToPermanentStorageHwmDate"
        ) != original.get("restrictToPermanentStorageHwmDate"):
            raise ValueError("Changed date type")
        if _date(dr["from"]) < _date(original["from"]):
            raise ValueError("Widened start")
        if original.get("to") and _date(dr["to"]) > _date(original["to"]):
            raise ValueError("Widened end")
        seen = state["seen"]
        if (
            not isinstance(seen, list)
            or len(seen) > 10000
            or any(not isinstance(x, str) or not x or len(x) > 256 for x in seen)
            or len(set(seen)) != len(seen)
        ):
            raise ValueError("Invalid deduplication state")
        for key in ("last_date", "truncated_boundary", "hwm"):
            if state[key] is not None:
                if not isinstance(state[key], str):
                    raise ValueError("Invalid boundary")
                _date(state[key])
        if bool(seen) != (state["last_date"] is not None):
            raise ValueError("Inconsistent deduplication boundary")
        if state["hwm"] is not None and _date(dr["to"]) > _date(state["hwm"]):
            raise ValueError("Request exceeds HWM")

    def advance(
        self, state: dict[str, Any], response: QueryInvoicesMetadataResponse
    ) -> InvoiceMetadataPage:
        replay = _dump(state)

        def fail(reason: str) -> NoReturn:
            raise KsefIncompletePaginationError(reason, last_cursor=replay)

        new = deepcopy(state)
        dr = new["request"]["dateRange"]
        restricted = (
            self.date_type == "PermanentStorage"
            and dr.get("restrictToPermanentStorageHwmDate") is True
        )
        if restricted:
            hwm = response.permanent_storage_hwm_date
            try:
                if not isinstance(hwm, str):
                    raise ValueError("Missing HWM")
                if new["hwm"] is not None and _date(hwm) < _date(new["hwm"]):
                    fail("hwm_regressed")
                if new["hwm"] is None:
                    new["hwm"] = hwm
                    if _date(hwm) < _date(dr["to"]):
                        dr["to"] = hwm
                if _date(dr["to"]) < _date(dr["from"]):
                    fail("hwm_before_start")
            except ValueError:
                fail("invalid_hwm")
        items = []
        last = new["last_date"]
        seen = set(new["seen"])
        start, end = _date(dr["from"]), _date(dr["to"])
        if self.date_type == "Issue":
            start, end = (
                (start[0].replace(hour=0, minute=0, second=0, microsecond=0), Decimal(0)),
                (end[0].replace(hour=0, minute=0, second=0, microsecond=0), Decimal(0)),
            )
        for invoice in response.invoices:
            boundary = getattr(invoice, _FIELDS[self.date_type])
            if not isinstance(invoice.ksef_number, str) or not invoice.ksef_number:
                fail("missing_ksef_number")
            try:
                if not isinstance(boundary, str):
                    raise ValueError("Missing date")
                key = _date(boundary)
            except ValueError:
                fail("invalid_invoice_date")
            if not start <= key <= end:
                fail("invoice_outside_range")
            if last is not None:
                previous = _date(last)
                if key < previous if self.ascending else key > previous:
                    fail("inconsistent_sort_order")
                if key != previous:
                    seen.clear()
            if invoice.ksef_number not in seen:
                items.append(invoice)
                seen.add(invoice.ksef_number)
            last = boundary
        if len(seen) > 10000:
            fail("boundary_limit_exceeded")
        new["last_date"], new["seen"] = last, sorted(seen)
        new["empty"] = 0 if response.invoices else new["empty"] + 1
        new["stalled"] = new["stalled"] + 1 if response.invoices and not items else 0
        if not response.has_more:
            return InvoiceMetadataPage(items, None, new["hwm"])
        if new["empty"] >= 3:
            fail("empty_pages")
        if new["stalled"] >= 3:
            fail("repeated_page")
        if response.is_truncated:
            if not response.invoices:
                fail("empty_truncated_page")
            if new["truncated_boundary"] is not None and _date(last) == _date(
                new["truncated_boundary"]
            ):
                fail("truncation_did_not_advance")
            dr["from" if self.ascending else "to"] = last
            new["truncated_boundary"], new["offset"] = last, 0
        else:
            new["offset"] += 1
            if new["offset"] * new["page_size"] >= 10000:
                fail("result_limit_without_truncation")
        return InvoiceMetadataPage(items, _dump(new), new["hwm"])


class InvoiceMetadataSearch:
    """Lazy metadata search. Store the next cursor only after committing items."""

    def __init__(
        self, machine: _MetadataMachine, fetch: Callable[..., QueryInvoicesMetadataResponse]
    ) -> None:
        self._machine, self._fetch = machine, fetch

    def page(self, cursor: str | None = None) -> InvoiceMetadataPage:
        state = self._machine.load(cursor)
        response = self._fetch(
            InvoiceQueryFilters.from_dict(state["request"]),
            page_offset=state["offset"],
            page_size=state["page_size"],
            sort_order=state["sort_order"],
        )
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


class AsyncInvoiceMetadataSearch:
    """Async counterpart using exactly the same cursor state machine."""

    def __init__(
        self,
        machine: _MetadataMachine,
        fetch: Callable[..., Awaitable[QueryInvoicesMetadataResponse]],
    ) -> None:
        self._machine, self._fetch = machine, fetch

    async def page(self, cursor: str | None = None) -> InvoiceMetadataPage:
        state = self._machine.load(cursor)
        response = await self._fetch(
            InvoiceQueryFilters.from_dict(state["request"]),
            page_offset=state["offset"],
            page_size=state["page_size"],
            sort_order=state["sort_order"],
        )
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
