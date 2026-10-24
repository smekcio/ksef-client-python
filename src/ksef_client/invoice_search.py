"""Opt-in metadata search with versioned, restartable, inclusive cursors.

The cursor is untrusted query data, not an authorization token or a snapshot.
Only PermanentStorage searches restricted to KSeF HWM describe a stable set.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, NoReturn

from .exceptions import (
    KsefIncompletePaginationError,
    KsefInvalidPaginationCursorError,
    KsefPaginationError,
)
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
    "last_page",
}


class _InvalidMetadataResponse(ValueError):
    """Internal sentinel: preserve strict search semantics without changing legacy parsers."""


def _parse_metadata_response(raw: Any) -> QueryInvoicesMetadataResponse:
    if (
        type(raw) is not dict
        or type(raw.get("hasMore")) is not bool
        or type(raw.get("isTruncated")) is not bool
        or type(raw.get("invoices")) is not list
        or any(type(item) is not dict for item in raw["invoices"])
    ):
        raise _InvalidMetadataResponse("Invalid metadata response")
    # Legacy models intentionally coerce strings. Identity and pagination dates
    # must retain their wire types here, before that conversion can hide damage.
    if any(
        type(item.get("ksefNumber")) is not str
        or not 1 <= len(item["ksefNumber"]) <= 256
        or any(
            item.get(key) is not None and type(item[key]) is not str
            for key in ("issueDate", "invoicingDate", "permanentStorageDate")
        )
        for item in raw["invoices"]
    ) or (
        raw.get("permanentStorageHwmDate") is not None
        and type(raw["permanentStorageHwmDate"]) is not str
    ):
        raise _InvalidMetadataResponse("Invalid metadata response")
    try:
        return QueryInvoicesMetadataResponse.from_dict(raw)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise _InvalidMetadataResponse("Invalid metadata response") from None


def _date(value: str) -> tuple[datetime, Decimal]:
    # Preserve sub-microsecond precision, but bound work on untrusted dates.
    if type(value) is not str or len(value) > 128:
        raise ValueError("Invalid pagination timestamp")
    fraction = re.search(r"\.(\d+)", value)
    remainder = fraction.group(1)[6:] if fraction else ""
    try:
        return parse_api_datetime(value), Decimal("0." + (remainder or "0"))
    except OverflowError:
        raise ValueError("Pagination timestamp exceeds UTC range") from None


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate cursor member")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise ValueError("Non-finite cursor number")


def _same_json(left: Any, right: Any) -> bool:
    # Unlike Python equality, JSON comparison must distinguish True from 1.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right,
        sort_keys=True,
        allow_nan=False,
    )


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
            "environment": "sha256:" + hashlib.sha256(environment.encode()).hexdigest(),
            "context_key": context_key,
            "filters": deepcopy(filters),
            "page_size": page_size,
            "sort_order": sort_order,
        }
        self._legacy_environment = environment
        if type(filters.get("dateRange")) is not dict:
            raise ValueError("Invoice search requires a dateRange object")
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
            state = {
                **deepcopy(self.identity),
                "request": request,
                "offset": 0,
                "empty": 0,
                "stalled": 0,
                "last_date": None,
                "seen": [],
                "truncated_boundary": None,
                "hwm": None,
                "last_page": None,
            }
            try:
                _dump(state)
            except KsefInvalidPaginationCursorError:
                raise KsefPaginationError(
                    "Search state exceeds pagination cursor size limit"
                ) from None
            return state
        try:
            if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR_BYTES:
                raise ValueError("Cursor size or type")
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            state = json.loads(raw, object_pairs_hook=_json_object, parse_constant=_reject_constant)
            if isinstance(state, dict):
                state.setdefault("last_page", None)  # Read earlier v1 cursors.
            if isinstance(state, dict) and state.get("environment") == self._legacy_environment:
                state["environment"] = self.identity["environment"]
            self._validate_state(state)
            # A compact UTF-8 cursor can expand when canonical JSON escapes
            # Unicode. Ensure its replay cursor fits before performing HTTP.
            _dump(state)
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
            if not _same_json(state[key], value):
                raise ValueError("Incompatible search")
        for key, maximum in (("offset", 999), ("empty", 2), ("stalled", 2)):
            if type(state[key]) is not int or not 0 <= state[key] <= maximum:
                raise ValueError("Invalid counter")
        if state["offset"] * state["page_size"] >= 10000:
            raise ValueError("Offset exceeds metadata result limit")
        if state["last_page"] is not None and (
            type(state["last_page"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", state["last_page"]) is None
        ):
            raise ValueError("Invalid last page fingerprint")
        request = state["request"]
        if not isinstance(request, dict) or set(request) != set(self.identity["filters"]):
            raise ValueError("Invalid request")
        for key, value in self.identity["filters"].items():
            if key != "dateRange" and not _same_json(request[key], value):
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
        return self.advance_state(state, response)[0]

    def advance_state(
        self, state: dict[str, Any], response: QueryInvoicesMetadataResponse
    ) -> tuple[InvoiceMetadataPage, dict[str, Any]]:
        """Advance one request and retain terminal boundary state for windowing."""
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
                # Historical queries report their own effective upper bound.
                # Desc truncation deliberately lowers that bound; compare to
                # the current request, not the original snapshot watermark.
                expected_hwm = min(_date(new["hwm"]), _date(dr["to"])) if new["hwm"] else None
                if expected_hwm is not None and _date(hwm) < expected_hwm:
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
            if not isinstance(invoice.ksef_number, str) or not 1 <= len(invoice.ksef_number) <= 256:
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
        # Re-reading known boundary records at increasing offsets is progress.
        # Only repeated wire pages (same boundary AND same page identifiers)
        # are suspicious; the seen set alone cannot distinguish overlap pages.
        fingerprint = hashlib.sha256(
            json.dumps(
                [
                    (item.ksef_number, getattr(item, _FIELDS[self.date_type]))
                    for item in response.invoices
                ]
            ).encode()
        ).hexdigest()
        new["stalled"] = (
            new["stalled"] + 1 if response.invoices and fingerprint == new["last_page"] else 0
        )
        new["last_page"] = fingerprint
        if not response.has_more:
            return InvoiceMetadataPage(items, None, new["hwm"]), new
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
            # Issue metadata has day precision even when the original bounds
            # have a time. Never widen or invert a range when narrowing it.
            candidate = last
            if _date(candidate) < _date(dr["from"]):
                candidate = dr["from"]
            dr["from" if self.ascending else "to"] = candidate
            new["truncated_boundary"], new["offset"] = last, 0
        else:
            new["offset"] += 1
            if new["offset"] * new["page_size"] >= 10000:
                fail("result_limit_without_truncation")
        try:
            next_cursor = _dump(new)
        except KsefInvalidPaginationCursorError:
            fail("cursor_size_limit")
        return InvoiceMetadataPage(items, next_cursor, new["hwm"]), new


class InvoiceMetadataSearch:
    """Lazy metadata search. Store the next cursor only after committing items."""

    def __init__(
        self, machine: _MetadataMachine, fetch: Callable[..., QueryInvoicesMetadataResponse]
    ) -> None:
        self._machine, self._fetch = machine, fetch

    def page(self, cursor: str | None = None) -> InvoiceMetadataPage:
        state = self._machine.load(cursor)
        try:
            response = self._fetch(
                InvoiceQueryFilters.from_dict(state["request"]),
                page_offset=state["offset"],
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
        try:
            response = await self._fetch(
                InvoiceQueryFilters.from_dict(state["request"]),
                page_offset=state["offset"],
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
