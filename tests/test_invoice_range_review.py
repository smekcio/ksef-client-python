"""Independent adversarial checks for range boundaries and cursor validation."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from ksef_client import models as m
from ksef_client.exceptions import KsefInvalidPaginationCursorError
from ksef_client.invoice_range_search import (
    AsyncInvoiceMetadataRangeSearch,
    InvoiceMetadataRangeSearch,
    _RangeMachine,
)
from ksef_client.invoice_search import (
    MAX_CURSOR_BYTES,
    AsyncInvoiceMetadataSearch,
    InvoiceMetadataSearch,
    _date,
    _dump,
    _MetadataMachine,
)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("multiple_windows", [False, True])
def test_unicode_cursor_expansion_is_rejected_before_http(asynchronous, multiple_windows):
    filters = {
        "subjectType": "Subject1",
        "dateRange": {
            "dateType": "PermanentStorage",
            "from": "2024-01-01T00:00:00Z",
            "to": "2026-01-01T00:00:00Z" if multiple_windows else "2024-02-01T00:00:00Z",
        },
    }
    settings: dict[str, Any] = {
        "environment": "https://api-test.ksef.mf.gov.pl/v2",
        "context_key": "Nip:DUMMY",
        "page_size": 100,
        "sort_order": "Asc",
    }
    machine: Any = (
        _RangeMachine(filters, **settings, window_days=100)
        if multiple_windows
        else _MetadataMachine(filters, **settings)
    )
    state = machine.load(None)
    child = state["child"] if multiple_windows else state
    child["last_date"] = "2024-01-01T01:00:00Z"
    child["seen"] = [str(index) + "\U0001f600" * 40 for index in range(5000)]
    compact = json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode()
    canonical = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode()
    cursor = base64.urlsafe_b64encode(compact).rstrip(b"=").decode()
    assert len(cursor) < MAX_CURSOR_BYTES
    assert len(base64.urlsafe_b64encode(canonical).rstrip(b"=")) > MAX_CURSOR_BYTES

    fetch = AsyncMock() if asynchronous else Mock()
    search: Any
    if multiple_windows:
        search = (
            AsyncInvoiceMetadataRangeSearch(machine, fetch)
            if asynchronous
            else InvoiceMetadataRangeSearch(machine, fetch)
        )
    else:
        search = (
            AsyncInvoiceMetadataSearch(machine, fetch)
            if asynchronous
            else InvoiceMetadataSearch(machine, fetch)
        )
    with pytest.raises(KsefInvalidPaginationCursorError) as caught:
        if asynchronous:
            asyncio.run(search.page(cursor))
        else:
            search.page(cursor)
    fetch.assert_not_called()
    assert cursor not in str(caught.value)


def _review_machine(kind: str, order: str) -> _RangeMachine:
    return _RangeMachine(
        {
            "subjectType": "Subject1",
            "dateRange": {
                "dateType": kind,
                "from": (
                    "2024-01-01T12:00:00+02:00"
                    if kind == "Issue"
                    else "2024-01-01T00:00:00.0000001Z"
                ),
                "to": (
                    "2024-01-08T12:00:00+02:00"
                    if kind == "Issue"
                    else "2024-01-08T00:00:00.0000001Z"
                ),
            },
        },
        environment="https://api-test.ksef.mf.gov.pl/v2",
        context_key="Nip:DUMMY",
        page_size=10,
        sort_order=order,
        window_days=1,
    )


class _EmptyTerminalServer:
    """Return a final empty page after every window's nonempty result page."""

    def __init__(self, rows: list[m.InvoiceMetadata], kind: str) -> None:
        self.rows = rows
        self.kind = kind
        self.empty_pages = 0

    def fetch(self, filters, *, page_offset, page_size, sort_order):
        dr = filters.to_dict()["dateRange"]
        low, high = _date(dr["from"]), _date(dr["to"])
        field = "issue_date" if self.kind == "Issue" else "invoicing_date"

        def stamp(item):
            return _date(getattr(item, field))

        if self.kind == "Issue":
            selected = [
                row for row in self.rows if low[0].date() <= stamp(row)[0].date() <= high[0].date()
            ]
        else:
            selected = [row for row in self.rows if low <= stamp(row) <= high]
        selected.sort(key=stamp, reverse=sort_order == "Desc")
        offset = page_offset * page_size
        chunk = selected[offset : offset + page_size]
        if not chunk:
            self.empty_pages += 1
        return m.QueryInvoicesMetadataResponse(
            invoices=chunk, has_more=bool(chunk), is_truncated=False
        )


def _restart_every_page(rows: list[m.InvoiceMetadata], kind: str, order: str):
    server = _EmptyTerminalServer(rows, kind)
    cursor = None
    actual: list[str | None] = []
    for _ in range(100):
        # Construct both objects again: all progress must live in the cursor.
        search = InvoiceMetadataRangeSearch(_review_machine(kind, order), server.fetch)
        page = search.page(cursor)
        actual.extend(item.ksef_number for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            return actual, server
    pytest.fail("Range search did not terminate")


@pytest.mark.parametrize("order", ["Asc", "Desc"])
def test_issue_noon_offset_boundaries_survive_empty_terminal_pages_and_restart(order):
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    rows = [
        m.InvoiceMetadata(
            ksef_number=f"ISSUE-{day}-{index}",
            issue_date=(start + timedelta(days=day)).date().isoformat(),
        )
        for day in range(8)
        for index in range(3)
    ]
    actual, server = _restart_every_page(rows, "Issue", order)
    expected = [
        item.ksef_number
        for item in sorted(rows, key=lambda item: item.issue_date or "", reverse=order == "Desc")
    ]
    assert actual == expected
    assert len(actual) == len(set(actual)) == 24
    assert server.empty_pages == 7


@pytest.mark.parametrize("order", ["Asc", "Desc"])
def test_submicrosecond_invoicing_boundaries_have_no_gaps_after_restart(order):
    stamps = ["2024-01-01T00:00:00.0000001Z", "2024-01-08T00:00:00.0000001Z"]
    for day in range(2, 8):
        stamps.extend(f"2024-01-{day:02}T00:00:00.000000{digit}Z" for digit in range(3))
    rows = [
        m.InvoiceMetadata(ksef_number=f"PRECISE-{index}", invoicing_date=stamp)
        for index, stamp in enumerate(stamps)
    ]
    actual, server = _restart_every_page(rows, "Invoicing", order)
    expected = [
        item.ksef_number
        for item in sorted(
            rows, key=lambda item: _date(item.invoicing_date or ""), reverse=order == "Desc"
        )
    ]
    assert actual == expected
    assert len(actual) == len(set(actual)) == 20
    assert server.empty_pages == 7


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "key,value",
    [("end", []), ("hwm", []), ("window", 10**100), ("window", True)],
    ids=["end-array", "hwm-array", "huge-window", "boolean-window"],
)
def test_malformed_composite_cursor_is_rejected_before_sync_or_async_http(
    asynchronous, key, value
):
    machine = _review_machine("Invoicing", "Asc")
    state = machine.load(None)
    state[key] = value
    cursor = _dump(state)
    fetch = AsyncMock() if asynchronous else Mock()
    search: Any = (
        AsyncInvoiceMetadataRangeSearch(machine, fetch)
        if asynchronous
        else InvoiceMetadataRangeSearch(machine, fetch)
    )
    with pytest.raises(KsefInvalidPaginationCursorError):
        if asynchronous:
            asyncio.run(search.page(cursor))
        else:
            search.page(cursor)
    fetch.assert_not_called()
