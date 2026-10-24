from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from ksef_client import KsefClientOptions
from ksef_client import models as m
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.exceptions import KsefIncompletePaginationError, KsefInvalidPaginationCursorError
from ksef_client.invoice_range_search import (
    MAX_CURSOR_BYTES,
    AsyncInvoiceMetadataRangeSearch,
    InvoiceMetadataRangeSearch,
    _RangeMachine,
    _shift,
)
from ksef_client.invoice_search import _date, _dump, _InvalidMetadataResponse


def filters(
    kind="PermanentStorage",
    start="2024-01-01T00:00:00Z",
    end="2026-01-01T00:00:00Z",
    restricted=True,
):
    return m.InvoiceQueryFilters(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_range=m.InvoiceQueryDateRange(
            date_type=m.InvoiceQueryDateType(kind),
            from_=start,
            to=end,
            restrict_to_permanent_storage_hwm_date=restricted and kind == "PermanentStorage",
        ),
    )


def machine(
    kind="PermanentStorage",
    order="Asc",
    days=100,
    end="2026-01-01T00:00:00Z",
    start="2024-01-01T00:00:00Z",
    restricted=True,
):
    return _RangeMachine(
        filters(kind, start, end, restricted).to_dict(),
        environment="https://api-test.ksef.mf.gov.pl/v2",
        context_key="Nip:test",
        page_size=37,
        sort_order=order,
        window_days=days,
    )


def row(number, stamp, kind="PermanentStorage"):
    field = {
        "Issue": "issue_date",
        "Invoicing": "invoicing_date",
        "PermanentStorage": "permanent_storage_date",
    }[kind]
    return m.InvoiceMetadata(ksef_number=str(number), **{field: stamp})


class Server:
    def __init__(self, rows, kind="PermanentStorage", hwm=None, cap=10000):
        self.rows, self.kind, self.hwm, self.cap = rows, kind, hwm, cap
        self.calls = []

    def fetch(self, request, *, page_offset, page_size, sort_order, **kwargs):
        dr = request.to_dict()["dateRange"]
        assert (_date(dr["to"])[0].date() - _date(dr["from"])[0].date()).days <= 100
        self.calls.append((deepcopy(dr), page_offset))
        low, high = _date(dr["from"]), _date(dr["to"])
        hwm = None
        if self.kind == "PermanentStorage" and dr.get("restrictToPermanentStorageHwmDate"):
            hwm = min((self.hwm or dr["to"], dr["to"]), key=_date)
            high = _date(hwm)
        field = {
            "Issue": "issue_date",
            "Invoicing": "invoicing_date",
            "PermanentStorage": "permanent_storage_date",
        }[self.kind]

        def key(item):
            return _date(getattr(item, field))

        if self.kind == "Issue":
            selected = [
                item for item in self.rows if low[0].date() <= key(item)[0].date() <= high[0].date()
            ]
        else:
            selected = [item for item in self.rows if low <= key(item) <= high]
        selected = sorted(selected, key=key, reverse=sort_order == "Desc")
        offset = page_offset * page_size
        chunk = selected[offset : min(offset + page_size, self.cap)]
        more = offset + len(chunk) < len(selected)
        return m.QueryInvoicesMetadataResponse(
            invoices=chunk,
            has_more=more,
            is_truncated=more and offset + len(chunk) == self.cap,
            permanent_storage_hwm_date=hwm,
        )


@pytest.mark.parametrize("kind", ["Issue", "Invoicing", "PermanentStorage"])
@pytest.mark.parametrize("order", ["Asc", "Desc"])
def test_two_year_scan_restarts_after_every_page_and_window_without_duplicates(kind, order):
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    rows = [
        row(
            i,
            (start + timedelta(hours=12 * i)).isoformat()
            if kind != "Issue"
            else (start + timedelta(hours=12 * i)).date().isoformat(),
            kind,
        )
        for i in range(1463)
    ]
    server = Server(rows, kind)
    cursor = None
    actual: list[str | None] = []
    while True:
        # New search object and machine on every request model a process restart.
        search = InvoiceMetadataRangeSearch(machine(kind, order), server.fetch)
        page = search.page(cursor)
        actual.extend(item.ksef_number for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    expected = [
        item.ksef_number
        for item in sorted(
            rows,
            key=lambda item: _date(
                getattr(
                    item,
                    {
                        "Issue": "issue_date",
                        "Invoicing": "invoicing_date",
                        "PermanentStorage": "permanent_storage_date",
                    }[kind],
                )
            ),
            reverse=order == "Desc",
        )
    ]
    assert actual == expected
    assert len(actual) == len(set(actual)) == len(rows)
    assert sum(offset == 0 for _, offset in server.calls) == 8


@pytest.mark.parametrize("order", ["Asc", "Desc"])
def test_sync_async_pages_have_identical_cursors_and_transitions(order):
    rows = [row(i, f"2024-01-{i + 1:02}T00:00:00.0000001Z") for i in range(20)]
    sync_server, async_server = Server(rows), Server(rows)
    sync = list(InvoiceMetadataRangeSearch(machine(order=order, days=7), sync_server.fetch).pages())

    async def run():
        async def fetch(*args, **kwargs):
            return async_server.fetch(*args, **kwargs)

        search = AsyncInvoiceMetadataRangeSearch(machine(order=order, days=7), fetch)
        pages = [page async for page in search.pages()]
        assert [item.ksef_number async for item in search] == [
            item.ksef_number for page in pages for item in page.items
        ]
        assert [item.ksef_number async for item in search.items()] == [
            item.ksef_number for page in pages for item in page.items
        ]
        return pages

    asynchronous = asyncio.run(run())
    assert asynchronous == sync
    assert list(InvoiceMetadataRangeSearch(machine(order=order, days=7), sync_server.fetch)) == [
        item for page in sync for item in page.items
    ]


def test_truncation_and_multi_page_overlap_at_an_inclusive_window_boundary():
    boundary = "2024-04-10T00:00:00Z"  # 100 UTC days after leap-year January 1.
    rows = [row(i, boundary) for i in range(120)]
    # First window has exactly the boundary records; next overlaps all of them.
    # Further newer invoices force continuation after that long dedupe prefix.
    rows.extend(row(i, "2024-04-11T00:00:00Z") for i in range(120, 160))
    server = Server(rows)
    search = InvoiceMetadataRangeSearch(machine(), server.fetch)
    assert [item.ksef_number for item in search] == [str(i) for i in range(160)]


def test_truncated_single_window_inside_a_two_year_scan():
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    rows = [row(i, (start + timedelta(seconds=i)).isoformat()) for i in range(10050)]
    server = Server(rows)
    actual = list(InvoiceMetadataRangeSearch(machine(), server.fetch))
    assert [item.ksef_number for item in actual] == [str(i) for i in range(10050)]


@pytest.mark.parametrize("order", ["Asc", "Desc"])
def test_hwm_clipping_reports_actual_upper_bound_and_never_jumps_a_gap(order):
    hwm = "2025-12-01T00:00:00Z" if order == "Desc" else "2024-02-01T00:00:00Z"
    rows = [row(1, "2024-01-15T00:00:00Z"), row(2, hwm), row(3, "2025-12-31T00:00:00Z")]
    server = Server(rows, hwm=hwm)
    pages = list(InvoiceMetadataRangeSearch(machine(order=order), server.fetch).pages())
    assert [item.ksef_number for page in pages for item in page.items] == (
        ["1", "2"] if order == "Asc" else ["2", "1"]
    )
    assert pages[-1].permanent_storage_hwm_date == hwm
    assert pages[-1].next_cursor is None
    if order == "Asc":
        assert len(server.calls) == 1


def test_missing_end_is_frozen_once_and_resume_does_not_expand_with_the_clock(monkeypatch):
    import ksef_client.invoice_range_search as ranges

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(ranges, "datetime", Clock)
    walk = machine(end=None)
    page = InvoiceMetadataRangeSearch(walk, Server([]).fetch).page()
    state = walk.load(page.next_cursor)
    assert state["end"] == "2026-01-01T00:00:00+00:00"

    class Future(Clock):
        @classmethod
        def now(cls, tz=None):
            return datetime(2027, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(ranges, "datetime", Future)
    assert machine(end=None).load(page.next_cursor)["end"] == state["end"]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_client_range_factory_accepts_long_period_and_keeps_single_request_limit(asynchronous):
    http = SimpleNamespace(_options=KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl"))
    client = (AsyncInvoicesClient if asynchronous else InvoicesClient)(http)
    server = Server([row(1, "2024-01-15T00:00:00Z")])

    async def fetch(*args, **kwargs):
        return server.fetch(*args, **kwargs)

    cast(Any, client)._query_invoice_metadata_search_page = fetch if asynchronous else server.fetch
    search = client.search_invoice_metadata_range(filters(), context_key="test", window_days=90)
    if asynchronous:

        async def run():
            return [item async for item in cast(AsyncInvoiceMetadataRangeSearch, search)]

        actual = asyncio.run(run())
    else:
        actual = list(cast(InvoiceMetadataRangeSearch, search))
    assert [item.ksef_number for item in actual] == ["1"]
    with pytest.raises(ValueError, match="100"):
        client.search_invoice_metadata(filters(), context_key="test")
    with pytest.raises(ValueError, match="environment"):
        (AsyncInvoicesClient if asynchronous else InvoicesClient)(
            SimpleNamespace()
        ).search_invoice_metadata_range(filters(), context_key="test")


@pytest.mark.parametrize(
    "key,value",
    [
        ("version", True),
        ("version", 2),
        ("kind", "other"),
        ("window", -1),
        ("window", True),
        ("window", 3_652_059),
        ("window", 10000),
        ("window_days", 1),
        ("context_key", "other"),
        ("environment", "https://evil.invalid"),
        ("end", "2027-01-01"),
        ("child", {}),
        ("hwm", "2027-01-01"),
    ],
)
def test_corrupt_range_cursor_is_rejected_before_fetch(key, value):
    walk = machine()
    state = walk.load(None)
    state[key] = value
    fetch = Mock()
    with pytest.raises(KsefInvalidPaginationCursorError):
        InvoiceMetadataRangeSearch(walk, fetch).page(_dump(state))
    fetch.assert_not_called()


@pytest.mark.parametrize(
    "cursor",
    [
        "",
        "bad!",
        3,
        "W10",
        "A" * (MAX_CURSOR_BYTES + 1),
        base64.urlsafe_b64encode(b'{"a":1,"a":2}').decode(),
    ],
    ids=["empty", "bad", "integer", "list", "oversized", "duplicate-json"],
)
def test_malformed_range_cursors(cursor):
    with pytest.raises(KsefInvalidPaginationCursorError):
        machine().load(cursor)


@pytest.mark.parametrize(
    "key,value",
    [
        ("window_days", 0),
        ("window_days", 101),
        ("window_days", True),
        ("sort_order", "bad"),
        ("context_key", " "),
    ],
)
def test_invalid_range_configuration(key, value):
    kwargs: dict[str, Any] = dict(
        environment="test", context_key="test", page_size=10, sort_order="Asc", window_days=100
    )
    kwargs[key] = value
    with pytest.raises((ValueError, TypeError)):
        _RangeMachine(filters().to_dict(), **kwargs)


def test_fractional_dates_and_calendar_extremes_never_lose_boundary_precision():
    assert _shift("2024-01-01T01:00:00.1234567+01:00", 1) == "2024-01-02T00:00:00.1234567+00:00"
    for order, start, end in [
        ("Asc", "9999-12-01", "9999-12-31"),
        ("Desc", "0001-01-01", "0001-01-31"),
    ]:
        pages = list(
            InvoiceMetadataRangeSearch(
                machine(order=order, start=start, end=end), Server([]).fetch
            ).pages()
        )
        assert len(pages) == 1 and pages[0].next_cursor is None


@pytest.mark.parametrize("asynchronous", [False, True])
def test_invalid_response_retains_the_outer_cursor(asynchronous):
    def invalid(*args, **kwargs):
        raise _InvalidMetadataResponse("invalid")

    search = InvoiceMetadataRangeSearch(machine(), invalid)
    if asynchronous:

        async def fetch(*args, **kwargs):
            return invalid(*args, **kwargs)

        async def run():
            await AsyncInvoiceMetadataRangeSearch(machine(), fetch).page()

        def call():
            return asyncio.run(run())
    else:
        call = search.page
    with pytest.raises(KsefIncompletePaginationError, match="invalid_response") as caught:
        call()
    state = machine().load(caught.value.last_cursor)
    assert state["kind"] == "invoice-metadata-range" and state["window"] == 0


def test_bad_range_bounds_are_explicit_validation_errors():
    kwargs: dict[str, Any] = dict(
        environment="test", context_key="test", page_size=10, sort_order="Asc", window_days=100
    )
    with pytest.raises(ValueError, match="dateRange"):
        _RangeMachine({}, **kwargs)
    with pytest.raises(ValueError, match="from <= to"):
        machine(start="2026-01-02", end="2026-01-01")
    with pytest.raises(ValueError, match="from <= to"):
        machine(start="9999-01-01", end=None).load(None)


def test_open_range_cursor_cannot_have_an_inverted_end():
    walk = machine(end=None)
    state = walk.load(None)
    state["end"] = "2023-01-01"
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))


def test_cursor_boundary_and_hwm_must_be_consistent_with_the_complete_range():
    walk = machine()
    state = walk.load(None)
    state["child"].update(last_date="2023-01-01", seen=["A"])
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))
    page = InvoiceMetadataRangeSearch(walk, Server([]).fetch).page()
    state = walk.load(page.next_cursor)
    state["hwm"] = None
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))
    state["hwm"] = "2025-01-01"
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))


def test_generated_outer_cursor_size_failures_keep_a_replayable_outer_cursor(monkeypatch):
    import ksef_client.invoice_search as searches
    from ksef_client import KsefPaginationError

    walk = machine()
    state = walk.load(None)
    child_limit = len(_dump(state["child"])) + 20
    outer_limit = len(_dump(state)) + 20
    monkeypatch.setattr(searches, "MAX_CURSOR_BYTES", child_limit)
    with pytest.raises(KsefPaginationError, match="Search state"):
        walk.load(None)
    monkeypatch.setattr(searches, "MAX_CURSOR_BYTES", outer_limit)
    with pytest.raises(KsefIncompletePaginationError, match="cursor_size_limit") as caught:
        walk.advance(
            state,
            Server([row(1, "2024-01-15T00:00:00Z")]).fetch(
                m.InvoiceQueryFilters.from_dict(state["child"]["request"]),
                page_offset=0,
                page_size=37,
                sort_order="Asc",
            ),
        )
    assert walk.load(caught.value.last_cursor)["window"] == 0


def test_incomplete_child_response_is_wrapped_with_outer_replay_state():
    walk = machine()
    with pytest.raises(KsefIncompletePaginationError, match="missing_ksef_number") as caught:
        walk.advance(
            walk.load(None),
            m.QueryInvoicesMetadataResponse(
                invoices=[m.InvoiceMetadata(permanent_storage_date="2024-01-01")],
                permanent_storage_hwm_date="2024-04-10T00:00:00Z",
            ),
        )
    assert walk.load(caught.value.last_cursor)["kind"] == "invoice-metadata-range"
