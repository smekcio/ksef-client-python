from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from ksef_client import (
    AsyncInvoiceMetadataSearch,
    InvoiceMetadataSearch,
    KsefClientOptions,
    KsefIncompletePaginationError,
    KsefInvalidPaginationCursorError,
)
from ksef_client import (
    models as m,
)
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.invoice_search import MAX_CURSOR_BYTES, _dump, _MetadataMachine


def filters(kind="PermanentStorage", restricted=False, end="2026-10-02T00:00:00Z"):
    return m.InvoiceQueryFilters(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_range=m.InvoiceQueryDateRange(
            date_type=m.InvoiceQueryDateType(kind),
            from_="2026-10-01T00:00:00Z",
            to=end,
            restrict_to_permanent_storage_hwm_date=restricted,
        ),
    )


def machine(kind="PermanentStorage", restricted=False, order="Asc", end="2026-10-02T00:00:00Z"):
    return _MetadataMachine(
        filters(kind, restricted, end).to_dict(),
        environment="https://api-test.ksef.mf.gov.pl/v2",
        context_key="Nip:test",
        page_size=10,
        sort_order=order,
    )


def invoice(number, stamp="2026-10-01T01:00:00Z", kind="PermanentStorage"):
    return m.InvoiceMetadata(
        ksef_number=str(number),
        **{
            {
                "Issue": "issue_date",
                "Invoicing": "invoicing_date",
                "PermanentStorage": "permanent_storage_date",
            }[kind]: stamp
        },
    )


def response(items=(), more=False, truncated=False, hwm=None):
    return m.QueryInvoicesMetadataResponse(
        invoices=list(items), has_more=more, is_truncated=truncated, permanent_storage_hwm_date=hwm
    )


def test_large_dataset_and_restart_after_every_page():
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    rows = [invoice(i, (start + timedelta(seconds=i // 3)).isoformat()) for i in range(10543)]
    cursor = None
    received: list[str | None] = []
    calls = 0
    while True:
        # A fresh machine for every request models a process restart.
        walk = machine()
        state = walk.load(cursor)
        dr = state["request"]["dateRange"]
        lower = datetime.fromisoformat(dr["from"].replace("Z", "+00:00"))
        subset = [
            row for row in rows if datetime.fromisoformat(row.permanent_storage_date) >= lower
        ]
        offset = state["offset"] * 10
        page_rows = subset[offset : offset + 10]
        more = len(subset) > offset + len(page_rows)
        page = walk.advance(state, response(page_rows, more, more and offset == 9990))
        received.extend(row.ksef_number for row in page.items)
        calls += 1
        cursor = page.next_cursor
        if cursor is None:
            break
    assert received == [str(i) for i in range(len(rows))]
    assert calls > 1000


@pytest.mark.parametrize("kind", ["Issue", "Invoicing", "PermanentStorage"])
@pytest.mark.parametrize("order", ["Asc", "Desc"])
def test_inclusive_boundary_deduplication(kind, order):
    walk = machine(kind, order=order)
    a = "2026-10-01" if kind == "Issue" else "2026-10-01T01:00:00.0000001Z"
    b = "2026-10-02" if kind == "Issue" else "2026-10-01T02:00:00Z"
    first, second = (a, b) if order == "Asc" else (b, a)
    page = walk.advance(walk.load(None), response([invoice(1, first, kind)], True, True))
    state = walk.load(page.next_cursor)
    assert state["request"]["dateRange"]["from" if order == "Asc" else "to"] == first
    page = walk.advance(
        state,
        response([invoice(1, first, kind), invoice(2, first, kind), invoice(3, second, kind)]),
    )
    assert [row.ksef_number for row in page.items] == ["2", "3"]
    assert page.next_cursor is None


def test_hwm_is_frozen_and_missing_end_is_frozen():
    walk = machine(restricted=True)
    hwm = "2026-10-01T12:00:00Z"
    page = walk.advance(walk.load(None), response([invoice(1)], True, hwm=hwm))
    state = walk.load(page.next_cursor)
    assert state["hwm"] == state["request"]["dateRange"]["to"] == hwm
    page = walk.advance(
        state, response([invoice(2, "2026-10-01T02:00:00Z")], True, hwm="2026-10-01T13:00:00Z")
    )
    assert walk.load(page.next_cursor)["hwm"] == hwm
    walk = machine(end=None)
    state = walk.load(None)
    state["request"]["dateRange"]["to"] = "2026-10-02T00:00:00Z"
    assert walk.load(_dump(state))["request"]["dateRange"]["to"] == "2026-10-02T00:00:00Z"


def test_empty_pages_and_duplicate_only_pages_keep_cursor():
    walk = machine()
    page = walk.advance(walk.load(None), response([invoice(1)], True, True))
    page = walk.advance(walk.load(page.next_cursor), response([invoice(1)], True))
    assert page.items == [] and page.next_cursor
    for _ in range(2):
        page = walk.advance(walk.load(page.next_cursor), response([], True))
        assert page.next_cursor
    with pytest.raises(KsefIncompletePaginationError, match="empty_pages") as caught:
        walk.advance(walk.load(page.next_cursor), response([], True))
    assert caught.value.last_cursor == page.next_cursor
    assert page.next_cursor not in repr(caught.value)
    assert page.next_cursor not in str(caught.value.to_dict())


@pytest.mark.parametrize(
    "reason,rows,kwargs",
    [
        ("missing_ksef_number", [m.InvoiceMetadata(permanent_storage_date="2026-10-01")], {}),
        ("invalid_invoice_date", [m.InvoiceMetadata(ksef_number="1")], {}),
        ("invalid_invoice_date", [invoice(1, "bad")], {}),
        ("invoice_outside_range", [invoice(1, "2025-01-01")], {}),
        ("inconsistent_sort_order", [invoice(1, "2026-10-01T03:00:00Z"), invoice(2)], {}),
        ("empty_truncated_page", [], {"more": True, "truncated": True}),
    ],
)
def test_incomplete_response(reason, rows, kwargs):
    walk = machine()
    with pytest.raises(KsefIncompletePaginationError, match=reason):
        walk.advance(walk.load(None), response(rows, **kwargs))


def test_truncation_stall_and_unmarked_limit():
    walk = machine()
    page = walk.advance(walk.load(None), response([invoice(1)], True, True))
    with pytest.raises(KsefIncompletePaginationError, match="truncation_did_not_advance"):
        walk.advance(walk.load(page.next_cursor), response([invoice(1)], True, True))
    state = walk.load(None)
    state["offset"] = 999
    with pytest.raises(KsefIncompletePaginationError, match="result_limit_without_truncation"):
        walk.advance(state, response([invoice(1)], True))
    with pytest.raises(KsefIncompletePaginationError, match="boundary_limit_exceeded"):
        walk.advance(walk.load(None), response([invoice(i) for i in range(10001)], True))


@pytest.mark.parametrize(
    "hwm,reason",
    [(None, "invalid_hwm"), ("bad", "invalid_hwm"), ("2026-09-01", "hwm_before_start")],
)
def test_bad_hwm(hwm, reason):
    walk = machine(restricted=True)
    with pytest.raises(KsefIncompletePaginationError, match=reason):
        walk.advance(walk.load(None), response(hwm=hwm))


def test_hwm_regression():
    walk = machine(restricted=True)
    page = walk.advance(walk.load(None), response([invoice(1)], True, hwm="2026-10-01T12:00:00Z"))
    with pytest.raises(KsefIncompletePaginationError, match="hwm_regressed"):
        walk.advance(walk.load(page.next_cursor), response(hwm="2026-10-01T11:00:00Z"))


@pytest.mark.parametrize(
    "cursor",
    [
        "",
        "!DUMMY_SECRET!",
        "x",
        "W10",
        "bnVsbA",
        42,
        "A" * (MAX_CURSOR_BYTES + 1),
        base64.urlsafe_b64encode(b'{"version":NaN}').decode(),
    ],
    ids=["empty", "invalid", "padding", "list", "null", "integer", "oversize", "nan"],
)
def test_invalid_cursor(cursor):
    with pytest.raises(KsefInvalidPaginationCursorError) as caught:
        machine().load(cursor)
    assert "DUMMY_SECRET" not in str(caught.value)


@pytest.mark.parametrize(
    "key,value",
    [
        ("version", True),
        ("version", 2),
        ("context_key", "different"),
        ("environment", "prod"),
        ("page_size", 20),
        ("sort_order", "Desc"),
        ("offset", -1),
        ("offset", True),
        ("offset", 1001),
        ("empty", 3),
        ("seen", [""]),
        ("seen", ["x", "x"]),
        ("seen", "x"),
        ("seen", [1]),
        ("seen", ["x" * 257]),
        ("last_date", 1),
        ("last_date", "bad"),
        ("last_date", "2026-10-01"),
        ("request", []),
        ("request", {}),
        ("hwm", "2026-09-01"),
    ],
)
def test_tampered_state(key, value):
    walk = machine()
    state = walk.load(None)
    state[key] = value
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))


@pytest.mark.parametrize(
    "change",
    [
        {"from": "2026-09-01"},
        {"to": "2026-10-03"},
        {"dateType": "Issue"},
        {"restrictToPermanentStorageHwmDate": True},
        {"extra": "not allowed"},
        {"from": 1},
        {"to": None},
        {"to": "bad"},
        {"from": "2027-01-01"},
        {"to": "2027-01-01"},
    ],
)
def test_cursor_cannot_widen_or_change_query(change):
    walk = machine()
    state = walk.load(None)
    state["request"]["dateRange"].update(change)
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))


def test_changed_non_date_filters_and_large_cursor():
    walk = machine()
    state = walk.load(None)
    state["request"]["subjectType"] = "Subject2"
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))
    with pytest.raises(KsefInvalidPaginationCursorError):
        _dump({"large": "x" * MAX_CURSOR_BYTES})


@pytest.mark.parametrize(
    "kwargs", [{"context_key": ""}, {"context_key": None}, {"sort_order": "desc"}, {"page_size": 9}]
)
def test_bad_search_settings(kwargs):
    settings: dict[str, Any] = dict(
        environment="test", context_key="Nip:test", page_size=10, sort_order="Asc"
    )
    settings.update(kwargs)
    with pytest.raises((ValueError, TypeError)):
        _MetadataMachine(filters().to_dict(), **settings)


def test_invalid_initial_ranges():
    for change in [
        {"dateType": "invalid"},
        {"from": None},
        {"to": None, "restrictToPermanentStorageHwmDate": "yes"},
        {"from": "bad"},
    ]:
        data = filters().to_dict()
        data["dateRange"].update(change)
        with pytest.raises(ValueError):
            walk = _MetadataMachine(
                data, environment="test", context_key="nip", page_size=10, sort_order="Asc"
            )
            walk.load(None)


def test_client_facades_sync_and_async():
    options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    calls = []

    def fetch(*args, **kwargs):
        calls.append(kwargs)
        return response([invoice(1)], kwargs["page_offset"] == 0)

    http = SimpleNamespace(_options=options)
    client = InvoicesClient(http)
    client.query_invoice_metadata = fetch
    search = client.search_invoice_metadata(filters(), context_key="nip", page_size=10)
    assert calls == []
    first = search.page()
    assert first.next_cursor is not None
    assert first.next_cursor not in repr(first)
    assert list(search.items(first.next_cursor)) == []
    assert [i.ksef_number for i in search] == ["1"]
    assert len(list(search.pages())) == 2
    with pytest.raises(ValueError, match="environment"):
        InvoicesClient(SimpleNamespace()).search_invoice_metadata(filters(), context_key="nip")
    with pytest.raises(ValueError, match="environment"):
        AsyncInvoicesClient(SimpleNamespace()).search_invoice_metadata(filters(), context_key="nip")

    async def run():
        async def afetch(*args, **kwargs):
            return fetch(*args, **kwargs)

        client = AsyncInvoicesClient(http)
        client.query_invoice_metadata = afetch
        search = client.search_invoice_metadata(filters(), context_key="nip", page_size=10)
        first = await search.page()
        assert [i async for i in search.items(first.next_cursor)] == []
        assert [i.ksef_number async for i in search] == ["1"]
        assert len([p async for p in search.pages()]) == 2

    asyncio.run(run())


def test_fetch_failure_does_not_advance_cursor():
    walk = machine()
    state = walk.load(None)
    cursor = _dump(state)

    def failed(*args, **kwargs):
        raise RuntimeError("network")

    with pytest.raises(RuntimeError):
        InvoiceMetadataSearch(walk, failed).page(cursor)
    assert _dump(walk.load(cursor)) == cursor

    async def run():
        async def failed(*args, **kwargs):
            raise RuntimeError("network")

        with pytest.raises(RuntimeError):
            await AsyncInvoiceMetadataSearch(walk, failed).page(cursor)

    asyncio.run(run())


def test_repeated_nonempty_pages_fail_instead_of_looping():
    walk = machine()
    page = walk.advance(walk.load(None), response([invoice(1)], True))
    for _ in range(2):
        page = walk.advance(walk.load(page.next_cursor), response([invoice(1)], True))
    with pytest.raises(KsefIncompletePaginationError, match="repeated_page"):
        walk.advance(walk.load(page.next_cursor), response([invoice(1)], True))
