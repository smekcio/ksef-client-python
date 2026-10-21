from __future__ import annotations

import asyncio
import warnings
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import pytest

from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.models import (
    InvoiceMetadata,
    InvoiceQueryDateRange,
    InvoiceQueryDateType,
    InvoiceQueryFilters,
    InvoiceQuerySubjectType,
    QueryInvoicesMetadataResponse,
)
from ksef_client.pagination import (
    INVOICE_METADATA_PAGE_SIZE_DEFAULT,
    INVOICE_METADATA_PAGE_SIZE_MAX,
    INVOICE_METADATA_RESULT_LIMIT,
    PAGE_SIZE_MIN,
    KsefPaginationWarning,
    iter_page_offsets,
    page_should_continue,
    pagination_warning,
    validate_max_pages,
    validate_page_offset,
    validate_page_size,
)


def _page(
    count: int,
    *,
    has_more: bool,
    is_truncated: bool = False,
) -> QueryInvoicesMetadataResponse:
    return QueryInvoicesMetadataResponse(
        invoices=[InvoiceMetadata(ksef_number=f"KSEF-{index}") for index in range(count)],
        has_more=has_more,
        is_truncated=is_truncated,
    )


def _filters() -> InvoiceQueryFilters:
    return InvoiceQueryFilters(
        subject_type=InvoiceQuerySubjectType.SUBJECT1,
        date_range=InvoiceQueryDateRange(
            date_type=InvoiceQueryDateType.ISSUE,
            from_="2026-01-01T00:00:00Z",
        ),
    )


class _RecordingInvoicesClient(InvoicesClient):
    """Klient bez transportu, który zapisuje wywołania i zwraca zaplanowane strony."""

    def __init__(self, pages: list[QueryInvoicesMetadataResponse]) -> None:
        super().__init__(http_client=cast(Any, None))
        self.pages = list(pages)
        self.calls: list[dict[str, Any]] = []

    def query_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        self.calls.append(
            {
                "payload": request_payload,
                "access_token": access_token,
                "page_offset": page_offset,
                "page_size": page_size,
                "sort_order": sort_order,
            }
        )
        return self.pages.pop(0)


class _RecordingAsyncInvoicesClient(AsyncInvoicesClient):
    def __init__(self, pages: list[QueryInvoicesMetadataResponse]) -> None:
        super().__init__(http_client=cast(Any, None))
        self.pages = list(pages)
        self.calls: list[dict[str, Any]] = []

    async def query_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        self.calls.append(
            {
                "payload": request_payload,
                "access_token": access_token,
                "page_offset": page_offset,
                "page_size": page_size,
                "sort_order": sort_order,
            }
        )
        return self.pages.pop(0)


def _collect(iterator: Any) -> list[Any]:
    return list(iterator)


def _collect_async(iterator: AsyncIterator[Any]) -> list[Any]:
    async def _run() -> list[Any]:
        return [item async for item in iterator]

    return asyncio.run(_run())


# --- walidacja parametrów -------------------------------------------------


def test_page_size_constants_match_the_contract() -> None:
    assert PAGE_SIZE_MIN == 10
    assert INVOICE_METADATA_PAGE_SIZE_MAX == 250
    assert PAGE_SIZE_MIN <= INVOICE_METADATA_PAGE_SIZE_DEFAULT <= INVOICE_METADATA_PAGE_SIZE_MAX
    assert INVOICE_METADATA_RESULT_LIMIT == 10_000


def test_validate_page_size_accepts_boundaries() -> None:
    assert validate_page_size(PAGE_SIZE_MIN) == PAGE_SIZE_MIN
    assert validate_page_size(INVOICE_METADATA_PAGE_SIZE_MAX) == INVOICE_METADATA_PAGE_SIZE_MAX
    assert validate_page_size(100, maximum=200, minimum=10) == 100


@pytest.mark.parametrize("value", [PAGE_SIZE_MIN - 1, INVOICE_METADATA_PAGE_SIZE_MAX + 1, 0, -5])
def test_validate_page_size_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="page_size musi mieścić się"):
        validate_page_size(value)


@pytest.mark.parametrize("value", [10.0, "10", None, True])
def test_validate_page_size_rejects_non_integers(value: Any) -> None:
    with pytest.raises(TypeError, match="page_size musi być liczbą całkowitą"):
        validate_page_size(value)


def test_validate_page_offset_accepts_zero_and_positive() -> None:
    assert validate_page_offset(0) == 0
    assert validate_page_offset(7) == 7


def test_validate_page_offset_rejects_negative() -> None:
    with pytest.raises(ValueError, match="nie może być ujemny"):
        validate_page_offset(-1)


@pytest.mark.parametrize("value", [1.5, "0", None, False])
def test_validate_page_offset_rejects_non_integers(value: Any) -> None:
    with pytest.raises(TypeError, match="page_offset musi być liczbą całkowitą"):
        validate_page_offset(value)


def test_validate_max_pages_allows_none_and_positive() -> None:
    assert validate_max_pages(None) is None
    assert validate_max_pages(1) == 1


@pytest.mark.parametrize("value", [0, -3])
def test_validate_max_pages_rejects_too_small(value: int) -> None:
    with pytest.raises(ValueError, match="musi być większe od zera"):
        validate_max_pages(value)


@pytest.mark.parametrize("value", [2.0, "3", False])
def test_validate_max_pages_rejects_non_integers(value: Any) -> None:
    with pytest.raises(TypeError, match="max_pages musi być liczbą całkowitą"):
        validate_max_pages(value)


# --- generowanie offsetów -------------------------------------------------


def test_iter_page_offsets_without_limit_is_infinite() -> None:
    offsets = iter_page_offsets(page_size=100)
    assert [next(offsets) for _ in range(4)] == [0, 100, 200, 300]


def test_iter_page_offsets_honours_start_and_max_pages() -> None:
    assert list(iter_page_offsets(page_size=50, start_offset=150, max_pages=2)) == [150, 200]


def test_iter_page_offsets_stops_at_max_pages_zero_pages() -> None:
    # max_pages jest walidowane, więc 0 jest odrzucane, a nie „puste”.
    with pytest.raises(ValueError):
        list(iter_page_offsets(page_size=50, max_pages=0))


def test_iter_page_offsets_validates_inputs() -> None:
    with pytest.raises(ValueError):
        list(iter_page_offsets(page_size=1))
    with pytest.raises(ValueError):
        list(iter_page_offsets(page_size=50, start_offset=-1))


# --- warunki zakończenia --------------------------------------------------


def test_page_should_continue_true_only_when_more_items() -> None:
    assert page_should_continue(_page(2, has_more=True)) is True
    assert page_should_continue(_page(2, has_more=False)) is False
    assert page_should_continue(_page(2, has_more=True, is_truncated=True)) is False
    assert page_should_continue(_page(0, has_more=True)) is False
    assert page_should_continue(_page(0, has_more=False)) is False


def test_pagination_warning_is_none_for_normal_end() -> None:
    assert pagination_warning(_page(3, has_more=False), page_size=100, page_offset=0) is None


def test_pagination_warning_reports_truncation() -> None:
    message = pagination_warning(
        _page(250, has_more=True, is_truncated=True), page_size=250, page_offset=0
    )
    assert message is not None
    assert "isTruncated" in message
    assert str(INVOICE_METADATA_RESULT_LIMIT) in message


def test_pagination_warning_reports_empty_page_with_more() -> None:
    message = pagination_warning(_page(0, has_more=True), page_size=100, page_offset=200)
    assert message is not None
    assert "pustą stronę" in message
    assert "pageOffset=200" in message


# --- klient synchroniczny -------------------------------------------------


def test_iter_pages_walks_all_pages_and_stops_on_has_more_false() -> None:
    client = _RecordingInvoicesClient(
        [
            _page(2, has_more=True),
            _page(1, has_more=True),
            _page(0, has_more=False),
        ]
    )

    pages = list(
        client.iter_invoice_metadata_pages(
            _filters(), access_token="token", page_size=50, sort_order="Desc"
        )
    )

    assert [len(page.invoices) for page in pages] == [2, 1, 0]
    assert [call["page_offset"] for call in client.calls] == [0, 50, 100]
    assert {call["page_size"] for call in client.calls} == {50}
    assert {call["sort_order"] for call in client.calls} == {"Desc"}
    assert {call["access_token"] for call in client.calls} == {"token"}


def test_iter_metadata_flattens_pages() -> None:
    client = _RecordingInvoicesClient(
        [
            _page(2, has_more=True),
            _page(3, has_more=False),
        ]
    )

    invoices = list(client.iter_invoice_metadata(_filters(), access_token="token"))

    assert [invoice.ksef_number for invoice in invoices] == [
        "KSEF-0",
        "KSEF-1",
        "KSEF-0",
        "KSEF-1",
        "KSEF-2",
    ]


def test_iter_metadata_honours_page_offset_and_max_pages() -> None:
    client = _RecordingInvoicesClient(
        [
            _page(2, has_more=True),
            _page(2, has_more=True),
        ]
    )

    invoices = list(
        client.iter_invoice_metadata(
            _filters(),
            access_token="token",
            page_size=10,
            page_offset=30,
            max_pages=2,
        )
    )

    assert len(invoices) == 4
    assert [call["page_offset"] for call in client.calls] == [30, 40]


def test_iter_metadata_by_date_range_builds_filters_and_iterates() -> None:
    client = _RecordingInvoicesClient([_page(1, has_more=False)])

    invoices = list(
        client.iter_invoice_metadata_by_date_range(
            subject_type=InvoiceQuerySubjectType.SUBJECT1,
            date_type=InvoiceQueryDateType.ISSUE,
            date_from="2026-01-01T00:00:00Z",
            date_to="2026-01-31T00:00:00Z",
            access_token="token",
            page_size=100,
        )
    )

    assert len(invoices) == 1
    payload = client.calls[0]["payload"]
    assert payload.to_dict()["dateRange"]["from"] == "2026-01-01T00:00:00Z"


def test_iter_pages_warns_and_stops_on_truncation() -> None:
    client = _RecordingInvoicesClient(
        [
            _page(2, has_more=True, is_truncated=True),
            _page(2, has_more=False),
        ]
    )

    with pytest.warns(KsefPaginationWarning, match="isTruncated"):
        pages = list(client.iter_invoice_metadata_pages(_filters(), access_token="token"))

    assert len(pages) == 1
    assert len(client.calls) == 1


def test_iter_pages_warns_and_stops_on_empty_page_with_more() -> None:
    client = _RecordingInvoicesClient(
        [
            _page(0, has_more=True),
            _page(1, has_more=False),
        ]
    )

    with pytest.warns(KsefPaginationWarning, match="pustą stronę"):
        pages = list(client.iter_invoice_metadata_pages(_filters(), access_token="token"))

    assert len(pages) == 1
    assert len(client.calls) == 1


def test_iter_pages_does_not_warn_for_last_page_with_items() -> None:
    client = _RecordingInvoicesClient([_page(1, has_more=False)])

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        pages = list(client.iter_invoice_metadata_pages(_filters(), access_token="token"))

    assert len(pages) == 1


def test_iter_pages_rejects_invalid_page_size_before_any_request() -> None:
    client = _RecordingInvoicesClient([_page(1, has_more=False)])

    with pytest.raises(ValueError, match="page_size"):
        list(client.iter_invoice_metadata_pages(_filters(), access_token="token", page_size=1))

    assert client.calls == []


# --- klient asynchroniczny ------------------------------------------------


def test_async_iter_pages_walks_all_pages() -> None:
    client = _RecordingAsyncInvoicesClient(
        [
            _page(1, has_more=True),
            _page(2, has_more=False),
        ]
    )

    pages = _collect_async(
        client.iter_invoice_metadata_pages(_filters(), access_token="token", page_size=250)
    )

    assert [len(page.invoices) for page in pages] == [1, 2]
    assert [call["page_offset"] for call in client.calls] == [0, 250]


def test_async_iter_metadata_flattens_pages() -> None:
    client = _RecordingAsyncInvoicesClient(
        [
            _page(2, has_more=True),
            _page(1, has_more=False),
        ]
    )

    invoices = _collect_async(client.iter_invoice_metadata(_filters(), access_token="token"))

    assert [invoice.ksef_number for invoice in invoices] == ["KSEF-0", "KSEF-1", "KSEF-0"]


def test_async_iter_metadata_by_date_range_builds_filters() -> None:
    client = _RecordingAsyncInvoicesClient([_page(1, has_more=False)])

    invoices = _collect_async(
        client.iter_invoice_metadata_by_date_range(
            subject_type=InvoiceQuerySubjectType.SUBJECT1,
            date_type=InvoiceQueryDateType.ISSUE,
            date_from="2026-01-01T00:00:00Z",
            access_token="token",
        )
    )

    assert len(invoices) == 1
    assert client.calls[0]["payload"].to_dict()["dateRange"]["from"] == "2026-01-01T00:00:00Z"


def test_async_iter_pages_warns_and_stops_on_truncation() -> None:
    client = _RecordingAsyncInvoicesClient(
        [
            _page(1, has_more=True, is_truncated=True),
            _page(1, has_more=False),
        ]
    )

    with pytest.warns(KsefPaginationWarning, match="isTruncated"):
        pages = _collect_async(
            client.iter_invoice_metadata_pages(_filters(), access_token="token")
        )

    assert len(pages) == 1
    assert len(client.calls) == 1


def test_async_iter_pages_warns_and_stops_on_empty_page_with_more() -> None:
    client = _RecordingAsyncInvoicesClient([_page(0, has_more=True)])

    with pytest.warns(KsefPaginationWarning, match="pustą stronę"):
        pages = _collect_async(
            client.iter_invoice_metadata_pages(_filters(), access_token="token")
        )

    assert len(pages) == 1


def test_async_iter_pages_rejects_invalid_max_pages() -> None:
    client = _RecordingAsyncInvoicesClient([_page(1, has_more=False)])

    with pytest.raises(ValueError, match="max_pages"):
        _collect_async(
            client.iter_invoice_metadata_pages(
                _filters(), access_token="token", max_pages=0
            )
        )

    assert client.calls == []


def test_async_iter_pages_honours_max_pages() -> None:
    client = _RecordingAsyncInvoicesClient(
        [
            _page(1, has_more=True),
            _page(1, has_more=True),
            _page(1, has_more=False),
        ]
    )

    pages = _collect_async(
        client.iter_invoice_metadata_pages(
            _filters(), access_token="token", page_size=10, max_pages=2
        )
    )

    assert len(pages) == 2
    assert len(client.calls) == 2


# --- review 2: atrybucja ostrzeżeń do kodu wołającego ----------------------


def test_pages_warning_points_to_caller() -> None:
    client = _RecordingInvoicesClient([_page(1, has_more=True, is_truncated=True)])

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        list(client.iter_invoice_metadata_pages(_filters(), access_token="token"))

    assert len(caught) == 1
    assert Path(caught[0].filename).name == "test_pagination.py"


def test_items_warning_points_to_caller() -> None:
    client = _RecordingInvoicesClient([_page(1, has_more=True, is_truncated=True)])

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        list(client.iter_invoice_metadata(_filters(), access_token="token"))

    assert len(caught) == 1
    assert Path(caught[0].filename).name == "test_pagination.py"


def test_date_range_warning_points_to_caller() -> None:
    client = _RecordingInvoicesClient([_page(1, has_more=True, is_truncated=True)])

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        list(
            client.iter_invoice_metadata_by_date_range(
                subject_type=InvoiceQuerySubjectType.SUBJECT1,
                date_type=InvoiceQueryDateType.ISSUE,
                date_from="2026-01-01T00:00:00Z",
                access_token="token",
            )
        )

    assert len(caught) == 1
    assert Path(caught[0].filename).name == "test_pagination.py"


def test_async_items_warn_on_truncation() -> None:
    client = _RecordingAsyncInvoicesClient([_page(1, has_more=True, is_truncated=True)])

    with pytest.warns(KsefPaginationWarning, match="isTruncated"):
        invoices = _collect_async(client.iter_invoice_metadata(_filters(), access_token="token"))

    assert len(invoices) == 1
    assert len(client.calls) == 1


def test_async_date_range_warns_on_truncation() -> None:
    client = _RecordingAsyncInvoicesClient([_page(1, has_more=True, is_truncated=True)])

    with pytest.warns(KsefPaginationWarning, match="isTruncated"):
        invoices = _collect_async(
            client.iter_invoice_metadata_by_date_range(
                subject_type=InvoiceQuerySubjectType.SUBJECT1,
                date_type=InvoiceQueryDateType.ISSUE,
                date_from="2026-01-01T00:00:00Z",
                access_token="token",
            )
        )

    assert len(invoices) == 1
    assert len(client.calls) == 1
