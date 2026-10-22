from __future__ import annotations

import re
import warnings
from collections.abc import AsyncIterator, Iterator
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from typing import Any

from ..models import (
    BinaryContent,
    ExportInvoicesResponse,
    InvoiceContent,
    InvoiceExportRequest,
    InvoiceExportStatusResponse,
    InvoiceMetadata,
    InvoiceQueryDateRange,
    InvoiceQueryDateType,
    InvoiceQueryFilters,
    InvoiceQuerySubjectType,
    QueryInvoicesMetadataResponse,
)
from ..pagination import (
    INVOICE_METADATA_PAGE_SIZE_DEFAULT,
    KsefPaginationWarning,
    iter_page_offsets,
    page_should_continue,
    pagination_warning,
    validate_page_size,
)
from ..utils.datetime_parsing import normalize_api_timestamp, try_parse_api_datetime
from .base import AsyncBaseApiClient, BaseApiClient, _serialize_json_payload

_OFFSET_SUFFIX_RE = re.compile(r"(?:Z|[+-]\d{2}:?\d{2})$")
INVOICE_QUERY_MAX_RANGE_DAYS = 100


class _SerializedInvoicePayload(dict[str, Any]):
    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__(payload)

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        _ = omit_none
        return deepcopy(dict(self))


def _last_sunday_of_month(year: int, month: int) -> int:
    cursor = date(year, 12, 31) if month == 12 else date(year, month + 1, 1) - timedelta(days=1)
    while cursor.weekday() != 6:
        cursor -= timedelta(days=1)
    return cursor.day


def _warsaw_offset_for_local_datetime(local_dt: datetime) -> timedelta:
    year = local_dt.year
    dst_start = datetime(year, 3, _last_sunday_of_month(year, 3), 2, 0, 0)
    dst_end = datetime(year, 10, _last_sunday_of_month(year, 10), 3, 0, 0)
    if dst_start <= local_dt < dst_end:
        return timedelta(hours=2)
    return timedelta(hours=1)


def _normalize_datetime_without_offset(value: str) -> str:
    """Uzupełnia strefę dla znacznika bez offsetu (czas lokalny Europe/Warsaw).

    Wartość z sufiksem ``Z`` albo z offsetem jest zwracana bez zmian — jej
    strefa jest już jednoznaczna. Dla wartości bez strefy parsujemy ją jako czas
    lokalny i dopiero potem doklejamy offset warszawski; wcześniej robiła to
    ta sama funkcja, która na Pythonie 3.10 nie umiała sparsować 7-cyfrowego
    ułamka, więc zwracała wartość bez offsetu (albo z błędnym offsetem).
    """
    if "T" not in value or _OFFSET_SUFFIX_RE.search(value):
        return value
    try:
        naive = datetime.fromisoformat(normalize_api_timestamp(value))
    except ValueError:
        return value
    if naive.tzinfo is not None:
        return value
    offset = _warsaw_offset_for_local_datetime(naive)
    return naive.replace(tzinfo=timezone(offset)).isoformat()


def _normalize_invoice_date_range_payload(request_payload: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(request_payload)
    date_range_candidates: list[dict[str, Any]] = []

    top_level = normalized.get("dateRange")
    if isinstance(top_level, dict):
        date_range_candidates.append(top_level)

    filters = normalized.get("filters")
    if isinstance(filters, dict):
        nested = filters.get("dateRange")
        if isinstance(nested, dict):
            date_range_candidates.append(nested)

    for date_range in date_range_candidates:
        for field_name in ("from", "to"):
            value = date_range.get(field_name)
            if isinstance(value, str):
                date_range[field_name] = _normalize_datetime_without_offset(value)
        _enforce_invoice_date_range_limit(date_range)
    return normalized


def _parse_invoice_range_datetime(value: str) -> datetime | None:
    """Parsuje granicę zakresu (toleruje 7 cyfr ułamka na Pythonie 3.10)."""
    return try_parse_api_datetime(value)


def _enforce_invoice_date_range_limit(date_range: dict[str, Any]) -> None:
    from_value = date_range.get("from")
    if not isinstance(from_value, str):
        return
    parsed_from = _parse_invoice_range_datetime(from_value)
    if parsed_from is None:
        return

    to_value = date_range.get("to")
    parsed_to: datetime | None
    if to_value is None:
        parsed_to = datetime.now(timezone.utc)
    elif isinstance(to_value, str):
        parsed_to = _parse_invoice_range_datetime(to_value)
        if parsed_to is None:
            return
    else:
        return

    # Porównanie DAT KALENDARZOWYCH jest tu celowe: KSeF rozumie limit jako okno
    # 100 dni kalendarzowych w UTC, nie jako 100 x 24 h. Sufit „do końca setnego
    # dnia" (`2026-01-01` → `2026-04-11T23:59:59Z`, czyli 100 dni 23:59:59
    # rzeczywistego czasu) jest przez API przyjmowany, a dopiero `2026-04-12`
    # przekracza okno. Zmiana na porównanie czasów odrzucałaby poprawny zakres.
    if (parsed_to.date() - parsed_from.date()).days > INVOICE_QUERY_MAX_RANGE_DAYS:
        raise ValueError(
            "Invoice query/export date range cannot exceed "
            f"{INVOICE_QUERY_MAX_RANGE_DAYS} days (UTC)"
        )


def _normalize_invoice_query_subject_type(
    subject_type: InvoiceQuerySubjectType | str,
) -> InvoiceQuerySubjectType:
    if isinstance(subject_type, InvoiceQuerySubjectType):
        return subject_type
    for candidate in InvoiceQuerySubjectType:
        if subject_type == candidate.value:
            return candidate
    raise ValueError(f"Unsupported invoice query subject type: {subject_type}")


def _normalize_invoice_query_date_type(
    date_type: InvoiceQueryDateType | str,
) -> InvoiceQueryDateType:
    if isinstance(date_type, InvoiceQueryDateType):
        return date_type
    for candidate in InvoiceQueryDateType:
        if date_type == candidate.value:
            return candidate
    raise ValueError(f"Unsupported invoice query date type: {date_type}")


def _build_invoice_query_filters(
    *,
    subject_type: InvoiceQuerySubjectType | str,
    date_type: InvoiceQueryDateType | str,
    date_from: str,
    date_to: str | None = None,
) -> InvoiceQueryFilters:
    return InvoiceQueryFilters(
        subject_type=_normalize_invoice_query_subject_type(subject_type),
        date_range=InvoiceQueryDateRange(
            date_type=_normalize_invoice_query_date_type(date_type),
            from_=date_from,
            to=date_to,
        ),
    )


def _serialize_invoice_payload(request_payload: Any) -> _SerializedInvoicePayload:
    serialized = _serialize_json_payload(request_payload)
    if serialized is None:
        raise TypeError("Invoice request payload is required.")
    return _SerializedInvoicePayload(_normalize_invoice_date_range_payload(serialized))


class InvoicesClient(BaseApiClient):
    def get_invoice(self, ksef_number: str, *, access_token: str | None = None) -> InvoiceContent:
        response = self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        return InvoiceContent(
            content=response.content.decode("utf-8"),
            sha256_base64=response.headers.get("x-ms-meta-hash"),
        )

    def get_invoice_bytes(
        self, ksef_number: str, *, access_token: str | None = None
    ) -> BinaryContent:
        response = self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        return BinaryContent(
            content=response.content,
            sha256_base64=response.headers.get("x-ms-meta-hash"),
        )

    def query_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str | None = None,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        if sort_order:
            params["sortOrder"] = sort_order
        return self._request_model(
            "POST",
            "/invoices/query/metadata",
            response_model=QueryInvoicesMetadataResponse,
            params=params or None,
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
        )

    def query_invoice_metadata_by_date_range(
        self,
        *,
        subject_type: InvoiceQuerySubjectType | str,
        date_type: InvoiceQueryDateType | str,
        date_from: str,
        date_to: str | None = None,
        access_token: str | None = None,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        return self.query_invoice_metadata(
            _build_invoice_query_filters(
                subject_type=subject_type,
                date_type=date_type,
                date_from=date_from,
                date_to=date_to,
            ),
            access_token=access_token,
            page_offset=page_offset,
            page_size=page_size,
            sort_order=sort_order,
        )

    def iter_invoice_metadata_pages(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str | None = None,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        page_offset: int = 0,
        max_pages: int | None = None,
        sort_order: str | None = None,
    ) -> Iterator[QueryInvoicesMetadataResponse]:
        """Iteruje po stronach metadanych faktur, aż KSeF zwróci ostatnią.

        Pętla respektuje ``hasMore`` i ``isTruncated``: po osiągnięciu limitu
        10 000 wyników kończy pracę i emituje
        :class:`~ksef_client.pagination.KsefPaginationWarning` zamiast wysyłać
        kolejne żądania, które i tak nie zwrócą brakujących faktur.

        Args:
            request_payload: Filtry zapytania (``InvoiceQueryFilters``).
            access_token: Token dostępu.
            page_size: Rozmiar strony (10–250). Domyślnie 100.
            page_offset: Numer pierwszej strony (0 = pierwsza strona).
            max_pages: Opcjonalny bezpiecznik liczby stron.
            sort_order: Kolejność sortowania (``Asc``/``Desc``).

        Yields:
            Kolejne strony odpowiedzi API.

        Raises:
            ValueError: Gdy ``page_size``, ``page_offset`` lub ``max_pages``
                są poza dozwolonym zakresem.
            TypeError: Gdy któryś z parametrów liczbowych nie jest liczbą
                całkowitą.

        Example:
            ```python
            for page in client.invoices.iter_invoice_metadata_pages(
                filters, access_token=token, page_size=250
            ):
                print(len(page.invoices), page.has_more)
            ```
        """
        validate_page_size(page_size)
        for offset in iter_page_offsets(
            start_offset=page_offset,
            max_pages=max_pages,
        ):
            page = self.query_invoice_metadata(
                request_payload,
                access_token=access_token,
                page_offset=offset,
                page_size=page_size,
                sort_order=sort_order,
            )
            yield page
            warning = pagination_warning(page, page_size=page_size, page_offset=offset)
            if warning is not None:
                warnings.warn(warning, KsefPaginationWarning, stacklevel=2)
            if not page_should_continue(page):
                return

    def iter_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str | None = None,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        page_offset: int = 0,
        max_pages: int | None = None,
        sort_order: str | None = None,
    ) -> Iterator[InvoiceMetadata]:
        """Iteruje po wszystkich fakturach pasujących do filtrów.

        Wygodna nakładka na :meth:`iter_invoice_metadata_pages`, która zwraca
        pojedyncze pozycje zamiast stron. Parametry i zachowanie przy obcięciu
        wyniku są identyczne.

        Args:
            request_payload: Filtry zapytania (``InvoiceQueryFilters``).
            access_token: Token dostępu.
            page_size: Rozmiar strony (10–250). Domyślnie 100.
            page_offset: Numer pierwszej strony (0 = pierwsza strona).
            max_pages: Opcjonalny bezpiecznik liczby stron.
            sort_order: Kolejność sortowania (``Asc``/``Desc``).

        Yields:
            Kolejne metadane faktur.

        Raises:
            ValueError: Gdy parametry paginacji są poza dozwolonym zakresem.
            TypeError: Gdy któryś z parametrów liczbowych nie jest liczbą
                całkowitą.
        """
        validate_page_size(page_size)
        for offset in iter_page_offsets(
            start_offset=page_offset,
            max_pages=max_pages,
        ):
            page = self.query_invoice_metadata(
                request_payload,
                access_token=access_token,
                page_offset=offset,
                page_size=page_size,
                sort_order=sort_order,
            )
            warning = pagination_warning(page, page_size=page_size, page_offset=offset)
            if warning is not None:
                warnings.warn(warning, KsefPaginationWarning, stacklevel=2)
            yield from page.invoices
            if not page_should_continue(page):
                return

    def iter_invoice_metadata_by_date_range(
        self,
        *,
        subject_type: InvoiceQuerySubjectType | str,
        date_type: InvoiceQueryDateType | str,
        date_from: str,
        date_to: str | None = None,
        access_token: str | None = None,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        page_offset: int = 0,
        max_pages: int | None = None,
        sort_order: str | None = None,
    ) -> Iterator[InvoiceMetadata]:
        """Iteruje po metadanych faktur z zakresu dat.

        Odpowiednik :meth:`query_invoice_metadata_by_date_range` dla całego
        wyniku, nie jednej strony.

        Args:
            subject_type: Podmiot, którego dotyczą faktury.
            date_type: Typ daty użytej do filtrowania.
            date_from: Początek zakresu (ISO 8601).
            date_to: Koniec zakresu; ``None`` znaczy „do teraz”.
            access_token: Token dostępu.
            page_size: Rozmiar strony (10–250). Domyślnie 100.
            page_offset: Numer pierwszej strony (0 = pierwsza strona).
            max_pages: Opcjonalny bezpiecznik liczby stron.
            sort_order: Kolejność sortowania (``Asc``/``Desc``).

        Yields:
            Kolejne metadane faktur.

        Raises:
            ValueError: Gdy zakres dat lub parametry paginacji są niepoprawne.
            TypeError: Gdy któryś z parametrów liczbowych nie jest liczbą
                całkowitą.
        """
        request_payload = _build_invoice_query_filters(
            subject_type=subject_type,
            date_type=date_type,
            date_from=date_from,
            date_to=date_to,
        )
        validate_page_size(page_size)
        for offset in iter_page_offsets(
            start_offset=page_offset,
            max_pages=max_pages,
        ):
            page = self.query_invoice_metadata(
                request_payload,
                access_token=access_token,
                page_offset=offset,
                page_size=page_size,
                sort_order=sort_order,
            )
            warning = pagination_warning(page, page_size=page_size, page_offset=offset)
            if warning is not None:
                warnings.warn(warning, KsefPaginationWarning, stacklevel=2)
            yield from page.invoices
            if not page_should_continue(page):
                return

    def export_invoices(
        self, request_payload: InvoiceExportRequest, *, access_token: str | None = None
    ) -> ExportInvoicesResponse:
        return self._request_model(
            "POST",
            "/invoices/exports",
            response_model=ExportInvoicesResponse,
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
            expected_status={201, 202},
        )

    def get_export_status(
        self, reference_number: str, *, access_token: str | None = None
    ) -> InvoiceExportStatusResponse:
        return self._request_model(
            "GET",
            f"/invoices/exports/{reference_number}",
            response_model=InvoiceExportStatusResponse,
            access_token=access_token,
        )

    def download_export_part(self, url: str) -> bytes:
        return self._request_bytes("GET", url, skip_auth=True)

    def download_package_part(self, url: str) -> bytes:
        return self.download_export_part(url)

    def download_export_part_with_hash(self, url: str) -> BinaryContent:
        response = self._request_raw("GET", url, skip_auth=True)
        return BinaryContent(
            content=response.content,
            sha256_base64=response.headers.get("x-ms-meta-hash"),
        )


class AsyncInvoicesClient(AsyncBaseApiClient):
    async def get_invoice(
        self, ksef_number: str, *, access_token: str | None = None
    ) -> InvoiceContent:
        response = await self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        return InvoiceContent(
            content=response.content.decode("utf-8"),
            sha256_base64=response.headers.get("x-ms-meta-hash"),
        )

    async def get_invoice_bytes(
        self, ksef_number: str, *, access_token: str | None = None
    ) -> BinaryContent:
        response = await self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        return BinaryContent(
            content=response.content,
            sha256_base64=response.headers.get("x-ms-meta-hash"),
        )

    async def query_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str | None = None,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        if sort_order:
            params["sortOrder"] = sort_order
        return await self._request_model(
            "POST",
            "/invoices/query/metadata",
            response_model=QueryInvoicesMetadataResponse,
            params=params or None,
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
        )

    async def query_invoice_metadata_by_date_range(
        self,
        *,
        subject_type: InvoiceQuerySubjectType | str,
        date_type: InvoiceQueryDateType | str,
        date_from: str,
        date_to: str | None = None,
        access_token: str | None = None,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        return await self.query_invoice_metadata(
            _build_invoice_query_filters(
                subject_type=subject_type,
                date_type=date_type,
                date_from=date_from,
                date_to=date_to,
            ),
            access_token=access_token,
            page_offset=page_offset,
            page_size=page_size,
            sort_order=sort_order,
        )

    async def iter_invoice_metadata_pages(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str | None = None,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        page_offset: int = 0,
        max_pages: int | None = None,
        sort_order: str | None = None,
    ) -> AsyncIterator[QueryInvoicesMetadataResponse]:
        """Asynchroniczny odpowiednik :meth:`InvoicesClient.iter_invoice_metadata_pages`.

        Args:
            request_payload: Filtry zapytania (``InvoiceQueryFilters``).
            access_token: Token dostępu.
            page_size: Rozmiar strony (10–250). Domyślnie 100.
            page_offset: Numer pierwszej strony (0 = pierwsza strona).
            max_pages: Opcjonalny bezpiecznik liczby stron.
            sort_order: Kolejność sortowania (``Asc``/``Desc``).

        Yields:
            Kolejne strony odpowiedzi API.

        Raises:
            ValueError: Gdy parametry paginacji są poza dozwolonym zakresem.
            TypeError: Gdy któryś z parametrów liczbowych nie jest liczbą
                całkowitą.
        """
        validate_page_size(page_size)
        for offset in iter_page_offsets(
            start_offset=page_offset,
            max_pages=max_pages,
        ):
            page = await self.query_invoice_metadata(
                request_payload,
                access_token=access_token,
                page_offset=offset,
                page_size=page_size,
                sort_order=sort_order,
            )
            yield page
            warning = pagination_warning(page, page_size=page_size, page_offset=offset)
            if warning is not None:
                warnings.warn(warning, KsefPaginationWarning, stacklevel=2)
            if not page_should_continue(page):
                return

    async def iter_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        access_token: str | None = None,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        page_offset: int = 0,
        max_pages: int | None = None,
        sort_order: str | None = None,
    ) -> AsyncIterator[InvoiceMetadata]:
        """Asynchroniczny odpowiednik :meth:`InvoicesClient.iter_invoice_metadata`.

        Args:
            request_payload: Filtry zapytania (``InvoiceQueryFilters``).
            access_token: Token dostępu.
            page_size: Rozmiar strony (10–250). Domyślnie 100.
            page_offset: Numer pierwszej strony (0 = pierwsza strona).
            max_pages: Opcjonalny bezpiecznik liczby stron.
            sort_order: Kolejność sortowania (``Asc``/``Desc``).

        Yields:
            Kolejne metadane faktur.

        Raises:
            ValueError: Gdy parametry paginacji są poza dozwolonym zakresem.
            TypeError: Gdy któryś z parametrów liczbowych nie jest liczbą
                całkowitą.
        """
        validate_page_size(page_size)
        for offset in iter_page_offsets(
            start_offset=page_offset,
            max_pages=max_pages,
        ):
            page = await self.query_invoice_metadata(
                request_payload,
                access_token=access_token,
                page_offset=offset,
                page_size=page_size,
                sort_order=sort_order,
            )
            warning = pagination_warning(page, page_size=page_size, page_offset=offset)
            if warning is not None:
                warnings.warn(warning, KsefPaginationWarning, stacklevel=2)
            for invoice in page.invoices:
                yield invoice
            if not page_should_continue(page):
                return

    async def iter_invoice_metadata_by_date_range(
        self,
        *,
        subject_type: InvoiceQuerySubjectType | str,
        date_type: InvoiceQueryDateType | str,
        date_from: str,
        date_to: str | None = None,
        access_token: str | None = None,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        page_offset: int = 0,
        max_pages: int | None = None,
        sort_order: str | None = None,
    ) -> AsyncIterator[InvoiceMetadata]:
        """Asynchroniczny odpowiednik iteracji po zakresie dat.

        Args:
            subject_type: Podmiot, którego dotyczą faktury.
            date_type: Typ daty użytej do filtrowania.
            date_from: Początek zakresu (ISO 8601).
            date_to: Koniec zakresu; ``None`` znaczy „do teraz”.
            access_token: Token dostępu.
            page_size: Rozmiar strony (10–250). Domyślnie 100.
            page_offset: Numer pierwszej strony (0 = pierwsza strona).
            max_pages: Opcjonalny bezpiecznik liczby stron.
            sort_order: Kolejność sortowania (``Asc``/``Desc``).

        Yields:
            Kolejne metadane faktur.

        Raises:
            ValueError: Gdy zakres dat lub parametry paginacji są niepoprawne.
            TypeError: Gdy któryś z parametrów liczbowych nie jest liczbą
                całkowitą.
        """
        request_payload = _build_invoice_query_filters(
            subject_type=subject_type,
            date_type=date_type,
            date_from=date_from,
            date_to=date_to,
        )
        validate_page_size(page_size)
        for offset in iter_page_offsets(
            start_offset=page_offset,
            max_pages=max_pages,
        ):
            page = await self.query_invoice_metadata(
                request_payload,
                access_token=access_token,
                page_offset=offset,
                page_size=page_size,
                sort_order=sort_order,
            )
            warning = pagination_warning(page, page_size=page_size, page_offset=offset)
            if warning is not None:
                warnings.warn(warning, KsefPaginationWarning, stacklevel=2)
            for invoice in page.invoices:
                yield invoice
            if not page_should_continue(page):
                return

    async def export_invoices(
        self, request_payload: InvoiceExportRequest, *, access_token: str | None = None
    ) -> ExportInvoicesResponse:
        return await self._request_model(
            "POST",
            "/invoices/exports",
            response_model=ExportInvoicesResponse,
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
            expected_status={201, 202},
        )

    async def get_export_status(
        self, reference_number: str, *, access_token: str | None = None
    ) -> InvoiceExportStatusResponse:
        return await self._request_model(
            "GET",
            f"/invoices/exports/{reference_number}",
            response_model=InvoiceExportStatusResponse,
            access_token=access_token,
        )

    async def download_export_part(self, url: str) -> bytes:
        return await self._request_bytes("GET", url, skip_auth=True)

    async def download_package_part(self, url: str) -> bytes:
        return await self.download_export_part(url)

    async def download_export_part_with_hash(self, url: str) -> BinaryContent:
        response = await self._request_raw("GET", url, skip_auth=True)
        return BinaryContent(
            content=response.content,
            sha256_base64=response.headers.get("x-ms-meta-hash"),
        )
