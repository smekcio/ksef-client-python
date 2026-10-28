from __future__ import annotations

import json
import re
import warnings
from collections.abc import AsyncIterator, Iterator, Sequence
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from functools import partial
from typing import TYPE_CHECKING, Any, cast

from ..config import KsefClientOptions
from ..invoice_range_search import (
    AsyncInvoiceMetadataRangeSearch,
    InvoiceMetadataRangeSearch,
    _RangeMachine,
)
from ..invoice_search import (
    AsyncInvoiceMetadataSearch,
    InvoiceMetadataSearch,
    _check_retained_filter_fields,
    _InvalidMetadataResponse,
    _json_object,
    _MetadataMachine,
    _parse_metadata_response,
    _reject_constant,
)
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

if TYPE_CHECKING:
    from ..invoice_sync import AsyncInvoiceSync, InvoiceSync


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


def _normalize_invoice_date_range_payload(
    request_payload: dict[str, Any],
    *,
    allow_open_range: bool = False,
    allow_long_range: bool = False,
) -> dict[str, Any]:
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
        if not allow_long_range and (not allow_open_range or date_range.get("to") is not None):
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


def _serialize_invoice_payload(
    request_payload: Any,
    *,
    allow_open_range: bool = False,
    allow_long_range: bool = False,
) -> _SerializedInvoicePayload:
    serialized = _serialize_json_payload(request_payload)
    if serialized is None:
        raise TypeError("Invoice request payload is required.")
    return _SerializedInvoicePayload(
        _normalize_invoice_date_range_payload(
            serialized, allow_open_range=allow_open_range, allow_long_range=allow_long_range
        )
    )


def _serialize_search_filters(
    payload: InvoiceQueryFilters,
    *,
    allow_long_range: bool = False,
) -> dict[str, Any]:
    serialized = dict(
        _serialize_invoice_payload(
            payload, allow_open_range=True, allow_long_range=allow_long_range
        )
    )
    if type(serialized.get("dateRange")) is not dict:
        raise ValueError("Invoice search requires a dateRange object")
    try:
        restored = InvoiceQueryFilters.from_dict(serialized).to_dict(omit_none=False)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("Invalid invoice search filters") from None

    _check_retained_filter_fields(serialized, restored)
    return serialized


class InvoicesClient(BaseApiClient):
    def sync(
        self,
        *,
        namespace: str,
        sync_key: str,
        context_key: str,
        since: str | None = None,
        subject_types: Sequence[InvoiceQuerySubjectType | str] | None = None,
        queries: Sequence[InvoiceQueryFilters] | None = None,
        page_size: int = 100,
        window_days: int = 100,
    ) -> InvoiceSync:
        """Construct a metadata synchronizer without I/O; token is resolved per request."""
        return _build_sync(
            self,
            namespace=namespace,
            sync_key=sync_key,
            context_key=context_key,
            since=since,
            subject_types=subject_types,
            queries=queries,
            page_size=page_size,
            window_days=window_days,
            asynchronous=False,
        )

    def _query_invoice_metadata_observation_page(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        page_offset: int,
        page_size: int,
        sort_order: str,
        expected_environment: str,
        access_token: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        http = cast(Any, self._http)
        if http.api_base_url != expected_environment:
            raise ValueError("Metadata source environment changed")
        response = http.request_json_limited(
            "POST",
            "/invoices/query/metadata",
            max_bytes=16 * 1024 * 1024,
            params={"pageOffset": page_offset, "pageSize": page_size, "sortOrder": sort_order},
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
        )
        try:
            raw = json.loads(
                response.content, object_pairs_hook=_json_object, parse_constant=_reject_constant
            )
            if (
                type(raw) is not dict
                or type(raw.get("invoices")) is not list
                or len(raw["invoices"]) > page_size
            ):
                raise ValueError("Invalid metadata page")
            return _parse_metadata_response(raw)
        except (ValueError, TypeError, RecursionError):
            raise _InvalidMetadataResponse("Invalid metadata response") from None

    def search_invoice_metadata_range(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        context_key: str,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        sort_order: str = "Asc",
        window_days: int = 100,
        access_token: str | None = None,
    ) -> InvoiceMetadataRangeSearch:
        """Search an arbitrary period through inclusive windows and one durable cursor.

        The application commits each page and next_cursor together. Restricted
        PermanentStorage searches confirm completeness only up to the reported HWM.
        """
        options = getattr(self._http, "_options", None)
        if not isinstance(options, KsefClientOptions):
            raise ValueError("Resumable search requires HTTP client environment options")
        machine = _RangeMachine(
            _serialize_search_filters(request_payload, allow_long_range=True),
            environment=options.normalized_base_url(),
            context_key=context_key,
            page_size=page_size,
            sort_order=sort_order,
            window_days=window_days,
        )
        return InvoiceMetadataRangeSearch(
            machine,
            partial(self._query_invoice_metadata_search_page, access_token=access_token),
            partial(
                self._query_invoice_metadata_observation_page,
                expected_environment=options.normalized_base_url(),
                access_token=access_token,
            ),
        )

    def search_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        context_key: str,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        sort_order: str = "Asc",
        access_token: str | None = None,
    ) -> InvoiceMetadataSearch:
        """Create a lazy, resumable metadata search without changing legacy iterators.

        context_key binds state to the application's authenticated context.
        Cursors contain private query data; never log them. Only HWM-restricted
        PermanentStorage queries describe a stable server-side set.
        """
        options = getattr(self._http, "_options", None)
        if not isinstance(options, KsefClientOptions):
            raise ValueError("Resumable search requires HTTP client environment options")
        machine = _MetadataMachine(
            _serialize_search_filters(request_payload),
            environment=options.normalized_base_url(),
            context_key=context_key,
            page_size=page_size,
            sort_order=sort_order,
        )
        return InvoiceMetadataSearch(
            machine,
            partial(self._query_invoice_metadata_search_page, access_token=access_token),
        )

    def _query_invoice_metadata_search_page(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        page_offset: int,
        page_size: int,
        sort_order: str,
        access_token: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        raw = self._request_json(
            "POST",
            "/invoices/query/metadata",
            params={"pageOffset": page_offset, "pageSize": page_size, "sortOrder": sort_order},
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
        )
        return _parse_metadata_response(raw)

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
    def sync(
        self,
        *,
        namespace: str,
        sync_key: str,
        context_key: str,
        since: str | None = None,
        subject_types: Sequence[InvoiceQuerySubjectType | str] | None = None,
        queries: Sequence[InvoiceQueryFilters] | None = None,
        page_size: int = 100,
        window_days: int = 100,
    ) -> AsyncInvoiceSync:
        """Construct a metadata synchronizer without I/O; token is resolved per request."""
        return _build_sync(
            self,
            namespace=namespace,
            sync_key=sync_key,
            context_key=context_key,
            since=since,
            subject_types=subject_types,
            queries=queries,
            page_size=page_size,
            window_days=window_days,
            asynchronous=True,
        )

    async def _query_invoice_metadata_observation_page(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        page_offset: int,
        page_size: int,
        sort_order: str,
        expected_environment: str,
        access_token: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        http = cast(Any, self._http)
        if http.api_base_url != expected_environment:
            raise ValueError("Metadata source environment changed")
        response = await http.request_json_limited(
            "POST",
            "/invoices/query/metadata",
            max_bytes=16 * 1024 * 1024,
            params={"pageOffset": page_offset, "pageSize": page_size, "sortOrder": sort_order},
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
        )
        try:
            raw = json.loads(
                response.content, object_pairs_hook=_json_object, parse_constant=_reject_constant
            )
            if (
                type(raw) is not dict
                or type(raw.get("invoices")) is not list
                or len(raw["invoices"]) > page_size
            ):
                raise ValueError("Invalid metadata page")
            return _parse_metadata_response(raw)
        except (ValueError, TypeError, RecursionError):
            raise _InvalidMetadataResponse("Invalid metadata response") from None

    def search_invoice_metadata_range(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        context_key: str,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        sort_order: str = "Asc",
        window_days: int = 100,
        access_token: str | None = None,
    ) -> AsyncInvoiceMetadataRangeSearch:
        """Async multi-year search with inclusive windows and one durable cursor."""
        options = getattr(self._http, "_options", None)
        if not isinstance(options, KsefClientOptions):
            raise ValueError("Resumable search requires HTTP client environment options")
        machine = _RangeMachine(
            _serialize_search_filters(request_payload, allow_long_range=True),
            environment=options.normalized_base_url(),
            context_key=context_key,
            page_size=page_size,
            sort_order=sort_order,
            window_days=window_days,
        )
        return AsyncInvoiceMetadataRangeSearch(
            machine,
            partial(self._query_invoice_metadata_search_page, access_token=access_token),
            partial(
                self._query_invoice_metadata_observation_page,
                expected_environment=options.normalized_base_url(),
                access_token=access_token,
            ),
        )

    def search_invoice_metadata(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        context_key: str,
        page_size: int = INVOICE_METADATA_PAGE_SIZE_DEFAULT,
        sort_order: str = "Asc",
        access_token: str | None = None,
    ) -> AsyncInvoiceMetadataSearch:
        """Create a lazy, resumable metadata search without changing legacy iterators.

        context_key binds state to the application's authenticated context.
        Cursors contain private query data; never log them. Only HWM-restricted
        PermanentStorage queries describe a stable server-side set.
        """
        options = getattr(self._http, "_options", None)
        if not isinstance(options, KsefClientOptions):
            raise ValueError("Resumable search requires HTTP client environment options")
        machine = _MetadataMachine(
            _serialize_search_filters(request_payload),
            environment=options.normalized_base_url(),
            context_key=context_key,
            page_size=page_size,
            sort_order=sort_order,
        )
        return AsyncInvoiceMetadataSearch(
            machine,
            partial(self._query_invoice_metadata_search_page, access_token=access_token),
        )

    async def _query_invoice_metadata_search_page(
        self,
        request_payload: InvoiceQueryFilters,
        *,
        page_offset: int,
        page_size: int,
        sort_order: str,
        access_token: str | None = None,
    ) -> QueryInvoicesMetadataResponse:
        raw = await self._request_json(
            "POST",
            "/invoices/query/metadata",
            params={"pageOffset": page_offset, "pageSize": page_size, "sortOrder": sort_order},
            json=_serialize_invoice_payload(request_payload),
            access_token=access_token,
        )
        return _parse_metadata_response(raw)

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


def _build_sync(
    client: Any,
    *,
    namespace: str,
    sync_key: str,
    context_key: str,
    since: str | None,
    subject_types: Sequence[InvoiceQuerySubjectType | str] | None,
    queries: Sequence[InvoiceQueryFilters] | None,
    page_size: int,
    window_days: int,
    asynchronous: bool,
) -> Any:
    from ..invoice_sync import (
        AsyncInvoiceSync,
        AsyncInvoiceSyncStream,
        InvoiceSync,
        InvoiceSyncStream,
    )
    from ..invoice_sync_state import (
        InvoiceSyncScope,
        _execution_parameters,
        canonical_spec,
        spec_fingerprint,
        utc_timestamp,
    )
    from ..operations import environment_key

    _execution_parameters(page_size, window_days)
    if queries is not None:
        if since is not None or subject_types is not None:
            raise ValueError("Choose queries or since/subject_types")
        selected = queries
    else:
        if since is None:
            raise ValueError("since or queries is required")
        since = utc_timestamp(since)
        roles = (
            subject_types
            if subject_types is not None
            else (InvoiceQuerySubjectType.SUBJECT1, InvoiceQuerySubjectType.SUBJECT2)
        )
        if not isinstance(roles, Sequence) or isinstance(roles, (str, bytes)):
            raise TypeError("subject_types must be a sequence of roles")
        selected = [
            InvoiceQueryFilters(
                subject_type=_normalize_invoice_query_subject_type(role),
                date_range=InvoiceQueryDateRange(
                    date_type=InvoiceQueryDateType.PERMANENTSTORAGE,
                    from_=since,
                    restrict_to_permanent_storage_hwm_date=True,
                ),
            )
            for role in roles
        ]
    if not isinstance(selected, Sequence) or isinstance(selected, (str, bytes)):
        raise TypeError("queries must be a sequence of typed queries")
    if not 1 <= len(selected) <= 4:
        raise ValueError("Sync requires one to four queries")
    streams: list[Any] = []
    for query in selected:
        spec = canonical_spec(query)
        # Reuse the existing strict typed-query normalization, retaining every filter.
        normalized = InvoiceQueryFilters.from_dict(
            _serialize_search_filters(
                InvoiceQueryFilters.from_dict(spec["query"]), allow_long_range=True
            )
        )
        spec = canonical_spec(normalized)
        scope = InvoiceSyncScope(
            namespace,
            environment_key(client._http.api_base_url),
            context_key,
            sync_key,
            spec_fingerprint(spec),
        )
        stream_type = AsyncInvoiceSyncStream if asynchronous else InvoiceSyncStream
        streams.append(
            stream_type(
                scope,
                InvoiceQueryFilters.from_dict(spec["query"]),
                client.search_invoice_metadata_range,
                page_size=page_size,
                window_days=window_days,
            )
        )
    return (AsyncInvoiceSync if asynchronous else InvoiceSync)(streams)
