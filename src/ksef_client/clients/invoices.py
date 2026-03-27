from __future__ import annotations

import re
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from typing import Any

from ..models import (
    BinaryContent,
    ExportInvoicesResponse,
    InvoiceContent,
    InvoiceExportRequest,
    InvoiceExportStatusResponse,
    InvoiceQueryDateRange,
    InvoiceQueryDateType,
    InvoiceQueryFilters,
    InvoiceQuerySubjectType,
    QueryInvoicesMetadataResponse,
)
from .base import AsyncBaseApiClient, BaseApiClient

_OFFSET_SUFFIX_RE = re.compile(r"(?:Z|[+-]\d{2}:?\d{2})$")


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
    if "T" not in value or _OFFSET_SUFFIX_RE.search(value):
        return value
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is not None:
        return value
    offset = _warsaw_offset_for_local_datetime(parsed)
    return parsed.replace(tzinfo=timezone(offset)).isoformat()


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
    return normalized


def _normalize_invoice_query_subject_type(
    subject_type: InvoiceQuerySubjectType | str,
) -> InvoiceQuerySubjectType:
    if isinstance(subject_type, InvoiceQuerySubjectType):
        return subject_type
    return InvoiceQuerySubjectType(subject_type)


def _normalize_invoice_query_date_type(
    date_type: InvoiceQueryDateType | str,
) -> InvoiceQueryDateType:
    if isinstance(date_type, InvoiceQueryDateType):
        return date_type
    return InvoiceQueryDateType(date_type)


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


class InvoicesClient(BaseApiClient):
    def get_invoice(self, ksef_number: str, *, access_token: str) -> InvoiceContent:
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

    def get_invoice_bytes(self, ksef_number: str, *, access_token: str) -> BinaryContent:
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
        access_token: str,
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
            json=_normalize_invoice_date_range_payload(request_payload.to_dict()),
            access_token=access_token,
        )

    def query_invoice_metadata_by_date_range(
        self,
        *,
        subject_type: InvoiceQuerySubjectType | str,
        date_type: InvoiceQueryDateType | str,
        date_from: str,
        date_to: str | None = None,
        access_token: str,
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

    def export_invoices(
        self, request_payload: InvoiceExportRequest, *, access_token: str
    ) -> ExportInvoicesResponse:
        return self._request_model(
            "POST",
            "/invoices/exports",
            response_model=ExportInvoicesResponse,
            json=_normalize_invoice_date_range_payload(request_payload.to_dict()),
            access_token=access_token,
            expected_status={201, 202},
        )

    def get_export_status(
        self, reference_number: str, *, access_token: str
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
    async def get_invoice(self, ksef_number: str, *, access_token: str) -> InvoiceContent:
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

    async def get_invoice_bytes(self, ksef_number: str, *, access_token: str) -> BinaryContent:
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
        access_token: str,
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
            json=_normalize_invoice_date_range_payload(request_payload.to_dict()),
            access_token=access_token,
        )

    async def query_invoice_metadata_by_date_range(
        self,
        *,
        subject_type: InvoiceQuerySubjectType | str,
        date_type: InvoiceQueryDateType | str,
        date_from: str,
        date_to: str | None = None,
        access_token: str,
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

    async def export_invoices(
        self, request_payload: InvoiceExportRequest, *, access_token: str
    ) -> ExportInvoicesResponse:
        return await self._request_model(
            "POST",
            "/invoices/exports",
            response_model=ExportInvoicesResponse,
            json=_normalize_invoice_date_range_payload(request_payload.to_dict()),
            access_token=access_token,
            expected_status={201, 202},
        )

    async def get_export_status(
        self, reference_number: str, *, access_token: str
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
