from __future__ import annotations

import re
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from typing import Any

from ..models import BinaryContent, InvoiceContent
from .base import AsyncBaseApiClient, BaseApiClient

_OFFSET_SUFFIX_RE = re.compile(r"(?:Z|[+-]\d{2}:?\d{2})$")


def _last_sunday_of_month(year: int, month: int) -> int:
    cursor = date(year, 12, 31) if month == 12 else date(year, month + 1, 1) - timedelta(days=1)
    while cursor.weekday() != 6:  # Sunday
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


class InvoicesClient(BaseApiClient):
    def get_invoice(self, ksef_number: str, *, access_token: str) -> InvoiceContent:
        response = self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        response_bytes = response.content
        hash_header = response.headers.get("x-ms-meta-hash")
        # The endpoint returns application/xml; hash is in header x-ms-meta-hash
        return InvoiceContent(content=response_bytes.decode("utf-8"), sha256_base64=hash_header)

    def get_invoice_bytes(self, ksef_number: str, *, access_token: str) -> BinaryContent:
        response = self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        return BinaryContent(
            content=response.content, sha256_base64=response.headers.get("x-ms-meta-hash")
        )

    def query_invoice_metadata(
        self,
        request_payload: dict[str, Any],
        *,
        access_token: str,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> Any:
        normalized_payload = _normalize_invoice_date_range_payload(request_payload)
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        if sort_order:
            params["sortOrder"] = sort_order
        return self._request_json(
            "POST",
            "/invoices/query/metadata",
            params=params or None,
            json=normalized_payload,
            access_token=access_token,
        )

    def export_invoices(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        normalized_payload = _normalize_invoice_date_range_payload(request_payload)
        return self._request_json(
            "POST",
            "/invoices/exports",
            json=normalized_payload,
            access_token=access_token,
            expected_status={201, 202},
        )

    def get_export_status(self, reference_number: str, *, access_token: str) -> Any:
        return self._request_json(
            "GET",
            f"/invoices/exports/{reference_number}",
            access_token=access_token,
        )

    def download_export_part(self, url: str) -> bytes:
        return self._request_bytes(
            "GET",
            url,
            skip_auth=True,
        )

    def download_package_part(self, url: str) -> bytes:
        return self.download_export_part(url)

    def download_export_part_with_hash(self, url: str) -> BinaryContent:
        response = self._request_raw("GET", url, skip_auth=True)
        return BinaryContent(
            content=response.content, sha256_base64=response.headers.get("x-ms-meta-hash")
        )


class AsyncInvoicesClient(AsyncBaseApiClient):
    async def get_invoice(self, ksef_number: str, *, access_token: str) -> InvoiceContent:
        response = await self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        response_bytes = response.content
        hash_header = response.headers.get("x-ms-meta-hash")
        return InvoiceContent(content=response_bytes.decode("utf-8"), sha256_base64=hash_header)

    async def get_invoice_bytes(self, ksef_number: str, *, access_token: str) -> BinaryContent:
        response = await self._request_raw(
            "GET",
            f"/invoices/ksef/{ksef_number}",
            headers={"Accept": "application/xml"},
            access_token=access_token,
        )
        return BinaryContent(
            content=response.content, sha256_base64=response.headers.get("x-ms-meta-hash")
        )

    async def query_invoice_metadata(
        self,
        request_payload: dict[str, Any],
        *,
        access_token: str,
        page_offset: int | None = None,
        page_size: int | None = None,
        sort_order: str | None = None,
    ) -> Any:
        normalized_payload = _normalize_invoice_date_range_payload(request_payload)
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        if sort_order:
            params["sortOrder"] = sort_order
        return await self._request_json(
            "POST",
            "/invoices/query/metadata",
            params=params or None,
            json=normalized_payload,
            access_token=access_token,
        )

    async def export_invoices(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        normalized_payload = _normalize_invoice_date_range_payload(request_payload)
        return await self._request_json(
            "POST",
            "/invoices/exports",
            json=normalized_payload,
            access_token=access_token,
            expected_status={201, 202},
        )

    async def get_export_status(self, reference_number: str, *, access_token: str) -> Any:
        return await self._request_json(
            "GET",
            f"/invoices/exports/{reference_number}",
            access_token=access_token,
        )

    async def download_export_part(self, url: str) -> bytes:
        return await self._request_bytes(
            "GET",
            url,
            skip_auth=True,
        )

    async def download_package_part(self, url: str) -> bytes:
        return await self.download_export_part(url)

    async def download_export_part_with_hash(self, url: str) -> BinaryContent:
        response = await self._request_raw("GET", url, skip_auth=True)
        return BinaryContent(
            content=response.content, sha256_base64=response.headers.get("x-ms-meta-hash")
        )
