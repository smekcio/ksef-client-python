from __future__ import annotations

from typing import Any

from ..models import BinaryContent, InvoiceContent
from .base import AsyncBaseApiClient, BaseApiClient


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
            json=request_payload,
            access_token=access_token,
        )

    def export_invoices(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/invoices/exports",
            json=request_payload,
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
            json=request_payload,
            access_token=access_token,
        )

    async def export_invoices(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/invoices/exports",
            json=request_payload,
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
