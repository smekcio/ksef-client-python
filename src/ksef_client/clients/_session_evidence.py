"""Strict reads for decisions that can authorize another invoice submission."""

from __future__ import annotations

import re
from typing import Any, TypeVar

from .._json_bounds import check_json_structure
from ..exceptions import KsefDocumentValidationError
from ..invoice_sync_state import _loads, utc_timestamp
from ..models import SessionInvoicesResponse, SessionInvoiceStatusResponse, SessionStatusResponse
from ..pagination import validate_page_size
from .base import _AsyncRequestClient, _ModelType, _RequestClient

T = TypeVar("T")
MAX_SESSION_PAGE_BYTES = 16 * 1024 * 1024
MAX_SESSION_STATUS_BYTES = 1024 * 1024
MAX_SESSION_PAGE_SIZE = 1000


def check_reference(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value) is None:
        raise ValueError("Invalid session or invoice reference")


def check_cursor(value: str | None) -> None:
    if value is not None and (
        type(value) is not str or re.fullmatch(r"[!-~]{0,8192}", value) is None
    ):
        raise ValueError("Invalid session continuation token")


def check_page_size(value: int | None) -> None:
    if value is not None:
        validate_page_size(value, maximum=MAX_SESSION_PAGE_SIZE)


def _check_status(row: Any) -> None:
    if not isinstance(row, dict) or not isinstance(row.get("status"), dict):
        raise ValueError("Missing status")
    if type(row["status"].get("code")) is not int:
        raise ValueError("Invalid status code")


def _check_invoice(row: Any) -> None:
    _check_status(row)
    ordinal = row.get("ordinalNumber")
    if ordinal is not None and (type(ordinal) is not int or ordinal < 1):
        raise ValueError("Invalid invoice ordinal")
    for field, limit in (
        ("invoiceHash", 44),
        ("invoiceFileName", 128),
        ("ksefNumber", 36),
        ("referenceNumber", 36),
    ):
        value = row.get(field)
        if value is not None and (type(value) is not str or len(value) > limit):
            raise ValueError("Invalid invoice identity")


def decode(body: bytes, model: _ModelType[T], *, page_size: int | None = None) -> T:
    """Validate the original JSON types before the general SDK model can coerce them."""
    try:
        check_json_structure(body, max_nodes=500_000, max_depth=32)
        raw = _loads(body)
        if type(raw) is not dict:
            raise ValueError("Expected a session response object")
        if model is SessionInvoicesResponse:
            rows = raw.get("invoices")
            if type(rows) is not list or len(rows) > (10 if page_size is None else page_size):
                raise ValueError("Invalid invoice page")
            check_cursor(raw.get("continuationToken"))
            for row in rows:
                _check_invoice(row)
        elif model is SessionStatusResponse:
            _check_status(raw)
            for field in ("dateCreated", "dateUpdated"):
                utc_timestamp(raw[field])
            for field in ("invoiceCount", "successfulInvoiceCount", "failedInvoiceCount"):
                value = raw.get(field)
                if value is not None and (type(value) is not int or value < 0):
                    raise ValueError("Invalid session count")
        else:
            _check_invoice(raw)
        return model.from_dict(raw)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError, OverflowError):
        raise KsefDocumentValidationError("Invalid KSeF session status response") from None


def _invoice_page_request(
    reference_number: str, page_size: int | None, continuation_token: str | None
) -> tuple[str, dict[str, int] | None, dict[str, str] | None]:
    check_reference(reference_number)
    check_cursor(continuation_token)
    check_page_size(page_size)
    params = {"pageSize": page_size} if page_size is not None else None
    headers = {"x-continuation-token": continuation_token} if continuation_token else None
    return f"/sessions/{reference_number}/invoices", params, headers


class ValidatedSessionReads:
    """Bounded session reads that validate evidence before model conversion."""

    def __init__(self, http_client: _RequestClient) -> None:
        self._http = http_client

    def get_session_status(
        self, reference_number: str, access_token: str | None = None
    ) -> SessionStatusResponse:
        check_reference(reference_number)
        response = self._http.request(
            "GET",
            f"/sessions/{reference_number}",
            access_token=access_token,
            expected_status={200},
            max_bytes=MAX_SESSION_STATUS_BYTES,
        )
        return decode(response.content, SessionStatusResponse)

    def get_session_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> SessionInvoicesResponse:
        path, params, headers = _invoice_page_request(
            reference_number, page_size, continuation_token
        )
        response = self._http.request(
            "GET",
            path,
            access_token=access_token,
            params=params,
            headers=headers,
            expected_status={200},
            max_bytes=MAX_SESSION_PAGE_BYTES,
        )
        return decode(response.content, SessionInvoicesResponse, page_size=page_size)

    def get_session_invoice_status(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> SessionInvoiceStatusResponse:
        check_reference(reference_number)
        check_reference(invoice_reference_number)
        response = self._http.request(
            "GET",
            f"/sessions/{reference_number}/invoices/{invoice_reference_number}",
            access_token=access_token,
            expected_status={200},
            max_bytes=MAX_SESSION_STATUS_BYTES,
        )
        return decode(response.content, SessionInvoiceStatusResponse)


class AsyncValidatedSessionReads:
    """Asynchronous bounded session reads on the existing transport."""

    def __init__(self, http_client: _AsyncRequestClient) -> None:
        self._http = http_client

    async def get_session_status(
        self, reference_number: str, access_token: str | None = None
    ) -> SessionStatusResponse:
        check_reference(reference_number)
        response = await self._http.request(
            "GET",
            f"/sessions/{reference_number}",
            access_token=access_token,
            expected_status={200},
            max_bytes=MAX_SESSION_STATUS_BYTES,
        )
        return decode(response.content, SessionStatusResponse)

    async def get_session_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> SessionInvoicesResponse:
        path, params, headers = _invoice_page_request(
            reference_number, page_size, continuation_token
        )
        response = await self._http.request(
            "GET",
            path,
            access_token=access_token,
            params=params,
            headers=headers,
            expected_status={200},
            max_bytes=MAX_SESSION_PAGE_BYTES,
        )
        return decode(response.content, SessionInvoicesResponse, page_size=page_size)

    async def get_session_invoice_status(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> SessionInvoiceStatusResponse:
        check_reference(reference_number)
        check_reference(invoice_reference_number)
        response = await self._http.request(
            "GET",
            f"/sessions/{reference_number}/invoices/{invoice_reference_number}",
            access_token=access_token,
            expected_status={200},
            max_bytes=MAX_SESSION_STATUS_BYTES,
        )
        return decode(response.content, SessionInvoiceStatusResponse)
