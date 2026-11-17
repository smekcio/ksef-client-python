"""Strict reads for decisions that can authorize another invoice submission."""

from __future__ import annotations

import re
from typing import Any, TypeVar

from .._json_bounds import check_json_structure
from ..exceptions import KsefDocumentValidationError
from ..invoice_sync_state import _loads
from ..models import SessionInvoicesResponse, SessionStatusResponse
from .base import _ModelType

T = TypeVar("T")
MAX_SESSION_PAGE_BYTES = 16 * 1024 * 1024
MAX_SESSION_STATUS_BYTES = 1024 * 1024


def check_reference(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value) is None:
        raise ValueError("Invalid session or invoice reference")


def check_cursor(value: str | None) -> None:
    if value is not None and (
        type(value) is not str or re.fullmatch(r"[!-~]{0,8192}", value) is None
    ):
        raise ValueError("Invalid session continuation token")


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
    for field in ("invoiceHash", "invoiceFileName", "ksefNumber", "referenceNumber"):
        if row.get(field) is not None and type(row[field]) is not str:
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
            if type(rows) is not list or len(rows) > (1000 if page_size is None else page_size):
                raise ValueError("Invalid invoice page")
            check_cursor(raw.get("continuationToken"))
            for row in rows:
                _check_invoice(row)
        elif model is SessionStatusResponse:
            _check_status(raw)
            for field in ("dateCreated", "dateUpdated"):
                if type(raw.get(field)) is not str or not raw[field]:
                    raise ValueError("Invalid session timestamp")
            for field in ("invoiceCount", "successfulInvoiceCount", "failedInvoiceCount"):
                value = raw.get(field)
                if value is not None and (type(value) is not int or value < 0):
                    raise ValueError("Invalid session count")
        else:
            _check_invoice(raw)
        return model.from_dict(raw)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError, OverflowError):
        raise KsefDocumentValidationError("Invalid KSeF session status response") from None
