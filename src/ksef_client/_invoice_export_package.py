"""Validate export package contents independently of their transfer and storage."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._invoice_metadata_validation import _validate_archive_metadata
from ._json_bounds import check_json_structure
from .exceptions import KsefDocumentValidationError
from .invoice_search import _date, _json_object, _reject_constant
from .invoice_sync_state import utc_timestamp
from .invoice_xml_types import hash_bytes, verify_hash
from .streaming_export import ExportFiles, check_control, safe_file
from .utils.ksef_number import canonical_ksef_number
from .utils.zip_utils import EXPORT_MAX_INVOICES


@dataclass(frozen=True)
class ExportInvoice:
    number: str = field(repr=False)
    metadata: dict[str, Any] = field(repr=False)
    path: Path = field(repr=False)

    def read_xml(self, max_bytes: int) -> bytes:
        content = _read(self.path, max_bytes)
        verify_hash(content, self.metadata["invoiceHash"])
        return content


@dataclass(frozen=True)
class ValidatedInvoicePackage:
    invoices: tuple[ExportInvoice, ...] = field(repr=False)
    continuation: str
    truncated: bool
    metadata_digest: str = field(default="", repr=False)


def _read(path: Path, limit: int) -> bytes:
    if type(limit) is not int or limit <= 0:
        raise ValueError("Export file size limit must be a positive integer")
    with safe_file(path).open("rb") as stream:
        data = bytearray()
        while len(data) <= limit:
            check_control()
            chunk = stream.read(min(1024 * 1024, limit + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
    raise KsefDocumentValidationError("Export file exceeds its size limit")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("Non-finite export metadata number")
    return parsed


def validate_invoice_package(
    files: ExportFiles, *, start: str, end: str, max_metadata_bytes: int
) -> ValidatedInvoicePackage:
    """Bind exported rows to files and distinguish a continuation from an HWM."""
    package = files.package
    if (
        type(package.invoice_count) is not int
        or not 0 <= package.invoice_count <= EXPORT_MAX_INVOICES
        or type(package.is_truncated) is not bool
    ):
        raise KsefDocumentValidationError("Invalid export package descriptor")

    try:
        if package.permanent_storage_hwm_date is None:
            raise ValueError
        lower, upper = _date(start), _date(end)
        hwm = utc_timestamp(package.permanent_storage_hwm_date)
        boundary = min((hwm, utc_timestamp(end)), key=_date)
        if lower > upper or _date(boundary) < lower:
            raise ValueError
        if package.is_truncated:
            if package.last_permanent_storage_date is None or not package.invoice_count:
                raise ValueError
            last = utc_timestamp(package.last_permanent_storage_date)
            if not lower <= _date(last) <= _date(boundary):
                raise ValueError
            boundary = last
    except (ValueError, OverflowError):
        raise KsefDocumentValidationError("Invalid export coverage boundary") from None

    if not files.files and not package.parts and not package.invoice_count:
        return ValidatedInvoicePackage((), boundary, False)

    paths: dict[str, Path] = {}
    metadata: Path | None = None
    try:
        for name in files.files:
            if name.lower() == "_metadata.json" and metadata is None:
                metadata = files.destination / name
                continue
            if not name.lower().endswith(".xml"):
                raise ValueError
            number = canonical_ksef_number(name[:-4])
            if number in paths:
                raise ValueError
            paths[number] = files.destination / name
        if (
            metadata is None
            or metadata != files.metadata_path
            or len(paths) != package.invoice_count
        ):
            raise ValueError
        raw = _read(metadata, max_metadata_bytes)
        check_json_structure(raw, max_depth=24, max_nodes=2_000_000)
        payload = json.loads(
            raw,
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        rows = payload.get("invoices") if type(payload) is dict else None
        if type(rows) is not list or len(rows) != package.invoice_count:
            raise ValueError
        invoices = []
        latest = lower
        ceiling = _date(boundary)
        for row in rows:
            check_control()
            if type(row) is not dict:
                raise ValueError
            _validate_archive_metadata(row)
            number = canonical_ksef_number(row["ksefNumber"])
            hash_bytes(row["invoiceHash"])
            stored_at = _date(utc_timestamp(row["permanentStorageDate"]))
            if not lower <= stored_at <= ceiling:
                raise ValueError
            latest = max(latest, stored_at)
            invoices.append(ExportInvoice(number, row, paths.pop(number)))
        if paths or (package.is_truncated and latest != ceiling):
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError):
        raise KsefDocumentValidationError("Invalid export metadata or invoice file set") from None
    return ValidatedInvoicePackage(
        tuple(invoices), boundary, package.is_truncated, hashlib.sha256(raw).hexdigest()
    )
