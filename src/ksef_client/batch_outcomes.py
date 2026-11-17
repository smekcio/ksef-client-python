"""Read-only per-document outcomes for a prepared KSeF batch."""

from __future__ import annotations

import base64
import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import models as m
from .invoice_xml_types import hash_bytes
from .utils.ksef_number import canonical_ksef_number
from .utils.zip_utils import _sanitize_archive_entry_name, build_tar_gz, build_zip

_MAX_INVOICES = 10_000
_FINAL_SESSION = {200, 445}
_XML_CORRECTION = {430, 450}
_REJECTED = _XML_CORRECTION | {405, 410, 415, 435}


class BatchInvoiceDisposition(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    CANCELLED = "cancelled"
    UNRESOLVED = "unresolved"


def _file_name(value: str) -> str:
    if type(value) is not str or len(value) > 1024:
        raise ValueError("Invalid batch invoice filename")
    name = _sanitize_archive_entry_name(value, archive_type="batch")
    if not name.lower().endswith(".xml"):
        raise ValueError("Batch invoice filenames must end in .xml")
    return name


@dataclass(frozen=True)
class BatchInvoice:
    file_name: str = field(repr=False)
    invoice_hash: str = field(repr=False)

    def __post_init__(self) -> None:
        if _file_name(self.file_name) != self.file_name:
            raise ValueError("Batch invoice filenames must use their archive spelling")
        hash_bytes(self.invoice_hash)


@dataclass(frozen=True)
class BatchInvoiceManifest:
    """Archive identity and ordered documents. Persist in a trusted local store."""

    file_size: int
    file_hash: str = field(repr=False)
    invoices: tuple[BatchInvoice, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.file_size) is not int or self.file_size <= 0:
            raise ValueError("Invalid batch manifest size")
        hash_bytes(self.file_hash)
        if (
            type(self.invoices) is not tuple
            or not 1 <= len(self.invoices) <= _MAX_INVOICES
            or any(not isinstance(invoice, BatchInvoice) for invoice in self.invoices)
        ):
            raise ValueError("Invalid batch manifest invoices")
        if len({invoice.file_name for invoice in self.invoices}) != len(self.invoices):
            raise ValueError("Duplicate batch invoice filename")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "invoices": [
                {"file_name": invoice.file_name, "invoice_hash": invoice.invoice_hash}
                for invoice in self.invoices
            ],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> BatchInvoiceManifest:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"version", "file_size", "file_hash", "invoices"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or type(value["invoices"]) is not list
            or not 1 <= len(value["invoices"]) <= _MAX_INVOICES
        ):
            raise ValueError("Invalid batch manifest format")
        entries = []
        for entry in value["invoices"]:
            if type(entry) is not dict or set(entry) != {"file_name", "invoice_hash"}:
                raise ValueError("Invalid batch manifest invoice format")
            entries.append(BatchInvoice(entry["file_name"], entry["invoice_hash"]))
        return cls(value["file_size"], value["file_hash"], tuple(entries))

    def bind(self, batch_file: m.BatchFileInfo) -> None:
        if self.file_size != batch_file.file_size or self.file_hash != batch_file.file_hash:
            raise ValueError("Manifest does not belong to this batch archive")


@dataclass(frozen=True)
class PreparedInvoiceBatch:
    archive_bytes: bytes = field(repr=False)
    manifest: BatchInvoiceManifest
    compression_type: m.CompressionType


def _sha256(content: bytes) -> str:
    return base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")


def prepare_invoice_batch(
    invoices: Mapping[str, bytes],
    *,
    compression_type: m.CompressionType = m.CompressionType.ZIP,
) -> PreparedInvoiceBatch:
    """Build an archive and its manifest from the same original XML bytes."""
    if not 1 <= len(invoices) <= _MAX_INVOICES:
        raise ValueError("A batch must contain 1 to 10000 invoices")
    builders = {m.CompressionType.ZIP: build_zip, m.CompressionType.TARGZ: build_tar_gz}
    compression_type = m.CompressionType(compression_type)
    if compression_type not in builders:
        raise ValueError("Unsupported batch compression type")

    files = {}
    entries = []
    for raw_name, xml in invoices.items():
        name = _file_name(raw_name)
        if name in files:
            raise ValueError("Duplicate batch invoice filename after normalization")
        if type(xml) is not bytes or not xml:
            raise ValueError("Batch invoice XML must be nonempty bytes")
        files[name] = xml
        entries.append(BatchInvoice(name, _sha256(xml)))
    archive = builders[compression_type](files)
    manifest = BatchInvoiceManifest(len(archive), _sha256(archive), tuple(entries))
    return PreparedInvoiceBatch(archive, manifest, compression_type)


@dataclass(frozen=True)
class BatchInvoiceOutcome:
    invoice: BatchInvoice
    disposition: BatchInvoiceDisposition
    status_code: int | None = None
    invoice_reference: str | None = field(default=None, repr=False)
    ksef_number: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class BatchInvoiceReport:
    session_reference: str = field(repr=False)
    session_status: int
    invoices: tuple[BatchInvoiceOutcome, ...]
    complete: bool

    @property
    def retry_candidates(self) -> tuple[BatchInvoice, ...]:
        """Original XML candidates confirmed cancelled in a complete final report."""
        return self._candidates(BatchInvoiceDisposition.CANCELLED, {550})

    @property
    def correction_candidates(self) -> tuple[BatchInvoice, ...]:
        """Entries rejected for invoice file or semantic checks (430 or 450)."""
        return self._candidates(BatchInvoiceDisposition.REJECTED, _XML_CORRECTION)

    def _candidates(
        self, disposition: BatchInvoiceDisposition, status_codes: set[int]
    ) -> tuple[BatchInvoice, ...]:
        if not self.complete:
            return ()
        counts = Counter(row.invoice.invoice_hash for row in self.invoices)
        return tuple(
            row.invoice
            for row in self.invoices
            if row.disposition is disposition
            and row.status_code in status_codes
            and counts[row.invoice.invoice_hash] == 1
        )


def _outcome(
    invoice: BatchInvoice,
    row: m.SessionInvoiceStatusResponse,
    invoice_count: int,
    number: str | None,
) -> BatchInvoiceOutcome:
    disposition = BatchInvoiceDisposition
    code = row.status.code
    reference = row.reference_number
    result = disposition.UNRESOLVED
    valid_ref = reference is not None and re.fullmatch(r"[A-Za-z0-9_-]{1,256}", reference)
    ordinal = row.ordinal_number
    if not valid_ref or type(ordinal) is not int or not 1 <= ordinal <= invoice_count:
        return BatchInvoiceOutcome(invoice, result, code)
    if code == 200 and number is not None:
        return BatchInvoiceOutcome(invoice, disposition.ACCEPTED, code, reference, number)
    if row.ksef_number is None:
        if code in _REJECTED:
            result = disposition.REJECTED
        elif code == 440:
            result = disposition.DUPLICATE
        elif code == 550:
            result = disposition.CANCELLED
    return BatchInvoiceOutcome(invoice, result, code, reference)


class _BatchResults:
    """Correlate rows from one bounded scan without treating missing rows as rejection."""

    def __init__(self, manifest: BatchInvoiceManifest, page_size: int, max_pages: int) -> None:
        if type(page_size) is not int or not 10 <= page_size <= 1000:
            raise ValueError("Batch outcome page_size must be between 10 and 1000")
        if type(max_pages) is not int or not 1 <= max_pages <= 1000:
            raise ValueError("Batch outcome max_pages must be between 1 and 1000")
        self.manifest = manifest
        self.page_size = page_size
        self.max_pages = max_pages
        self.by_name = {invoice.file_name: invoice for invoice in manifest.invoices}
        self.by_hash: dict[str, set[str]] = defaultdict(set)
        for invoice in manifest.invoices:
            self.by_hash[invoice.invoice_hash].add(invoice.file_name)
        self.rows: dict[str, BatchInvoiceOutcome] = {}
        self.conflicted: set[str] = set()
        self.identifiers: dict[tuple[str, int | str], str | None] = {}
        self.tokens: set[str] = set()
        self.count = 0
        self.consistent = True
        self.exhausted = False

    @staticmethod
    def is_final(status: m.SessionStatusResponse) -> bool:
        return status.status.code in _FINAL_SESSION

    def accept(self, page: m.SessionInvoicesResponse) -> str | None:
        self.count += len(page.invoices)
        if len(page.invoices) > self.page_size or self.count > len(self.manifest.invoices):
            self.consistent = False
            return None
        for row in page.invoices:
            self._record(row)
        token = page.continuation_token
        if token is None or token == "":
            self.exhausted = True
            return None
        if (
            token in self.tokens
            or not 1 <= len(token) <= 8192
            or re.fullmatch(r"[!-~]+", token) is None
        ):
            self.consistent = False
            return None
        self.tokens.add(token)
        return token

    def _record(self, row: m.SessionInvoiceStatusResponse) -> None:
        candidates = self.by_hash.get(row.invoice_hash or "", set())
        name = row.invoice_file_name
        if name is None and len(candidates) == 1:
            name = next(iter(candidates))
        matched = name if name in candidates else None
        number = None
        if row.ksef_number is not None:
            with suppress(ValueError):
                number = canonical_ksef_number(row.ksef_number)
        # Unmatched rows can still contradict the identity of a matched row.
        for kind, value in (
            ("reference", row.reference_number),
            ("ordinal", row.ordinal_number),
            ("ksef_number", number),
        ):
            if value is None:
                continue
            previous = self.identifiers.setdefault((kind, value), matched)
            if previous != matched:
                self.consistent = False
                self.conflicted.update(item for item in (previous, matched) if item is not None)
        if matched is None:
            self.consistent = False
            self.conflicted.update(candidates)
            if name is not None and name in self.by_name:
                self.conflicted.add(name)
            return
        if matched in self.rows:
            self.consistent = False
            self.conflicted.add(matched)
        self.rows[matched] = _outcome(
            self.by_name[matched], row, len(self.manifest.invoices), number
        )

    def report(
        self,
        session_reference: str,
        initial: m.SessionStatusResponse,
        current: m.SessionStatusResponse,
    ) -> BatchInvoiceReport:
        unresolved = BatchInvoiceDisposition.UNRESOLVED
        results = tuple(
            self.rows.get(invoice.file_name, BatchInvoiceOutcome(invoice, unresolved))
            if invoice.file_name not in self.conflicted
            else BatchInvoiceOutcome(invoice, unresolved)
            for invoice in self.manifest.invoices
        )
        accepted = sum(row.disposition is BatchInvoiceDisposition.ACCEPTED for row in results)

        def counters(status: m.SessionStatusResponse) -> tuple[int | str | None, ...]:
            return (
                status.status.code,
                status.date_updated,
                status.invoice_count,
                status.successful_invoice_count,
                status.failed_invoice_count,
            )

        complete = (
            self.consistent
            and self.exhausted
            and self.is_final(initial)
            and counters(initial) == counters(current)
            and initial.invoice_count == len(results)
            and initial.successful_invoice_count in {None, accepted}
            and initial.failed_invoice_count in {None, len(results) - accepted}
            and (initial.status.code != 445 or accepted == 0)
            and all(row.disposition is not unresolved for row in results)
        )
        return BatchInvoiceReport(session_reference, current.status.code, results, complete)
