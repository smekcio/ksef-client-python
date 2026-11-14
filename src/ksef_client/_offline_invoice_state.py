"""Pure transitions for durable offline invoice submission."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import Enum

from . import models as m
from .exceptions import KsefDocumentValidationError
from .invoice_xml_types import hash_bytes
from .utils.ksef_number import canonical_ksef_number

_REFERENCE = re.compile(r"[A-Za-z0-9_-]{1,256}")


class OfflineInvoiceStatus(str, Enum):
    QUEUED = "queued"
    SESSION_OPEN = "session_open"
    SUBMISSION_UNKNOWN = "submission_unknown"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    COMPLETE = "complete"


def offline_invoice_hash(xml: bytes) -> str:
    if type(xml) is not bytes or not xml:
        raise KsefDocumentValidationError("An offline invoice requires original XML bytes")
    return base64.b64encode(hashlib.sha256(xml).digest()).decode("ascii")


@dataclass(frozen=True)
class OfflineInvoiceProgress:
    """Safe lifecycle state. Session and document identifiers are private."""

    invoice_hash: str = field(repr=False)
    status: OfflineInvoiceStatus = OfflineInvoiceStatus.QUEUED
    session_reference: str | None = field(default=None, repr=False)
    invoice_reference: str | None = field(default=None, repr=False)
    ksef_number: str | None = field(default=None, repr=False)
    ksef_status: int | None = None

    def __post_init__(self) -> None:
        hash_bytes(self.invoice_hash)
        if not isinstance(self.status, OfflineInvoiceStatus):
            raise ValueError("Invalid offline invoice status")
        if (self.status is OfflineInvoiceStatus.QUEUED) != (self.session_reference is None):
            raise ValueError("Inconsistent offline invoice session")
        if any(
            value is not None and (type(value) is not str or _REFERENCE.fullmatch(value) is None)
            for value in (self.session_reference, self.invoice_reference)
        ):
            raise ValueError("Invalid offline invoice operation reference")
        has_reference = self.status in {
            OfflineInvoiceStatus.SUBMITTED,
            OfflineInvoiceStatus.ACCEPTED,
            OfflineInvoiceStatus.REJECTED,
            OfflineInvoiceStatus.DUPLICATE,
            OfflineInvoiceStatus.COMPLETE,
        }
        if has_reference != (self.invoice_reference is not None):
            raise ValueError("Inconsistent offline invoice reference")
        accepted = self.status in {OfflineInvoiceStatus.ACCEPTED, OfflineInvoiceStatus.COMPLETE}
        if accepted != (self.ksef_number is not None):
            raise ValueError("Inconsistent offline invoice KSeF number")
        if self.ksef_number is not None:
            object.__setattr__(self, "ksef_number", canonical_ksef_number(self.ksef_number))

    def open_session(self, session_reference: str) -> OfflineInvoiceProgress:
        if self.status is not OfflineInvoiceStatus.QUEUED:
            raise ValueError("Offline invoice already has a session")
        return replace(
            self, status=OfflineInvoiceStatus.SESSION_OPEN, session_reference=session_reference
        )

    def begin_submission(self) -> OfflineInvoiceProgress:
        if self.status is not OfflineInvoiceStatus.SESSION_OPEN:
            raise ValueError("Offline invoice cannot be submitted again")
        return replace(self, status=OfflineInvoiceStatus.SUBMISSION_UNKNOWN)

    def confirm_reference(self, reference: str) -> OfflineInvoiceProgress:
        if self.status is not OfflineInvoiceStatus.SUBMISSION_UNKNOWN:
            raise ValueError("Offline invoice has no unresolved submission")
        return replace(self, status=OfflineInvoiceStatus.SUBMITTED, invoice_reference=reference)

    def observe(self, invoice: m.SessionInvoiceStatusResponse) -> OfflineInvoiceProgress:
        if self.status not in {
            OfflineInvoiceStatus.SUBMISSION_UNKNOWN,
            OfflineInvoiceStatus.SUBMITTED,
        }:
            raise ValueError("Offline invoice is not awaiting a submission result")
        if invoice.invoice_hash != self.invoice_hash or not invoice.reference_number:
            raise KsefDocumentValidationError("KSeF result does not identify the offline invoice")
        if (
            self.invoice_reference is not None
            and invoice.reference_number != self.invoice_reference
        ):
            raise KsefDocumentValidationError("KSeF returned a different offline invoice reference")
        code = invoice.status.code
        if type(code) is not int:
            raise KsefDocumentValidationError("Invalid KSeF offline invoice status")
        if code == 200 and invoice.ksef_number:
            status = OfflineInvoiceStatus.ACCEPTED
        elif code == 440 and not invoice.ksef_number:
            # A duplicate is not eligible for technical correction.
            status = OfflineInvoiceStatus.DUPLICATE
        elif code in {405, 410, 415, 430, 435, 450, 500, 550} and not invoice.ksef_number:
            status = OfflineInvoiceStatus.REJECTED
        elif code in {100, 150} and not invoice.ksef_number:
            status = OfflineInvoiceStatus.SUBMITTED
        else:
            raise KsefDocumentValidationError("Unrecognized KSeF offline invoice result")
        return replace(
            self,
            status=status,
            invoice_reference=invoice.reference_number,
            ksef_number=invoice.ksef_number,
            ksef_status=code,
        )

    def confirm_upo(self) -> OfflineInvoiceProgress:
        if self.status is not OfflineInvoiceStatus.ACCEPTED:
            raise ValueError("Offline invoice has not been accepted")
        return replace(self, status=OfflineInvoiceStatus.COMPLETE)
