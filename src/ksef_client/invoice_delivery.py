"""Durable delivery of verified incoming invoices from a local archive."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .invoice_xml_types import InvoiceXmlKey, KsefXmlIntegrityError, KsefXmlSyncError, verify_hash

if TYPE_CHECKING:
    from .models import InvoiceMetadata


class KsefInvoiceDeliveryLeaseLostError(KsefXmlSyncError):
    """The delivery attempt has expired, been released or been superseded."""

    def __init__(self) -> None:
        super().__init__("invoice_delivery_lease_lost")


@dataclass(frozen=True, repr=False)
class IncomingInvoiceDelivery:
    """One verified delivery attempt. The XML and metadata may contain sensitive data."""

    event_id: str
    key: InvoiceXmlKey
    metadata: InvoiceMetadata
    xml: bytes
    consumer: str
    expires_at: float
    _token: str
    _epoch: str


@dataclass(frozen=True, repr=False)
class _PendingDelivery:
    key: InvoiceXmlKey
    metadata: InvoiceMetadata
    consumer: str
    expires_at: float
    token: str
    epoch: str
    expected_hash: str
    size: int

    def verified(self, xml: bytes) -> IncomingInvoiceDelivery:
        if type(xml) is not bytes or len(xml) != self.size:
            raise KsefXmlIntegrityError("stored_size_mismatch")
        verify_hash(xml, self.expected_hash)
        identity = json.dumps(
            ["ksef-incoming-invoice/v1", *self.key.values], separators=(",", ":"), ensure_ascii=True
        )
        event_id = hashlib.sha256(identity.encode("ascii")).hexdigest()
        return IncomingInvoiceDelivery(
            event_id,
            self.key,
            self.metadata,
            xml,
            self.consumer,
            self.expires_at,
            self.token,
            self.epoch,
        )
