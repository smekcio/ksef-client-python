"""Durable delivery of verified incoming invoices from a local archive."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass

from . import models as m
from .invoice_sync_state import _loads, utc_timestamp
from .invoice_xml_types import InvoiceXmlKey, KsefXmlIntegrityError, KsefXmlSyncError, verify_hash
from .utils.ksef_number import canonical_ksef_number


class KsefInvoiceDeliveryLeaseLostError(KsefXmlSyncError):
    """The delivery attempt has expired, been released or been superseded."""

    def __init__(self) -> None:
        super().__init__("invoice_delivery_lease_lost")


@dataclass(frozen=True, repr=False)
class IncomingInvoiceDelivery:
    """One verified delivery attempt. The XML and metadata may contain sensitive data."""

    event_id: str
    key: InvoiceXmlKey
    metadata: m.InvoiceMetadata
    xml: bytes
    consumer: str
    expires_at: float
    _token: str
    _epoch: str


def _delivery_metadata(raw: str, key: InvoiceXmlKey, expected_hash: str) -> m.InvoiceMetadata:
    try:
        payload = _loads(raw)
        if type(payload) is not dict:
            raise ValueError
        number = payload["ksefNumber"]
        if (
            type(number) is not str
            or canonical_ksef_number(number) != key.ksef_number
            or payload["invoiceHash"] != expected_hash
        ):
            raise ValueError
        utc_timestamp(payload["permanentStorageDate"])
        for name in ("netAmount", "vatAmount", "grossAmount"):
            amount = payload.get(name)
            if amount is not None and (
                type(amount) not in (int, float) or not math.isfinite(amount)
            ):
                raise ValueError
        for name in ("hasAttachment", "isSelfInvoicing"):
            flag = payload.get(name)
            if flag is not None and type(flag) is not bool:
                raise ValueError
        return m.InvoiceMetadata.from_dict(payload)
    except (TypeError, ValueError, AttributeError, KeyError, OverflowError, RecursionError):
        raise KsefXmlIntegrityError("invalid_delivery_metadata") from None


@dataclass(frozen=True, repr=False)
class _PendingDelivery:
    key: InvoiceXmlKey
    metadata: m.InvoiceMetadata
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
