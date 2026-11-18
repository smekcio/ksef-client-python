"""Durable delivery of verified incoming invoices from a local archive."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from . import models as m
from ._invoice_metadata_validation import _validate_archive_metadata
from .invoice_sync_state import _loads, utc_timestamp
from .invoice_xml_types import InvoiceXmlKey, KsefXmlIntegrityError, KsefXmlSyncError, verify_hash
from .utils.ksef_number import canonical_ksef_number


class KsefInvoiceDeliveryLeaseLostError(KsefXmlSyncError):
    """The attempt expired, was superseded or the archive entry stopped being ready."""

    def __init__(self) -> None:
        super().__init__("invoice_delivery_lease_lost")


@dataclass(frozen=True, repr=False)
class InvoiceDeliveryReceipt:
    """Private proof of a particular delivery attempt, usable across process restarts."""

    key: InvoiceXmlKey
    consumer: str
    _token: str
    _epoch: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "key": asdict(self.key),
            "consumer": self.consumer,
            "token": self._token,
            "epoch": self._epoch,
        }

    @classmethod
    def from_dict(cls, data: object) -> InvoiceDeliveryReceipt:
        try:
            if (
                not isinstance(data, dict)
                or type(data.get("version")) is not int
                or data["version"] != 1
            ):
                raise ValueError
            key = InvoiceXmlKey(**data["key"])
            consumer, token, epoch = data["consumer"], data["token"], data["epoch"]
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", consumer) or not all(
                re.fullmatch(r"[0-9a-f]{32}", value) for value in (token, epoch)
            ):
                raise ValueError
            return cls(key, consumer, token, epoch)
        except (KeyError, TypeError, ValueError):
            raise ValueError("Invalid invoice delivery receipt") from None


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

    @property
    def receipt(self) -> InvoiceDeliveryReceipt:
        return InvoiceDeliveryReceipt(self.key, self.consumer, self._token, self._epoch)


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
        _validate_archive_metadata(payload)
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
