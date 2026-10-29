"""Durable document identities, receipts and database/storage extension contracts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from .exceptions import KsefSyncError
from .invoice_sync import AsyncInvoiceSyncStore, InvoiceSyncReport, InvoiceSyncStore
from .invoice_sync_state import (
    InvoiceSyncBatch,
    InvoiceSyncCheckpoint,
    InvoiceSyncCommitReceipt,
    InvoiceSyncScope,
)


class KsefXmlSyncError(KsefSyncError):
    """Document failure with a bounded, non-sensitive machine-readable reason."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.message = "Invoice XML synchronization failed"
        self.args = (self.message,)


class KsefXmlIntegrityError(KsefXmlSyncError):
    pass


class KsefXmlStorageError(KsefXmlSyncError):
    pass


class KsefXmlLeaseLostError(KsefXmlSyncError):
    def __init__(self) -> None:
        super().__init__("lease_lost")


class KsefXmlRunError(KsefXmlSyncError):
    def __init__(self, report: Any) -> None:
        super().__init__("document_failures")
        self.report = report


def positive(value: float, name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite positive number")
    try:
        number = float(value)
    except OverflowError:
        raise ValueError(f"{name} must be a finite positive number") from None
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return number


def positive_int(value: int, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def hash_bytes(encoded: str) -> bytes:
    try:
        if type(encoded) is not str or len(encoded) != 44:
            raise ValueError
        value = base64.b64decode(encoded, validate=True)
        if len(value) != 32 or base64.b64encode(value).decode("ascii") != encoded:
            raise ValueError
        return value
    except (ValueError, binascii.Error):
        raise KsefXmlIntegrityError("invalid_hash") from None


def verify_hash(content: bytes, expected: str) -> None:
    if hashlib.sha256(content).digest() != hash_bytes(expected):
        raise KsefXmlIntegrityError("hash_mismatch")


@dataclass(frozen=True, repr=False)
class InvoiceXmlKey:
    namespace: str
    environment: str
    context_key: str
    ksef_number: str
    variant: str = "invoice-xml/v1"

    def __post_init__(self) -> None:
        if self.variant != "invoice-xml/v1":
            raise ValueError("Unsupported XML variant")
        # Reuse the bounded application scope validation without parsing invoice bytes.
        InvoiceSyncScope(self.namespace, self.environment, self.context_key, "xml", "0" * 64)
        from .utils.ksef_number import require_ksef_number

        require_ksef_number(self.ksef_number)

    @property
    def values(self) -> tuple[str, ...]:
        return (self.namespace, self.environment, self.context_key, self.ksef_number, self.variant)

    def object_key(self, expected_hash: str) -> str:
        digest = hashlib.sha256(json.dumps(self.values, separators=(",", ":")).encode()).hexdigest()
        return digest + "-" + hash_bytes(expected_hash).hex() + ".xml"


@dataclass(frozen=True, repr=False)
class InvoiceXmlReceipt:
    storage_id: str
    object_key: str
    sha256_base64: str
    size: int

    def validate(self, key: InvoiceXmlKey, expected_hash: str, storage_id: str) -> None:
        if (
            self.storage_id != storage_id
            or self.object_key != key.object_key(expected_hash)
            or self.sha256_base64 != expected_hash
            or type(self.size) is not int
            or self.size < 0
        ):
            raise KsefXmlIntegrityError("invalid_receipt")


@dataclass(frozen=True, repr=False)
class InvoiceXmlClaim:
    key: InvoiceXmlKey
    expected_hash: str
    storage_id: str
    token: str
    fencing: int
    epoch: str
    expires_at: float
    failures: int
    attempts: int = 1


@dataclass(frozen=True)
class InvoiceXmlReport:
    observed: int
    not_enqueued: int
    pending: int
    leased: int
    retry_wait: int
    blocked: int
    ready: int
    backfill_complete: bool
    observed_at: str
    next_attempt_at: float | None = None
    downloaded: int = 0
    recovered: int = 0
    downloaded_bytes: int = 0
    claims: int = 0
    errors: int = 0
    stop_reason: str | None = None
    checkpoints: tuple[InvoiceSyncCheckpoint | None, ...] = field(default=(), repr=False)

    @property
    def xml_ready_for_observed(self) -> bool:
        return self.ready == self.observed and self.not_enqueued == 0

    def to_dict(self) -> dict[str, Any]:
        result = {
            name: getattr(self, name) for name in self.__dataclass_fields__ if name != "checkpoints"
        }
        result["xml_ready_for_observed"] = self.xml_ready_for_observed
        result["checkpoint_versions"] = [
            {"generation": cp.generation_id, "revision": cp.revision} if cp else None
            for cp in self.checkpoints
        ]
        return result


@dataclass(frozen=True)
class InvoiceDocumentReport:
    metadata: InvoiceSyncReport
    xml: InvoiceXmlReport
    metadata_changed: bool = False

    @property
    def metadata_complete(self) -> bool:
        return self.metadata.complete and not self.metadata_changed

    @property
    def xml_ready_for_observed(self) -> bool:
        return self.xml.xml_ready_for_observed

    @property
    def complete(self) -> bool:
        return self.metadata_complete and self.xml_ready_for_observed and self.xml.backfill_complete

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "xml": self.xml.to_dict(),
            "metadata_changed": self.metadata_changed,
            "metadata_complete": self.metadata_complete,
            "xml_ready_for_observed": self.xml_ready_for_observed,
            "complete": self.complete,
        }


@dataclass(frozen=True)
class InvoiceXmlBackfillReport:
    processed: int
    complete: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class InvoiceXmlStorage(Protocol):
    @property
    def storage_id(self) -> str: ...
    def inspect(self, key: InvoiceXmlKey, expected_hash: str) -> InvoiceXmlReceipt | None: ...
    def put_verified(
        self, key: InvoiceXmlKey, content: bytes, expected_hash: str
    ) -> InvoiceXmlReceipt: ...
    def read(
        self, key: InvoiceXmlKey, expected_hash: str, *, max_bytes: int = 16 * 1024 * 1024
    ) -> bytes: ...


class AsyncInvoiceXmlStorage(Protocol):
    @property
    def storage_id(self) -> str: ...
    async def inspect(self, key: InvoiceXmlKey, expected_hash: str) -> InvoiceXmlReceipt | None: ...
    async def put_verified(
        self, key: InvoiceXmlKey, content: bytes, expected_hash: str
    ) -> InvoiceXmlReceipt: ...
    async def read(
        self, key: InvoiceXmlKey, expected_hash: str, *, max_bytes: int = 16 * 1024 * 1024
    ) -> bytes: ...


class InvoiceDocumentStore(InvoiceSyncStore, Protocol):
    def validate_xml(self, scopes: Sequence[InvoiceSyncScope], storage_id: str) -> None: ...
    def claim_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, lease_seconds: float
    ) -> InvoiceXmlClaim | None: ...
    def finish_xml(self, claim: InvoiceXmlClaim, receipt: InvoiceXmlReceipt) -> None: ...
    def defer_xml(
        self,
        claim: InvoiceXmlClaim,
        *,
        reason: str,
        delay: float,
        blocked: bool = False,
        failure: bool = False,
    ) -> None: ...
    def describe_xml(self, scopes: Sequence[InvoiceSyncScope]) -> InvoiceXmlReport: ...
    def backfill_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, batch_size: int = 500, time_budget: float = 60
    ) -> InvoiceXmlBackfillReport: ...
    def list_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, after: str = "", limit: int = 100
    ) -> list[dict[str, Any]]: ...
    def verify_ready(
        self,
        scopes: Sequence[InvoiceSyncScope],
        storage: InvoiceXmlStorage,
        *,
        after: str = "",
        limit: int = 100,
    ) -> str | None: ...
    def retry_blocked(
        self, scopes: Sequence[InvoiceSyncScope], *, reason: str, limit: int = 100
    ) -> int: ...
    def fence_workers(self) -> None: ...


class AsyncInvoiceDocumentStore(AsyncInvoiceSyncStore, Protocol):
    async def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None: ...
    async def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt: ...
    async def validate_xml(self, scopes: Sequence[InvoiceSyncScope], storage_id: str) -> None: ...
    async def claim_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, lease_seconds: float
    ) -> InvoiceXmlClaim | None: ...
    async def finish_xml(self, claim: InvoiceXmlClaim, receipt: InvoiceXmlReceipt) -> None: ...
    async def defer_xml(
        self,
        claim: InvoiceXmlClaim,
        *,
        reason: str,
        delay: float,
        blocked: bool = False,
        failure: bool = False,
    ) -> None: ...
    async def describe_xml(self, scopes: Sequence[InvoiceSyncScope]) -> InvoiceXmlReport: ...
    async def backfill_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, batch_size: int = 500, time_budget: float = 60
    ) -> InvoiceXmlBackfillReport: ...
    async def list_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, after: str = "", limit: int = 100
    ) -> list[dict[str, Any]]: ...
    async def verify_ready(
        self,
        scopes: Sequence[InvoiceSyncScope],
        storage: AsyncInvoiceXmlStorage,
        *,
        after: str = "",
        limit: int = 100,
    ) -> str | None: ...
    async def retry_blocked(
        self, scopes: Sequence[InvoiceSyncScope], *, reason: str, limit: int = 100
    ) -> int: ...
    async def fence_workers(self) -> None: ...
