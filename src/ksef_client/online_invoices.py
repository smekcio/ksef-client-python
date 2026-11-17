"""Durable, application-identified online invoice submission."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ._offline_invoice_state import OfflineInvoiceStatus as OnlineInvoiceStatus
from ._offline_invoice_store import (
    AsyncSQLiteOfflineInvoiceStore as AsyncSQLiteOnlineInvoiceStore,
)
from ._offline_invoice_store import SQLiteOfflineInvoiceStore as SQLiteOnlineInvoiceStore
from ._offline_invoice_store import StoredOfflineInvoice
from .config import KsefClientOptions
from .exceptions import KsefDocumentValidationError
from .offline_invoices import AsyncOfflineInvoices, OfflineInvoices
from .request_control import request_control

if TYPE_CHECKING:
    from .async_facade import AsyncKsef
    from .facade import Ksef

_ONLINE_SUBMISSION_KIND = (
    "online-invoices",
    hashlib.sha256(b"ksef-online-submission/v1").hexdigest(),
)


@dataclass(frozen=True)
class OnlineInvoice:
    """Durable result of one identified submission, with private values hidden from repr."""

    local_id: str = field(repr=False)
    status: OnlineInvoiceStatus
    revision: int
    session_reference: str | None = field(repr=False)
    invoice_reference: str | None = field(repr=False)
    ksef_number: str | None = field(repr=False)
    ksef_status: int | None


def _result(local_id: str, row: StoredOfflineInvoice) -> OnlineInvoice:
    progress = row.progress
    return OnlineInvoice(
        local_id,
        progress.status,
        row.revision,
        progress.session_reference,
        progress.invoice_reference,
        progress.ksef_number,
        progress.ksef_status,
    )


def _required(row: StoredOfflineInvoice | None) -> StoredOfflineInvoice:
    if row is None:
        raise KsefDocumentValidationError("Online invoice is missing in this scope")
    return row


def _validate_options(options: KsefClientOptions) -> None:
    if options.follow_redirects or (
        options.retry is not None and "/sessions/online" in options.retry.retryable_post_paths
    ):
        raise ValueError("Durable online submission requires a non-replaying HTTP configuration")


class _OnlineWorker(OfflineInvoices):
    _submission_mode = False
    _submission_kind = _ONLINE_SUBMISSION_KIND


class _AsyncOnlineWorker(AsyncOfflineInvoices):
    _submission_mode = False
    _submission_kind = _ONLINE_SUBMISSION_KIND


class OnlineInvoices:
    """Register XML once and advance its online submission through the individual UPO."""

    def __init__(self, client: Ksef, store: SQLiteOnlineInvoiceStore, *, namespace: str) -> None:
        _validate_options(client.options)
        self._worker = _OnlineWorker(client, store, namespace=namespace)
        self._store = store

    def enqueue(self, local_id: str, xml: bytes) -> OnlineInvoice:
        """Bind the application ID and original XML atomically in this scope."""
        return _result(local_id, self._store._enqueue_online(self._worker.scope, local_id, xml))

    def status(self, local_id: str) -> OnlineInvoice | None:
        row = self._store._load_online(self._worker.scope, local_id)
        return None if row is None else _result(local_id, row)

    def advance(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        """Run one step, reconciling unknown sends through the persisted session."""
        with request_control(timeout_seconds=timeout):
            row = _required(self._store._load_online(self._worker.scope, local_id))
            return _result(
                local_id, self._worker.advance(row.progress.invoice_hash, timeout=timeout)
            )

    def retry_if_unsubmitted(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        """Permit a new attempt only after KSeF proves that the old session was empty."""
        with request_control(timeout_seconds=timeout):
            row = _required(self._store._load_online(self._worker.scope, local_id))
            return _result(
                local_id,
                self._worker.retry_if_unsubmitted(row.progress.invoice_hash, timeout=timeout),
            )

    def retry_cancelled(self, local_id: str) -> OnlineInvoice:
        """Requeue only a submission KSeF explicitly cancelled with status 550."""
        row = _required(self._store._load_online(self._worker.scope, local_id))
        return _result(local_id, self._worker.retry_cancelled(row.progress.invoice_hash))

    def read_upo(self, local_id: str) -> bytes:
        """Read the locally stored per-invoice UPO."""
        row = _required(self._store._load_online(self._worker.scope, local_id))
        return self._worker.read_upo(row.progress.invoice_hash)


class AsyncOnlineInvoices:
    """Async durable submission using native async KSeF requests."""

    def __init__(
        self, client: AsyncKsef, store: AsyncSQLiteOnlineInvoiceStore, *, namespace: str
    ) -> None:
        _validate_options(client.options)
        self._worker = _AsyncOnlineWorker(client, store, namespace=namespace)
        self._store = store

    async def enqueue(self, local_id: str, xml: bytes) -> OnlineInvoice:
        row = await self._store._call("_enqueue_online", self._worker.scope, local_id, xml)
        return _result(local_id, row)

    async def status(self, local_id: str) -> OnlineInvoice | None:
        row = await self._store._call("_load_online", self._worker.scope, local_id)
        return None if row is None else _result(local_id, row)

    async def advance(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        with request_control(timeout_seconds=timeout):
            row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
            updated = await self._worker.advance(row.progress.invoice_hash, timeout=timeout)
            return _result(local_id, updated)

    async def retry_if_unsubmitted(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        with request_control(timeout_seconds=timeout):
            row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
            updated = await self._worker.retry_if_unsubmitted(
                row.progress.invoice_hash, timeout=timeout
            )
            return _result(local_id, updated)

    async def retry_cancelled(self, local_id: str) -> OnlineInvoice:
        row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
        updated = await self._worker.retry_cancelled(row.progress.invoice_hash)
        return _result(local_id, updated)

    async def read_upo(self, local_id: str) -> bytes:
        row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
        return await self._worker.read_upo(row.progress.invoice_hash)


__all__ = [
    "AsyncOnlineInvoices",
    "AsyncSQLiteOnlineInvoiceStore",
    "OnlineInvoice",
    "OnlineInvoiceStatus",
    "OnlineInvoices",
    "SQLiteOnlineInvoiceStore",
]
