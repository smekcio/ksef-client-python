"""Durable offline submission through the authenticated KSeF facade."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, cast

from . import models as m
from ._offline_invoice_state import OfflineInvoiceStatus
from ._offline_invoice_store import (
    AsyncSQLiteOfflineInvoiceStore,
    SQLiteOfflineInvoiceStore,
    StoredOfflineInvoice,
)
from .exceptions import KsefDocumentValidationError
from .invoice_sync_state import InvoiceSyncScope
from .request_control import request_control

if TYPE_CHECKING:
    from .async_facade import AsyncKsef
    from .facade import Ksef

_OFFLINE_STREAM = hashlib.sha256(b"ksef-offline-submission/v1").hexdigest()
_RECONCILIATION_PAGE_LIMIT = 10


class OfflineInvoices:
    """One-step worker with a persistent, context-bound submission record.

    Run advance again after a pending result or a transient read failure. A
    lost submission response is reconciled using the persisted session and
    exact invoice hash. The worker never automatically resends that invoice.
    """

    def __init__(self, client: Ksef, store: SQLiteOfflineInvoiceStore, *, namespace: str):
        self._client, self._store = client, store
        self.scope = InvoiceSyncScope(
            namespace, client.environment, client.context_key, "offline-invoices", _OFFLINE_STREAM
        )

    def enqueue(
        self, xml: bytes, *, due_at: str, correction_of: str | None = None
    ) -> StoredOfflineInvoice:
        return self._store.enqueue(self.scope, xml, due_at=due_at, correction_of=correction_of)

    def status(self, invoice_hash: str) -> StoredOfflineInvoice | None:
        return self._store.load(self.scope, invoice_hash)

    def read_xml(self, invoice_hash: str) -> bytes:
        return self._store.read_xml(self.scope, invoice_hash)

    def read_upo(self, invoice_hash: str) -> bytes:
        return self._store.read_upo(self.scope, invoice_hash)

    def advance(self, invoice_hash: str, *, timeout: float = 60) -> StoredOfflineInvoice:
        with request_control(timeout_seconds=timeout):
            return self._advance(invoice_hash)

    def _advance(self, invoice_hash: str) -> StoredOfflineInvoice:
        row = self.status(invoice_hash)
        if row is None:
            raise KsefDocumentValidationError("Offline invoice is missing in this scope")
        progress = row.progress
        status = progress.status
        if status is OfflineInvoiceStatus.QUEUED:
            # Check that the archive can be decrypted before producing remote state.
            self.read_xml(invoice_hash)
            session = self._client.online_session().resume_state()
            return self._store._advance(
                self.scope, row, progress.open_session(session.reference_number), session=session
            )
        if status is OfflineInvoiceStatus.SESSION_OPEN:
            state = self._store._read_session(self.scope, row)
            retry = self._client.options.retry
            path = f"/sessions/online/{state.reference_number}/invoices"
            if retry is not None and path in retry.retryable_post_paths:
                raise ValueError("Disable transport-level retries for offline invoice submission")
            xml = self.read_xml(invoice_hash)
            session_handle = self._client.resume_session(state)
            # Persist before the POST. The revision check allows only one sender.
            pending = self._store._advance(self.scope, row, progress.begin_submission())
            sent = session_handle.send_invoice(
                xml, offline_mode=True, hash_of_corrected_invoice=row.correction_of
            )
            return self._store._advance(
                self.scope,
                pending,
                pending.progress.confirm_reference(sent.resume_state().reference_number),
            )
        if status in {OfflineInvoiceStatus.SUBMISSION_UNKNOWN, OfflineInvoiceStatus.SUBMITTED}:
            reference = cast(str, progress.session_reference)
            sessions = self._client.api.sessions
            if progress.invoice_reference is None:
                match = self._find_submission(reference, invoice_hash)
                if match is None:
                    return row
            else:
                match = sessions.get_session_invoice_status(reference, progress.invoice_reference)
            observed = progress.observe(match)
            if observed == progress:
                return row
            return self._store._advance(self.scope, row, observed)
        if status is OfflineInvoiceStatus.ACCEPTED:
            session_ref, invoice_ref = (
                cast(str, progress.session_reference),
                cast(str, progress.invoice_reference),
            )
            sessions = self._client.api.sessions
            session_status = sessions.get_session_status(session_ref).status.code
            if session_status == 100:
                sessions.close_online_session(session_ref)
                return row
            if session_status == 170:
                return row
            if session_status != 200:
                raise KsefDocumentValidationError("KSeF session cannot provide the offline UPO")
            upo = sessions.get_session_invoice_upo_by_ref(session_ref, invoice_ref)
            return self._store._advance(self.scope, row, progress.confirm_upo(), upo=upo)
        return row

    def _find_submission(
        self, session: str, invoice_hash: str
    ) -> m.SessionInvoiceStatusResponse | None:
        match = None
        seen: set[str] = set()
        token = None
        for _ in range(_RECONCILIATION_PAGE_LIMIT):
            page = self._client.api.sessions.get_session_invoices(
                session, page_size=100, continuation_token=token
            )
            match = _match_invoice(match, page, invoice_hash)
            token = page.continuation_token
            if token is None:
                return match
            if len(token) > 16_384 or token in seen:
                break
            seen.add(token)
        raise KsefDocumentValidationError("KSeF offline session listing did not complete")


class AsyncOfflineInvoices:
    """Asynchronous variant of OfflineInvoices using native async KSeF requests."""

    def __init__(self, client: AsyncKsef, store: AsyncSQLiteOfflineInvoiceStore, *, namespace: str):
        self._client, self._store = client, store
        self.scope = InvoiceSyncScope(
            namespace, client.environment, client.context_key, "offline-invoices", _OFFLINE_STREAM
        )

    async def enqueue(
        self, xml: bytes, *, due_at: str, correction_of: str | None = None
    ) -> StoredOfflineInvoice:
        return await self._store._call(
            "enqueue", self.scope, xml, due_at=due_at, correction_of=correction_of
        )

    async def status(self, invoice_hash: str) -> StoredOfflineInvoice | None:
        return await self._store._call("load", self.scope, invoice_hash)

    async def read_xml(self, invoice_hash: str) -> bytes:
        return await self._store._call("read_xml", self.scope, invoice_hash)

    async def read_upo(self, invoice_hash: str) -> bytes:
        return await self._store._call("read_upo", self.scope, invoice_hash)

    async def advance(self, invoice_hash: str, *, timeout: float = 60) -> StoredOfflineInvoice:
        with request_control(timeout_seconds=timeout):
            return await self._advance(invoice_hash)

    async def _advance(self, invoice_hash: str) -> StoredOfflineInvoice:
        row = await self.status(invoice_hash)
        if row is None:
            raise KsefDocumentValidationError("Offline invoice is missing in this scope")
        progress = row.progress
        status = progress.status
        if status is OfflineInvoiceStatus.QUEUED:
            # Check that the archive can be decrypted before producing remote state.
            await self.read_xml(invoice_hash)
            session = (await self._client.online_session()).resume_state()
            return await self._store._call(
                "_advance",
                self.scope,
                row,
                progress.open_session(session.reference_number),
                session=session,
            )
        if status is OfflineInvoiceStatus.SESSION_OPEN:
            state = await self._store._call("_read_session", self.scope, row)
            retry = self._client.options.retry
            path = f"/sessions/online/{state.reference_number}/invoices"
            if retry is not None and path in retry.retryable_post_paths:
                raise ValueError("Disable transport-level retries for offline invoice submission")
            xml = await self.read_xml(invoice_hash)
            session_handle = self._client.resume_session(state)
            # Persist before the POST. The revision check allows only one sender.
            pending = await self._store._call(
                "_advance", self.scope, row, progress.begin_submission()
            )
            sent = await session_handle.send_invoice(
                xml, offline_mode=True, hash_of_corrected_invoice=row.correction_of
            )
            return await self._store._call(
                "_advance",
                self.scope,
                pending,
                pending.progress.confirm_reference(sent.resume_state().reference_number),
            )
        if status in {OfflineInvoiceStatus.SUBMISSION_UNKNOWN, OfflineInvoiceStatus.SUBMITTED}:
            reference = cast(str, progress.session_reference)
            sessions = self._client.api.sessions
            if progress.invoice_reference is None:
                match = await self._find_submission(reference, invoice_hash)
                if match is None:
                    return row
            else:
                match = await sessions.get_session_invoice_status(
                    reference, progress.invoice_reference
                )
            observed = progress.observe(match)
            if observed == progress:
                return row
            return await self._store._call("_advance", self.scope, row, observed)
        if status is OfflineInvoiceStatus.ACCEPTED:
            session_ref, invoice_ref = (
                cast(str, progress.session_reference),
                cast(str, progress.invoice_reference),
            )
            sessions = self._client.api.sessions
            session_status = (await sessions.get_session_status(session_ref)).status.code
            if session_status == 100:
                await sessions.close_online_session(session_ref)
                return row
            if session_status == 170:
                return row
            if session_status != 200:
                raise KsefDocumentValidationError("KSeF session cannot provide the offline UPO")
            upo = await sessions.get_session_invoice_upo_by_ref(session_ref, invoice_ref)
            return await self._store._call(
                "_advance", self.scope, row, progress.confirm_upo(), upo=upo
            )
        return row

    async def _find_submission(
        self, session: str, invoice_hash: str
    ) -> m.SessionInvoiceStatusResponse | None:
        match = None
        seen: set[str] = set()
        token = None
        for _ in range(_RECONCILIATION_PAGE_LIMIT):
            page = await self._client.api.sessions.get_session_invoices(
                session, page_size=100, continuation_token=token
            )
            match = _match_invoice(match, page, invoice_hash)
            token = page.continuation_token
            if token is None:
                return match
            if len(token) > 16_384 or token in seen:
                break
            seen.add(token)
        raise KsefDocumentValidationError("KSeF offline session listing did not complete")


def _match_invoice(
    match: m.SessionInvoiceStatusResponse | None,
    page: m.SessionInvoicesResponse,
    invoice_hash: str,
) -> m.SessionInvoiceStatusResponse | None:
    for item in page.invoices:
        if item.invoice_hash != invoice_hash:
            continue
        if not item.reference_number:
            raise KsefDocumentValidationError("KSeF offline result has no reference")
        if match is not None and item.reference_number != match.reference_number:
            raise KsefDocumentValidationError("KSeF returned ambiguous offline invoice references")
        match = item
    return match


__all__ = [
    "AsyncOfflineInvoices",
    "AsyncSQLiteOfflineInvoiceStore",
    "OfflineInvoiceStatus",
    "OfflineInvoices",
    "SQLiteOfflineInvoiceStore",
    "StoredOfflineInvoice",
]
