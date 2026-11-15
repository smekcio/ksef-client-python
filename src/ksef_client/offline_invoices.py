"""Durable offline submission through the authenticated KSeF facade."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from . import models as m
from ._offline_invoice_state import (
    OfflineInvoiceMode,
    OfflineInvoiceProgress,
    OfflineInvoiceStatus,
)
from ._offline_invoice_store import (
    AsyncSQLiteOfflineInvoiceStore,
    SQLiteOfflineInvoiceStore,
    StoredOfflineInvoice,
)
from ._offline_verification import OfflineVerificationLinks, build_offline_verification_links
from .config import KsefClientOptions
from .exceptions import (
    KsefAuthenticationError,
    KsefAuthorizationError,
    KsefDocumentValidationError,
    KsefHttpError,
    KsefPermissionError,
    KsefSyncConflictError,
    KsefTransportTimeoutError,
)
from .invoice_sync_state import InvoiceSyncScope
from .operations import environment_key
from .rate_limiting import KsefRateLimitWaitTimeout
from .request_control import current_request_control, request_control
from .services.auth import _normalize_context_identifier_type
from .services.xades import XadesKeyPair

if TYPE_CHECKING:
    from .async_facade import AsyncKsef
    from .facade import Ksef

_OFFLINE_STREAM = hashlib.sha256(b"ksef-offline-submission/v1").hexdigest()
_RECONCILIATION_PAGE_LIMIT = 10


@dataclass(frozen=True)
class OfflineBatchFailure:
    """One failed item in a batch that can continue processing other invoices."""

    invoice_hash: str
    code: str


class OfflineInvoiceQueue:
    """Stage and present offline invoices without connecting to KSeF."""

    def __init__(
        self,
        store: SQLiteOfflineInvoiceStore,
        *,
        options: KsefClientOptions,
        context_type: str,
        context_value: str,
        namespace: str,
    ) -> None:
        kind = _normalize_context_identifier_type(context_type).value
        if not context_value or not context_value.strip():
            raise ValueError("Offline invoice context is required")
        self._store, self._options = store, options
        self.scope = InvoiceSyncScope(
            namespace,
            environment_key(options.normalized_base_url()),
            f"{kind}:{context_value}",
            "offline-invoices",
            _OFFLINE_STREAM,
        )

    def enqueue(
        self,
        xml: bytes,
        *,
        due_at: str,
        correction_of: str | None = None,
        mode: OfflineInvoiceMode = OfflineInvoiceMode.OFFLINE24,
    ) -> StoredOfflineInvoice:
        return self._store.enqueue(
            self.scope, xml, due_at=due_at, correction_of=correction_of, mode=mode
        )

    def status(self, invoice_hash: str) -> StoredOfflineInvoice | None:
        return self._store.load(self.scope, invoice_hash)

    def reschedule(
        self, invoice_hash: str, *, due_at: str, expected_revision: int
    ) -> StoredOfflineInvoice:
        """Update the deadline on the specified revision of an active invoice."""
        return self._store.reschedule(
            self.scope, invoice_hash, due_at=due_at, expected_revision=expected_revision
        )

    def retry_cancelled(self, invoice_hash: str) -> StoredOfflineInvoice:
        """Queue the original XML again after KSeF confirms cancellation (status 550)."""
        return self._store.retry_cancelled(self.scope, invoice_hash)

    def pending(
        self, *, limit: int = 100, after: tuple[str, str] | None = None
    ) -> tuple[StoredOfflineInvoice, ...]:
        """Return active entries ordered by deadline, including unresolved submissions."""
        return self._store.pending(self.scope, limit=limit, after=after)

    def read_xml(self, invoice_hash: str) -> bytes:
        return self._store.read_xml(self.scope, invoice_hash)

    def read_upo(self, invoice_hash: str) -> bytes:
        return self._store.read_upo(self.scope, invoice_hash)

    def verification_links(
        self, invoice_hash: str, signer: XadesKeyPair
    ) -> OfflineVerificationLinks:
        row = self.status(invoice_hash)
        if row is None:
            raise KsefDocumentValidationError("Offline invoice is missing in this scope")
        return build_offline_verification_links(
            self._options,
            self.scope.context_key,
            row.progress,
            self.read_xml(invoice_hash),
            signer,
        )


class OfflineInvoices(OfflineInvoiceQueue):
    """One-step worker with a persistent, context-bound submission record.

    Run advance again after a pending result or a transient read failure. A
    lost submission response is reconciled using the persisted session and
    exact invoice hash. The worker never automatically resends that invoice.
    """

    def __init__(self, client: Ksef, store: SQLiteOfflineInvoiceStore, *, namespace: str):
        self._client, self._store, self._options = client, store, client.options
        self.scope = InvoiceSyncScope(
            namespace, client.environment, client.context_key, "offline-invoices", _OFFLINE_STREAM
        )

    def advance(self, invoice_hash: str, *, timeout: float = 60) -> StoredOfflineInvoice:
        with request_control(timeout_seconds=timeout):
            return self._advance(invoice_hash, timeout)

    def advance_batch(
        self,
        entries: Sequence[StoredOfflineInvoice],
        *,
        timeout: float = 60,
        submit_immediately: bool = False,
    ) -> tuple[list[StoredOfflineInvoice], list[OfflineBatchFailure]]:
        """Process independent entries, retaining state even if a send times out.

        For scheduled submission, advance already-open sessions first within the
        page and use the same item deadline for opening and sending a new entry.
        """
        rows: list[StoredOfflineInvoice] = []
        failures: list[OfflineBatchFailure] = []
        if submit_immediately:
            entries = sorted(
                entries,
                key=lambda entry: entry.progress.status is not OfflineInvoiceStatus.SESSION_OPEN,
            )
        parent = current_request_control()
        for entry in entries:
            digest = entry.progress.invoice_hash
            try:
                with request_control(timeout_seconds=timeout):
                    row = self.advance(digest, timeout=timeout)
                    if (
                        submit_immediately
                        and entry.progress.status is OfflineInvoiceStatus.QUEUED
                        and row.progress.status is OfflineInvoiceStatus.SESSION_OPEN
                    ):
                        row = self.advance(digest, timeout=timeout)
                rows.append(row)
            except (KsefRateLimitWaitTimeout, KsefTransportTimeoutError):
                if parent is not None:
                    parent.check()
                failures.append(OfflineBatchFailure(digest, "request_timeout"))
            except (KsefAuthenticationError, KsefAuthorizationError, KsefPermissionError):
                raise
            except (KsefDocumentValidationError, KsefSyncConflictError, KsefHttpError) as exc:
                if isinstance(exc, KsefHttpError) and exc.status_code not in {
                    400,
                    404,
                    409,
                    410,
                    422,
                    425,
                }:
                    raise
                failures.append(OfflineBatchFailure(digest, exc.code.value))
        return rows, failures

    def retry_if_unsubmitted(
        self, invoice_hash: str, *, timeout: float = 60
    ) -> StoredOfflineInvoice:
        """Release an unknown send only after KSeF finalizes an empty session."""
        with request_control(timeout_seconds=timeout):
            row = _require_unknown(self.status(invoice_hash))
            reference = cast(str, row.progress.session_reference)
            sessions = self._client.api.sessions
            status = sessions.get_session_status(reference)
            if status.status.code == 100:
                sessions.close_online_session(reference)
                return row
            if (
                status.status.code == 440
                and type(status.invoice_count) is int
                and status.invoice_count == 0
                and not self._scan_submission(reference, invoice_hash)[1]
            ):
                return self._store._advance(self.scope, row, OfflineInvoiceProgress(invoice_hash))
            return row

    def _advance(self, invoice_hash: str, timeout: float) -> StoredOfflineInvoice:
        row = self.status(invoice_hash)
        if row is None:
            raise KsefDocumentValidationError("Offline invoice is missing in this scope")
        progress = row.progress
        status = progress.status
        if status is OfflineInvoiceStatus.QUEUED:
            # Check that the archive can be decrypted before producing remote state.
            self.read_xml(invoice_hash)
            claim = self._store._claim_open(self.scope, invoice_hash, timeout)
            if claim is None:
                return row
            session = self._client.online_session().resume_state()
            return self._store._advance(
                self.scope,
                row,
                progress.open_session(session.reference_number),
                session=session,
                opening_token=claim,
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
                match, _ = self._scan_submission(reference, invoice_hash)
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

    def _scan_submission(
        self, session: str, invoice_hash: str
    ) -> tuple[m.SessionInvoiceStatusResponse | None, bool]:
        match = None
        nonempty = False
        seen: set[str] = set()
        token = None
        for _ in range(_RECONCILIATION_PAGE_LIMIT):
            page = self._client.api.sessions.get_session_invoices(
                session, page_size=100, continuation_token=token
            )
            nonempty |= bool(page.invoices)
            match = _match_invoice(match, page, invoice_hash)
            token = page.continuation_token
            if not token:
                return match, nonempty
            if len(token) > 16_384 or token in seen:
                break
            seen.add(token)
        raise KsefDocumentValidationError("KSeF offline session listing did not complete")


class AsyncOfflineInvoiceQueue:
    """Stage and present offline invoices without connecting to KSeF."""

    def __init__(
        self,
        store: AsyncSQLiteOfflineInvoiceStore,
        *,
        options: KsefClientOptions,
        context_type: str,
        context_value: str,
        namespace: str,
    ) -> None:
        kind = _normalize_context_identifier_type(context_type).value
        if not context_value or not context_value.strip():
            raise ValueError("Offline invoice context is required")
        self._store, self._options = store, options
        self.scope = InvoiceSyncScope(
            namespace,
            environment_key(options.normalized_base_url()),
            f"{kind}:{context_value}",
            "offline-invoices",
            _OFFLINE_STREAM,
        )

    async def enqueue(
        self,
        xml: bytes,
        *,
        due_at: str,
        correction_of: str | None = None,
        mode: OfflineInvoiceMode = OfflineInvoiceMode.OFFLINE24,
    ) -> StoredOfflineInvoice:
        return await self._store._call(
            "enqueue", self.scope, xml, due_at=due_at, correction_of=correction_of, mode=mode
        )

    async def status(self, invoice_hash: str) -> StoredOfflineInvoice | None:
        return await self._store._call("load", self.scope, invoice_hash)

    async def reschedule(
        self, invoice_hash: str, *, due_at: str, expected_revision: int
    ) -> StoredOfflineInvoice:
        """Update the deadline on the specified revision of an active invoice."""
        return await self._store._call(
            "reschedule",
            self.scope,
            invoice_hash,
            due_at=due_at,
            expected_revision=expected_revision,
        )

    async def retry_cancelled(self, invoice_hash: str) -> StoredOfflineInvoice:
        """Queue the original XML again after KSeF confirms cancellation (status 550)."""
        return await self._store._call("retry_cancelled", self.scope, invoice_hash)

    async def pending(
        self, *, limit: int = 100, after: tuple[str, str] | None = None
    ) -> tuple[StoredOfflineInvoice, ...]:
        """Return active entries ordered by deadline, including unresolved submissions."""
        return await self._store._call("pending", self.scope, limit=limit, after=after)

    async def read_xml(self, invoice_hash: str) -> bytes:
        return await self._store._call("read_xml", self.scope, invoice_hash)

    async def read_upo(self, invoice_hash: str) -> bytes:
        return await self._store._call("read_upo", self.scope, invoice_hash)

    async def verification_links(
        self, invoice_hash: str, signer: XadesKeyPair
    ) -> OfflineVerificationLinks:
        row = await self.status(invoice_hash)
        if row is None:
            raise KsefDocumentValidationError("Offline invoice is missing in this scope")
        xml = await self.read_xml(invoice_hash)
        return await asyncio.to_thread(
            build_offline_verification_links,
            self._options,
            self.scope.context_key,
            row.progress,
            xml,
            signer,
        )


class AsyncOfflineInvoices(AsyncOfflineInvoiceQueue):
    """Asynchronous variant of OfflineInvoices using native async KSeF requests."""

    def __init__(self, client: AsyncKsef, store: AsyncSQLiteOfflineInvoiceStore, *, namespace: str):
        self._client, self._store, self._options = client, store, client.options
        self.scope = InvoiceSyncScope(
            namespace, client.environment, client.context_key, "offline-invoices", _OFFLINE_STREAM
        )

    async def advance(self, invoice_hash: str, *, timeout: float = 60) -> StoredOfflineInvoice:
        with request_control(timeout_seconds=timeout):
            return await self._advance(invoice_hash, timeout)

    async def retry_if_unsubmitted(
        self, invoice_hash: str, *, timeout: float = 60
    ) -> StoredOfflineInvoice:
        """Release an unknown send only after KSeF finalizes an empty session."""
        with request_control(timeout_seconds=timeout):
            row = _require_unknown(await self.status(invoice_hash))
            reference = cast(str, row.progress.session_reference)
            sessions = self._client.api.sessions
            status = await sessions.get_session_status(reference)
            if status.status.code == 100:
                await sessions.close_online_session(reference)
                return row
            if (
                status.status.code == 440
                and type(status.invoice_count) is int
                and status.invoice_count == 0
                and not (await self._scan_submission(reference, invoice_hash))[1]
            ):
                return await self._store._call(
                    "_advance", self.scope, row, OfflineInvoiceProgress(invoice_hash)
                )
            return row

    async def _advance(self, invoice_hash: str, timeout: float) -> StoredOfflineInvoice:
        row = await self.status(invoice_hash)
        if row is None:
            raise KsefDocumentValidationError("Offline invoice is missing in this scope")
        progress = row.progress
        status = progress.status
        if status is OfflineInvoiceStatus.QUEUED:
            # Check that the archive can be decrypted before producing remote state.
            await self.read_xml(invoice_hash)
            claim = await self._store._call("_claim_open", self.scope, invoice_hash, timeout)
            if claim is None:
                return row
            session = (await self._client.online_session()).resume_state()
            return await self._store._call(
                "_advance",
                self.scope,
                row,
                progress.open_session(session.reference_number),
                session=session,
                opening_token=claim,
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
                match, _ = await self._scan_submission(reference, invoice_hash)
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

    async def _scan_submission(
        self, session: str, invoice_hash: str
    ) -> tuple[m.SessionInvoiceStatusResponse | None, bool]:
        match = None
        nonempty = False
        seen: set[str] = set()
        token = None
        for _ in range(_RECONCILIATION_PAGE_LIMIT):
            page = await self._client.api.sessions.get_session_invoices(
                session, page_size=100, continuation_token=token
            )
            nonempty |= bool(page.invoices)
            match = _match_invoice(match, page, invoice_hash)
            token = page.continuation_token
            if not token:
                return match, nonempty
            if len(token) > 16_384 or token in seen:
                break
            seen.add(token)
        raise KsefDocumentValidationError("KSeF offline session listing did not complete")


def _require_unknown(row: StoredOfflineInvoice | None) -> StoredOfflineInvoice:
    if row is None or row.progress.status is not OfflineInvoiceStatus.SUBMISSION_UNKNOWN:
        raise KsefDocumentValidationError("Offline invoice has no unknown submission to release")
    return row


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
    "AsyncOfflineInvoiceQueue",
    "AsyncOfflineInvoices",
    "AsyncSQLiteOfflineInvoiceStore",
    "OfflineInvoiceStatus",
    "OfflineInvoiceMode",
    "OfflineInvoiceQueue",
    "OfflineInvoices",
    "OfflineVerificationLinks",
    "SQLiteOfflineInvoiceStore",
    "StoredOfflineInvoice",
]
