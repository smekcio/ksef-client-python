"""Import verified KSeF export windows into the durable invoice archive."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import stat
from dataclasses import dataclass, replace
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

from . import models as m
from ._async_cleanup import shield_and_drain
from ._invoice_export_package import ValidatedInvoicePackage, validate_invoice_package
from ._invoice_export_state import ExportCheckpoint, ExportProgress
from .exceptions import KsefDocumentValidationError
from .invoice_search import _date
from .invoice_sync_state import InvoiceSyncScope, canonical_json, utc_timestamp
from .invoice_xml_storage import _safe_directory
from .invoice_xml_types import (
    AsyncInvoiceXmlStorage,
    InvoiceXmlKey,
    InvoiceXmlStorage,
    positive,
    positive_int,
)
from .operations import ExportOperationError, OperationState
from .request_control import request_control
from .sqlite_store import AsyncSQLiteInvoiceSyncStore, SQLiteInvoiceSyncStore
from .streaming_export import (
    AsyncExportOperation,
    ExportFiles,
    ExportOperation,
    directory_lock,
)
from .utils.zip_utils import EXPORT_MAX_ARCHIVE_ENTRIES

if TYPE_CHECKING:
    from .async_facade import AsyncKsef
    from .facade import Ksef

_CHUNK = 32
_MAX_METADATA = 32 * 1024 * 1024
_Client = TypeVar("_Client", bound="Ksef | AsyncKsef")


@dataclass(frozen=True)
class InvoiceExportSyncReport:
    """Progress of one role, using committed coverage only for the HWM."""

    committed_hwm: str | None
    continuation: str | None
    imported: int = 0
    inserted: int = 0
    status: str = "idle"


class _InvoiceExportConfig(Generic[_Client]):
    def __init__(
        self,
        client: _Client,
        *,
        namespace: str,
        sync_key: str,
        since: str,
        work_dir: str | Path,
        state_key: bytes,
        subject_type: m.InvoiceQuerySubjectType = m.InvoiceQuerySubjectType.SUBJECT2,
        compression_type: m.CompressionType = m.CompressionType.TARGZ,
        max_xml_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if type(state_key) is not bytes or len(state_key) != 32:
            raise ValueError("Export checkpoint encryption requires a 32-byte key")
        if not isinstance(subject_type, m.InvoiceQuerySubjectType):
            raise TypeError("subject_type must be InvoiceQuerySubjectType")
        if not isinstance(compression_type, m.CompressionType):
            raise TypeError("compression_type must be CompressionType")
        self._initial = ExportProgress(since)
        self._subject_type, self._compression_type = subject_type, compression_type
        identity = hashlib.sha256(
            f"invoice-export/v1:{subject_type.value}".encode("ascii")
        ).hexdigest()
        self.scope = InvoiceSyncScope(
            namespace, client.environment, client.context_key, sync_key, identity
        )
        work_key = hashlib.sha256(canonical_json(self.scope.to_dict(), 8192)).hexdigest()
        self._workspace = Path(os.path.abspath(work_dir)) / work_key
        self._max_xml_bytes = positive_int(max_xml_bytes, "max_xml_bytes")
        self._client, self._state_key = client, state_key

    def _resume(self, previous: tuple[int, bytes] | None) -> tuple[int, ExportCheckpoint]:
        if previous is None:
            return 0, ExportCheckpoint(self._initial)
        revision, raw = previous
        state = ExportCheckpoint.decode(raw, self._state_key)
        if state.progress.since != self._initial.since:
            raise ValueError("Existing export stream has a different starting date")
        return revision, state

    def _query(self, start: str, end: str) -> m.InvoiceQueryFilters:
        return m.InvoiceQueryFilters(
            subject_type=self._subject_type,
            date_range=m.InvoiceQueryDateRange(
                date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                from_=start,
                to=end,
                restrict_to_permanent_storage_hwm_date=True,
            ),
        )


class InvoiceExportSync(_InvoiceExportConfig["Ksef"]):
    """One export stream. Run once per role and repeat for history or new data."""

    def run_once(
        self,
        store: SQLiteInvoiceSyncStore,
        storage: InvoiceXmlStorage,
        *,
        until: str | None = None,
        timeout: float = 600,
        max_documents: int = 10_000,
    ) -> InvoiceExportSyncReport:
        """Resume at most one export fragment, committing XML in bounded chunks."""
        if until is not None:
            until = utc_timestamp(until)
        positive(timeout, "timeout")
        positive_int(max_documents, "max_documents")
        store.validate_xml((self.scope,), storage.storage_id)
        _private_workspace(self._workspace)
        with request_control(timeout_seconds=timeout), directory_lock(self._workspace):
            return self._run(store, storage, until, timeout, max_documents)

    def _run(
        self,
        store: SQLiteInvoiceSyncStore,
        storage: InvoiceXmlStorage,
        until: str | None,
        timeout: float,
        max_documents: int,
    ) -> InvoiceExportSyncReport:
        client = self._client
        revision, state = self._resume(store._load_export(self.scope))

        bounds = (
            state.progress.bounds(until) if state.end is None else (state.progress.start, state.end)
        )
        if bounds is None:
            return _report(state.progress)
        start, end = bounds
        if until is not None and state.end is not None and _date(until) < _date(end):
            raise ValueError("Cannot shorten an active export window")

        if state.operation is None:
            state = replace(state, end=end)
            revision, _ = store._commit_export(
                self.scope, revision, state.encode(self._state_key), storage_id=storage.storage_id
            )
            operation = client.exports.start(
                self._query(start, end), compression_type=self._compression_type
            )
            state = replace(state, operation=operation.resume_state())
            revision, _ = store._commit_export(
                self.scope, revision, state.encode(self._state_key), storage_id=storage.storage_id
            )
        else:
            operation = ExportOperation(client, state.operation)

        operation_state = operation.resume_state()
        operation_state.bind(self.scope.environment, self.scope.context_key)
        directory = _operation_directory(self._workspace, operation_state)
        _private_workspace(directory)
        try:
            files = _receive(operation, directory, timeout)
        except ExportOperationError as error:
            if error.status_code not in {210, 420}:
                raise
            fresh = ExportCheckpoint(state.progress, end=end)
            store._commit_export(
                self.scope, revision, fresh.encode(self._state_key), storage_id=storage.storage_id
            )
            shutil.rmtree(directory)
            status = "expired" if error.status_code == 210 else "waiting_hwm"
            return _report(state.progress, status=status)

        package, state, fingerprint = _prepare_package(files, state, operation_state, start, end)
        offset, inserted = state.offset, state.inserted
        last = min(offset + max_documents, len(package.invoices))
        for first in range(offset, last, _CHUNK):
            stop = min(first + _CHUNK, last)
            documents = []
            for invoice in package.invoices[first:stop]:
                content = invoice.read_xml(self._max_xml_bytes)
                key = InvoiceXmlKey(
                    self.scope.namespace,
                    self.scope.environment,
                    self.scope.context_key,
                    invoice.number,
                )
                receipt = storage.put_verified(key, content, invoice.metadata["invoiceHash"])
                documents.append((invoice.metadata, receipt))
            state = replace(state, offset=stop, inserted=inserted, package_id=fingerprint)
            revision, new = store._commit_export(
                self.scope,
                revision,
                state.encode(self._state_key),
                storage_id=storage.storage_id,
                documents=documents,
                count_insertions=True,
            )
            inserted += new

        if last < len(package.invoices):
            return _report(state.progress, last - offset, inserted, "importing")
        progress = state.progress.finish(package, window_end=end, new_at_boundary=inserted)
        store._commit_export(
            self.scope,
            revision,
            ExportCheckpoint(progress).encode(self._state_key),
            storage_id=storage.storage_id,
        )
        shutil.rmtree(directory)
        return _report(
            progress, last - offset, inserted, "truncated" if package.truncated else "committed"
        )


class AsyncInvoiceExportSync(_InvoiceExportConfig["AsyncKsef"]):
    """Use native async transport, with blocking archive I/O off the event loop."""

    async def run_once(
        self,
        store: AsyncSQLiteInvoiceSyncStore,
        storage: AsyncInvoiceXmlStorage,
        *,
        until: str | None = None,
        timeout: float = 600,
        max_documents: int = 10_000,
    ) -> InvoiceExportSyncReport:
        """Resume at most one export fragment, committing XML in bounded chunks."""
        if until is not None:
            until = utc_timestamp(until)
        positive(timeout, "timeout")
        positive_int(max_documents, "max_documents")
        await store.validate_xml((self.scope,), storage.storage_id)
        await asyncio.to_thread(_private_workspace, self._workspace)
        with request_control(timeout_seconds=timeout), directory_lock(self._workspace):
            return await self._run(store, storage, until, timeout, max_documents)

    async def _run(
        self,
        store: AsyncSQLiteInvoiceSyncStore,
        storage: AsyncInvoiceXmlStorage,
        until: str | None,
        timeout: float,
        max_documents: int,
    ) -> InvoiceExportSyncReport:
        client = self._client
        revision, state = self._resume(await store._call("_load_export", self.scope))

        bounds = (
            state.progress.bounds(until) if state.end is None else (state.progress.start, state.end)
        )
        if bounds is None:
            return _report(state.progress)
        start, end = bounds
        if until is not None and state.end is not None and _date(until) < _date(end):
            raise ValueError("Cannot shorten an active export window")

        if state.operation is None:
            state = replace(state, end=end)
            revision, _ = await store._call(
                "_commit_export",
                self.scope,
                revision,
                state.encode(self._state_key),
                storage_id=storage.storage_id,
            )
            operation = await client.exports.start(
                self._query(start, end), compression_type=self._compression_type
            )
            state = replace(state, operation=operation.resume_state())
            revision, _ = await store._call(
                "_commit_export",
                self.scope,
                revision,
                state.encode(self._state_key),
                storage_id=storage.storage_id,
            )
        else:
            operation = AsyncExportOperation(client, state.operation)

        operation_state = operation.resume_state()
        operation_state.bind(self.scope.environment, self.scope.context_key)
        directory = _operation_directory(self._workspace, operation_state)
        await asyncio.to_thread(_private_workspace, directory)
        try:
            files = await _receive_async(operation, directory, timeout)
        except ExportOperationError as error:
            if error.status_code not in {210, 420}:
                raise
            fresh = ExportCheckpoint(state.progress, end=end)
            await store._call(
                "_commit_export",
                self.scope,
                revision,
                fresh.encode(self._state_key),
                storage_id=storage.storage_id,
            )
            await shield_and_drain(asyncio.to_thread(shutil.rmtree, directory))
            status = "expired" if error.status_code == 210 else "waiting_hwm"
            return _report(state.progress, status=status)

        package, state, fingerprint = await shield_and_drain(
            asyncio.to_thread(_prepare_package, files, state, operation_state, start, end)
        )
        offset, inserted = state.offset, state.inserted
        last = min(offset + max_documents, len(package.invoices))
        for first in range(offset, last, _CHUNK):
            stop = min(first + _CHUNK, last)
            documents = []
            for invoice in package.invoices[first:stop]:
                content = await shield_and_drain(
                    asyncio.to_thread(invoice.read_xml, self._max_xml_bytes)
                )
                key = InvoiceXmlKey(
                    self.scope.namespace,
                    self.scope.environment,
                    self.scope.context_key,
                    invoice.number,
                )
                receipt = await storage.put_verified(key, content, invoice.metadata["invoiceHash"])
                documents.append((invoice.metadata, receipt))
            state = replace(state, offset=stop, inserted=inserted, package_id=fingerprint)
            revision, new = await store._call(
                "_commit_export",
                self.scope,
                revision,
                state.encode(self._state_key),
                storage_id=storage.storage_id,
                documents=documents,
                count_insertions=True,
            )
            inserted += new

        if last < len(package.invoices):
            return _report(state.progress, last - offset, inserted, "importing")
        progress = state.progress.finish(package, window_end=end, new_at_boundary=inserted)
        await store._call(
            "_commit_export",
            self.scope,
            revision,
            ExportCheckpoint(progress).encode(self._state_key),
            storage_id=storage.storage_id,
        )
        await shield_and_drain(asyncio.to_thread(shutil.rmtree, directory))
        return _report(
            progress, last - offset, inserted, "truncated" if package.truncated else "committed"
        )


def _private_workspace(directory: Path) -> None:
    _safe_directory(directory, allow_missing=True)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _safe_directory(directory)
    if os.name == "posix" and stat.S_IMODE(directory.stat().st_mode) & 0o077:
        raise ValueError("Export synchronization work directory must be private (mode 0700)")


def _operation_directory(workspace: Path, state: OperationState) -> Path:
    identifier = hashlib.sha256(state.reference_number.encode("ascii")).hexdigest()
    return workspace / identifier


def _receive(operation: ExportOperation, directory: Path, timeout: float) -> ExportFiles:
    destination = directory / "documents"
    if not destination.exists():
        return operation.download_to(destination, work_dir=directory / "transfer", timeout=timeout)
    saved = operation.resume_state().payload.get("archive_descriptor")
    package = (
        operation.wait(timeout=timeout).package
        if saved is None
        else m.InvoicePackage.from_dict(saved)
    )
    return _local_files(destination, package)


async def _receive_async(
    operation: AsyncExportOperation, directory: Path, timeout: float
) -> ExportFiles:
    destination = directory / "documents"
    if not destination.exists():
        return await operation.download_to(
            destination, work_dir=directory / "transfer", timeout=timeout
        )
    saved = operation.resume_state().payload.get("archive_descriptor")
    package = (
        (await operation.wait(timeout=timeout)).package
        if saved is None
        else m.InvoicePackage.from_dict(saved)
    )
    return await shield_and_drain(asyncio.to_thread(_local_files, destination, package))


def _local_files(destination: Path, package: m.InvoicePackage | None) -> ExportFiles:
    _safe_directory(destination)
    if package is None:
        raise KsefDocumentValidationError("Successful export has no package")
    with os.scandir(destination) as entries:
        names = tuple(entry.name for entry in islice(entries, EXPORT_MAX_ARCHIVE_ENTRIES + 1))
    if len(names) > EXPORT_MAX_ARCHIVE_ENTRIES:
        raise KsefDocumentValidationError("Local export has too many files")
    metadata = next(
        (destination / name for name in names if name.lower() == "_metadata.json"), None
    )
    return ExportFiles(destination, names, metadata, package)


def _prepare_package(
    files: ExportFiles,
    state: ExportCheckpoint,
    operation_state: OperationState,
    start: str,
    end: str,
) -> tuple[ValidatedInvoicePackage, ExportCheckpoint, str]:
    package = validate_invoice_package(
        files, start=start, end=end, max_metadata_bytes=_MAX_METADATA
    )
    fingerprint = _fingerprint(package)
    if state.package_id is not None and state.package_id != fingerprint:
        raise KsefDocumentValidationError("Export package changed after import began")
    if state.offset > len(package.invoices):
        raise KsefDocumentValidationError("Export import offset is outside the package")
    # Authenticate the descriptor without storing signed URLs. A local import
    # can then finish after KSeF expires the already downloaded package.
    descriptor = replace(files.package, parts=[]).to_dict()
    operation_state = replace(
        operation_state, payload=dict(operation_state.payload, archive_descriptor=descriptor)
    )
    state = replace(state, operation=operation_state)
    return package, state, fingerprint


def _fingerprint(package: ValidatedInvoicePackage) -> str:
    identity = f"{package.continuation}:{package.truncated}:{package.metadata_digest}"
    return hashlib.sha256(identity.encode("ascii")).hexdigest()


def _report(
    progress: ExportProgress, imported: int = 0, inserted: int = 0, status: str = "idle"
) -> InvoiceExportSyncReport:
    return InvoiceExportSyncReport(
        progress.committed_hwm, progress.continuation, imported, inserted, status
    )
