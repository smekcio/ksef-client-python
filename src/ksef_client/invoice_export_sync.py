"""Import verified KSeF export windows into the durable invoice archive."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from . import models as m
from ._invoice_export_package import ValidatedInvoicePackage, validate_invoice_package
from ._invoice_export_state import ExportCheckpoint, ExportProgress
from .exceptions import KsefDocumentValidationError
from .invoice_search import _date
from .invoice_sync_state import InvoiceSyncScope, canonical_json, utc_timestamp
from .invoice_xml_storage import _safe_directory
from .invoice_xml_types import InvoiceXmlKey, InvoiceXmlStorage, positive, positive_int
from .operations import ExportOperationError, OperationState
from .request_control import request_control
from .sqlite_store import SQLiteInvoiceSyncStore
from .streaming_export import ExportFiles, ExportOperation, directory_lock

if TYPE_CHECKING:
    from .facade import Ksef

_CHUNK = 32
_MAX_METADATA = 32 * 1024 * 1024


@dataclass(frozen=True)
class InvoiceExportSyncReport:
    """Progress of one role, using committed coverage only for the HWM."""

    committed_hwm: str | None
    continuation: str | None
    imported: int = 0
    inserted: int = 0
    status: str = "idle"


class InvoiceExportSync:
    """One export stream. Run once per role and repeat for history or new data."""

    def __init__(
        self,
        client: Ksef,
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
        previous = store._load_export(self.scope)
        if previous is None:
            revision, state = 0, ExportCheckpoint(self._initial)
        else:
            revision, raw = previous
            state = ExportCheckpoint.decode(raw, self._state_key)
            if state.progress.since != self._initial.since:
                raise ValueError("Existing export stream has a different starting date")

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
            operation = self._client.exports.start(
                m.InvoiceQueryFilters(
                    subject_type=self._subject_type,
                    date_range=m.InvoiceQueryDateRange(
                        date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                        from_=start,
                        to=end,
                        restrict_to_permanent_storage_hwm_date=True,
                    ),
                ),
                compression_type=self._compression_type,
            )
            state = replace(state, operation=operation.resume_state())
            revision, _ = store._commit_export(
                self.scope, revision, state.encode(self._state_key), storage_id=storage.storage_id
            )
        else:
            operation = ExportOperation(self._client, state.operation)

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
    _safe_directory(destination)
    saved = operation.resume_state().payload.get("archive_descriptor")
    if saved is None:
        package = operation.wait(timeout=timeout).package
        if package is None:
            raise KsefDocumentValidationError("Successful export has no package")
    else:
        package = m.InvoicePackage.from_dict(saved)
    names = tuple(path.name for path in destination.iterdir())
    metadata = next(
        (destination / name for name in names if name.lower() == "_metadata.json"), None
    )
    return ExportFiles(destination, names, metadata, package)


def _fingerprint(package: ValidatedInvoicePackage) -> str:
    checksum = hashlib.sha256(f"{package.continuation}:{package.truncated}".encode("ascii"))
    for invoice in package.invoices:
        checksum.update(canonical_json(invoice.metadata, _MAX_METADATA, page=True))
    return checksum.hexdigest()


def _report(
    progress: ExportProgress, imported: int = 0, inserted: int = 0, status: str = "idle"
) -> InvoiceExportSyncReport:
    return InvoiceExportSyncReport(
        progress.committed_hwm, progress.continuation, imported, inserted, status
    )
