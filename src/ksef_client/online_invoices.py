"""Durable, application-identified online invoice submission."""

from __future__ import annotations

import asyncio
import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast
from xml.etree import ElementTree as ET

from ._offline_invoice_state import OfflineInvoiceProgress, offline_invoice_hash
from ._offline_invoice_state import OfflineInvoiceStatus as OnlineInvoiceStatus
from ._offline_invoice_store import (
    AsyncSQLiteOfflineInvoiceStore as AsyncSQLiteOnlineInvoiceStore,
)
from ._offline_invoice_store import SQLiteOfflineInvoiceStore as SQLiteOnlineInvoiceStore
from ._offline_invoice_store import StoredOfflineInvoice
from ._private_files import private_output
from .config import KsefClientOptions
from .exceptions import KsefDocumentValidationError
from .invoice_sync_state import InvoiceSyncScope
from .offline_invoices import AsyncOfflineInvoices, OfflineInvoices
from .operations import environment_key
from .request_control import request_control
from .token_manager import _durable_online_requests
from .utils.ksef_number import canonical_ksef_number

if TYPE_CHECKING:
    from .async_facade import AsyncKsef
    from .facade import Ksef

_ONLINE_SUBMISSION_KIND = (
    "online-invoices",
    hashlib.sha256(b"ksef-online-submission/v1").hexdigest(),
)
_INDIVIDUAL_UPO_BYTES = 1024 * 1024
_UPO_NAMESPACES = (
    "{http://upo.schematy.mf.gov.pl/KSeF/v4-2}",
    "{http://upo.schematy.mf.gov.pl/KSeF/v4-3}",
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


@dataclass(frozen=True)
class OnlineInvoiceBundle:
    """A snapshot of a tracked invoice. An individual UPO exists only after completion."""

    invoice: OnlineInvoice
    xml: bytes = field(repr=False)
    upo: bytes | None = field(repr=False)
    invoice_hash: str = field(repr=False, kw_only=True)

    options: KsefClientOptions | None = field(default=None, repr=False, kw_only=True)

    def __post_init__(self) -> None:
        if offline_invoice_hash(self.xml) != self.invoice_hash:
            raise KsefDocumentValidationError("Stored XML does not match the tracked invoice hash")
        progress = OfflineInvoiceProgress(
            invoice_hash=self.invoice_hash,
            status=self.invoice.status,
            session_reference=self.invoice.session_reference,
            invoice_reference=self.invoice.invoice_reference,
            ksef_number=self.invoice.ksef_number,
            ksef_status=self.invoice.ksef_status,
        )
        if (self.upo is not None) != (progress.status is OnlineInvoiceStatus.COMPLETE):
            raise KsefDocumentValidationError("UPO availability conflicts with the invoice status")
        if self.upo is not None:
            if type(self.upo) is not bytes:
                raise KsefDocumentValidationError("Individual UPO must be immutable XML bytes")
            _checked_upo(progress, self.upo)

    @property
    def upo_status(self) -> Literal["available", "pending", "unavailable"]:
        if self.upo is not None:
            return "available"
        if self.invoice.status in {
            OnlineInvoiceStatus.REJECTED,
            OnlineInvoiceStatus.DUPLICATE,
            OnlineInvoiceStatus.RETRYABLE,
        }:
            return "unavailable"
        return "pending"

    def save(self, path: str | Path, *, pdf_renderer: Literal["local", "mf"] = "local") -> None:
        """Write a new private ZIP in an existing directory. PDF requires the pdf extra."""
        from .invoice_pdf import render_invoice_pdf
        from .mf_pdf import InvoicePdfContext, generator_info, render_upo_pdf

        if pdf_renderer == "mf":
            context = None
            if self.invoice.ksef_number:
                if self.options is None:
                    raise KsefDocumentValidationError("MF bundle requires matching KSeF options")
                context = InvoicePdfContext.accepted(self.options, self.invoice.ksef_number)
            pdf = render_invoice_pdf(
                self.xml, ksef_number=self.invoice.ksef_number, renderer="mf", context=context
            )
        else:
            if pdf_renderer != "local":
                raise ValueError("Unknown PDF renderer")
            pdf = render_invoice_pdf(self.xml, ksef_number=self.invoice.ksef_number)
        documents = {"invoice.xml": self.xml, "invoice.pdf": pdf}
        if self.upo is not None:
            documents["upo.xml"] = self.upo
            if pdf_renderer == "mf":
                documents["upo.pdf"] = render_upo_pdf(self.upo)
        manifest = {
            "version": 1,
            "local_id": self.invoice.local_id,
            "status": self.invoice.status.value,
            "revision": self.invoice.revision,
            "ksef_status": self.invoice.ksef_status,
            "ksef_number": self.invoice.ksef_number,
            "upo_status": self.upo_status,
            "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in documents.items()},
        }
        if pdf_renderer == "mf":
            info = generator_info()
            manifest["version"] = 2
            manifest["generator"] = {
                "version": info["version"],
                "commit": info["commit"],
                "name": info["repository"],
            }
        with (
            private_output(Path(path)) as output,
            zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive,
        ):
            for name, content in documents.items():
                archive.writestr(name, content)
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))


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


def _validate_transport(client: Ksef | AsyncKsef, scope: InvoiceSyncScope) -> None:
    transport = client.api.http_client
    if client.api.sessions._http is not transport or client.api.security._http is not transport:
        raise ValueError("Durable online submission requires a shared KSeF API transport")
    if (
        environment_key(transport.api_base_url) != scope.environment
        or environment_key(client.options.normalized_base_url()) != scope.environment
        or client.environment != scope.environment
        or client.context_key != scope.context_key
    ):
        raise ValueError("Durable online submission transport does not match the saved scope")
    for options in (client.options, transport._options):
        if any(name.lower() in {"authorization", "host"} for name in options.custom_headers or ()):
            raise ValueError("Durable online submission requires managed authentication and host")
        if options.follow_redirects or (
            options.retry is not None
            and any(
                path == "/sessions/online" or path.startswith("/sessions/online/")
                for path in options.retry.retryable_post_paths
            )
        ):
            raise ValueError(
                "Durable online submission requires a non-replaying HTTP configuration"
            )


class _UpoTreeBuilder(ET.TreeBuilder):
    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise ET.ParseError("KSeF UPO must not declare a DTD")


def _text(parent: ET.Element, name: str) -> str | None:
    nodes = parent.findall(name)
    if len(nodes) != 1 or len(nodes[0]) != 0:
        return None
    return (nodes[0].text or "").strip()


def _matches_ksef_number(parent: ET.Element, name: str, expected: str | None) -> bool:
    try:
        return canonical_ksef_number(_text(parent, name) or "") == expected
    except ValueError:
        return False


def _checked_upo(progress: OfflineInvoiceProgress, upo: bytes) -> bytes:
    if not 0 < len(upo) <= _INDIVIDUAL_UPO_BYTES:
        raise KsefDocumentValidationError("KSeF UPO exceeds the individual receipt size policy")
    try:
        root = ET.fromstring(upo, parser=ET.XMLParser(target=_UpoTreeBuilder()))
    except (ET.ParseError, LookupError, ValueError):
        raise KsefDocumentValidationError("KSeF UPO is not well-formed XML") from None
    for namespace in _UPO_NAMESPACES:
        if root.tag == namespace + "Potwierdzenie":
            documents = root.findall(namespace + "Dokument")
            if (
                len(documents) == 1
                and root.find(namespace + "OpisPotwierdzenia") is None
                and _text(root, namespace + "NumerReferencyjnySesji") == progress.session_reference
                and _matches_ksef_number(
                    documents[0], namespace + "NumerKSeFDokumentu", progress.ksef_number
                )
                and _text(documents[0], namespace + "SkrotDokumentu") == progress.invoice_hash
            ):
                return upo
    raise KsefDocumentValidationError("KSeF UPO does not identify the submitted invoice")


def _bundle_snapshot(
    local_id: str,
    row: StoredOfflineInvoice,
    xml: bytes,
    upo: bytes | None,
    options: KsefClientOptions | None = None,
) -> OnlineInvoiceBundle:
    return OnlineInvoiceBundle(
        _result(local_id, row), xml, upo, invoice_hash=row.progress.invoice_hash, options=options
    )


class _OnlineWorker(OfflineInvoices):
    _submission_mode = False
    _submission_kind = _ONLINE_SUBMISSION_KIND

    def _download_upo(self, progress: OfflineInvoiceProgress) -> bytes:
        upo = self._client.api.sessions.get_session_invoice_upo_by_ref(
            cast(str, progress.session_reference),
            cast(str, progress.invoice_reference),
            max_bytes=_INDIVIDUAL_UPO_BYTES,
        )
        return _checked_upo(progress, upo)


class _AsyncOnlineWorker(AsyncOfflineInvoices):
    _submission_mode = False
    _submission_kind = _ONLINE_SUBMISSION_KIND

    async def _download_upo(self, progress: OfflineInvoiceProgress) -> bytes:
        upo = await self._client.api.sessions.get_session_invoice_upo_by_ref(
            cast(str, progress.session_reference),
            cast(str, progress.invoice_reference),
            max_bytes=_INDIVIDUAL_UPO_BYTES,
        )
        return _checked_upo(progress, upo)


class OnlineInvoiceQueue:
    """Local operations by application ID, including access to an already verified UPO."""

    def __init__(
        self,
        store: SQLiteOnlineInvoiceStore,
        *,
        namespace: str,
        environment: str,
        context_key: str,
        options: KsefClientOptions | None = None,
    ) -> None:
        if options is not None and environment_key(options.normalized_base_url()) != environment:
            raise ValueError("PDF options do not match the queue environment")
        self._options = options
        self._store = store
        self._scope = InvoiceSyncScope(
            namespace, environment, context_key, *_ONLINE_SUBMISSION_KIND
        )

    def enqueue(self, local_id: str, xml: bytes) -> OnlineInvoice:
        return _result(local_id, self._store._enqueue_online(self._scope, local_id, xml))

    def status(self, local_id: str) -> OnlineInvoice | None:
        row = self._store._load_online(self._scope, local_id)
        return None if row is None else _result(local_id, row)

    def retry_cancelled(self, local_id: str) -> OnlineInvoice:
        row = _required(self._store._load_online(self._scope, local_id))
        return _result(
            local_id, self._store.retry_cancelled(self._scope, row.progress.invoice_hash)
        )

    def read_upo(self, local_id: str) -> bytes:
        row = _required(self._store._load_online(self._scope, local_id))
        upo = self._store.read_upo(self._scope, row.progress.invoice_hash)
        return _checked_upo(row.progress, upo)

    def bundle(self, local_id: str) -> OnlineInvoiceBundle:
        """Read original XML, its saved submission state and any verified individual UPO locally."""
        row = _required(self._store._load_online(self._scope, local_id))
        digest = row.progress.invoice_hash
        xml = self._store.read_xml(self._scope, digest)
        upo = None
        if row.progress.status is OnlineInvoiceStatus.COMPLETE:
            upo = self._store.read_upo(self._scope, digest)
        return _bundle_snapshot(local_id, row, xml, upo, self._options)


class OnlineInvoices(OnlineInvoiceQueue):
    """Register XML once and advance its online submission through the individual UPO."""

    def __init__(self, client: Ksef, store: SQLiteOnlineInvoiceStore, *, namespace: str) -> None:
        super().__init__(
            store,
            namespace=namespace,
            environment=client.environment,
            options=client.options,
            context_key=client.context_key,
        )
        self._worker = _OnlineWorker(client, store, namespace=namespace)
        self._client = client
        _validate_transport(client, self._worker.scope)

    def enqueue(self, local_id: str, xml: bytes) -> OnlineInvoice:
        """Bind the application ID and original XML atomically in this scope."""
        _validate_transport(self._client, self._worker.scope)
        return super().enqueue(local_id, xml)

    def advance(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        """Run one step, reconciling unknown sends through the persisted session."""
        with (
            request_control(timeout_seconds=timeout),
            _durable_online_requests(self._client.api.http_client),
        ):
            row = _required(self._store._load_online(self._worker.scope, local_id))
            _validate_transport(self._client, self._worker.scope)
            return _result(
                local_id, self._worker.advance(row.progress.invoice_hash, timeout=timeout)
            )

    def retry_if_unsubmitted(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        """Permit a new attempt only after KSeF proves that the old session was empty."""
        with (
            request_control(timeout_seconds=timeout),
            _durable_online_requests(self._client.api.http_client),
        ):
            row = _required(self._store._load_online(self._worker.scope, local_id))
            _validate_transport(self._client, self._worker.scope)
            return _result(
                local_id,
                self._worker.retry_if_unsubmitted(row.progress.invoice_hash, timeout=timeout),
            )

    def retry_cancelled(self, local_id: str) -> OnlineInvoice:
        """Requeue only a submission KSeF explicitly cancelled with status 550."""
        _validate_transport(self._client, self._worker.scope)
        return super().retry_cancelled(local_id)


class AsyncOnlineInvoices:
    """Async durable submission using native async KSeF requests."""

    def __init__(
        self, client: AsyncKsef, store: AsyncSQLiteOnlineInvoiceStore, *, namespace: str
    ) -> None:
        self._worker = _AsyncOnlineWorker(client, store, namespace=namespace)
        self._client, self._store = client, store
        _validate_transport(client, self._worker.scope)

    async def enqueue(self, local_id: str, xml: bytes) -> OnlineInvoice:
        _validate_transport(self._client, self._worker.scope)
        row = await self._store._call("_enqueue_online", self._worker.scope, local_id, xml)
        return _result(local_id, row)

    async def status(self, local_id: str) -> OnlineInvoice | None:
        row = await self._store._call("_load_online", self._worker.scope, local_id)
        return None if row is None else _result(local_id, row)

    async def advance(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        with (
            request_control(timeout_seconds=timeout),
            _durable_online_requests(self._client.api.http_client),
        ):
            row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
            _validate_transport(self._client, self._worker.scope)
            updated = await self._worker.advance(row.progress.invoice_hash, timeout=timeout)
            return _result(local_id, updated)

    async def retry_if_unsubmitted(self, local_id: str, *, timeout: float = 60) -> OnlineInvoice:
        with (
            request_control(timeout_seconds=timeout),
            _durable_online_requests(self._client.api.http_client),
        ):
            row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
            _validate_transport(self._client, self._worker.scope)
            updated = await self._worker.retry_if_unsubmitted(
                row.progress.invoice_hash, timeout=timeout
            )
            return _result(local_id, updated)

    async def retry_cancelled(self, local_id: str) -> OnlineInvoice:
        _validate_transport(self._client, self._worker.scope)
        row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
        updated = await self._worker.retry_cancelled(row.progress.invoice_hash)
        return _result(local_id, updated)

    async def read_upo(self, local_id: str) -> bytes:
        row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
        upo = await self._worker.read_upo(row.progress.invoice_hash)
        return await asyncio.to_thread(_checked_upo, row.progress, upo)

    async def bundle(self, local_id: str) -> OnlineInvoiceBundle:
        """Read a local bundle snapshot without advancing the submission."""
        row = _required(await self._store._call("_load_online", self._worker.scope, local_id))
        digest = row.progress.invoice_hash
        xml = await self._worker.read_xml(digest)
        upo = None
        if row.progress.status is OnlineInvoiceStatus.COMPLETE:
            upo = await self._worker.read_upo(digest)
        return await asyncio.to_thread(
            _bundle_snapshot, local_id, row, xml, upo, self._client.options
        )


__all__ = [
    "AsyncOnlineInvoices",
    "AsyncSQLiteOnlineInvoiceStore",
    "OnlineInvoice",
    "OnlineInvoiceBundle",
    "OnlineInvoiceQueue",
    "OnlineInvoiceStatus",
    "OnlineInvoices",
    "SQLiteOnlineInvoiceStore",
]
