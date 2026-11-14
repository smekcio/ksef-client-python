"""Transactional storage for offline invoices and their submission progress."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._offline_invoice_state import (
    OfflineInvoiceProgress,
    OfflineInvoiceStatus,
    offline_invoice_hash,
)
from .exceptions import KsefDocumentValidationError, KsefSyncConflictError
from .invoice_sync_state import InvoiceSyncScope, utc_timestamp
from .invoice_xml_storage import _safe_directory
from .invoice_xml_types import positive
from .operations import OperationState

_SCHEMA = """
CREATE TABLE IF NOT EXISTS offline_invoices_v1 (
    scope TEXT NOT NULL,
    invoice_hash TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    due_at TEXT NOT NULL,
    progress BLOB NOT NULL,
    correction_of TEXT,
    xml BLOB NOT NULL,
    upo BLOB,
    session_state BLOB,
    PRIMARY KEY(scope, invoice_hash),
    FOREIGN KEY(scope, correction_of) REFERENCES offline_invoices_v1(scope, invoice_hash)
);
CREATE UNIQUE INDEX IF NOT EXISTS offline_single_correction_v1
    ON offline_invoices_v1(scope, correction_of) WHERE correction_of IS NOT NULL;
"""
MAX_OFFLINE_XML_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class StoredOfflineInvoice:
    progress: OfflineInvoiceProgress
    revision: int
    due_at: str
    correction_of: str | None = field(default=None, repr=False)


class SQLiteOfflineInvoiceStore:
    """An exclusive SQLite connection and an application-owned 32-byte data key."""

    def __init__(self, connection: sqlite3.Connection, key: bytes, *, owned: bool = False):
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("Offline archive encryption requires a 32-byte key")
        if connection.in_transaction or connection.row_factory not in (None, sqlite3.Row):
            raise ValueError("Offline archive requires an idle SQLite connection")
        self._db, self._cipher, self._owned = connection, AESGCM(key), owned
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(_SCHEMA)

    @classmethod
    def open(cls, path: str | Path, *, key: bytes, timeout: float = 5) -> SQLiteOfflineInvoiceStore:
        positive(timeout, "timeout")
        target = Path(os.path.abspath(path))
        _safe_directory(target.parent, allow_missing=True)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _safe_directory(target.parent)
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(str(target) + suffix)
            if candidate.is_symlink() or (
                candidate.exists()
                and (
                    not candidate.is_file()
                    or candidate.stat().st_nlink != 1
                    or getattr(candidate.lstat(), "st_file_attributes", 0) & 1024
                )
            ):
                raise ValueError("Unsafe offline archive file")
        connection = sqlite3.connect(target, timeout=timeout, isolation_level=None)
        try:
            return cls(connection, key, owned=True)
        except BaseException:
            connection.close()
            raise

    def __enter__(self) -> SQLiteOfflineInvoiceStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owned:
            self._db.close()

    @contextlib.contextmanager
    def _write(self) -> Iterator[None]:
        if self._db.in_transaction:
            raise ValueError("Offline archive connection already has a transaction")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._db.execute("COMMIT")
        except BaseException:
            try:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
            except sqlite3.Error:
                self._db.close()
            raise

    @staticmethod
    def _scope(scope: InvoiceSyncScope) -> str:
        identity = json.dumps(scope.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(identity).hexdigest()

    def _encrypt(self, scope: str, invoice_hash: str, purpose: str, content: bytes) -> bytes:
        nonce = os.urandom(12)
        aad = f"ksef:offline:v1:{scope}:{invoice_hash}:{purpose}".encode("ascii")
        return nonce + self._cipher.encrypt(nonce, content, aad)

    def _decrypt(self, scope: str, invoice_hash: str, purpose: str, value: bytes) -> bytes:
        aad = f"ksef:offline:v1:{scope}:{invoice_hash}:{purpose}".encode("ascii")
        try:
            return self._cipher.decrypt(value[:12], value[12:], aad)
        except (InvalidTag, ValueError):
            raise KsefDocumentValidationError("Offline archive authentication failed") from None

    def _seal_progress(self, identity: str, row: StoredOfflineInvoice) -> bytes:
        values = asdict(row)
        return self._encrypt(
            identity, row.progress.invoice_hash, "progress", json.dumps(values).encode()
        )

    def load(self, scope: InvoiceSyncScope, invoice_hash: str) -> StoredOfflineInvoice | None:
        row = self._db.execute(
            "SELECT revision,due_at,progress,correction_of FROM offline_invoices_v1 "
            "WHERE scope=? AND invoice_hash=?",
            (self._scope(scope), invoice_hash),
        ).fetchone()
        if row is None:
            return None
        raw = self._decrypt(self._scope(scope), invoice_hash, "progress", row[2])
        payload = json.loads(raw)
        attributes = payload.pop("progress")
        attributes["status"] = OfflineInvoiceStatus(attributes["status"])
        progress = OfflineInvoiceProgress(**attributes)
        if progress.invoice_hash != invoice_hash or (
            payload["revision"],
            payload["due_at"],
            payload["correction_of"],
        ) != (row[0], row[1], row[3]):
            raise KsefDocumentValidationError("Offline archive identity mismatch")
        return StoredOfflineInvoice(progress=progress, **payload)

    def enqueue(
        self,
        scope: InvoiceSyncScope,
        xml: bytes,
        *,
        due_at: str,
        correction_of: str | None = None,
    ) -> StoredOfflineInvoice:
        if type(xml) is not bytes or len(xml) > MAX_OFFLINE_XML_BYTES:
            raise KsefDocumentValidationError("Offline XML exceeds the storage policy")
        invoice_hash = offline_invoice_hash(xml)
        due_at = utc_timestamp(due_at)
        identity = self._scope(scope)
        progress = OfflineInvoiceProgress(invoice_hash)
        record = StoredOfflineInvoice(progress, 1, due_at, correction_of)
        encrypted = self._encrypt(identity, invoice_hash, "xml", xml)
        with self._write():
            previous = self.load(scope, invoice_hash)
            if previous is not None:
                if previous.due_at != due_at or previous.correction_of != correction_of:
                    raise KsefSyncConflictError("offline_invoice_identity_conflict")
                return previous
            if correction_of is not None:
                original = self.load(scope, correction_of)
                if (
                    original is None
                    or original.progress.status is not OfflineInvoiceStatus.REJECTED
                    or original.progress.ksef_status not in {430, 450}
                ):
                    raise KsefDocumentValidationError("Technical correction requires a rejection")
                if self._db.execute(
                    "SELECT 1 FROM offline_invoices_v1 WHERE scope=? AND correction_of=?",
                    (identity, correction_of),
                ).fetchone():
                    raise KsefSyncConflictError("offline_correction_already_exists")
            self._db.execute(
                "INSERT INTO offline_invoices_v1 VALUES (?,?,1,?,?,?,?,NULL,NULL)",
                (
                    identity,
                    invoice_hash,
                    due_at,
                    self._seal_progress(identity, record),
                    correction_of,
                    encrypted,
                ),
            )
        return record

    def read_xml(self, scope: InvoiceSyncScope, invoice_hash: str) -> bytes:
        return self._read_blob(scope, invoice_hash, upo=False)

    def read_upo(self, scope: InvoiceSyncScope, invoice_hash: str) -> bytes:
        return self._read_blob(scope, invoice_hash, upo=True)

    def _read_blob(self, scope: InvoiceSyncScope, invoice_hash: str, *, upo: bool) -> bytes:
        identity = self._scope(scope)
        row = self._db.execute(
            ("SELECT upo" if upo else "SELECT xml")
            + " FROM offline_invoices_v1 WHERE scope=? AND invoice_hash=?",
            (identity, invoice_hash),
        ).fetchone()
        if row is None or row[0] is None:
            raise KsefDocumentValidationError("Offline archive content is unavailable")
        return self._decrypt(identity, invoice_hash, "upo" if upo else "xml", row[0])

    def _read_session(
        self, scope: InvoiceSyncScope, current: StoredOfflineInvoice
    ) -> OperationState:
        identity, invoice_hash = self._scope(scope), current.progress.invoice_hash
        row = self._db.execute(
            "SELECT session_state FROM offline_invoices_v1 WHERE scope=? AND invoice_hash=?",
            (identity, invoice_hash),
        ).fetchone()
        if row is None or row[0] is None:
            raise KsefDocumentValidationError("Offline archive session is unavailable")
        encoded = self._decrypt(identity, invoice_hash, "session", row[0])
        state = OperationState.from_json(encoded.decode())
        state.bind(scope.environment, scope.context_key)
        if state.kind != "online" or state.reference_number != current.progress.session_reference:
            raise KsefDocumentValidationError("Offline archive session identity mismatch")
        return state

    def _advance(
        self,
        scope: InvoiceSyncScope,
        current: StoredOfflineInvoice,
        progress: OfflineInvoiceProgress,
        *,
        upo: bytes | None = None,
        session: OperationState | None = None,
    ) -> StoredOfflineInvoice:
        invoice_hash = current.progress.invoice_hash
        if invoice_hash != progress.invoice_hash:
            raise ValueError("Offline archive transition changed identity")
        if (upo is not None) != (progress.status is OfflineInvoiceStatus.COMPLETE):
            raise ValueError("Offline completion requires an UPO")
        identity = self._scope(scope)
        if upo is not None and (
            type(upo) is not bytes or not 0 < len(upo) <= MAX_OFFLINE_XML_BYTES
        ):
            raise KsefDocumentValidationError("Invalid offline UPO size")
        encrypted = self._encrypt(identity, invoice_hash, "upo", upo) if upo is not None else None
        session_bytes = None
        if session is not None:
            session.bind(scope.environment, scope.context_key)
            if session.kind != "online" or session.reference_number != progress.session_reference:
                raise KsefDocumentValidationError("Offline archive session identity mismatch")
            session_bytes = self._encrypt(
                identity, invoice_hash, "session", session.to_json().encode()
            )
        updated = StoredOfflineInvoice(
            progress, current.revision + 1, current.due_at, current.correction_of
        )
        with self._write():
            result = self._db.execute(
                "UPDATE offline_invoices_v1 SET progress=?,revision=revision+1,upo=? "
                " ,session_state=COALESCE(?,session_state) "
                "WHERE scope=? AND invoice_hash=? AND revision=?",
                (
                    self._seal_progress(identity, updated),
                    encrypted,
                    session_bytes,
                    identity,
                    invoice_hash,
                    current.revision,
                ),
            )
            if result.rowcount != 1:
                raise KsefSyncConflictError("offline_invoice_revision_conflict")
        return updated
