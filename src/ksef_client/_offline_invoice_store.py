"""Transactional storage for offline invoices and their submission progress."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from functools import partial
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._async_cleanup import shield_and_drain
from ._offline_invoice_state import (
    OfflineInvoiceMode,
    OfflineInvoiceProgress,
    OfflineInvoiceStatus,
    offline_invoice_hash,
)
from .exceptions import KsefDocumentValidationError, KsefSyncConflictError
from .invoice_sync_state import InvoiceSyncScope, utc_timestamp
from .invoice_xml_storage import _safe_directory
from .invoice_xml_types import hash_bytes, positive, positive_int
from .operations import OperationState

_PROGRESS_COLUMNS = "revision,due_at,progress,correction_of,active,due_sort"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS offline_invoices_v1 (
    scope TEXT NOT NULL,
    invoice_hash TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    due_at TEXT NOT NULL,
    due_sort TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    progress BLOB NOT NULL,
    correction_of TEXT,
    xml BLOB NOT NULL,
    upo BLOB,
    session_state BLOB,
    PRIMARY KEY(scope, invoice_hash),
    FOREIGN KEY(scope, correction_of) REFERENCES offline_invoices_v1(scope, invoice_hash)
);
CREATE INDEX IF NOT EXISTS offline_active_due_v1
    ON offline_invoices_v1(scope, due_sort, invoice_hash) WHERE active=1;
CREATE INDEX IF NOT EXISTS offline_corrections_v1
    ON offline_invoices_v1(scope, correction_of) WHERE correction_of IS NOT NULL;
CREATE TABLE IF NOT EXISTS offline_session_open_v1 (
    scope TEXT NOT NULL,
    invoice_hash TEXT NOT NULL,
    fence TEXT NOT NULL,
    expires REAL NOT NULL,
    PRIMARY KEY(scope, invoice_hash),
    FOREIGN KEY(scope, invoice_hash) REFERENCES offline_invoices_v1(scope, invoice_hash)
);
CREATE TABLE IF NOT EXISTS offline_attempts_v1 (
    scope TEXT NOT NULL,
    invoice_hash TEXT NOT NULL,
    revision INTEGER NOT NULL,
    progress BLOB NOT NULL,
    PRIMARY KEY(scope, invoice_hash, revision),
    FOREIGN KEY(scope, invoice_hash) REFERENCES offline_invoices_v1(scope, invoice_hash)
);
"""
_ONLINE_SCHEMA = (
    """
    CREATE TABLE online_archive_key_v1 (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        verifier BLOB NOT NULL
    )
    """,
    """
    CREATE TABLE online_invoice_ids_v1 (
        scope TEXT NOT NULL,
        local_key TEXT NOT NULL,
        invoice_hash TEXT NOT NULL,
        binding BLOB NOT NULL,
        PRIMARY KEY(scope, local_key),
        UNIQUE(scope, invoice_hash),
        FOREIGN KEY(scope, invoice_hash) REFERENCES offline_invoices_v1(scope, invoice_hash)
    )
    """,
)
MAX_OFFLINE_XML_BYTES = 16 * 1024 * 1024
_TERMINAL = {
    OfflineInvoiceStatus.COMPLETE,
    OfflineInvoiceStatus.REJECTED,
    OfflineInvoiceStatus.DUPLICATE,
}


def _due_sort(timestamp: str) -> str:
    second, _, fraction = timestamp[:-1].partition(".")
    return second + fraction.ljust(128, "0")


@dataclass(frozen=True)
class StoredOfflineInvoice:
    progress: OfflineInvoiceProgress
    revision: int
    due_at: str
    correction_of: str | None = field(default=None, repr=False)
    mode: OfflineInvoiceMode = OfflineInvoiceMode.OFFLINE24


class SQLiteOfflineInvoiceStore:
    """An exclusive SQLite connection and an application-owned 32-byte data key."""

    def __init__(self, connection: sqlite3.Connection, key: bytes, *, owned: bool = False):
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("Offline archive encryption requires a 32-byte key")
        if connection.in_transaction or connection.row_factory not in (None, sqlite3.Row):
            raise ValueError("Offline archive requires an idle SQLite connection")
        self._db, self._cipher, self._owned = connection, AESGCM(key), owned
        self._online_key = hmac.digest(key, b"ksef-online-local-id/v1", "sha256")
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
        # SQLite derives journal permissions from the database file.
        try:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
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
        identity = self._scope(scope)
        row = self._db.execute(
            f"SELECT {_PROGRESS_COLUMNS} FROM offline_invoices_v1 WHERE scope=? AND invoice_hash=?",
            (identity, invoice_hash),
        ).fetchone()
        if row is None:
            return None
        return self._decode_progress(identity, invoice_hash, row)

    def _decode_progress(
        self, identity: str, invoice_hash: str, row: Sequence[Any]
    ) -> StoredOfflineInvoice:
        raw = self._decrypt(identity, invoice_hash, "progress", row[2])
        payload = json.loads(raw)
        attributes = payload.pop("progress")
        attributes["status"] = OfflineInvoiceStatus(attributes["status"])
        progress = OfflineInvoiceProgress(**attributes)
        if progress.invoice_hash != invoice_hash or (
            payload["revision"],
            payload["due_at"],
            payload["correction_of"],
            int(progress.status not in _TERMINAL),
            _due_sort(payload["due_at"]),
        ) != (row[0], row[1], row[3], row[4], row[5]):
            raise KsefDocumentValidationError("Offline archive identity mismatch")
        payload["mode"] = OfflineInvoiceMode(payload["mode"])
        return StoredOfflineInvoice(progress=progress, **payload)

    def enqueue(
        self,
        scope: InvoiceSyncScope,
        xml: bytes,
        *,
        due_at: str,
        correction_of: str | None = None,
        mode: OfflineInvoiceMode = OfflineInvoiceMode.OFFLINE24,
    ) -> StoredOfflineInvoice:
        if type(xml) is not bytes or len(xml) > MAX_OFFLINE_XML_BYTES:
            raise KsefDocumentValidationError("Offline XML exceeds the storage policy")
        if not isinstance(mode, OfflineInvoiceMode):
            raise ValueError("Offline invoice mode must be explicit")
        invoice_hash = offline_invoice_hash(xml)
        due_at = utc_timestamp(due_at)
        with self._write():
            return self._register(scope, xml, invoice_hash, due_at, correction_of, mode)

    def _register(
        self,
        scope: InvoiceSyncScope,
        xml: bytes,
        invoice_hash: str,
        due_at: str,
        correction_of: str | None,
        mode: OfflineInvoiceMode,
    ) -> StoredOfflineInvoice:
        identity = self._scope(scope)
        previous = self.load(scope, invoice_hash)
        if previous is not None:
            if (
                previous.due_at != due_at
                or previous.correction_of != correction_of
                or previous.mode is not mode
            ):
                raise KsefSyncConflictError("offline_invoice_identity_conflict")
            return previous
        record = StoredOfflineInvoice(
            OfflineInvoiceProgress(invoice_hash), 1, due_at, correction_of, mode
        )
        if correction_of is not None:
            original = self.load(scope, correction_of)
            if (
                original is None
                or original.correction_of is not None
                or original.progress.status is not OfflineInvoiceStatus.REJECTED
                or original.progress.ksef_status not in {430, 450}
            ):
                raise KsefDocumentValidationError("Technical correction requires a rejection")
            self._ensure_no_live_correction(identity, correction_of, invoice_hash)
        self._db.execute(
            "INSERT INTO offline_invoices_v1 "
            "(scope,invoice_hash,revision,due_at,due_sort,active,progress,correction_of,xml) "
            "VALUES (?,?,1,?,?,1,?,?,?)",
            (
                identity,
                invoice_hash,
                due_at,
                _due_sort(due_at),
                self._seal_progress(identity, record),
                correction_of,
                self._encrypt(identity, invoice_hash, "xml", xml),
            ),
        )
        return record

    def _check_online_key(self, *, create: bool = False) -> bool:
        schema_count = self._db.execute(
            "SELECT count(*) FROM main.sqlite_master WHERE type='table' AND "
            "name IN ('online_archive_key_v1', 'online_invoice_ids_v1')"
        ).fetchone()[0]
        if schema_count == 1:
            raise KsefDocumentValidationError("Online archive schema is incomplete")
        if schema_count == 0:
            if not create:
                return False
            # First enqueue already holds the archive's write transaction.
            for statement in _ONLINE_SCHEMA:
                self._db.execute(statement)
        verifier = hmac.digest(self._online_key, b"ksef-online-archive/v1", "sha256")
        row = self._db.execute("SELECT verifier FROM online_archive_key_v1").fetchone()
        if row is None:
            if self._db.execute("SELECT 1 FROM online_invoice_ids_v1 LIMIT 1").fetchone():
                raise KsefDocumentValidationError("Online archive key verification is missing")
            if create:
                self._db.execute("INSERT INTO online_archive_key_v1 VALUES (1,?)", (verifier,))
        elif type(row[0]) is not bytes or not hmac.compare_digest(verifier, row[0]):
            raise KsefDocumentValidationError("Online archive authentication failed")
        return True

    def _local_key(self, identity: str, local_id: str) -> str:
        if type(local_id) is not str or not 1 <= len(local_id) <= 256 or not local_id.isprintable():
            raise KsefDocumentValidationError("Invalid local invoice identifier")
        return hmac.digest(self._online_key, f"{identity}:{local_id}".encode(), "sha256").hex()

    def _mapped_hash(self, identity: str, local_key: str) -> str | None:
        row = self._db.execute(
            "SELECT invoice_hash,binding FROM online_invoice_ids_v1 WHERE scope=? AND local_key=?",
            (identity, local_key),
        ).fetchone()
        if row is None:
            return None
        invoice_hash, binding = row
        hash_bytes(invoice_hash)
        if self._decrypt(identity, local_key, "online-binding", binding) != invoice_hash.encode():
            raise KsefDocumentValidationError("Online invoice identity mismatch")
        return invoice_hash

    def _load_online(self, scope: InvoiceSyncScope, local_id: str) -> StoredOfflineInvoice | None:
        identity = self._scope(scope)
        local_key = self._local_key(identity, local_id)
        if not self._check_online_key():
            return None
        invoice_hash = self._mapped_hash(identity, local_key)
        if invoice_hash is None:
            return None
        return self._require_mapped_document(scope, invoice_hash)

    def _require_mapped_document(
        self, scope: InvoiceSyncScope, invoice_hash: str
    ) -> StoredOfflineInvoice:
        row = self.load(scope, invoice_hash)
        if row is None:
            raise KsefDocumentValidationError("Online invoice binding has no stored document")
        return row

    def _enqueue_online(
        self, scope: InvoiceSyncScope, local_id: str, xml: bytes
    ) -> StoredOfflineInvoice:
        if type(xml) is not bytes or len(xml) > MAX_OFFLINE_XML_BYTES:
            raise KsefDocumentValidationError("Online XML exceeds the storage policy")
        invoice_hash = offline_invoice_hash(xml)
        identity = self._scope(scope)
        local_key = self._local_key(identity, local_id)
        with self._write():
            self._check_online_key(create=True)
            existing = self._mapped_hash(identity, local_key)
            if existing is not None:
                if existing != invoice_hash:
                    raise KsefSyncConflictError("online_invoice_identity_conflict")
                return self._require_mapped_document(scope, existing)
            if self.load(scope, invoice_hash) is not None:
                raise KsefSyncConflictError("online_invoice_already_registered")
            # The shared storage has required scheduling fields. The online
            # facade does not expose them and submits in a separate scope.
            row = self._register(
                scope, xml, invoice_hash, "1970-01-01T00:00:00Z", None, OfflineInvoiceMode.OFFLINE24
            )
            binding = self._encrypt(identity, local_key, "online-binding", invoice_hash.encode())
            self._db.execute(
                "INSERT INTO online_invoice_ids_v1 VALUES (?,?,?,?)",
                (identity, local_key, invoice_hash, binding),
            )
            return row

    def _ensure_no_live_correction(self, identity: str, original: str, current: str) -> None:
        attempts = self._db.execute(
            f"SELECT invoice_hash,{_PROGRESS_COLUMNS} FROM offline_invoices_v1 "
            "WHERE scope=? AND correction_of=? AND invoice_hash<>?",
            (identity, original, current),
        )
        if any(
            self._decode_progress(identity, digest, columns).progress.status
            is not OfflineInvoiceStatus.REJECTED
            for digest, *columns in attempts
        ):
            raise KsefSyncConflictError("offline_correction_already_exists")

    def pending(
        self,
        scope: InvoiceSyncScope,
        *,
        limit: int = 100,
        after: tuple[str, str] | None = None,
    ) -> tuple[StoredOfflineInvoice, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Offline queue page limit must be 1 to 100")
        identity = self._scope(scope)
        sql = (
            f"SELECT invoice_hash,{_PROGRESS_COLUMNS} FROM offline_invoices_v1 "
            "WHERE scope=? AND active=1 "
        )
        values: tuple[object, ...] = (identity,)
        if after is not None:
            timestamp, invoice_hash = after
            hash_bytes(invoice_hash)
            sql += "AND (due_sort,invoice_hash)>(?,?) "
            values += (_due_sort(utc_timestamp(timestamp)), invoice_hash)
        rows = self._db.execute(sql + "ORDER BY due_sort,invoice_hash LIMIT ?", (*values, limit))
        return tuple(self._decode_progress(identity, digest, columns) for digest, *columns in rows)

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

    def reschedule(
        self, scope: InvoiceSyncScope, invoice_hash: str, *, due_at: str, expected_revision: int
    ) -> StoredOfflineInvoice:
        positive_int(expected_revision, "expected_revision")
        due_at = utc_timestamp(due_at)
        identity = self._scope(scope)
        with self._write():
            row = self.load(scope, invoice_hash)
            if row is None or row.progress.status in _TERMINAL:
                raise KsefDocumentValidationError("Offline invoice is not active")
            if row.revision != expected_revision:
                raise KsefSyncConflictError("offline_invoice_revision_conflict")
            if row.due_at == due_at:
                return row
            updated = replace(row, revision=row.revision + 1, due_at=due_at)
            self._db.execute(
                "UPDATE offline_invoices_v1 SET revision=?,due_at=?,due_sort=?,progress=? "
                "WHERE scope=? AND invoice_hash=?",
                (
                    updated.revision,
                    due_at,
                    _due_sort(due_at),
                    self._seal_progress(identity, updated),
                    identity,
                    invoice_hash,
                ),
            )
        return updated

    def retry_cancelled(self, scope: InvoiceSyncScope, invoice_hash: str) -> StoredOfflineInvoice:
        row = self.load(scope, invoice_hash)
        if (
            row is None
            or row.progress.ksef_status != 550
            or row.progress.status
            not in {OfflineInvoiceStatus.RETRYABLE, OfflineInvoiceStatus.REJECTED}
        ):
            raise KsefDocumentValidationError("Offline invoice has no confirmed cancellation")
        return self._advance(scope, row, OfflineInvoiceProgress(invoice_hash))

    def _claim_open(self, scope: InvoiceSyncScope, invoice_hash: str, timeout: float) -> str | None:
        identity = self._scope(scope)
        with self._write():
            row = self.load(scope, invoice_hash)
            if row is None or row.progress.status is not OfflineInvoiceStatus.QUEUED:
                return None
            now = time.time()
            fence = uuid.uuid4().hex
            result = self._db.execute(
                "INSERT INTO offline_session_open_v1 VALUES (?,?,?,?) "
                "ON CONFLICT(scope,invoice_hash) DO UPDATE SET "
                "fence=excluded.fence,expires=excluded.expires "
                "WHERE offline_session_open_v1.expires<=?",
                (identity, invoice_hash, fence, now + timeout, now),
            )
            return fence if result.rowcount == 1 else None

    def _advance(
        self,
        scope: InvoiceSyncScope,
        current: StoredOfflineInvoice,
        progress: OfflineInvoiceProgress,
        *,
        upo: bytes | None = None,
        session: OperationState | None = None,
        opening_token: str | None = None,
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
        with self._write():
            if opening_token is not None:
                claim = self._db.execute(
                    "SELECT fence FROM offline_session_open_v1 WHERE scope=? AND invoice_hash=?",
                    (identity, invoice_hash),
                ).fetchone()
                latest = self.load(scope, invoice_hash)
                if (
                    claim is None
                    or claim[0] != opening_token
                    or latest is None
                    or (latest.progress.status is not OfflineInvoiceStatus.QUEUED)
                ):
                    raise KsefSyncConflictError("offline_session_open_claim_lost")
                current = latest
            if progress.status is OfflineInvoiceStatus.QUEUED and current.correction_of is not None:
                self._ensure_no_live_correction(identity, current.correction_of, invoice_hash)
            updated = replace(current, progress=progress, revision=current.revision + 1)
            result = self._db.execute(
                "UPDATE offline_invoices_v1 SET progress=?,revision=revision+1,upo=?, "
                "active=?, session_state=CASE WHEN ? THEN NULL ELSE COALESCE(?,session_state) END "
                "WHERE scope=? AND invoice_hash=? AND revision=?",
                (
                    self._seal_progress(identity, updated),
                    encrypted,
                    int(progress.status not in _TERMINAL),
                    int(progress.status is OfflineInvoiceStatus.QUEUED),
                    session_bytes,
                    identity,
                    invoice_hash,
                    current.revision,
                ),
            )
            if result.rowcount != 1:
                raise KsefSyncConflictError("offline_invoice_revision_conflict")
            if opening_token is not None:
                self._db.execute(
                    "DELETE FROM offline_session_open_v1 WHERE scope=? AND invoice_hash=?",
                    (identity, invoice_hash),
                )
            if progress.status is OfflineInvoiceStatus.QUEUED:
                attempt = self._encrypt(
                    identity,
                    invoice_hash,
                    f"attempt:{current.revision}",
                    json.dumps(asdict(current.progress)).encode(),
                )
                self._db.execute(
                    "INSERT INTO offline_attempts_v1 VALUES (?,?,?,?)",
                    (identity, invoice_hash, current.revision, attempt),
                )
        return updated


class AsyncSQLiteOfflineInvoiceStore:
    """Own the SQLite connection on a dedicated thread and drain started writes."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ksef-offline")
        self._store: SQLiteOfflineInvoiceStore | None = None

    @classmethod
    async def open(
        cls, path: str | Path, *, key: bytes, timeout: float = 5
    ) -> AsyncSQLiteOfflineInvoiceStore:
        instance = cls()

        async def initialize() -> None:
            instance._store = await asyncio.get_running_loop().run_in_executor(
                instance._executor,
                partial(SQLiteOfflineInvoiceStore.open, path, key=key, timeout=timeout),
            )

        try:
            await shield_and_drain(initialize())
        except BaseException:
            await instance.close()
            raise
        return instance

    async def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        store = self._store
        if store is None:
            raise ValueError("Offline archive is closed")
        return await shield_and_drain(
            asyncio.get_running_loop().run_in_executor(
                self._executor, partial(getattr(store, method), *args, **kwargs)
            )
        )

    async def close(self) -> None:
        store, self._store = self._store, None
        try:
            if store is not None:
                await shield_and_drain(
                    asyncio.get_running_loop().run_in_executor(self._executor, store.close)
                )
        finally:
            await shield_and_drain(asyncio.to_thread(self._executor.shutdown, wait=True))

    async def __aenter__(self) -> AsyncSQLiteOfflineInvoiceStore:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
