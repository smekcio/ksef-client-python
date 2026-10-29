"""Public SQLite metadata adapter and fenced durable XML queue (local filesystems)."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
import uuid
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import asdict
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any

from ._async_cleanup import shield_and_drain
from ._sqlite_metadata import SCHEMA as METADATA_SCHEMA
from ._sqlite_metadata import MetadataSQLiteStore
from .exceptions import KsefSyncDataConflictError, KsefSyncStoreError
from .invoice_sync_state import (
    InvoiceSyncBatch,
    InvoiceSyncCheckpoint,
    InvoiceSyncCommitReceipt,
    InvoiceSyncScope,
)
from .invoice_xml_storage import _safe_directory
from .invoice_xml_types import (
    InvoiceXmlBackfillReport,
    InvoiceXmlClaim,
    InvoiceXmlKey,
    InvoiceXmlReceipt,
    InvoiceXmlReport,
    InvoiceXmlStorage,
    KsefXmlIntegrityError,
    KsefXmlLeaseLostError,
    KsefXmlStorageError,
    hash_bytes,
    positive,
    positive_int,
)

XML_SCHEMA = """
CREATE TABLE xml_store_meta (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL,
    epoch TEXT NOT NULL, storage_id TEXT);
CREATE TABLE invoice_xml_documents (
    namespace TEXT NOT NULL, environment TEXT NOT NULL, context_key TEXT NOT NULL,
    ksef_number TEXT NOT NULL, variant TEXT NOT NULL DEFAULT 'invoice-xml/v1',
    expected_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
      CHECK(status IN ('pending','leased','retry_wait','ready','blocked')),
    created_at REAL NOT NULL, next_attempt_at REAL NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
    lease_token TEXT, fencing INTEGER NOT NULL DEFAULT 0, lease_epoch TEXT,
    lease_until REAL, receipt_json TEXT, last_reason TEXT, verified_at REAL,
    PRIMARY KEY(namespace,environment,context_key,ksef_number,variant),
    FOREIGN KEY(namespace,environment,context_key,ksef_number)
      REFERENCES invoices(namespace,environment,context_key,ksef_number)
);
CREATE INDEX xml_due ON invoice_xml_documents(status,next_attempt_at,lease_until,created_at);
CREATE INDEX xml_claim_due ON invoice_xml_documents(
    namespace,environment,context_key,status,next_attempt_at,created_at,ksef_number);
CREATE INDEX xml_claim_expired ON invoice_xml_documents(
    namespace,environment,context_key,status,lease_until,created_at,ksef_number);
CREATE INDEX xml_observations_document ON invoice_observations(
    namespace,environment,context_key,ksef_number,sync_key,stream_id);
CREATE TABLE xml_backfill (
    namespace TEXT NOT NULL, environment TEXT NOT NULL, context_key TEXT NOT NULL,
    sync_key TEXT NOT NULL, stream_id TEXT NOT NULL, last_number TEXT NOT NULL,
    complete INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(namespace,environment,context_key,sync_key,stream_id)
);
"""
DOC_KEY = "namespace=? AND environment=? AND context_key=? AND ksef_number=? AND variant=?"
SAFE_REASONS = frozenset(
    {
        "not_available",
        "rate_limited",
        "invalid_retry_after",
        "transient_http",
        "network_error",
        "retry_exhausted",
        "not_found",
        "forbidden",
        "authentication",
        "api_error",
        "hash_mismatch",
        "stored_hash_mismatch",
        "invalid_hash",
        "invalid_receipt",
        "response_size_limit",
        "response_encoding",
        "response_redirect",
        "document_time_budget",
        "cancelled",
        "verified_missing",
        "verified_corrupt",
        "invalid_ksef_number",
        "unsafe_storage_file",
        "stored_object_unreadable",
    }
)


def _valid_number(number: str) -> bool:
    from .utils.ksef_number import is_valid_ksef_number

    return isinstance(number, str) and is_valid_ksef_number(number)


def _scope_values(scope: InvoiceSyncScope) -> tuple[str, ...]:
    return tuple(scope.to_dict().values())


def _selection(scopes: Sequence[InvoiceSyncScope]) -> tuple[str, tuple[str, ...]]:
    if not 1 <= len(scopes) <= 4 or any(not isinstance(s, InvoiceSyncScope) for s in scopes):
        raise ValueError("One to four synchronization scopes required")
    if len({(s.namespace, s.environment, s.context_key) for s in scopes}) != 1:
        raise ValueError("Scopes must share document namespace, environment and context")
    sql = " OR ".join(
        "(o.namespace=? AND o.environment=? AND o.context_key=? AND o.sync_key=? AND o.stream_id=?)"
        for _ in scopes
    )
    return sql, tuple(v for s in scopes for v in _scope_values(s))


def _legacy_shape(connection: sqlite3.Connection) -> bool:
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(METADATA_SCHEMA)
        expected = dict(reference.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
        actual = dict(connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
        if not expected.keys() <= actual.keys() or any(
            name.startswith("xml_") or name == "invoice_xml_documents" for name in actual
        ):
            return False

        def normalize(value: str) -> str:
            return " ".join(value.replace("IF NOT EXISTS ", "").split()).lower()

        return all(normalize(actual[k]) == normalize(v) for k, v in expected.items())
    finally:
        reference.close()


def _canonicalize_legacy_numbers(connection: sqlite3.Connection) -> None:
    """Offline canonicalization, preserving observations and download obligations."""
    from .utils.ksef_number import canonical_ksef_number

    last = ""
    while True:
        rows = connection.execute(
            "SELECT namespace,environment,context_key,ksef_number,invoice_hash FROM invoices "
            "WHERE ksef_number IN (SELECT DISTINCT ksef_number FROM invoices WHERE "
            "length(ksef_number)=36 AND ksef_number>? ORDER BY ksef_number LIMIT "
            "500) ORDER BY ksef_number",
            (last,),
        ).fetchall()
        if not rows:
            break
        for namespace, environment, context, old, expected in rows:
            last = old
            if not _valid_number(old):
                continue
            new = canonical_ksef_number(old)
            prefix = (namespace, environment, context)
            old_key, new_key = (*prefix, old), (*prefix, new)
            where = "namespace=? AND environment=? AND context_key=? AND ksef_number=?"
            connection.execute(
                "INSERT INTO invoices VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
                (*new_key, expected),
            )
            if (
                connection.execute(
                    "SELECT invoice_hash FROM invoices WHERE " + where, new_key
                ).fetchone()[0]
                != expected
            ):
                raise KsefSyncDataConflictError("invoice_hash_conflict")
            connection.execute(
                "INSERT INTO invoice_observations SELECT "
                "namespace,environment,context_key,sync_key,stream_id,?,metadata_json "
                "FROM invoice_observations WHERE " + where + " ON CONFLICT DO NOTHING",
                (new, *old_key),
            )
            connection.execute(
                "INSERT INTO outbox SELECT "
                "namespace,environment,context_key,?,kind,variant,status FROM outbox "
                "WHERE " + where + " ON CONFLICT DO NOTHING",
                (new, *old_key),
            )
            # Published names include the old identity. Revalidate via a fresh task;
            # do not falsely mark a newly named object ready or delete old files.
            connection.execute(
                "INSERT INTO "
                "invoice_xml_documents(namespace,environment,context_key,ksef_number,va"
                "riant,expected_hash,status,created_at,next_attempt_at,attempts,failure"
                "s,last_reason) SELECT "
                "namespace,environment,context_key,?,variant,expected_hash,CASE WHEN "
                "status IN ('leased','ready') THEN 'pending' ELSE status "
                "END,created_at,next_attempt_at,attempts,failures,last_reason FROM "
                "invoice_xml_documents WHERE " + where + " ON CONFLICT DO NOTHING",
                (new, *old_key),
            )
            for table in ("invoice_xml_documents", "invoice_observations", "outbox", "invoices"):
                connection.execute("DELETE FROM " + table + " WHERE " + where, old_key)
    connection.execute("UPDATE xml_backfill SET complete=0,last_number='' WHERE complete=0")


class SQLiteInvoiceSyncStore(MetadataSQLiteStore):
    """Each worker owns a connection. Use a local disk; do not share via network mounts."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        enqueue_xml: bool = False,
        xml_storage_id: str | None = None,
    ) -> None:
        if connection.in_transaction:
            raise ValueError("The adapter requires an idle connection")
        if connection.row_factory not in (None, sqlite3.Row):
            raise ValueError("Use tuple rows or sqlite3.Row for the SDK connection")
        if enqueue_xml and (
            not isinstance(xml_storage_id, str) or not xml_storage_id or len(xml_storage_id) > 256
        ):
            raise ValueError("enqueue_xml requires xml_storage_id")
        tables = {
            r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        fresh = not tables
        if not fresh and "xml_store_meta" not in tables:
            raise KsefXmlStorageError("schema_migration_required")
        if not fresh:
            row = connection.execute(
                "SELECT version,storage_id FROM xml_store_meta WHERE id=1"
            ).fetchone()
            if row is None or row[0] != 2:
                raise KsefXmlStorageError(
                    "schema_migration_required"
                    if row is not None and row[0] == 1
                    else "unsupported_schema"
                )
            if xml_storage_id is not None and row[1] is not None and row[1] != xml_storage_id:
                raise KsefXmlStorageError("storage_id_mismatch")
        if fresh:
            try:
                connection.execute("BEGIN IMMEDIATE")
                # A competing opener may have initialized the database while we waited.
                current = {
                    r[0]
                    for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                if not current:
                    for statement in (METADATA_SCHEMA + XML_SCHEMA).split(";"):
                        if statement.strip():
                            connection.execute(statement)
                    connection.execute(
                        "INSERT INTO xml_store_meta VALUES (1,2,?,?)",
                        (uuid.uuid4().hex, xml_storage_id),
                    )
                else:
                    if "xml_store_meta" not in current:
                        raise KsefXmlStorageError("schema_migration_required")
                    existing = connection.execute(
                        "SELECT version,storage_id FROM xml_store_meta WHERE id=1"
                    ).fetchone()
                    if existing is None or existing[0] != 2:
                        raise KsefXmlStorageError("unsupported_schema")
                    if existing[1] != xml_storage_id:
                        raise KsefXmlStorageError("storage_id_mismatch")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        elif xml_storage_id is not None:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "UPDATE xml_store_meta SET storage_id=? WHERE id=1 AND storage_id IS NULL",
                    (xml_storage_id,),
                )
                bound = connection.execute(
                    "SELECT storage_id FROM xml_store_meta WHERE id=1"
                ).fetchone()[0]
                if bound != xml_storage_id:
                    raise KsefXmlStorageError("storage_id_mismatch")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        super().__init__(connection, enqueue_xml=enqueue_xml)
        self.xml_storage_id = connection.execute(
            "SELECT storage_id FROM xml_store_meta WHERE id=1"
        ).fetchone()[0]
        self._owned = False

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        enqueue_xml: bool = False,
        xml_storage_id: str | None = None,
        timeout: float = 5,
    ) -> SQLiteInvoiceSyncStore:
        positive(timeout, "timeout")
        target = Path(os.path.abspath(path))
        _safe_directory(target.parent, allow_missing=True)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _safe_directory(target.parent)
        for candidate in (
            target,
            Path(str(target) + "-wal"),
            Path(str(target) + "-shm"),
            Path(str(target) + "-journal"),
        ):
            if candidate.is_symlink() or (
                candidate.exists() and getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400
            ):
                raise KsefXmlStorageError("unsafe_database_path")
        try:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        connection = sqlite3.connect(target, timeout=timeout)
        try:
            store = cls(connection, enqueue_xml=enqueue_xml, xml_storage_id=xml_storage_id)
            store._owned = True
            return store
        except BaseException:
            connection.close()
            raise

    @classmethod
    def migrate_legacy_example(
        cls, connection: sqlite3.Connection, *, xml_storage_id: str | None = None
    ) -> None:
        """Explicit offline adoption; existing outbox entries remain untouched."""
        if connection.in_transaction or (
            xml_storage_id is not None
            and (
                not isinstance(xml_storage_id, str)
                or not xml_storage_id
                or len(xml_storage_id) > 256
            )
        ):
            raise ValueError("Migration requires an idle connection and a storage identity")
        tables = {
            r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "xml_store_meta" in tables:
            cls(connection, enqueue_xml=xml_storage_id is not None, xml_storage_id=xml_storage_id)
            return
        if not _legacy_shape(connection):
            raise KsefXmlStorageError("unrecognized_legacy_schema")
        try:
            connection.executescript("BEGIN IMMEDIATE;" + XML_SCHEMA)
            connection.execute(
                "INSERT INTO xml_store_meta VALUES (1,2,?,?)", (uuid.uuid4().hex, xml_storage_id)
            )
            _canonicalize_legacy_numbers(connection)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        # Import is bounded and restartable through backfill_xml. All old outbox rows
        # remain durable and are included in per-scope backfill through observations.

    @classmethod
    def migrate_schema(cls, connection: sqlite3.Connection) -> None:
        """Offline v1 -> v2 index upgrade. Stop every writer and back up first."""
        if connection.in_transaction:
            raise ValueError("Migration requires an idle connection")
        version = connection.execute("SELECT version FROM xml_store_meta WHERE id=1").fetchone()
        if version is None or version[0] not in (1, 2):
            raise KsefXmlStorageError("unsupported_schema")
        if version[0] == 2:
            return
        try:
            connection.execute("BEGIN IMMEDIATE")
            for name, clock in (
                ("xml_claim_due", "next_attempt_at"),
                ("xml_claim_expired", "lease_until"),
            ):
                connection.execute(
                    "CREATE INDEX "
                    + name
                    + " ON invoice_xml_documents(namespace,environment,context_key,status,"
                    + clock
                    + ",created_at,ksef_number)"
                )
            _canonicalize_legacy_numbers(connection)
            connection.execute("UPDATE xml_store_meta SET version=2 WHERE id=1")
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @contextmanager
    def _transaction(self, *, write: bool = True) -> Iterator[None]:
        self._require_idle("commit" if write else "load")
        started, committing = False, False
        try:
            self._execute("BEGIN IMMEDIATE" if write else "BEGIN")
            started = True
            yield
            committing = True
            self._execute("COMMIT")
        except BaseException as error:
            outcome = "unknown" if committing else "rolled_back" if started else "not_started"
            try:
                if self.connection.in_transaction:
                    self._execute("ROLLBACK")
                    outcome = "rolled_back"
            except BaseException:
                with suppress(BaseException):
                    self.connection.close()
                if not isinstance(error, Exception):
                    raise error from None
                raise KsefSyncStoreError(
                    operation="commit" if write else "load",
                    commit_outcome="unknown" if write else "not_started",
                    failure_scope="store",
                    original_error=error,
                ) from None
            if isinstance(error, sqlite3.Error):
                raise KsefSyncStoreError(
                    operation="commit" if write else "load",
                    commit_outcome=outcome if write else "not_started",
                    failure_scope="store",
                    original_error=error,
                ) from None
            raise

    def _prepare_xml_scope(self, scope: InvoiceSyncScope, new: bool) -> None:
        if self.enqueue_xml and new:
            self._execute(
                "INSERT INTO xml_backfill VALUES (?,?,?,?,?,?,1) ON CONFLICT DO NOTHING",
                (*_scope_values(scope), ""),
            )
        elif not self.enqueue_xml:
            self._execute(
                "UPDATE xml_backfill SET complete=0,last_number='' WHERE "
                "namespace=? AND environment=? AND context_key=? AND sync_key=? AND stream_id=?",
                _scope_values(scope),
            )

    def _document_number(self, number: str) -> str:
        from .utils.ksef_number import canonical_ksef_number

        return canonical_ksef_number(number) if _valid_number(number) else number

    def _enqueue_xml(self, document: tuple[str, ...], expected_hash: str) -> None:
        hash_bytes(expected_hash)
        self._execute(
            "INSERT INTO invoice_xml_documents "
            "(namespace,environment,context_key,ksef_number,expected_hash,created_a"
            "t,status,last_reason) "
            "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
            (
                *document,
                expected_hash,
                time.time(),
                "pending" if _valid_number(document[3]) else "blocked",
                None if _valid_number(document[3]) else "invalid_ksef_number",
            ),
        )

    def validate_xml(self, scopes: Sequence[InvoiceSyncScope], storage_id: str) -> None:
        _selection(scopes)
        self._require_idle("load")
        row = self._execute("SELECT storage_id FROM xml_store_meta WHERE id=1").fetchone()
        if not self.enqueue_xml:
            raise KsefXmlStorageError("xml_enqueue_disabled")
        if row is None or row[0] != storage_id or self.xml_storage_id != storage_id:
            raise KsefXmlStorageError("storage_id_mismatch")

    def _selected(self, scopes: Sequence[InvoiceSyncScope]) -> tuple[str, tuple[str, ...]]:
        condition, values = _selection(scopes)
        return (
            "WITH selected AS (SELECT DISTINCT "
            "o.namespace,o.environment,o.context_key,o.ksef_number "
            "FROM invoice_observations o WHERE " + condition + ") ",
            values,
        )

    def _claim_query(
        self, scopes: Sequence[InvoiceSyncScope], now: float
    ) -> tuple[str, tuple[Any, ...]]:
        condition, scope_values = _selection(scopes)
        identity = _scope_values(scopes[0])[:3]
        # Three index-ordered, single-row probes. Only their winners are sorted.
        # EXISTS uses the observation PK; no history-wide DISTINCT under the writer lock.
        probes: list[str] = []
        parameters: list[Any] = []
        for status, clock, index in (
            ("pending", "next_attempt_at", "xml_claim_due"),
            ("retry_wait", "next_attempt_at", "xml_claim_due"),
            ("leased", "lease_until", "xml_claim_expired"),
        ):
            probes.append(
                "SELECT * FROM (SELECT d.namespace,d.environment,d.context_key,d.ksef_number,"
                "d.variant,d.expected_hash,d.fencing,d.failures,d.attempts,d."
                + clock
                + " AS available,d.created_at FROM invoice_xml_documents d INDEXED BY "
                + index
                + " WHERE d.namespace=? AND d.environment=? AND d.context_key=? "
                "AND d.status=? AND d."
                + clock
                + "<=? AND EXISTS(SELECT 1 FROM invoice_observations o WHERE ("
                + condition
                + ") AND o.ksef_number=d.ksef_number) ORDER BY d."
                + clock
                + ",d.created_at,d.ksef_number LIMIT 1)"
            )
            parameters.extend((*identity, status, now, *scope_values))
        return "SELECT * FROM (" + " UNION ALL ".join(
            probes
        ) + ") ORDER BY available,created_at,ksef_number LIMIT 1", tuple(parameters)

    def claim_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, lease_seconds: float = 120
    ) -> InvoiceXmlClaim | None:
        positive(lease_seconds, "lease_seconds")
        with self._transaction():
            now = time.time()
            query, parameters = self._claim_query(scopes, now)
            # Bound corruption recovery per call; the next invocation resumes scanning.
            for _ in range(100):
                row = self._execute(query, parameters).fetchone()
                if row is None:
                    return None
                try:
                    key = InvoiceXmlKey(*row[:5])
                    if key.ksef_number != row[3]:
                        raise ValueError("Noncanonical queued identity requires migration")
                    hash_bytes(row[5])
                except (ValueError, KsefXmlIntegrityError) as error:
                    self._execute(
                        "UPDATE invoice_xml_documents SET status='blocked',last_reason=? WHERE "
                        + DOC_KEY,
                        (
                            "invalid_hash"
                            if isinstance(error, KsefXmlIntegrityError)
                            else "invalid_ksef_number",
                            *row[:5],
                        ),
                    )
                    continue
                epoch, storage_id = self._execute(
                    "SELECT epoch,storage_id FROM xml_store_meta WHERE id=1"
                ).fetchone()
                if storage_id is None:
                    raise KsefXmlStorageError("storage_id_mismatch")
                token = uuid.uuid4().hex
                claim = InvoiceXmlClaim(
                    key,
                    row[5],
                    storage_id,
                    token,
                    row[6] + 1,
                    epoch,
                    now + lease_seconds,
                    row[7],
                    row[8] + 1,
                )
                self._execute(
                    "UPDATE invoice_xml_documents SET status='leased',attempts=attempts+1,"
                    "lease_token=?,fencing=?,lease_epoch=?,lease_until=? WHERE " + DOC_KEY,
                    (token, claim.fencing, epoch, claim.expires_at, *key.values),
                )
                return claim
            return None

    def _claim_update(
        self, claim: InvoiceXmlClaim, assignment: str, parameters: tuple[Any, ...]
    ) -> None:
        result = self._execute(
            "UPDATE invoice_xml_documents SET "
            + assignment
            + " WHERE "
            + DOC_KEY
            + " AND status='leased' AND lease_token=? AND fencing=? AND "
            "lease_epoch=? AND lease_until>? "
            "AND expected_hash=? AND EXISTS(SELECT 1 FROM xml_store_meta "
            "WHERE id=1 AND epoch=? AND storage_id=?)",
            (
                *parameters,
                *claim.key.values,
                claim.token,
                claim.fencing,
                claim.epoch,
                time.time(),
                claim.expected_hash,
                claim.epoch,
                claim.storage_id,
            ),
        )
        if result.rowcount != 1:
            raise KsefXmlLeaseLostError()

    def finish_xml(self, claim: InvoiceXmlClaim, receipt: InvoiceXmlReceipt) -> None:
        receipt.validate(claim.key, claim.expected_hash, claim.storage_id)
        with self._transaction():
            self._claim_update(
                claim,
                "status='ready',receipt_json=?,verified_at=?,lease_token=NULL,"
                "lease_until=NULL,last_reason=NULL,failures=0",
                (json.dumps(asdict(receipt)), time.time()),
            )

    def defer_xml(
        self,
        claim: InvoiceXmlClaim,
        *,
        reason: str,
        delay: float,
        blocked: bool = False,
        failure: bool = False,
    ) -> None:
        if (
            reason not in SAFE_REASONS
            or type(delay) not in (int, float)
            or delay < 0
            or delay == float("inf")
            or delay != delay
        ):
            raise ValueError("Invalid safe retry attributes")
        with self._transaction():
            self._claim_update(
                claim,
                "status=?,next_attempt_at=?,last_reason=?,failures=failures+?,"
                "lease_token=NULL,lease_until=NULL",
                ("blocked" if blocked else "retry_wait", time.time() + delay, reason, int(failure)),
            )

    def describe_xml(self, scopes: Sequence[InvoiceSyncScope]) -> InvoiceXmlReport:
        cte, values = self._selected(scopes)
        with self._transaction(write=False):
            checkpoints = tuple(self._read_checkpoint(scope) for scope in scopes)
            counts = dict(
                self._execute(
                    cte + "SELECT COALESCE(d.status,'not_enqueued'),COUNT(*) "
                    "FROM selected s LEFT JOIN invoice_xml_documents d "
                    "INDEXED BY sqlite_autoindex_invoice_xml_documents_1 "
                    "USING(namespace,environment,context_key,ksef_number) "
                    "GROUP BY COALESCE(d.status,'not_enqueued')",
                    values,
                ).fetchall()
            )
            next_time = self._execute(
                cte + "SELECT MIN(CASE WHEN d.status='leased' THEN d.lease_until "
                "ELSE d.next_attempt_at END) FROM selected s JOIN invoice_xml_documents d "
                "INDEXED BY sqlite_autoindex_invoice_xml_documents_1 "
                "USING(namespace,environment,context_key,ksef_number) WHERE "
                "d.status IN ('retry_wait','leased')",
                values,
            ).fetchone()[0]
            complete = all(
                (
                    row := self._execute(
                        "SELECT complete FROM xml_backfill WHERE namespace=? AND environment=? "
                        "AND context_key=? AND sync_key=? AND stream_id=?",
                        _scope_values(scope),
                    ).fetchone()
                )
                is not None
                and row[0] == 1
                for scope in scopes
            )
            reasons = self._execute(
                cte + "SELECT d.last_reason,COUNT(*) FROM selected s JOIN invoice_xml_documents d "
                "INDEXED BY sqlite_autoindex_invoice_xml_documents_1 "
                "USING(namespace,environment,context_key,ksef_number) WHERE "
                "d.last_reason IS NOT NULL GROUP BY d.last_reason",
                values,
            ).fetchall()
            return InvoiceXmlReport(
                reason_counts=tuple(
                    (reason, count) for reason, count in reasons if reason in SAFE_REASONS
                ),
                observed=sum(counts.values()),
                not_enqueued=counts.get("not_enqueued", 0),
                pending=counts.get("pending", 0),
                leased=counts.get("leased", 0),
                retry_wait=counts.get("retry_wait", 0),
                blocked=counts.get("blocked", 0),
                ready=counts.get("ready", 0),
                backfill_complete=complete,
                observed_at=datetime.now(timezone.utc).isoformat(),
                next_attempt_at=next_time,
                checkpoints=checkpoints,
            )

    def backfill_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, batch_size: int = 500, time_budget: float = 60
    ) -> InvoiceXmlBackfillReport:
        _selection(scopes)
        positive_int(batch_size, "batch_size")
        if batch_size > 1000:
            raise ValueError("batch_size must not exceed 1000")
        end = time.monotonic() + positive(time_budget, "time_budget")
        self.validate_xml(scopes, self.xml_storage_id)
        processed = 0
        for scope in scopes:
            while time.monotonic() < end:
                with self._transaction():
                    previous = self._execute(
                        "SELECT last_number,complete FROM xml_backfill WHERE "
                        "namespace=? AND environment=? AND context_key=? AND "
                        "sync_key=? AND stream_id=?",
                        _scope_values(scope),
                    ).fetchone()
                    if previous and previous[1]:
                        break
                    last = previous[0] if previous else ""
                    # Restart a completed scan invalidated by concurrent metadata writes.
                    rows = self._execute(
                        "SELECT o.ksef_number,i.invoice_hash FROM invoice_observations o "
                        "JOIN invoices i USING(namespace,environment,context_key,ksef_number) "
                        "LEFT JOIN invoice_xml_documents d "
                        "INDEXED BY sqlite_autoindex_invoice_xml_documents_1 "
                        "USING(namespace,environment,context_key,ksef_number) "
                        "WHERE o.namespace=? AND o.environment=? AND o.context_key=? "
                        "AND o.sync_key=? AND o.stream_id=? "
                        "AND o.ksef_number>? ORDER BY o.ksef_number LIMIT ?",
                        (*_scope_values(scope), last, batch_size),
                    ).fetchall()
                    for number, expected_hash in rows:
                        self._enqueue_xml((*_scope_values(scope)[:3], number), expected_hash)
                    done = len(rows) < batch_size
                    self._execute(
                        "INSERT INTO xml_backfill VALUES (?,?,?,?,?,?,?) "
                        "ON CONFLICT(namespace,environment,context_key,sync_key,stream_id) "
                        "DO UPDATE SET last_number=excluded.last_number,complete=excluded.complete",
                        (*_scope_values(scope), rows[-1][0] if rows else last, int(done)),
                    )
                    processed += len(rows)
                if done:
                    break
        return InvoiceXmlBackfillReport(processed, self.describe_xml(scopes).backfill_complete)

    def list_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, after: str = "", limit: int = 100
    ) -> list[dict[str, Any]]:
        positive_int(limit, "limit")
        if limit > 1000:
            raise ValueError("limit must not exceed 1000")
        cte, values = self._selected(scopes)
        with self._transaction(write=False):
            cursor = self._execute(
                cte + "SELECT s.ksef_number,d.status,d.expected_hash,d.attempts,d.failures,"
                "d.last_reason,d.next_attempt_at,d.verified_at,d.fencing "
                "FROM selected s LEFT JOIN invoice_xml_documents d "
                "INDEXED BY sqlite_autoindex_invoice_xml_documents_1 "
                "USING(namespace,environment,context_key,ksef_number) WHERE "
                "s.ksef_number>? ORDER BY s.ksef_number LIMIT ?",
                (*values, after, limit),
            )
            names = [d[0] for d in cursor.description]
            return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]

    def retry_blocked(
        self, scopes: Sequence[InvoiceSyncScope], *, reason: str, limit: int = 100
    ) -> int:
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 256:
            raise ValueError("A bounded operator reason is required")
        positive_int(limit, "limit")
        if limit > 1000:
            raise ValueError("limit must not exceed 1000")
        cte, values = self._selected(scopes)
        with self._transaction():
            rows = self._execute(
                cte + "SELECT d.ksef_number FROM invoice_xml_documents d JOIN selected s "
                "USING(namespace,environment,context_key,ksef_number) WHERE "
                "d.status='blocked' ORDER BY d.ksef_number LIMIT ?",
                (*values, limit),
            ).fetchall()
            for (number,) in rows:
                self._execute(
                    "UPDATE invoice_xml_documents SET "
                    "status='pending',failures=0,next_attempt_at=0,"
                    "fencing=fencing+1,last_reason=NULL WHERE namespace=? AND "
                    "environment=? AND context_key=? AND ksef_number=?",
                    (*_scope_values(scopes[0])[:3], number),
                )
            return len(rows)

    def verify_ready(
        self,
        scopes: Sequence[InvoiceSyncScope],
        storage: InvoiceXmlStorage,
        *,
        after: str = "",
        limit: int = 100,
    ) -> str | None:
        self.validate_xml(scopes, storage.storage_id)
        cte, values = self._selected(scopes)
        positive_int(limit, "limit")
        if limit > 1000:
            raise ValueError("limit must not exceed 1000")
        with self._transaction(write=False):
            rows = self._execute(
                cte + "SELECT d.ksef_number,d.expected_hash,d.fencing FROM invoice_xml_documents d "
                "INDEXED BY sqlite_autoindex_invoice_xml_documents_1 "
                "JOIN selected s USING(namespace,environment,context_key,ksef_number) "
                "WHERE d.status='ready' AND d.ksef_number>? ORDER BY d.ksef_number LIMIT ?",
                (*values, after, limit),
            ).fetchall()
        for number, expected_hash, fencing in rows:
            key = InvoiceXmlKey(
                scopes[0].namespace, scopes[0].environment, scopes[0].context_key, number
            )
            try:
                receipt = storage.inspect(key, expected_hash)
                if receipt is not None:
                    receipt.validate(key, expected_hash, storage.storage_id)
                state, reason = (
                    ("ready", None) if receipt is not None else ("pending", "verified_missing")
                )
            except KsefXmlIntegrityError:
                state, reason = "blocked", "verified_corrupt"
            with self._transaction():
                self._execute(
                    "UPDATE invoice_xml_documents SET status=?,last_reason=?,verified_at=?,"
                    "fencing=fencing+1,next_attempt_at=0 WHERE "
                    + DOC_KEY
                    + " AND status='ready' AND fencing=?",
                    (state, reason, time.time(), *key.values, fencing),
                )
        return rows[-1][0] if len(rows) == limit else None

    def fence_workers(self) -> None:
        with self._transaction():
            self._execute("UPDATE xml_store_meta SET epoch=? WHERE id=1", (uuid.uuid4().hex,))
            self._execute(
                "UPDATE invoice_xml_documents SET "
                "status='pending',lease_token=NULL,lease_until=NULL,"
                "next_attempt_at=0,fencing=fencing+1 WHERE status='leased'"
            )

    def _verified_update(
        self, key: InvoiceXmlKey, expected_hash: str, state: str, reason: str | None, fencing: int
    ) -> None:
        with self._transaction():
            self._execute(
                "UPDATE invoice_xml_documents SET status=?,last_reason=?,verified_at=?,"
                "fencing=fencing+1,next_attempt_at=0 WHERE "
                + DOC_KEY
                + " AND status='ready' AND fencing=? AND expected_hash=?",
                (state, reason, time.time(), *key.values, fencing, expected_hash),
            )

    def close(self) -> None:
        if self._owned:
            self.connection.close()

    def __enter__(self) -> SQLiteInvoiceSyncStore:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AsyncSQLiteInvoiceSyncStore:
    """A private SQLite connection on one dedicated thread; all calls drain cancellation."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ksef-sqlite")
        self._store: SQLiteInvoiceSyncStore | None = None

    @classmethod
    async def open(cls, path: str | Path, **kwargs: Any) -> AsyncSQLiteInvoiceSyncStore:
        instance = cls()

        async def initialize() -> None:
            loop = asyncio.get_running_loop()
            instance._store = await loop.run_in_executor(
                instance._executor, partial(SQLiteInvoiceSyncStore.open, path, **kwargs)
            )

        try:
            await shield_and_drain(initialize())
        except BaseException:
            await instance.close()
            raise
        return instance

    async def _call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        if self._store is None:
            raise KsefXmlStorageError("store_closed")
        callback = partial(getattr(self._store, name), *args, **kwargs)
        return await shield_and_drain(
            asyncio.get_running_loop().run_in_executor(self._executor, callback)
        )

    async def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None:
        return await self._call("load", scope)

    async def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt:
        return await self._call("commit", batch)

    async def validate_xml(self, scopes: Sequence[InvoiceSyncScope], storage_id: str) -> None:
        await self._call("validate_xml", scopes, storage_id)

    async def claim_xml(
        self, scopes: Sequence[InvoiceSyncScope], *, lease_seconds: float = 120
    ) -> InvoiceXmlClaim | None:
        return await self._call("claim_xml", scopes, lease_seconds=lease_seconds)

    async def finish_xml(self, claim: InvoiceXmlClaim, receipt: InvoiceXmlReceipt) -> None:
        await self._call("finish_xml", claim, receipt)

    async def defer_xml(self, claim: InvoiceXmlClaim, **kwargs: Any) -> None:
        await self._call("defer_xml", claim, **kwargs)

    async def describe_xml(self, scopes: Sequence[InvoiceSyncScope]) -> InvoiceXmlReport:
        return await self._call("describe_xml", scopes)

    async def backfill_xml(
        self, scopes: Sequence[InvoiceSyncScope], **kwargs: Any
    ) -> InvoiceXmlBackfillReport:
        return await self._call("backfill_xml", scopes, **kwargs)

    async def list_xml(
        self, scopes: Sequence[InvoiceSyncScope], **kwargs: Any
    ) -> list[dict[str, Any]]:
        return await self._call("list_xml", scopes, **kwargs)

    async def retry_blocked(self, scopes: Sequence[InvoiceSyncScope], **kwargs: Any) -> int:
        return await self._call("retry_blocked", scopes, **kwargs)

    async def fence_workers(self) -> None:
        await self._call("fence_workers")

    async def verify_ready(
        self, scopes: Sequence[InvoiceSyncScope], storage: Any, *, after: str = "", limit: int = 100
    ) -> str | None:
        # File storage's async wrapper exposes a sync implementation, but arbitrary
        # async storage must be driven on the event loop (never inside SQLite's thread).
        await self.validate_xml(scopes, storage.storage_id)
        rows = await self.list_xml(scopes, after=after, limit=limit)
        for row in rows:
            if row["status"] != "ready":
                continue
            key = InvoiceXmlKey(
                scopes[0].namespace,
                scopes[0].environment,
                scopes[0].context_key,
                row["ksef_number"],
            )
            try:
                receipt = await storage.inspect(key, row["expected_hash"])
                if receipt is not None:
                    receipt.validate(key, row["expected_hash"], storage.storage_id)
                state, reason = ("ready", None) if receipt else ("pending", "verified_missing")
            except KsefXmlIntegrityError:
                state, reason = "blocked", "verified_corrupt"
            await self._call(
                "_verified_update", key, row["expected_hash"], state, reason, row["fencing"]
            )
        return rows[-1]["ksef_number"] if len(rows) == limit else None

    async def close(self) -> None:
        try:
            if self._store is not None:
                try:
                    await self._call("close")
                finally:
                    self._store = None
        finally:
            await shield_and_drain(asyncio.to_thread(self._executor.shutdown, wait=True))

    async def __aenter__(self) -> AsyncSQLiteInvoiceSyncStore:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()
