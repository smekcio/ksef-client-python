"""Transactional application adapter for InvoiceSync (metadata, not invoice XML).

Keep the database, WAL/SHM and backups in a private directory. Each worker owns
its connection. A transaction is opened only after HTTP has finished. The SDK
does not own this connection. Set a finite sqlite busy timeout.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import suppress
from typing import Any

from .exceptions import (
    KsefSyncConflictError,
    KsefSyncDataConflictError,
    KsefSyncStoreError,
)
from .invoice_sync_state import (
    InvoiceSyncBatch,
    InvoiceSyncCheckpoint,
    InvoiceSyncCommitReceipt,
    InvoiceSyncScope,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_checkpoints (
    namespace TEXT NOT NULL, environment TEXT NOT NULL, context_key TEXT NOT NULL,
    sync_key TEXT NOT NULL, stream_id TEXT NOT NULL, generation TEXT NOT NULL,
    revision INTEGER NOT NULL, spec_hash TEXT NOT NULL, checkpoint_json TEXT NOT NULL,
    last_commit_id TEXT NOT NULL,
    PRIMARY KEY (namespace, environment, context_key, sync_key, stream_id)
);
CREATE TABLE IF NOT EXISTS invoices (
    namespace TEXT NOT NULL, environment TEXT NOT NULL, context_key TEXT NOT NULL,
    ksef_number TEXT NOT NULL, invoice_hash TEXT NOT NULL,
    PRIMARY KEY (namespace, environment, context_key, ksef_number)
);
CREATE TABLE IF NOT EXISTS invoice_observations (
    namespace TEXT NOT NULL, environment TEXT NOT NULL, context_key TEXT NOT NULL,
    sync_key TEXT NOT NULL, stream_id TEXT NOT NULL, ksef_number TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    PRIMARY KEY (namespace, environment, context_key, sync_key, stream_id, ksef_number),
    FOREIGN KEY (namespace, environment, context_key, ksef_number)
        REFERENCES invoices(namespace, environment, context_key, ksef_number)
);
CREATE TABLE IF NOT EXISTS outbox (
    namespace TEXT NOT NULL, environment TEXT NOT NULL, context_key TEXT NOT NULL,
    ksef_number TEXT NOT NULL, kind TEXT NOT NULL, variant TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    PRIMARY KEY (namespace, environment, context_key, ksef_number, kind, variant),
    FOREIGN KEY (namespace, environment, context_key, ksef_number)
        REFERENCES invoices(namespace, environment, context_key, ksef_number)
);
"""
KEY = "namespace=? AND environment=? AND context_key=? AND sync_key=? AND stream_id=?"


def _key(scope: InvoiceSyncScope) -> tuple[str, ...]:
    return tuple(scope.to_dict().values())


class MetadataSQLiteStore:
    def __init__(self, connection: sqlite3.Connection, *, enqueue_xml: bool = False) -> None:
        if connection.in_transaction:
            raise ValueError("The adapter requires an idle connection")
        self.connection, self.enqueue_xml = connection, enqueue_xml
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(SCHEMA)

    def _execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        return self.connection.execute(sql, parameters)

    def _require_idle(self, operation: str) -> None:
        try:
            active = self.connection.in_transaction
        except Exception as error:
            raise KsefSyncStoreError(
                operation=operation,
                failure_scope="store",
                original_error=error,
            ) from None
        if active:
            raise KsefSyncStoreError(operation=operation, failure_scope="store")

    def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None:
        self._require_idle("load")
        return self._read_checkpoint(scope)

    def _read_checkpoint(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None:
        try:
            row = self._execute(
                "SELECT checkpoint_json, generation, revision, spec_hash, last_commit_id "
                "FROM sync_checkpoints WHERE " + KEY,
                _key(scope),
            ).fetchone()
        except Exception as error:
            raise KsefSyncStoreError(
                operation="load", failure_scope="store", original_error=error
            ) from None
        if row is None:
            return None
        checkpoint = InvoiceSyncCheckpoint.from_json(row[0])
        if (
            checkpoint.scope != scope
            or checkpoint.generation_id != row[1]
            or checkpoint.revision != row[2]
            or checkpoint.scope.stream_id != row[3]
            or checkpoint.last_commit_id != row[4]
        ):
            raise KsefSyncStoreError(operation="load", failure_scope="store")
        return checkpoint

    def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt:
        self._require_idle("commit")
        checkpoint, scope = batch.next_checkpoint, batch.scope
        started, committing = False, False
        try:
            self._execute("BEGIN IMMEDIATE")
            started = True
            previous = self._read_checkpoint(scope)
            if previous is None:
                if batch.expected_generation is not None or batch.expected_revision is not None:
                    raise KsefSyncConflictError("checkpoint_conflict")
            elif (
                previous.generation_id != batch.expected_generation
                or previous.revision != batch.expected_revision
            ):
                raise KsefSyncConflictError("checkpoint_conflict")
            if checkpoint.revision != (previous.revision + 1 if previous else 1):
                raise KsefSyncConflictError("checkpoint_conflict")
            self._prepare_xml_scope(scope, previous is None)
            document_scope = (scope.namespace, scope.environment, scope.context_key)
            for value in batch.observation_dicts:
                document = (*document_scope, value["ksefNumber"])
                self._execute(
                    "INSERT INTO invoices VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                    (*document, value["invoiceHash"]),
                )
                existing = self._execute(
                    "SELECT invoice_hash FROM invoices WHERE namespace=? AND environment=? "
                    "AND context_key=? AND ksef_number=?",
                    document,
                ).fetchone()
                if existing is None or existing[0] != value["invoiceHash"]:
                    raise KsefSyncDataConflictError("invoice_hash_conflict")
                # Batch snapshots are already validated and bounded by the SDK.
                metadata = json.dumps(
                    value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
                )
                self._execute(
                    "INSERT INTO invoice_observations VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(namespace, environment, context_key, sync_key, stream_id, "
                    "ksef_number) DO UPDATE SET metadata_json=excluded.metadata_json",
                    (*_key(scope), value["ksefNumber"], metadata),
                )
                if self.enqueue_xml:
                    self._execute(
                        "INSERT INTO outbox "
                        "(namespace,environment,context_key,ksef_number,kind,variant) "
                        "VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                        (*document, "invoice-xml", "v1"),
                    )
                    self._enqueue_xml(document, value["invoiceHash"])
            columns = (
                checkpoint.generation_id,
                checkpoint.revision,
                scope.stream_id,
                checkpoint.to_json(),
                checkpoint.last_commit_id,
            )
            if previous is None:
                self._execute(
                    "INSERT INTO sync_checkpoints VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (*_key(scope), *columns),
                )
            else:
                updated = self._execute(
                    "UPDATE sync_checkpoints SET generation=?, revision=?, spec_hash=?, "
                    "checkpoint_json=?, last_commit_id=? WHERE "
                    + KEY
                    + " AND generation=? AND revision=?",
                    (*columns, *_key(scope), previous.generation_id, previous.revision),
                )
                if updated.rowcount != 1:
                    raise KsefSyncConflictError("checkpoint_conflict")
            committing = True
            # Explicit SQL also works with sqlite3 autocommit=True (Python >=3.12).
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
                    operation="commit",
                    commit_outcome="unknown",
                    failure_scope="store",
                    original_error=error,
                ) from None
            if isinstance(error, (KsefSyncConflictError, KsefSyncDataConflictError)):
                raise error from None
            if not isinstance(error, Exception):
                raise error from None
            raise KsefSyncStoreError(
                operation="commit",
                commit_outcome=outcome,
                failure_scope="store",
                original_error=error,
            ) from None
        return batch.receipt

    def _enqueue_xml(self, document: tuple[str, ...], expected_hash: str) -> None:
        pass

    def _prepare_xml_scope(self, scope: InvoiceSyncScope, new: bool) -> None:
        pass
