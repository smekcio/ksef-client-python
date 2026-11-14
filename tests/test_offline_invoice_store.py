import asyncio
import sqlite3
from dataclasses import replace

import pytest

from ksef_client._offline_invoice_state import OfflineInvoiceStatus
from ksef_client._offline_invoice_store import (
    AsyncSQLiteOfflineInvoiceStore,
    SQLiteOfflineInvoiceStore,
)
from ksef_client.exceptions import KsefDocumentValidationError, KsefSyncConflictError
from ksef_client.invoice_sync_state import InvoiceSyncScope
from ksef_client.operations import OperationState
from tests.test_offline_invoice_state import NUMBER, remote_invoice

SCOPE = InvoiceSyncScope("company", "a" * 64, "Nip:test", "offline", "b" * 64)
DUE = "2026-12-01T00:00:00Z"
KEY = b"k" * 32
XML = b"<invoice/>"


def test_archive_cas_survives_restart_and_preserves_encrypted_original_and_upo(tmp_path):
    database = tmp_path / "offline.db"
    with SQLiteOfflineInvoiceStore.open(database, key=KEY) as store:
        original = store.enqueue(SCOPE, XML, due_at=DUE)
        assert store.enqueue(SCOPE, XML, due_at=DUE) == original
        opened = store._advance(SCOPE, original, original.progress.open_session("session-1"))
        with pytest.raises(KsefSyncConflictError):
            store._advance(SCOPE, original, original.progress.open_session("session-2"))
        pending = store._advance(SCOPE, opened, opened.progress.begin_submission())
    with SQLiteOfflineInvoiceStore.open(database, key=KEY) as store:
        assert store.load(SCOPE, pending.progress.invoice_hash) == pending
        assert store.read_xml(SCOPE, pending.progress.invoice_hash) == XML
        accepted = pending.progress.observe(remote_invoice(200, number=NUMBER))
        saved = store._advance(SCOPE, pending, accepted)
        complete = store._advance(SCOPE, saved, accepted.confirm_upo(), upo=b"<upo/>")
        assert store.read_upo(SCOPE, pending.progress.invoice_hash) == b"<upo/>"
        assert complete.progress.status is OfflineInvoiceStatus.COMPLETE
        assert (
            store.load(replace(SCOPE, context_key="Nip:other"), pending.progress.invoice_hash)
            is None
        )
    assert XML not in database.read_bytes()
    assert b"<upo/>" not in database.read_bytes()
    with (
        SQLiteOfflineInvoiceStore.open(database, key=b"x" * 32) as store,
        pytest.raises(KsefDocumentValidationError, match="authentication failed"),
    ):
        store.read_xml(SCOPE, pending.progress.invoice_hash)


def test_technical_correction_requires_same_scope_and_a_terminal_rejection(tmp_path):
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        row = store.enqueue(SCOPE, XML, due_at=DUE)
        original = row.progress.invoice_hash
        with pytest.raises(KsefDocumentValidationError, match="requires a rejection"):
            store.enqueue(SCOPE, b"<corrected/>", due_at=DUE, correction_of=original)
        row = store._advance(SCOPE, row, row.progress.open_session("session-1"))
        row = store._advance(SCOPE, row, row.progress.begin_submission())
        store._advance(SCOPE, row, row.progress.observe(remote_invoice(450)))
        corrected = store.enqueue(SCOPE, b"<corrected/>", due_at=DUE, correction_of=original)
        assert corrected.correction_of == original
        with pytest.raises(KsefSyncConflictError):
            store.enqueue(SCOPE, b"<another/>", due_at=DUE, correction_of=original)
        opened = store._advance(SCOPE, corrected, corrected.progress.open_session("session-2"))
        pending = store._advance(SCOPE, opened, opened.progress.begin_submission())
        rejected = pending.progress.observe(
            remote_invoice(450, invoice_hash=corrected.progress.invoice_hash)
        )
        store._advance(SCOPE, pending, rejected)
        with pytest.raises(KsefDocumentValidationError, match="requires a rejection"):
            store.enqueue(
                SCOPE, b"<nested/>", due_at=DUE, correction_of=corrected.progress.invoice_hash
            )
        second = store.enqueue(SCOPE, b"<another/>", due_at=DUE, correction_of=original)
        opened = store._advance(SCOPE, second, second.progress.open_session("session-3"))
        pending = store._advance(SCOPE, opened, opened.progress.begin_submission())
        accepted = pending.progress.observe(
            remote_invoice(200, invoice_hash=second.progress.invoice_hash, number=NUMBER)
        )
        store._advance(SCOPE, pending, accepted)
        with pytest.raises(KsefSyncConflictError):
            store.enqueue(SCOPE, b"<third/>", due_at=DUE, correction_of=original)


def test_sqlite_offline_store_validates_connection_and_path(tmp_path):
    with pytest.raises(ValueError, match="32-byte key"):
        SQLiteOfflineInvoiceStore.open(tmp_path / "db", key=b"k")
    folder = tmp_path / "directory"
    folder.mkdir()
    with pytest.raises(ValueError, match="Unsafe offline archive file"):
        SQLiteOfflineInvoiceStore.open(folder, key=KEY)
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.execute("BEGIN")
        with pytest.raises(ValueError, match="idle SQLite"):
            SQLiteOfflineInvoiceStore(connection, KEY)
        connection.execute("ROLLBACK")
        store = SQLiteOfflineInvoiceStore(connection, KEY)
        store.close()
        connection.execute("BEGIN")
        with pytest.raises(ValueError, match="already has a transaction"):
            store.enqueue(SCOPE, XML, due_at=DUE)
        connection.execute("ROLLBACK")
    finally:
        connection.close()


@pytest.mark.parametrize("column", ["revision=revision+1", "active=0", "due_sort='invalid'"])
def test_authenticated_state_rejects_inconsistent_sqlite_index(tmp_path, column):
    path = tmp_path / "offline.db"
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        store = SQLiteOfflineInvoiceStore(connection, KEY)
        row = store.enqueue(SCOPE, XML, due_at=DUE)
        digest = row.progress.invoice_hash
        connection.execute(f"UPDATE offline_invoices_v1 SET {column}")
        with pytest.raises(KsefDocumentValidationError, match="identity mismatch"):
            store.load(SCOPE, digest)
    finally:
        connection.close()


def test_validates_storage_boundaries_before_effects(tmp_path):
    with SQLiteOfflineInvoiceStore.open(tmp_path / "db", key=KEY) as store:
        created = store.enqueue(SCOPE, XML, due_at=DUE)
        digest = created.progress.invoice_hash
        with pytest.raises(ValueError, match="size|storage policy"):
            store.enqueue(SCOPE, bytearray(XML), due_at=DUE)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="mode"):
            store.enqueue(SCOPE, XML, due_at=DUE, mode="offline24")  # type: ignore[arg-type]
        with pytest.raises(KsefSyncConflictError):
            store.enqueue(SCOPE, XML, due_at="2026-12-02T00:00:00Z")
        with pytest.raises(ValueError, match="limit"):
            store.pending(SCOPE, limit=0)
        with pytest.raises(ValueError, match="unavailable"):
            store.read_upo(SCOPE, digest)
        with pytest.raises(ValueError, match="session is unavailable"):
            store._read_session(SCOPE, created)
        wrong = OperationState("online", SCOPE.environment, SCOPE.context_key, "session-2")
        opened = created.progress.open_session("session-1")
        with pytest.raises(ValueError, match="session identity mismatch"):
            store._advance(SCOPE, created, opened, session=wrong)
        session = replace(wrong, reference_number="session-1")
        opened_row = store._advance(SCOPE, created, opened, session=session)
        changed_reference = replace(opened, session_reference="session-3")
        with pytest.raises(ValueError, match="session identity mismatch"):
            store._read_session(SCOPE, replace(opened_row, progress=changed_reference))
        other = store.enqueue(SCOPE, b"<other/>", due_at=DUE)
        with pytest.raises(ValueError, match="changed identity"):
            store._advance(SCOPE, created, other.progress)
        with pytest.raises(ValueError, match="completion requires an UPO"):
            store._advance(SCOPE, opened_row, opened, upo=b"not yet")
        unconfirmed = store._advance(SCOPE, opened_row, opened.begin_submission())
        accepted = unconfirmed.progress.observe(remote_invoice(200, number=NUMBER))
        accepted_row = store._advance(SCOPE, unconfirmed, accepted)
        with pytest.raises(ValueError, match="Invalid offline UPO size"):
            store._advance(SCOPE, accepted_row, accepted.confirm_upo(), upo=b"")


def test_async_sqlite_cleanup_after_failed_open_and_close(tmp_path):
    async def run():
        with pytest.raises(ValueError, match="32-byte key"):
            await AsyncSQLiteOfflineInvoiceStore.open(tmp_path / "db", key=b"bad")
        store = await AsyncSQLiteOfflineInvoiceStore.open(tmp_path / "db", key=KEY)
        await store.close()
        with pytest.raises(ValueError, match="archive is closed"):
            await store._call("load", SCOPE, "unused")

    asyncio.run(run())


def test_unrecoverable_rollback_closes_the_connection():
    class FailedRollback(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "ROLLBACK":
                raise sqlite3.OperationalError("rollback failed")
            return super().execute(sql, *args)

    connection = sqlite3.connect(":memory:", isolation_level=None, factory=FailedRollback)
    store = SQLiteOfflineInvoiceStore(connection, KEY)
    store.enqueue(SCOPE, XML, due_at=DUE)
    with pytest.raises(KsefSyncConflictError):
        store.enqueue(SCOPE, XML, due_at="2026-12-02T00:00:00Z")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
