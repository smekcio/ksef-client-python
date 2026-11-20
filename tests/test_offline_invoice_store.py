import asyncio
import sqlite3
from contextlib import closing
from dataclasses import replace
from typing import Any

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


def test_legacy_offline_archive_stays_readable_and_upgrades_on_first_online_write(tmp_path):
    path = tmp_path / "existing offline.db"
    online_scope = replace(SCOPE, sync_key="online-invoices", stream_id="c" * 64)
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        original = store.enqueue(SCOPE, XML, due_at=DUE)
    original_file = path.read_bytes()
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        store = SQLiteOfflineInvoiceStore(connection, KEY)
        assert {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        } == {"offline_invoices_v1", "offline_session_open_v1", "offline_attempts_v1"}
        assert store.pending(SCOPE) == (original,)
        assert store.read_xml(SCOPE, original.progress.invoice_hash) == XML
        assert store._load_online(online_scope, "INV-1") is None
        with pytest.raises(KsefDocumentValidationError, match="identifier"):
            store._load_online(online_scope, "")
    assert path.read_bytes() == original_file

    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        registered = store._enqueue_online(online_scope, "INV-1", XML)
        assert store.load(SCOPE, original.progress.invoice_hash) == original
        assert store._enqueue_online(online_scope, "INV-1", XML) == registered
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        store = SQLiteOfflineInvoiceStore(connection, KEY)
        assert store._load_online(online_scope, "INV-1") == registered
        assert store.load(SCOPE, original.progress.invoice_hash) == original


def test_online_archive_refuses_incomplete_identity_schema(tmp_path):
    path = tmp_path / "archive.db"
    with closing(sqlite3.connect(path, isolation_level=None)) as connection:
        store = SQLiteOfflineInvoiceStore(connection, KEY)
        original = store.enqueue(SCOPE, XML, due_at=DUE)
        online_scope = replace(SCOPE, sync_key="online-invoices", stream_id="c" * 64)
        store._enqueue_online(online_scope, "INV-1", XML)
        connection.execute("DROP TABLE online_archive_key_v1")
        with pytest.raises(KsefDocumentValidationError, match="schema is incomplete"):
            store._load_online(online_scope, "INV-1")
        with pytest.raises(KsefDocumentValidationError, match="schema is incomplete"):
            store._enqueue_online(online_scope, "INV-2", b"<different/>")
        assert store.load(SCOPE, original.progress.invoice_hash) == original


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
        invalid_xml: Any = bytearray(XML)
        with pytest.raises(ValueError, match="size|storage policy"):
            store.enqueue(SCOPE, invalid_xml, due_at=DUE)
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


def test_reschedule_keeps_hash_and_fences_stale_revision(tmp_path):
    later = "2026-12-03T00:00:00Z"
    with SQLiteOfflineInvoiceStore.open(tmp_path / "db", key=KEY) as store:
        row = store.enqueue(SCOPE, XML, due_at=DUE)
        digest = row.progress.invoice_hash
        other = store.enqueue(SCOPE, b"<other/>", due_at="2026-12-02T00:00:00Z")
        with pytest.raises(ValueError, match="not active"):
            store.reschedule(
                SCOPE, other.progress.invoice_hash + "x", due_at=later, expected_revision=1
            )
        unchanged = store.reschedule(SCOPE, digest, due_at=DUE, expected_revision=row.revision)
        assert unchanged == row
        updated = store.reschedule(SCOPE, digest, due_at=later, expected_revision=row.revision)
        assert store.pending(SCOPE) == (other, updated)
        assert updated.progress == row.progress
        assert store.read_xml(SCOPE, digest) == XML
        with pytest.raises(KsefSyncConflictError):
            store.reschedule(SCOPE, digest, due_at=DUE, expected_revision=row.revision)


def test_session_open_claim_recovers_after_expiry_without_stale_publish(tmp_path, monkeypatch):
    clock = [1.0]
    monkeypatch.setattr("ksef_client._offline_invoice_store.time.time", lambda: clock[0])
    path = tmp_path / "db"
    with (
        SQLiteOfflineInvoiceStore.open(path, key=KEY) as first,
        SQLiteOfflineInvoiceStore.open(path, key=KEY) as second,
    ):
        row = first.enqueue(SCOPE, XML, due_at=DUE)
        digest = row.progress.invoice_hash
        assert first._claim_open(SCOPE, digest + "wrong", 5) is None
        original_claim = first._claim_open(SCOPE, digest, 5)
        assert original_claim is not None
        assert second._claim_open(SCOPE, digest, 5) is None
        clock[0] = 7.0
        current_claim = second._claim_open(SCOPE, digest, 5)
        assert current_claim is not None and current_claim != original_claim
        with pytest.raises(KsefSyncConflictError):
            first._advance(
                SCOPE, row, row.progress.open_session("stale"), opening_token=original_claim
            )
        moved = first.reschedule(
            SCOPE, digest, due_at="2026-12-02T00:00:00Z", expected_revision=row.revision
        )
        reopened = second._advance(
            SCOPE, row, row.progress.open_session("fresh"), opening_token=current_claim
        )
        assert reopened.due_at == moved.due_at and reopened.revision == moved.revision + 1
        assert first._claim_open(SCOPE, digest, 5) is None


def test_retry_confirmed_cancellation_keeps_encrypted_attempt_history_after_restart(tmp_path):
    path = tmp_path / "db"
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        initial = store.enqueue(SCOPE, XML, due_at=DUE)
        digest = initial.progress.invoice_hash
        opened = store._advance(SCOPE, initial, initial.progress.open_session("old-session"))
        sent = store._advance(SCOPE, opened, opened.progress.begin_submission())
        cancelled = sent.progress.observe(remote_invoice(550))
        # Prior versions stored status 550 as REJECTED. The upgrade can requeue it.
        legacy = replace(cancelled, status=OfflineInvoiceStatus.REJECTED)
        old = store._advance(SCOPE, sent, legacy)
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        current = store.retry_cancelled(SCOPE, digest)
        assert current.progress == initial.progress
        auth_scope = store._scope(SCOPE)
        attempt = store._db.execute(
            "SELECT revision, progress FROM offline_attempts_v1 WHERE scope=? AND invoice_hash=?",
            (auth_scope, digest),
        ).fetchone()
        assert attempt[0] == old.revision and b"old-session" not in attempt[1]
        assert b"old-session" in store._decrypt(
            auth_scope, digest, f"attempt:{attempt[0]}", attempt[1]
        )


def test_retry_correction_respects_newer_active_correction(tmp_path):
    with SQLiteOfflineInvoiceStore.open(tmp_path / "db", key=KEY) as store:

        def reject(row, code):
            opened = store._advance(SCOPE, row, row.progress.open_session("session-1"))
            sent = store._advance(SCOPE, opened, opened.progress.begin_submission())
            observed = sent.progress.observe(
                remote_invoice(code, invoice_hash=sent.progress.invoice_hash)
            )
            return store._advance(
                SCOPE, sent, replace(observed, status=OfflineInvoiceStatus.REJECTED)
            )

        original = reject(store.enqueue(SCOPE, XML, due_at=DUE), 450)
        original_hash = original.progress.invoice_hash
        cancelled = reject(
            store.enqueue(SCOPE, b"<first/>", due_at=DUE, correction_of=original_hash), 550
        )
        digest = cancelled.progress.invoice_hash
        newer = store.enqueue(SCOPE, b"<second/>", due_at=DUE, correction_of=original_hash)
        with pytest.raises(KsefSyncConflictError):
            store.retry_cancelled(SCOPE, digest)
        reject(newer, 450)
        assert store.retry_cancelled(SCOPE, digest).correction_of == original_hash
