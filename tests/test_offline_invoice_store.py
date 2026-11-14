from dataclasses import replace

import pytest

from ksef_client._offline_invoice_state import OfflineInvoiceStatus
from ksef_client._offline_invoice_store import SQLiteOfflineInvoiceStore
from ksef_client.exceptions import KsefDocumentValidationError, KsefSyncConflictError
from ksef_client.invoice_sync_state import InvoiceSyncScope
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
        store._advance(SCOPE, row, row.progress.observe(remote_invoice(440)))
        corrected = store.enqueue(SCOPE, b"<corrected/>", due_at=DUE, correction_of=original)
        assert corrected.correction_of == original
        with pytest.raises(KsefSyncConflictError):
            store.enqueue(SCOPE, b"<another/>", due_at=DUE, correction_of=original)
