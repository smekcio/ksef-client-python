import asyncio
from types import SimpleNamespace

import pytest

from ksef_client import models as m
from ksef_client._offline_invoice_store import SQLiteOfflineInvoiceStore
from ksef_client.exceptions import KsefSyncConflictError
from ksef_client.offline_invoices import (
    AsyncOfflineInvoices,
    AsyncSQLiteOfflineInvoiceStore,
    OfflineInvoices,
    OfflineInvoiceStatus,
)
from ksef_client.operations import OperationState
from tests.test_offline_invoice_state import NUMBER, remote_invoice
from tests.test_offline_invoice_store import DUE, KEY, XML


class TestClient:
    __test__ = False
    environment = "a" * 64
    context_key = "Nip:test"
    options = SimpleNamespace(retry=None)

    def __init__(self):
        self.send_count = 0
        self.close_count = 0
        self.open_count = 0
        self.upo_count = 0
        self.failed_once = False
        self.api = SimpleNamespace(sessions=self)

    def online_session(self):
        self.open_count += 1
        return self

    def resume_state(self):
        return OperationState("online", self.environment, self.context_key, "session-1")

    def resume_session(self, state):
        assert state.reference_number == "session-1"
        return self

    def send_invoice(self, xml, *, offline_mode, hash_of_corrected_invoice):
        assert (xml, offline_mode, hash_of_corrected_invoice) == (XML, True, None)
        self.send_count += 1
        raise OSError("simulated lost response after acceptance")

    def get_session_invoices(self, reference_number, *, page_size, continuation_token):
        assert reference_number == "session-1" and page_size == 100
        if continuation_token is None:
            return m.SessionInvoicesResponse([], "page-2")
        assert continuation_token == "page-2"
        return m.SessionInvoicesResponse([remote_invoice(200, number=NUMBER)])

    def get_session_status(self, reference_number):
        assert reference_number == "session-1"
        return SimpleNamespace(status=m.StatusInfo(200 if self.close_count else 100, ""))

    def close_online_session(self, reference_number):
        assert reference_number == "session-1"
        self.close_count += 1
        raise OSError("simulated lost close response")

    def get_session_invoice_upo_by_ref(self, reference, invoice_reference):
        assert (reference, invoice_reference) == ("session-1", "invoice-1")
        self.upo_count += 1
        if self.upo_count == 1:
            raise OSError("simulated interrupted UPO download")
        return b"<UPO/>"


def test_restart_after_lost_send_response_recovers_result_and_upo_without_resending(tmp_path):
    client = TestClient()
    path = tmp_path / "offline.db"
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        outbox = OfflineInvoices(client, store, namespace="company")
        entry = outbox.enqueue(XML, due_at=DUE)
        digest = entry.progress.invoice_hash
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.SESSION_OPEN
        with pytest.raises(OSError, match="lost response"):
            outbox.advance(digest)
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        outbox = OfflineInvoices(client, store, namespace="company")
        assert outbox.status(digest).progress.status is OfflineInvoiceStatus.SUBMISSION_UNKNOWN
        accepted = outbox.advance(digest)
        assert accepted.progress.ksef_number == NUMBER
        with pytest.raises(OSError, match="lost close"):
            outbox.advance(digest)
        with pytest.raises(OSError, match="interrupted UPO"):
            outbox.advance(digest)
        assert outbox.status(digest) == accepted
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        outbox = OfflineInvoices(client, store, namespace="company")
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.COMPLETE
        assert outbox.read_upo(digest) == b"<UPO/>"
        assert outbox.read_xml(digest) == XML
    assert client.open_count == client.send_count == client.close_count == 1


def test_duplicate_does_not_make_original_eligible_for_correction(tmp_path):
    client = TestClient()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        outbox = OfflineInvoices(client, store, namespace="company")
        entry = outbox.enqueue(XML, due_at=DUE)
        digest = entry.progress.invoice_hash
        outbox.advance(digest)
        with pytest.raises(OSError):
            outbox.advance(digest)
        client.get_session_invoices = lambda *args, **kwargs: m.SessionInvoicesResponse(
            [remote_invoice(440)]
        )
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.DUPLICATE
        with pytest.raises(ValueError, match="requires a rejection"):
            outbox.enqueue(b"<corrected/>", due_at=DUE, correction_of=digest)


def test_async_submission_reconciles_cancelled_send(tmp_path):
    class AsyncClient(TestClient):
        async def online_session(self):
            return super().online_session()

        async def send_invoice(self, xml, *, offline_mode, hash_of_corrected_invoice):
            self.send_count += 1
            raise asyncio.CancelledError

        async def get_session_invoices(self, *args, **kwargs):
            return super().get_session_invoices(*args, **kwargs)

        async def get_session_status(self, reference_number):
            return super().get_session_status(reference_number)

        async def close_online_session(self, reference_number):
            self.close_count += 1

        async def get_session_invoice_upo_by_ref(self, reference, invoice_reference):
            return b"<UPO/>"

    async def run():
        client = AsyncClient()
        path = tmp_path / "offline.db"
        async with await AsyncSQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
            outbox = AsyncOfflineInvoices(client, store, namespace="company")
            entry = await outbox.enqueue(XML, due_at=DUE)
            digest = entry.progress.invoice_hash
            await outbox.advance(digest)
            with pytest.raises(asyncio.CancelledError):
                await outbox.advance(digest)
        async with await AsyncSQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
            outbox = AsyncOfflineInvoices(client, store, namespace="company")
            assert (await outbox.status(digest)).progress.status is (
                OfflineInvoiceStatus.SUBMISSION_UNKNOWN
            )
            assert (await outbox.advance(digest)).progress.ksef_number == NUMBER
            assert (await outbox.advance(digest)).progress.status is OfflineInvoiceStatus.ACCEPTED
            assert (await outbox.advance(digest)).progress.status is OfflineInvoiceStatus.COMPLETE
            assert await outbox.read_upo(digest) == b"<UPO/>"
        assert client.send_count == client.close_count == 1

    asyncio.run(run())


def test_queue_pages_order_precise_deadlines_and_exclude_terminal_rows(tmp_path):
    client = TestClient()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        outbox = OfflineInvoices(client, store, namespace="company")
        later = outbox.enqueue(b"<later/>", due_at="2026-12-01T00:00:00.01Z")
        earlier = outbox.enqueue(XML, due_at=DUE)
        assert outbox.pending(limit=1) == (earlier,)
        digest = earlier.progress.invoice_hash
        assert outbox.pending(after=(earlier.due_at, digest)) == (later,)
        outbox.advance(digest)
        with pytest.raises(OSError):
            outbox.advance(digest)
        client.get_session_invoices = lambda *args, **kwargs: m.SessionInvoicesResponse(
            [remote_invoice(450)]
        )
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.REJECTED
        assert outbox.pending() == (later,)


def test_concurrent_workers_cannot_both_submit_the_same_document(tmp_path):
    client = TestClient()
    path = tmp_path / "offline.db"
    with (
        SQLiteOfflineInvoiceStore.open(path, key=KEY) as first_store,
        SQLiteOfflineInvoiceStore.open(path, key=KEY) as second_store,
    ):
        first = OfflineInvoices(client, first_store, namespace="company")
        second = OfflineInvoices(client, second_store, namespace="company")
        digest = first.enqueue(XML, due_at=DUE).progress.invoice_hash
        first.advance(digest)
        resume = client.resume_session

        def race(state):
            client.resume_session = resume
            with pytest.raises(OSError, match="lost response"):
                second.advance(digest)
            return resume(state)

        client.resume_session = race
        with pytest.raises(KsefSyncConflictError):
            first.advance(digest)
        assert client.send_count == 1
        assert first.status(digest).progress.status is OfflineInvoiceStatus.SUBMISSION_UNKNOWN
