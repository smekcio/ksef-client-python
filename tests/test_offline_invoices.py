import asyncio
from contextlib import AsyncExitStack
from inspect import isawaitable
from types import SimpleNamespace
from typing import TypedDict, cast

import pytest

from ksef_client import AsyncKsef, Ksef, KsefClientOptions, KsefEnvironment
from ksef_client import models as m
from ksef_client._offline_invoice_store import SQLiteOfflineInvoiceStore
from ksef_client.client import AsyncAuthenticatedClient, AuthenticatedClient
from ksef_client.exceptions import (
    KsefAuthenticationError,
    KsefDocumentValidationError,
    KsefHttpError,
    KsefSyncConflictError,
)
from ksef_client.offline_invoices import (
    AsyncOfflineInvoiceQueue,
    AsyncOfflineInvoices,
    AsyncSQLiteOfflineInvoiceStore,
    OfflineInvoiceMode,
    OfflineInvoiceQueue,
    OfflineInvoices,
    OfflineInvoiceStatus,
)
from ksef_client.operations import OperationState
from tests.test_e2e_token_flows import _build_invoice_xml
from tests.test_offline_invoice_state import NUMBER, remote_invoice
from tests.test_offline_invoice_store import DUE, KEY, XML
from tests.test_offline_verification import SELLER, signer


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
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        entry = outbox.enqueue(XML, due_at=DUE)
        digest = entry.progress.invoice_hash
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.SESSION_OPEN
        with pytest.raises(OSError, match="lost response"):
            outbox.advance(digest)
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        current = outbox.status(digest)
        assert current is not None
        assert current.progress.status is OfflineInvoiceStatus.SUBMISSION_UNKNOWN
        accepted = outbox.advance(digest)
        assert accepted.progress.ksef_number == NUMBER
        with pytest.raises(OSError, match="lost close"):
            outbox.advance(digest)
        with pytest.raises(OSError, match="interrupted UPO"):
            outbox.advance(digest)
        assert outbox.status(digest) == accepted
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.COMPLETE
        assert outbox.read_upo(digest) == b"<UPO/>"
        assert outbox.read_xml(digest) == XML
    assert client.open_count == client.send_count == client.close_count == 1


def test_duplicate_does_not_make_original_eligible_for_correction(tmp_path):
    client = TestClient()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        entry = outbox.enqueue(XML, due_at=DUE)
        digest = entry.progress.invoice_hash
        outbox.advance(digest)
        with pytest.raises(OSError):
            outbox.advance(digest)
        client.get_session_invoices = lambda *args, **kwargs: m.SessionInvoicesResponse(  # type: ignore[method-assign]
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
            outbox = AsyncOfflineInvoices(cast(AsyncKsef, client), store, namespace="company")
            entry = await outbox.enqueue(XML, due_at=DUE)
            digest = entry.progress.invoice_hash
            await outbox.advance(digest)
            with pytest.raises(asyncio.CancelledError):
                await outbox.advance(digest)
        async with await AsyncSQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
            outbox = AsyncOfflineInvoices(cast(AsyncKsef, client), store, namespace="company")
            current = await outbox.status(digest)
            assert current is not None
            assert current.progress.status is (OfflineInvoiceStatus.SUBMISSION_UNKNOWN)
            assert (await outbox.advance(digest)).progress.ksef_number == NUMBER
            assert (await outbox.advance(digest)).progress.status is OfflineInvoiceStatus.ACCEPTED
            assert (await outbox.advance(digest)).progress.status is OfflineInvoiceStatus.COMPLETE
            assert (await outbox.advance(digest)).progress.status is OfflineInvoiceStatus.COMPLETE
            assert await outbox.read_upo(digest) == b"<UPO/>"
        assert client.send_count == client.close_count == 1

    asyncio.run(run())


def test_queue_pages_order_precise_deadlines_and_exclude_terminal_rows(tmp_path):
    client = TestClient()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        later = outbox.enqueue(b"<later/>", due_at="2026-12-01T00:00:00.01Z")
        earlier = outbox.enqueue(XML, due_at=DUE)
        assert outbox.pending(limit=1) == (earlier,)
        digest = earlier.progress.invoice_hash
        assert outbox.pending(after=(earlier.due_at, digest)) == (later,)
        outbox.advance(digest)
        with pytest.raises(OSError):
            outbox.advance(digest)
        client.get_session_invoices = lambda *args, **kwargs: m.SessionInvoicesResponse(  # type: ignore[method-assign]
            [remote_invoice(450)]
        )
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.REJECTED
        assert outbox.pending() == (later,)
        assert outbox.advance(digest).progress.status is OfflineInvoiceStatus.REJECTED


def test_concurrent_workers_cannot_both_submit_the_same_document(tmp_path):
    client = TestClient()
    path = tmp_path / "offline.db"
    with (
        SQLiteOfflineInvoiceStore.open(path, key=KEY) as first_store,
        SQLiteOfflineInvoiceStore.open(path, key=KEY) as second_store,
    ):
        first = OfflineInvoices(cast(Ksef, client), first_store, namespace="company")
        second = OfflineInvoices(cast(Ksef, client), second_store, namespace="company")
        digest = first.enqueue(XML, due_at=DUE).progress.invoice_hash
        first.advance(digest)
        resume = client.resume_session

        def race(state):
            client.resume_session = resume  # type: ignore[method-assign]
            with pytest.raises(OSError, match="lost response"):
                second.advance(digest)
            return resume(state)

        client.resume_session = race  # type: ignore[method-assign]
        with pytest.raises(KsefSyncConflictError):
            first.advance(digest)
        assert client.send_count == 1
        current = first.status(digest)
        assert current is not None
        assert current.progress.status is OfflineInvoiceStatus.SUBMISSION_UNKNOWN


def test_explicit_retry_requires_an_authoritatively_empty_finalized_session(tmp_path):
    client = TestClient()
    path = tmp_path / "offline.db"
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        row = outbox.enqueue(XML, due_at=DUE, mode=OfflineInvoiceMode.UNAVAILABLE)
        digest = row.progress.invoice_hash
        with pytest.raises(ValueError, match="no unknown submission"):
            outbox.retry_if_unsubmitted(digest)
        outbox.advance(digest)
        with pytest.raises(OSError, match="lost response"):
            outbox.advance(digest)
        client.get_session_status = lambda _: SimpleNamespace(  # type: ignore[method-assign]
            status=m.StatusInfo(440, ""), invoice_count=None
        )
        assert outbox.retry_if_unsubmitted(digest).progress.status is (
            OfflineInvoiceStatus.SUBMISSION_UNKNOWN
        )
        client.get_session_status = lambda _: SimpleNamespace(  # type: ignore[method-assign]
            status=m.StatusInfo(440, ""), invoice_count=0
        )
        assert outbox.retry_if_unsubmitted(digest).progress.status is (
            OfflineInvoiceStatus.SUBMISSION_UNKNOWN
        )
        client.get_session_invoices = lambda *args, **kwargs: m.SessionInvoicesResponse(  # type: ignore[method-assign]
            [remote_invoice(200, invoice_hash="another invoice", number=NUMBER)]
        )
        assert outbox.retry_if_unsubmitted(digest).progress.status is (
            OfflineInvoiceStatus.SUBMISSION_UNKNOWN
        )
        client.get_session_invoices = lambda *args, **kwargs: m.SessionInvoicesResponse([])  # type: ignore[method-assign]
        queued = outbox.retry_if_unsubmitted(digest)
        assert queued.progress.status is OfflineInvoiceStatus.QUEUED
        assert queued.mode is OfflineInvoiceMode.UNAVAILABLE
        assert client.send_count == 1


def test_stage_before_authentication_and_resume_using_normal_facade(tmp_path):
    options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
    path = tmp_path / "offline.db"
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        local = OfflineInvoiceQueue(
            store,
            options=options,
            context_type="nip",
            context_value="5265877635",
            namespace="company",
        )
        staged = local.enqueue(XML, due_at=DUE, mode=OfflineInvoiceMode.EMERGENCY)
        digest = staged.progress.invoice_hash
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        client = Ksef(
            cast(AuthenticatedClient, None), options, context_type="Nip", context_value="5265877635"
        )
        assert client.invoices.offline(store, namespace="company").status(digest) == staged
        assert client.invoices.offline(store, namespace="other").status(digest) is None


class ProtocolClient(TestClient):
    def __init__(self):
        super().__init__()
        self.listing = m.SessionInvoicesResponse([])
        self.remote_code = 150
        self.session_code = 100
        self.fail_send = False
        self.inv_ref = SimpleNamespace(
            resume_state=lambda: SimpleNamespace(reference_number="invoice-1")
        )

    def send_invoice(self, xml, *, offline_mode, hash_of_corrected_invoice):
        self.send_count += 1
        if self.fail_send:
            raise OSError("test send failure")
        assert (xml, offline_mode, hash_of_corrected_invoice) == (XML, True, None)
        return self.inv_ref

    def get_session_invoice_status(self, session, invoice):
        assert (session, invoice) == ("session-1", "invoice-1")
        return remote_invoice(self.remote_code, number=NUMBER if self.remote_code == 200 else None)

    def get_session_invoices(self, *args, **kwargs):
        return self.listing

    def get_session_status(self, reference_number):
        return SimpleNamespace(status=m.StatusInfo(self.session_code, ""), invoice_count=0)

    def close_online_session(self, reference_number):
        self.close_count += 1
        self.session_code = 170


class AsyncProtocolClient(ProtocolClient):
    async def online_session(self):
        return super().online_session()

    async def send_invoice(self, *args, **kwargs):
        return super().send_invoice(*args, **kwargs)

    async def get_session_invoice_status(self, *args):
        return super().get_session_invoice_status(*args)

    async def get_session_invoices(self, *args, **kwargs):
        return super().get_session_invoices(*args, **kwargs)

    async def get_session_status(self, reference_number):
        return super().get_session_status(reference_number)

    async def close_online_session(self, reference_number):
        super().close_online_session(reference_number)


async def invoke(function, *args, **kwargs):
    outcome = function(*args, **kwargs)
    return await outcome if isawaitable(outcome) else outcome


@pytest.mark.parametrize("asynchronous", [False, True])
def test_poll_known_reference_and_close_pending_states(tmp_path, asynchronous):
    async def run():
        client = AsyncProtocolClient() if asynchronous else ProtocolClient()
        path = tmp_path / "offline.db"
        async with AsyncExitStack() as stack:
            queue: OfflineInvoices | AsyncOfflineInvoices
            if asynchronous:
                async_store = await stack.enter_async_context(
                    await AsyncSQLiteOfflineInvoiceStore.open(path, key=KEY)
                )
                queue = AsyncOfflineInvoices(
                    cast(AsyncKsef, client), async_store, namespace="company"
                )
            else:
                store = stack.enter_context(SQLiteOfflineInvoiceStore.open(path, key=KEY))
                queue = OfflineInvoices(cast(Ksef, client), store, namespace="company")
            with pytest.raises(ValueError, match="missing"):
                await invoke(queue.advance, "missing")
            row = await invoke(queue.enqueue, XML, due_at=DUE)
            digest = row.progress.invoice_hash
            assert (await invoke(queue.pending, limit=1)) == (row,)
            assert await invoke(queue.read_xml, digest) == XML
            await invoke(queue.advance, digest)
            client.options = SimpleNamespace(
                retry=SimpleNamespace(retryable_post_paths={"/sessions/online/session-1/invoices"})
            )
            with pytest.raises(ValueError, match="transport-level retries"):
                await invoke(queue.advance, digest)
            client.options = SimpleNamespace(retry=None)
            submitted = await invoke(queue.advance, digest)
            assert submitted.progress.status is OfflineInvoiceStatus.SUBMITTED
            pending = await invoke(queue.advance, digest)
            assert (await invoke(queue.advance, digest)) == pending
            client.remote_code = 200
            accepted = await invoke(queue.advance, digest)
            assert accepted.progress.status is OfflineInvoiceStatus.ACCEPTED
            assert (await invoke(queue.advance, digest)) == accepted
            assert (await invoke(queue.advance, digest)) == accepted
            client.session_code = 445
            with pytest.raises(ValueError, match="cannot provide"):
                await invoke(queue.advance, digest)
            assert client.send_count == client.close_count == 1

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_unknown_submission_does_not_retry_with_ambiguous_listing(tmp_path, asynchronous):
    async def run():
        client = AsyncProtocolClient() if asynchronous else ProtocolClient()
        client.fail_send = True
        path = tmp_path / "offline.db"
        async with AsyncExitStack() as stack:
            queue: OfflineInvoices | AsyncOfflineInvoices
            if asynchronous:
                async_store = await stack.enter_async_context(
                    await AsyncSQLiteOfflineInvoiceStore.open(path, key=KEY)
                )
                queue = AsyncOfflineInvoices(
                    cast(AsyncKsef, client), async_store, namespace="company"
                )
            else:
                store = stack.enter_context(SQLiteOfflineInvoiceStore.open(path, key=KEY))
                queue = OfflineInvoices(cast(Ksef, client), store, namespace="company")
            row = await invoke(queue.enqueue, XML, due_at=DUE)
            digest = row.progress.invoice_hash
            await invoke(queue.advance, digest)
            with pytest.raises(OSError, match="send failure"):
                await invoke(queue.advance, digest)
            unknown = await invoke(queue.status, digest)
            assert (await invoke(queue.advance, digest)) == unknown
            for page, match in (
                (m.SessionInvoicesResponse([], "same-token"), "did not complete"),
                (m.SessionInvoicesResponse([remote_invoice(150, reference=None)]), "no reference"),
                (
                    m.SessionInvoicesResponse(
                        [remote_invoice(150), remote_invoice(150, reference="invoice-2")]
                    ),
                    "ambiguous",
                ),
            ):
                client.listing = page
                with pytest.raises(ValueError, match=match):
                    await invoke(queue.advance, digest)
            client.listing = m.SessionInvoicesResponse([], "")
            assert (await invoke(queue.retry_if_unsubmitted, digest)) == unknown
            assert (await invoke(queue.retry_if_unsubmitted, digest)) == unknown
            client.session_code = 440
            assert (await invoke(queue.retry_if_unsubmitted, digest)).progress.status is (
                OfflineInvoiceStatus.QUEUED
            )
            assert client.send_count == client.close_count == 1

    asyncio.run(run())


class OfflineIdentity(TypedDict):
    options: KsefClientOptions
    context_type: str
    context_value: str
    namespace: str


def test_offline_verification_public_sync_and_async_paths(tmp_path):
    options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
    identity = OfflineIdentity(
        options=options, context_type="nip", context_value=SELLER, namespace="company"
    )
    missing_context: OfflineIdentity = {**identity, "context_value": " "}
    certificate = signer()
    xml = _build_invoice_xml(seller_nip=SELLER, environment_name="offline-queue")
    path = tmp_path / "offline.db"
    with SQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
        with pytest.raises(ValueError, match="context is required"):
            OfflineInvoiceQueue(store, **missing_context)
        queue = OfflineInvoiceQueue(store, **identity)
        digest = queue.enqueue(xml, due_at=DUE).progress.invoice_hash
        with pytest.raises(ValueError, match="missing"):
            queue.verification_links("missing", certificate)
        assert queue.verification_links(digest, certificate).invoice_label == "OFFLINE"

    async def run():
        async with await AsyncSQLiteOfflineInvoiceStore.open(path, key=KEY) as store:
            with pytest.raises(ValueError, match="context is required"):
                AsyncOfflineInvoiceQueue(store, **missing_context)
            queue = AsyncOfflineInvoiceQueue(store, **identity)
            with pytest.raises(ValueError, match="missing"):
                await queue.verification_links("missing", certificate)
            assert (await queue.verification_links(digest, certificate)).invoice_label == "OFFLINE"
            client = AsyncKsef(
                cast(AsyncAuthenticatedClient, None),
                options,
                context_type="Nip",
                context_value=SELLER,
            )
            assert await client.invoices.offline(store, namespace="company").read_xml(digest) == xml

    asyncio.run(run())


def test_correction_sends_distinct_xml_with_exact_original_hash(tmp_path):
    class CorrectionClient(TestClient):
        def send_invoice(self, xml, *, offline_mode, hash_of_corrected_invoice):
            self.send_count += 1
            if hash_of_corrected_invoice is None:
                assert xml == XML and offline_mode is True
                raise OSError("lost original response")
            assert xml == b"<corrected/>" and offline_mode is True
            assert hash_of_corrected_invoice == original
            return SimpleNamespace(
                resume_state=lambda: SimpleNamespace(reference_number="correction-1")
            )

        def get_session_invoices(self, reference_number, *, page_size, continuation_token):
            return m.SessionInvoicesResponse([remote_invoice(450)])

    client = CorrectionClient()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        queue = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        original = queue.enqueue(XML, due_at=DUE).progress.invoice_hash
        queue.advance(original)
        with pytest.raises(OSError, match="lost original response"):
            queue.advance(original)
        assert queue.advance(original).progress.status is OfflineInvoiceStatus.REJECTED
        correction = queue.enqueue(b"<corrected/>", due_at=DUE, correction_of=original)
        digest = correction.progress.invoice_hash
        queue.advance(digest)
        assert queue.advance(digest).progress.invoice_reference == "correction-1"
        assert queue.read_xml(original) == XML
        assert client.send_count == 2


@pytest.mark.parametrize("asynchronous", [False, True])
def test_confirmed_cancellation_requeues_original_and_preserves_new_deadline(
    tmp_path, monkeypatch, asynchronous
):
    clock = [1.0]
    monkeypatch.setattr("ksef_client._offline_invoice_store.time.time", lambda: clock[0])

    async def run():
        client = AsyncProtocolClient() if asynchronous else ProtocolClient()
        path = tmp_path / "offline.db"
        async with AsyncExitStack() as stack:
            queue: OfflineInvoices | AsyncOfflineInvoices
            if asynchronous:
                async_store = await stack.enter_async_context(
                    await AsyncSQLiteOfflineInvoiceStore.open(path, key=KEY)
                )
                queue = AsyncOfflineInvoices(
                    cast(AsyncKsef, client), async_store, namespace="company"
                )
            else:
                store = stack.enter_context(SQLiteOfflineInvoiceStore.open(path, key=KEY))
                queue = OfflineInvoices(cast(Ksef, client), store, namespace="company")
            row = await invoke(queue.enqueue, XML, due_at=DUE)
            digest = row.progress.invoice_hash
            with pytest.raises(ValueError, match="no confirmed cancellation"):
                await invoke(queue.retry_cancelled, digest)
            # Another connection holds the open claim. Neither client may open until it expires.
            with SQLiteOfflineInvoiceStore.open(path, key=KEY) as other:
                assert other._claim_open(queue.scope, digest, 5) is not None
                assert (await invoke(queue.advance, digest)) == row
                assert client.open_count == 0
            clock[0] = 7.0
            await invoke(queue.advance, digest)
            await invoke(queue.advance, digest)
            client.remote_code = 550
            cancelled = await invoke(queue.advance, digest)
            assert cancelled.progress.status is OfflineInvoiceStatus.RETRYABLE
            assert await invoke(queue.pending) == (cancelled,)
            assert (await invoke(queue.advance, digest)) == cancelled
            updated = await invoke(
                queue.reschedule,
                digest,
                due_at="2026-12-02T00:00:00Z",
                expected_revision=cancelled.revision,
            )
            queued = await invoke(queue.retry_cancelled, digest)
            assert queued.progress.status is OfflineInvoiceStatus.QUEUED
            assert queued.due_at == updated.due_at
            assert await invoke(queue.read_xml, digest) == XML
            assert client.send_count == 1
            await invoke(queue.advance, digest)
            await invoke(queue.advance, digest)
            client.remote_code = 200
            assert (await invoke(queue.advance, digest)).progress.ksef_number == NUMBER
            assert client.send_count == 2 and client.open_count == 2

    asyncio.run(run())


@pytest.mark.parametrize("wire_timeout", [False, True])
def test_batch_sends_open_sessions_before_opening_new_and_reconciles_timeout(
    tmp_path, wire_timeout
):
    from ksef_client.exceptions import KsefTransportTimeoutError
    from ksef_client.rate_limiting import KsefRateLimitWaitTimeout

    calls: list[bytes | str] = []

    class Client(TestClient):
        def online_session(self):
            calls.append("open")
            return super().online_session()

        def send_invoice(self, xml, *, offline_mode, hash_of_corrected_invoice):
            assert offline_mode
            calls.append(xml)
            if xml == XML:
                if wire_timeout:
                    raise KsefTransportTimeoutError(0, "HTTP transport timeout")
                raise KsefRateLimitWaitTimeout("timeout during the first send")
            return SimpleNamespace(
                resume_state=lambda: SimpleNamespace(reference_number="invoice-2")
            )

    client = Client()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        first = outbox.enqueue(XML, due_at="2026-02-01T00:00:00Z")
        next_ = outbox.enqueue(b"<other/>", due_at="2026-01-01T00:00:00Z")
        outbox.advance(first.progress.invoice_hash)
        calls.clear()
        rows, failures = outbox.advance_batch(outbox.pending(), submit_immediately=True, timeout=10)
        assert calls == [XML, "open", b"<other/>"]
        assert [(row.progress.invoice_hash, row.progress.status) for row in rows] == [
            (next_.progress.invoice_hash, OfflineInvoiceStatus.SUBMITTED)
        ]
        assert [(failure.invoice_hash, failure.code) for failure in failures] == [
            (first.progress.invoice_hash, "request_timeout")
        ]
        timed_out = outbox.status(first.progress.invoice_hash)
        assert timed_out is not None
        assert timed_out.progress.status is OfflineInvoiceStatus.SUBMISSION_UNKNOWN
        recovered, failures = outbox.advance_batch([timed_out], submit_immediately=True)
        assert not failures
        assert recovered[0].progress.status is OfflineInvoiceStatus.ACCEPTED
        assert calls.count(XML) == 1


@pytest.mark.parametrize(
    ("exception", "stops"),
    [
        (KsefDocumentValidationError("document"), False),
        (KsefSyncConflictError("revision"), False),
        (KsefHttpError(404, "missing"), False),
        (KsefHttpError(429, "limit"), True),
        (KsefHttpError(401, "authentication"), True),
        (KsefAuthenticationError(400, "invalid token"), True),
    ],
)
def test_batch_isolates_only_item_errors(tmp_path, monkeypatch, exception, stops):
    client = TestClient()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        first = outbox.enqueue(XML, due_at="2026-01-01T00:00:00Z")
        second = outbox.enqueue(b"<other/>", due_at="2026-01-02T00:00:00Z")
        calls: list[str] = []

        def advance(digest, *, timeout):
            calls.append(digest)
            if digest == first.progress.invoice_hash:
                raise exception
            return second

        monkeypatch.setattr(outbox, "advance", advance)
        if stops:
            with pytest.raises(type(exception)):
                outbox.advance_batch(outbox.pending())
            assert calls == [first.progress.invoice_hash]
        else:
            rows, failures = outbox.advance_batch(outbox.pending())
            assert rows == [second]
            assert failures[0].invoice_hash == first.progress.invoice_hash


def test_batch_respects_parent_cancellation_after_local_timeout(tmp_path, monkeypatch):
    from ksef_client.rate_limiting import (
        CancellationToken,
        KsefRateLimitWaitTimeout,
        KsefRequestCancelledError,
    )
    from ksef_client.request_control import request_control

    cancellation = CancellationToken()
    client = TestClient()
    with SQLiteOfflineInvoiceStore.open(tmp_path / "offline.db", key=KEY) as store:
        outbox = OfflineInvoices(cast(Ksef, client), store, namespace="company")
        entry = outbox.enqueue(XML, due_at=DUE)

        def advance(digest, *, timeout):
            cancellation.cancel()
            raise KsefRateLimitWaitTimeout("item timeout")

        monkeypatch.setattr(outbox, "advance", advance)
        with request_control(cancellation=cancellation), pytest.raises(KsefRequestCancelledError):
            outbox.advance_batch([entry])
