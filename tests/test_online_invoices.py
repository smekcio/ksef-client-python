import asyncio
import base64
import sqlite3
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import replace
from inspect import isawaitable
from types import SimpleNamespace
from typing import cast

import pytest

from ksef_client import (
    AsyncAuthenticatedClient,
    AsyncKsef,
    AuthenticatedClient,
    Ksef,
    KsefClientOptions,
    RetryConfig,
)
from ksef_client import models as m
from ksef_client.async_facade import AsyncInvoices
from ksef_client.exceptions import KsefDocumentValidationError, KsefSyncConflictError
from ksef_client.facade import Invoices
from ksef_client.online_invoices import (
    AsyncSQLiteOnlineInvoiceStore,
    SQLiteOnlineInvoiceStore,
)
from ksef_client.online_invoices import (
    OnlineInvoiceStatus as Status,
)
from ksef_client.operations import environment_key
from ksef_client.token_manager import AsyncTokenManager, TokenManager
from tests.test_offline_invoice_state import HASH, NUMBER, remote_invoice
from tests.test_offline_invoice_store import DUE, KEY, XML
from tests.test_offline_invoices import TestClient

LOCAL_ID = "FV-ą/private-123"


def individual_upo(*, version="4-3", session="session-1", number=NUMBER, digest=HASH):
    return (
        f'<Potwierdzenie xmlns="http://upo.schematy.mf.gov.pl/KSeF/v{version}">'
        f"<NumerReferencyjnySesji>{session}</NumerReferencyjnySesji><Dokument>"
        f"<NumerKSeFDokumentu>{number}</NumerKSeFDokumentu><SkrotDokumentu>{digest}</SkrotDokumentu>"
        f"</Dokument></Potwierdzenie>"
    ).encode()


class Server(TestClient):
    options = KsefClientOptions(  # type: ignore[assignment]
        base_url="https://api-test.ksef.mf.gov.pl"
    )

    def __init__(self):
        super().__init__()
        self.environment = environment_key(self.options.normalized_base_url())
        self._http = SimpleNamespace(
            _options=self.options, api_base_url=self.options.normalized_base_url()
        )
        self.api.http_client = self._http
        self.api.security = self
        self.result = None
        self.session_code = None
        self.lose_send = True
        self.lose_open = False
        self.after_open = None
        self.upo = individual_upo()

    def online_session(self):
        result = super().online_session()
        if self.after_open:
            self.after_open()
        if self.lose_open:
            raise OSError("lost open")
        return result

    def send_invoice(self, xml, *, offline_mode, hash_of_corrected_invoice):
        assert (xml, offline_mode, hash_of_corrected_invoice) == (XML, False, None)
        self.send_count += 1
        if self.lose_send:
            raise OSError("lost send")
        return SimpleNamespace(resume_state=lambda: SimpleNamespace(reference_number="invoice-1"))

    def get_session_invoices(self, reference_number, *, page_size, continuation_token):
        assert (reference_number, page_size, continuation_token) == ("session-1", 100, None)
        return m.SessionInvoicesResponse([self.result] if self.result is not None else [])

    def get_session_invoice_status(self, reference_number, invoice_reference):
        assert (reference_number, invoice_reference) == ("session-1", "invoice-1")
        return self.result

    def get_session_status(self, reference_number):
        assert reference_number == "session-1"
        code = (
            self.session_code if self.session_code is not None else 200 if self.close_count else 100
        )
        return SimpleNamespace(status=m.StatusInfo(code, ""), invoice_count=0)

    def get_session_invoice_upo_by_ref(self, reference, invoice_reference, *, max_bytes=None):
        assert (reference, invoice_reference) == ("session-1", "invoice-1")
        assert max_bytes == 1024 * 1024
        return self.upo


class AsyncServer:
    def __init__(self, sync):
        self.sync = sync
        self.options = sync.options
        self.context_key = sync.context_key
        self.environment = sync.environment
        self._http = sync._http
        self.api = SimpleNamespace(sessions=self, security=self, http_client=self._http)

    def resume_session(self, state):
        self.sync.resume_session(state)
        return self

    async def online_session(self):
        return self.sync.online_session()

    def __getattr__(self, name):
        async def call(*args, **kwargs):
            return getattr(self.sync, name)(*args, **kwargs)

        return call


async def call(method, *args, **kwargs):
    value = method(*args, **kwargs)
    return await value if isawaitable(value) else value


@asynccontextmanager
async def online(server, path, use_async, *, key=KEY, namespace="company"):
    if use_async:
        async with await AsyncSQLiteOnlineInvoiceStore.open(path, key=key) as store:
            yield AsyncInvoices(cast(AsyncKsef, AsyncServer(server))).online(
                store, namespace=namespace
            )
    else:
        with SQLiteOnlineInvoiceStore.open(path, key=key) as store:
            yield Invoices(cast(Ksef, server)).online(store, namespace=namespace)


@pytest.mark.parametrize("use_async", [False, True])
def test_reopens_database_and_recovers_send_and_upo(tmp_path, use_async):
    async def run():
        server = Server()
        path = tmp_path / "online.db"
        async with online(server, path, use_async) as worker:
            assert await call(worker.status, LOCAL_ID) is None
            with pytest.raises(KsefDocumentValidationError, match="missing"):
                await call(worker.advance, LOCAL_ID)
            with pytest.raises(KsefDocumentValidationError, match="missing"):
                await call(worker.read_upo, LOCAL_ID)
            row = await call(worker.enqueue, LOCAL_ID, XML)
            assert row.status is Status.QUEUED
            assert row.local_id == LOCAL_ID and LOCAL_ID not in repr(row)
            assert await call(worker.enqueue, LOCAL_ID, XML) == row
            with pytest.raises(KsefSyncConflictError) as conflict:
                await call(worker.enqueue, LOCAL_ID, b"<changed/>")
            assert conflict.value.reason_code == "online_invoice_identity_conflict"
            with pytest.raises(KsefSyncConflictError) as duplicate:
                await call(worker.enqueue, "second-id", XML)
            assert duplicate.value.reason_code == "online_invoice_already_registered"
            assert (await call(worker.advance, LOCAL_ID)).status is Status.SESSION_OPEN
            with pytest.raises(OSError, match="lost send"):
                await call(worker.advance, LOCAL_ID)

        async with online(server, path, use_async) as worker:
            uncertain = await call(worker.enqueue, LOCAL_ID, XML)
            assert uncertain.status is Status.SUBMISSION_UNKNOWN
            for _ in range(2):
                assert await call(worker.advance, LOCAL_ID) == uncertain
            assert server.send_count == 1
            server.result = remote_invoice(200, number=NUMBER)
            accepted = await call(worker.advance, LOCAL_ID)
            assert accepted.ksef_number == NUMBER
            assert accepted.session_reference == "session-1"
            assert accepted.invoice_reference == "invoice-1"
            with pytest.raises(OSError, match="lost close"):
                await call(worker.advance, LOCAL_ID)

        async with online(server, path, use_async) as worker:
            assert (await call(worker.advance, LOCAL_ID)).status is Status.COMPLETE
            assert (await call(worker.status, LOCAL_ID)).status is Status.COMPLETE
            assert await call(worker.read_upo, LOCAL_ID) == server.upo

        assert server.open_count == server.send_count == server.close_count == 1
        assert LOCAL_ID.encode() not in path.read_bytes()

    asyncio.run(run())


@pytest.mark.parametrize("use_async", [False, True])
@pytest.mark.parametrize(
    ("code", "status"), [(450, Status.REJECTED), (440, Status.DUPLICATE), (550, Status.RETRYABLE)]
)
def test_nonaccepted_invoice_finalizes_session(tmp_path, use_async, code, status):
    async def run():
        server = Server()
        server.lose_send = False
        async with online(server, tmp_path / "online.db", use_async) as worker:
            await call(worker.enqueue, LOCAL_ID, XML)
            await call(worker.advance, LOCAL_ID)
            assert (await call(worker.advance, LOCAL_ID)).status is Status.SUBMITTED
            server.result = remote_invoice(code)
            with pytest.raises(OSError, match="lost close"):
                await call(worker.advance, LOCAL_ID)
            assert (await call(worker.status, LOCAL_ID)).status is Status.SUBMITTED
            assert (await call(worker.advance, LOCAL_ID)).status is status
            assert (await call(worker.advance, LOCAL_ID)).status is status
            if code == 550:
                queued = await call(worker.retry_cancelled, LOCAL_ID)
                assert queued.status is Status.QUEUED and queued.session_reference is None
                with pytest.raises(KsefDocumentValidationError, match="confirmed cancellation"):
                    await call(worker.retry_cancelled, LOCAL_ID)
            else:
                with pytest.raises(KsefDocumentValidationError, match="confirmed cancellation"):
                    await call(worker.retry_cancelled, LOCAL_ID)
        assert server.send_count == server.close_count == 1

    asyncio.run(run())


@pytest.mark.parametrize("use_async", [False, True])
def test_explicit_retry_requires_finalized_empty_session(tmp_path, use_async):
    async def run():
        server = Server()
        async with online(server, tmp_path / "online.db", use_async) as worker:
            await call(worker.enqueue, LOCAL_ID, XML)
            await call(worker.advance, LOCAL_ID)
            with pytest.raises(OSError, match="lost send"):
                await call(worker.advance, LOCAL_ID)
            with pytest.raises(OSError, match="lost close"):
                await call(worker.retry_if_unsubmitted, LOCAL_ID)
            assert (await call(worker.retry_if_unsubmitted, LOCAL_ID)).status is (
                Status.SUBMISSION_UNKNOWN
            )
            server.session_code = 440
            server.result = remote_invoice(200, number=NUMBER)
            assert (await call(worker.retry_if_unsubmitted, LOCAL_ID)).status is (
                Status.SUBMISSION_UNKNOWN
            )
            server.result = None
            assert (await call(worker.retry_if_unsubmitted, LOCAL_ID)).status is Status.QUEUED
            assert (await call(worker.enqueue, LOCAL_ID, XML)).status is Status.QUEUED

        assert server.send_count == server.close_count == 1

    asyncio.run(run())


@pytest.mark.parametrize(
    "options",
    [
        replace(Server.options, follow_redirects=True),
        replace(
            Server.options,
            retry=RetryConfig(retryable_post_paths=frozenset({"/sessions/online"})),
        ),
    ],
)
def test_replaying_configuration_is_rejected(tmp_path, options):
    server = Server()
    server.options = options
    with (
        SQLiteOnlineInvoiceStore.open(tmp_path / "online.db", key=KEY) as store,
        pytest.raises(ValueError, match="non-replaying"),
    ):
        Invoices(cast(Ksef, server)).online(store, namespace="company")


@pytest.mark.parametrize("use_async", [False, True])
def test_live_transport_configuration_is_bound_to_the_queue(tmp_path, monkeypatch, use_async):
    async def run():
        declared = KsefClientOptions(base_url="https://example.test")
        replaying = replace(
            declared,
            retry=RetryConfig(
                retryable_post_paths=frozenset({"/sessions/online/session-1/invoices"})
            ),
        )
        other = replace(declared, base_url="https://other.example.test")
        async with AsyncExitStack() as stack:
            path = tmp_path / "online.db"
            store: SQLiteOnlineInvoiceStore | AsyncSQLiteOnlineInvoiceStore
            if use_async:
                store = await stack.enter_async_context(
                    await AsyncSQLiteOnlineInvoiceStore.open(path, key=KEY)
                )

                async def make(options):
                    api = AsyncAuthenticatedClient(options, AsyncTokenManager("token"))
                    await stack.enter_async_context(api)
                    return AsyncKsef(api, declared, context_type="Nip", context_value="test")
            else:
                store = stack.enter_context(SQLiteOnlineInvoiceStore.open(path, key=KEY))

                async def make(options):
                    api = AuthenticatedClient(options, TokenManager("token"))
                    stack.enter_context(api)
                    return Ksef(api, declared, context_type="Nip", context_value="test")

            for options, error in [
                (other, "saved scope"),
                (replaying, "non-replaying"),
                (replace(declared, follow_redirects=True), "non-replaying"),
            ]:
                client = await make(options)
                with pytest.raises(ValueError, match=error):
                    client.invoices.online(store, namespace="company")

            client = await make(declared)
            worker = client.invoices.online(store, namespace="company")
            before = await call(worker.enqueue, LOCAL_ID, XML)
            for options, error in [(other, "saved scope"), (replaying, "non-replaying")]:
                monkeypatch.setattr(client.api.http_client, "_options", options)
                with pytest.raises(ValueError, match=error):
                    await call(worker.enqueue, "new-id", b"<new/>")
                with pytest.raises(ValueError, match=error):
                    await call(worker.advance, LOCAL_ID)
                assert await call(worker.status, "new-id") is None
                assert await call(worker.status, LOCAL_ID) == before

            monkeypatch.setattr(client.api.sessions, "_http", object())
            with pytest.raises(ValueError, match="shared KSeF API transport"):
                await call(worker.advance, LOCAL_ID)

    asyncio.run(run())


@pytest.mark.parametrize("use_async", [False, True])
@pytest.mark.parametrize("version", ["4-2", "4-3"])
def test_invalid_receipts_do_not_complete_the_invoice(tmp_path, use_async, version):
    async def run():
        server = Server()
        server.lose_send = False
        async with online(server, tmp_path / "online.db", use_async) as worker:
            await call(worker.enqueue, LOCAL_ID, XML)
            await call(worker.advance, LOCAL_ID)
            await call(worker.advance, LOCAL_ID)
            server.result = remote_invoice(200, number=NUMBER)
            accepted = await call(worker.advance, LOCAL_ID)
            server.session_code = 200
            for invalid, error in [
                (b"", "size policy"),
                (b" " * (1024 * 1024 + 1), "size policy"),
                (b"<html>", "well-formed XML"),
                (b"<html/>", "does not identify"),
                ("<!DOCTYPE UPO><UPO/>".encode("utf-16"), "well-formed XML"),
                (individual_upo(session="wrong"), "does not identify"),
                (individual_upo(number="wrong"), "does not identify"),
                (individual_upo(digest="wrong"), "does not identify"),
                (individual_upo(version="0-0"), "does not identify"),
            ]:
                server.upo = invalid
                with pytest.raises(KsefDocumentValidationError, match=error):
                    await call(worker.advance, LOCAL_ID)
                assert await call(worker.status, LOCAL_ID) == accepted

            server.upo = individual_upo(version=version)
            assert (await call(worker.advance, LOCAL_ID)).status is Status.COMPLETE
            assert await call(worker.read_upo, LOCAL_ID) == server.upo

    asyncio.run(run())


def test_scope_separation_and_wrong_key_rejected(tmp_path):
    path = tmp_path / "online.db"
    server = Server()
    invoices = Invoices(cast(Ksef, server))
    with SQLiteOnlineInvoiceStore.open(path, key=KEY) as store:
        first = invoices.online(store, namespace="first")
        second = invoices.online(store, namespace="second")
        first.enqueue(LOCAL_ID, XML)
        assert second.status(LOCAL_ID) is None
        assert second.enqueue(LOCAL_ID, b"<different/>").status is Status.QUEUED
        assert invoices.offline(store, namespace="first").enqueue(XML, due_at=DUE)
        assert server.send_count == 0
        with pytest.raises(KsefDocumentValidationError, match="Invalid local invoice identifier"):
            first.enqueue("id\n", XML)
        with pytest.raises(KsefDocumentValidationError, match="storage policy"):
            first.enqueue("id", cast(bytes, "not bytes"))
    with SQLiteOnlineInvoiceStore.open(path, key=b"b" * 32) as store:
        worker = invoices.online(store, namespace="first")
        with pytest.raises(KsefDocumentValidationError, match="authentication failed"):
            worker.status(LOCAL_ID)
        with pytest.raises(KsefDocumentValidationError, match="authentication failed"):
            worker.enqueue("unregistered", b"<different/>")


@pytest.mark.parametrize(
    "damage", ["swap", "mismatched_digest", "missing_document", "missing_verifier"]
)
def test_archive_corruption_refuses_to_register_again(tmp_path, damage):
    path = tmp_path / "online.db"
    invoices = Invoices(cast(Ksef, Server()))
    with SQLiteOnlineInvoiceStore.open(path, key=KEY) as store:
        worker = invoices.online(store, namespace="company")
        worker.enqueue(LOCAL_ID, XML)
        worker.enqueue("second", b"<different/>")
    with sqlite3.connect(path) as db:
        if damage == "swap":
            # The encrypted original bindings no longer match these document hashes.
            db.execute(
                "UPDATE online_invoice_ids_v1 SET binding=(SELECT binding "
                "FROM online_invoice_ids_v1 ORDER BY rowid LIMIT 1)"
            )
        if damage == "mismatched_digest":
            unrelated = base64.b64encode(b"a" * 32).decode()
            db.execute(
                "UPDATE online_invoice_ids_v1 SET invoice_hash=? WHERE rowid=1", (unrelated,)
            )
        if damage == "missing_document":
            db.execute("DELETE FROM offline_invoices_v1")
        if damage == "missing_verifier":
            db.execute("DELETE FROM online_archive_key_v1")
    with SQLiteOnlineInvoiceStore.open(path, key=KEY) as store:
        worker = invoices.online(store, namespace="company")
        lookup = "second" if damage == "swap" else LOCAL_ID
        with pytest.raises(KsefDocumentValidationError):
            worker.status(lookup)
        with pytest.raises(KsefDocumentValidationError):
            worker.enqueue(lookup, b"<different/>" if damage == "swap" else XML)


def test_two_stores_compete_for_the_same_invoice_and_recover_open(tmp_path, monkeypatch):
    # Time is mocked only for the opening lease. The subsequent POST is fenced by revision.
    path = tmp_path / "online.db"
    server = Server()
    owner = Invoices(cast(Ksef, server))
    now = [10_000.0]
    monkeypatch.setattr("ksef_client._offline_invoice_store.time.time", lambda: now[0])
    with (
        SQLiteOnlineInvoiceStore.open(path, key=KEY) as first_store,
        SQLiteOnlineInvoiceStore.open(path, key=KEY) as second_store,
    ):
        first = owner.online(first_store, namespace="company")
        second = owner.online(second_store, namespace="company")
        first.enqueue(LOCAL_ID, XML)
        server.lose_open = True
        with pytest.raises(OSError, match="lost open"):
            first.advance(LOCAL_ID)
        assert second.advance(LOCAL_ID).status is Status.QUEUED
        assert server.open_count == 1
        now[0] += 61
        server.lose_open = False
        assert second.advance(LOCAL_ID).status is Status.SESSION_OPEN
        assert server.open_count == 2
        resume = server.resume_session

        def race(state):
            server.resume_session = resume  # type: ignore[method-assign]
            with pytest.raises(OSError, match="lost send"):
                second.advance(LOCAL_ID)
            return resume(state)

        server.resume_session = race  # type: ignore[method-assign]
        with pytest.raises(KsefSyncConflictError):
            first.advance(LOCAL_ID)
        uncertain = first.status(LOCAL_ID)
        assert uncertain is not None and uncertain.status is Status.SUBMISSION_UNKNOWN
        assert server.send_count == 1
