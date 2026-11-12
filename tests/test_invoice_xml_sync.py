from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import replace

import httpx
import pytest

from ksef_client import (
    AsyncFileInvoiceXmlStore,
    AsyncSQLiteInvoiceSyncStore,
    FileInvoiceXmlStore,
    InvoiceXmlKey,
    KsefSyncStoreError,
    KsefXmlIntegrityError,
    KsefXmlLeaseLostError,
    KsefXmlRunError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
)
from ksef_client._sqlite_metadata import MetadataSQLiteStore
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.invoice_xml_types import hash_bytes
from tests.test_invoice_sync import H1, START, Server, make_sync, row

NUMBER = "5555555555-20250828-010080615740-E4"
NUMBER2 = "5265877635-20250925-010020A0A242-0A"
XML = b'<?xml version="1.0"?><invoice>unaltered\r\n bytes</invoice>'
HASH = base64.b64encode(hashlib.sha256(XML).digest()).decode()


class XmlServer(Server):
    def __init__(self, rows=None):
        super().__init__([row(NUMBER, hash_=HASH)] if rows is None else rows)
        self.downloads = 0
        self.reply = lambda request: httpx.Response(
            200, stream=httpx.ByteStream(XML), headers={"x-ms-meta-hash": HASH}
        )

    def handle(self, request):
        if request.method == "GET":
            self.downloads += 1
            assert request.headers["accept-encoding"] == "identity"
            return self.reply(request)
        return super().handle(request)


async def call(function, *args, **kwargs):
    value = function(*args, **kwargs)
    return await value if inspect.isawaitable(value) else value


@asynccontextmanager
async def environment(tmp_path, asynchronous, server=None, **xml_options):
    server = server or XmlServer()
    metadata, http = make_sync(server, asynchronous=asynchronous)
    api = (AsyncInvoicesClient if asynchronous else InvoicesClient)(http)
    sync = api.sync_documents(
        namespace="tenant",
        sync_key="job",
        context_key="Nip:test",
        since=START,
        subject_types=("Subject1",),
        page_size=10,
        xml_options=xml_options,
    )
    storage = (
        await AsyncFileInvoiceXmlStore.open(tmp_path / "xml")
        if asynchronous
        else FileInvoiceXmlStore(tmp_path / "xml")
    )
    store = await call(
        (AsyncSQLiteInvoiceSyncStore if asynchronous else SQLiteInvoiceSyncStore).open,
        tmp_path / "db.sqlite",
        enqueue_xml=True,
        xml_storage_id=storage.storage_id,
    )
    try:
        yield sync, store, storage, server
    finally:
        await call(store.close)
        await call(storage.close)
        await call(http.aclose if asynchronous else http.close)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_complete_replay_and_raw_bytes(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            report = await call(sync.run_once, store, storage)
            assert report.complete and report.metadata_complete
            assert report.xml.ready == report.xml.observed == report.xml.downloaded == 1
            assert report.xml.downloaded_bytes == len(XML)
            assert HASH not in repr(report)
            assert XML.decode() not in json.dumps(report.to_dict())
            key = InvoiceXmlKey("tenant", sync.xml.scopes[0].environment, "Nip:test", NUMBER)
            assert await call(storage.read, key, HASH) == XML
            assert (await call(sync.describe, store)).complete
            report = await call(sync.run_once, store, storage)
            assert report.complete and report.xml.downloaded == 0 and server.downloads == 1
            rows = await call(store.list_xml, sync.xml.scopes, limit=1)
            assert rows[0]["status"] == "ready" and rows[0]["attempts"] == 1

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_published_file_without_ack_recovers_without_http(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            await call(sync.metadata.run_once, store)
            claim = await call(store.claim_xml, sync.xml.scopes, lease_seconds=120)
            receipt = await call(storage.put_verified, claim.key, XML, HASH)
            # Simulate process death after publication; another process reclaims the lease.
            await call(store.fence_workers)
            with pytest.raises(KsefXmlLeaseLostError):
                await call(store.finish_xml, claim, receipt)
            report = await call(sync.xml.run_once, store, storage)
            assert report.ready == report.recovered == 1 and server.downloads == 0

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "status,code,expected",
    [
        (400, 21165, "retry_wait"),
        (400, 21164, "blocked"),
        (403, None, "blocked"),
        (401, None, "retry_wait"),
        (429, None, "retry_wait"),
        (500, None, "retry_wait"),
        (502, None, "retry_wait"),
        (503, None, "retry_wait"),
        (504, None, "retry_wait"),
        (400, 21405, "blocked"),
    ],
)
def test_durable_error_classification(tmp_path, asynchronous, status, code, expected):
    async def run():
        server = XmlServer()

        def reply(request):
            body = {"exception": {"exceptionDetailList": [{"exceptionCode": code}]}} if code else {}
            return httpx.Response(
                status,
                stream=httpx.ByteStream(json.dumps(body).encode()),
                headers={"Retry-After": "86400", "Content-Type": "application/json"},
            )

        server.reply = reply
        async with environment(tmp_path, asynchronous, server) as (sync, store, storage, _):
            report = await call(sync.run_once, store, storage, raise_on_error=False)
            assert not report.complete
            rows = await call(store.list_xml, sync.xml.scopes)
            assert rows[0]["status"] == expected
            assert report.xml.errors == 1
            assert report.xml.claims == 1
            if status == 429:
                import time

                assert rows[0]["next_attempt_at"] >= time.time() + 86390
            if status == 401:
                assert report.xml.stop_reason == "authentication"
            if expected == "blocked":
                with pytest.raises(KsefXmlRunError):
                    await call(sync.xml.run_once, store, storage)
            if status in (429, 400) and code != 21164 and code != 21405:
                assert rows[0]["failures"] == 0

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("header,body", [("invalid", XML), (HASH, b"wrong"), (None, XML)])
def test_hashes_and_missing_header(tmp_path, asynchronous, header, body):
    async def run():
        server = XmlServer()
        server.reply = lambda request: httpx.Response(
            200, stream=httpx.ByteStream(body), headers={"x-ms-meta-hash": header} if header else {}
        )
        async with environment(tmp_path, asynchronous, server) as (sync, store, storage, _):
            report = await call(sync.run_once, store, storage, raise_on_error=False)
            assert report.complete == (header is None)
            assert report.xml.blocked == (header is not None)

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_size_limit_and_network_exhaustion(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous, max_xml_bytes=5, max_failures=1) as (
            sync,
            store,
            storage,
            server,
        ):
            report = await call(sync.run_once, store, storage, raise_on_error=False)
            assert report.xml.blocked == 1
            assert (await call(store.list_xml, sync.xml.scopes))[0][
                "last_reason"
            ] == "response_size_limit"
            await call(store.retry_blocked, sync.xml.scopes, reason="Raised document size limit")
            sync.xml.max_xml_bytes = 16 * 1024 * 1024

            def disconnect(request):
                raise httpx.ReadError("credential-bearing-transport-error")

            server.reply = disconnect
            report = await call(sync.xml.run_once, store, storage, raise_on_error=False)
            assert report.blocked == 1
            assert (await call(store.list_xml, sync.xml.scopes))[0][
                "last_reason"
            ] == "retry_exhausted"
            assert "credential-bearing" not in str(report.to_dict())

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_verify_missing_and_corrupt_ready(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            assert (await call(sync.run_once, store, storage)).complete
            await call(store.verify_ready, sync.xml.scopes, storage)
            path = next((tmp_path / "xml").glob("*.xml"))
            path.unlink()
            await call(store.verify_ready, sync.xml.scopes, storage)
            assert (await call(sync.describe, store)).xml.pending == 1
            await call(store.verify_ready, sync.xml.scopes, storage)
            assert (await call(sync.xml.run_once, store, storage)).ready == 1
            path.write_bytes(b"corrupted")
            await call(store.verify_ready, sync.xml.scopes, storage)
            assert (await call(sync.describe, store)).xml.blocked == 1
            assert server.downloads == 2

    asyncio.run(run())


def test_fencing_receipts_and_storage_identity(tmp_path):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, server):
            sync.metadata.run_once(store)
            old = store.claim_xml(sync.xml.scopes, lease_seconds=120)
            store.connection.execute("UPDATE invoice_xml_documents SET lease_until=0")
            store.connection.commit()
            new = store.claim_xml(sync.xml.scopes, lease_seconds=120)
            receipt = storage.put_verified(new.key, XML, HASH)
            assert new.fencing > old.fencing and new.token != old.token
            with pytest.raises(KsefXmlLeaseLostError):
                store.finish_xml(old, receipt)
            with pytest.raises(KsefXmlLeaseLostError):
                store.defer_xml(old, reason="network_error", delay=5)
            with pytest.raises(KsefXmlIntegrityError):
                store.finish_xml(new, replace(receipt, size=-1))
            store.finish_xml(new, receipt)
            with pytest.raises(KsefXmlLeaseLostError):
                store.finish_xml(new, receipt)
            other = FileInvoiceXmlStore(tmp_path / "other")
            try:
                with pytest.raises(KsefXmlStorageError):
                    sync.xml.run_once(store, other)
                assert server.downloads == 0
            finally:
                other.close()

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_explicit_history_backfill_keeps_metadata_checkpoint(tmp_path, asynchronous):
    async def run():
        server = XmlServer([row(NUMBER, hash_=HASH), row(NUMBER2, hash_=HASH)])
        metadata, http = make_sync(server, asynchronous=asynchronous)
        store_cls = AsyncSQLiteInvoiceSyncStore if asynchronous else SQLiteInvoiceSyncStore
        old = await call(store_cls.open, tmp_path / "history.db")
        try:
            await call(metadata.run_once, old)
            cp = await call(old.load, metadata.streams[0].scope)
        finally:
            await call(old.close)
        storage = (
            await AsyncFileInvoiceXmlStore.open(tmp_path / "files")
            if asynchronous
            else FileInvoiceXmlStore(tmp_path / "files")
        )
        store = await call(
            store_cls.open,
            tmp_path / "history.db",
            enqueue_xml=True,
            xml_storage_id=storage.storage_id,
        )
        try:
            scopes = [metadata.streams[0].scope]
            assert (await call(store.describe_xml, scopes)).not_enqueued == 2
            report = await call(store.backfill_xml, scopes, batch_size=1)
            assert report.complete and report.processed == 2
            assert await call(store.load, scopes[0]) == cp
            assert (await call(store.backfill_xml, scopes)).processed == 0
            assert (await call(store.describe_xml, scopes)).pending == 2
        finally:
            await call(store.close)
            await call(storage.close)
            await call(http.aclose if asynchronous else http.close)

    asyncio.run(run())


def test_explicit_legacy_migration(tmp_path):
    connection = sqlite3.connect(tmp_path / "old.db")
    old = MetadataSQLiteStore(connection, enqueue_xml=True)
    metadata, http = make_sync(XmlServer())
    try:
        metadata.run_once(old)
        original = old.load(metadata.streams[0].scope)
        with pytest.raises(KsefXmlStorageError, match="XML"):
            SQLiteInvoiceSyncStore(connection)
        SQLiteInvoiceSyncStore.migrate_legacy_example(connection, xml_storage_id="files")
        SQLiteInvoiceSyncStore.migrate_legacy_example(connection, xml_storage_id="files")
        store = SQLiteInvoiceSyncStore(connection, enqueue_xml=True, xml_storage_id="files")
        assert store.load(metadata.streams[0].scope) == original
        assert store.backfill_xml([metadata.streams[0].scope]).complete
        assert connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1
        assert store.describe_xml([metadata.streams[0].scope]).pending == 1
    finally:
        connection.close()
        http.close()


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize(
    "statement", ["INSERT INTO invoice_xml_documents", "INSERT INTO sync_checkpoints", "COMMIT"]
)
def test_atomic_metadata_enqueue_faults(tmp_path, after, statement):
    class FaultStore(SQLiteInvoiceSyncStore):
        armed = False

        def _execute(self, sql, parameters=()):
            hit = self.armed and sql.startswith(statement)
            if hit:
                self.armed = False
            if hit and not after:
                raise sqlite3.OperationalError("private-db-details")
            result = super()._execute(sql, parameters)
            if hit:
                raise sqlite3.OperationalError("private-db-details")
            return result

    store = FaultStore.open(tmp_path / "db", enqueue_xml=True, xml_storage_id="files")
    assert isinstance(store, FaultStore)
    metadata, http = make_sync(XmlServer(), since="2025-01-01T00:00:00Z")
    try:
        stream = metadata.streams[0]
        first = stream.begin_cycle(None, until=H1)
        cp = first.confirm(store.commit(first))
        page = stream.next_batch(cp)
        # A page updates an existing checkpoint; use that operation for this case.
        armed_statement = statement.replace(
            "INSERT INTO sync_checkpoints", "UPDATE sync_checkpoints"
        )
        statement = armed_statement
        store.armed = True
        with pytest.raises(KsefSyncStoreError):
            store.commit(page)
        persisted = after and statement == "COMMIT"
        assert store.load(stream.scope) == (page.next_checkpoint if persisted else cp)
        assert store.connection.execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == int(
            persisted
        )
        assert store.connection.execute("SELECT COUNT(*) FROM invoice_xml_documents").fetchone()[
            0
        ] == int(persisted)
    finally:
        store.close()
        http.close()


@pytest.mark.parametrize("encoded", ["bad", "=" * 44, base64.b64encode(b"x" * 31).decode(), 4])
def test_invalid_hash_inputs(encoded):
    with pytest.raises(KsefXmlIntegrityError):
        hash_bytes(encoded)


def test_file_store_never_overwrites_corrupt_existing_object(tmp_path):
    with FileInvoiceXmlStore(tmp_path) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        receipt = storage.put_verified(key, XML, HASH)
        assert storage.put_verified(key, XML, HASH) == receipt
        path = tmp_path / receipt.object_key
        path.write_bytes(b"broken")
        with pytest.raises(KsefXmlIntegrityError):
            storage.put_verified(key, XML, HASH)
        assert path.read_bytes() == b"broken"
        with pytest.raises(KsefXmlStorageError):
            storage.read(key, HASH, max_bytes=1)


def test_unknown_schema_and_wrong_binding_are_rejected(tmp_path):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE invoices(value TEXT)")
    with pytest.raises(KsefXmlStorageError):
        SQLiteInvoiceSyncStore.migrate_legacy_example(conn, xml_storage_id="files")
    conn.close()
    with SQLiteInvoiceSyncStore.open(tmp_path / "db", enqueue_xml=True, xml_storage_id="one"):
        pass
    with pytest.raises(KsefXmlStorageError):
        SQLiteInvoiceSyncStore.open(tmp_path / "db", enqueue_xml=True, xml_storage_id="two")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_empty_selection_complete_and_work_limit(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous, XmlServer([])) as (sync, store, storage, _):
            assert (await call(sync.run_once, store, storage)).complete
            with pytest.raises(ValueError):
                await call(sync.xml.run_once, store, storage, max_documents=True)

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_roles_and_sync_keys_share_one_document_and_download(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (first, store, storage, server):
            assert (await call(first.run_once, store, storage)).complete
            other = first.xml.client.sync_documents(
                namespace="tenant",
                sync_key="another-job",
                context_key="Nip:test",
                since=START,
                subject_types=("Subject1", "Subject2"),
                page_size=10,
            )
            report = await call(other.run_once, store, storage)
            assert report.complete and len(report.metadata.streams) == 2
            assert report.xml.observed == report.xml.ready == 1
            assert report.xml.downloaded == 0 and server.downloads == 1

    asyncio.run(run())
