import asyncio
from types import SimpleNamespace

import pytest

from ksef_client._invoice_export_state import ExportCheckpoint
from ksef_client.invoice_export_sync import AsyncInvoiceExportSync, InvoiceExportSync
from ksef_client.invoice_xml_storage import AsyncFileInvoiceXmlStore, FileInvoiceXmlStore
from ksef_client.invoice_xml_types import InvoiceXmlKey
from ksef_client.operations import ExportOperationError, OperationState
from ksef_client.sqlite_store import AsyncSQLiteInvoiceSyncStore, SQLiteInvoiceSyncStore
from tests.test_invoice_export_package import END, HASH, LAST, START, XML, package
from tests.test_invoice_xml_sync import NUMBER, NUMBER2

KEY = b"k" * 32


class Export:
    def __init__(self, owner, state):
        self.owner, self.state = owner, state

    def resume_state(self):
        return self.state

    def download_to(self, destination, **kwargs):
        self.owner.downloads += 1
        destination.mkdir()
        return package(destination)

    def wait(self, **kwargs):
        raise AssertionError("A verified local package must remain usable after export expiry")


class Client:
    environment = "a" * 64
    context_key = "Nip:test"

    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.downloads = 0
        self.requests = []
        self.exports = SimpleNamespace(start=self.start)

    def start(self, filters, **kwargs):
        self.requests.append(filters)
        return Export(self, OperationState("export", self.environment, self.context_key, "op-1"))


def test_resume_partial_import_without_transfer_or_early_hwm(tmp_path, monkeypatch):
    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", Export)
    client = Client(package(tmp_path).package)
    arguments = dict(
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    sync = InvoiceExportSync(client, **arguments)
    database = tmp_path / "archive.db"
    with FileInvoiceXmlStore(tmp_path / "xml") as storage:
        options = dict(enqueue_xml=True, xml_storage_id=storage.storage_id)
        with SQLiteInvoiceSyncStore.open(database, **options) as store:
            first = sync.run_once(store, storage, until=END, max_documents=1)
            assert first.status == "importing" and first.imported == first.inserted == 1
            assert first.committed_hwm is None
            checkpoint = store._load_export(sync.scope)
            assert checkpoint is not None
            assert ExportCheckpoint.decode(checkpoint[1], KEY).inserted == 1
        sync = InvoiceExportSync(client, **arguments)
        with SQLiteInvoiceSyncStore.open(database, **options) as store:
            second = sync.run_once(store, storage, until=END)
            assert second.status == "committed" and second.committed_hwm == END
            assert second.imported == 1 and second.inserted == 2
            rows = store.list_xml([sync.scope])
            assert {r["ksef_number"] for r in rows} == {NUMBER, NUMBER2}
            for row in rows:
                key = InvoiceXmlKey(
                    "company", client.environment, client.context_key, row["ksef_number"]
                )
                assert row["status"] == "ready"
                assert storage.read(key, HASH) == XML
            assert sync.run_once(store, storage, until=END).status == "idle"
    assert client.downloads == 1 and len(client.requests) == 1
    assert client.requests[0].subject_type.value == "Subject2"
    assert client.requests[0].date_range.restrict_to_permanent_storage_hwm_date is True


def test_wrong_checkpoint_key_stops_before_remote_operations(tmp_path, monkeypatch):
    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", Export)
    client = Client(package(tmp_path).package)
    arguments = dict(
        namespace="company", sync_key="history", since=START, work_dir=tmp_path / "work"
    )
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "archive.db", enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as store,
    ):
        InvoiceExportSync(client, state_key=KEY, **arguments).run_once(
            store, storage, until=END, max_documents=1
        )
        with pytest.raises(ValueError, match="unreadable export checkpoint"):
            InvoiceExportSync(client, state_key=b"x" * 32, **arguments).run_once(
                store, storage, until=END
            )
        assert client.downloads == 1 and len(client.requests) == 1


def test_async_import_resumes_the_same_archive_and_checkpoint_as_sync(tmp_path, monkeypatch):
    class AsyncExport(Export):
        async def download_to(self, destination, **kwargs):
            return super().download_to(destination, **kwargs)

        async def wait(self, **kwargs):
            return super().wait(**kwargs)

    class AsyncClient(Client):
        async def start(self, filters, **kwargs):
            export = super().start(filters, **kwargs)
            return AsyncExport(self, export.state)

    monkeypatch.setattr("ksef_client.invoice_export_sync.AsyncExportOperation", AsyncExport)
    args = dict(
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    descriptor = package(tmp_path).package
    db = tmp_path / "archive.db"
    folder = tmp_path / "xml"

    async def import_first():
        async with (
            await AsyncFileInvoiceXmlStore.open(folder) as storage,
            await AsyncSQLiteInvoiceSyncStore.open(
                db, enqueue_xml=True, xml_storage_id=storage.storage_id
            ) as store,
        ):
            sync = AsyncInvoiceExportSync(async_client, **args)
            result = await sync.run_once(store, storage, until=END, max_documents=1)
            assert result.status == "importing" and result.committed_hwm is None

    async_client = AsyncClient(descriptor)
    asyncio.run(import_first())
    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", Export)
    client = Client(descriptor)
    with (
        FileInvoiceXmlStore(folder) as storage,
        SQLiteInvoiceSyncStore.open(
            db, enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as store,
    ):
        sync = InvoiceExportSync(client, **args)
        result = sync.run_once(store, storage, until=END)
        assert result.status == "committed" and result.committed_hwm == END
        assert len(store.list_xml([sync.scope])) == 2
    assert async_client.downloads == 1 and client.downloads == 0


def test_expired_export_and_overlapping_truncated_fragments_keep_committed_hwm(tmp_path):
    class Fragments(Client):
        def start(self, filters, **kwargs):
            self.requests.append(filters)
            sequence = len(self.requests)
            state = OperationState("export", self.environment, self.context_key, f"op-{sequence}")
            return Fragment(self, state)

    class Fragment(Export):
        def download_to(self, destination, **kwargs):
            if self.state.reference_number == "op-1":
                result = SimpleNamespace(status=SimpleNamespace(code=210))
                raise ExportOperationError("rejected", self.state, result)
            destination.mkdir()
            if self.state.reference_number == "op-2":
                return package(destination, truncated=True, numbers=(NUMBER,))
            return package(destination, truncated=self.state.reference_number == "op-3")

    client = Fragments(package(tmp_path).package)
    sync = InvoiceExportSync(
        client,
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "archive.db", enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as store,
    ):
        expired = sync.run_once(store, storage, until=END)
        assert expired.status == "expired" and expired.committed_hwm is None
        for _ in range(2):
            result = sync.run_once(store, storage, until=END)
            assert result.status == "truncated" and result.continuation == LAST
            assert result.committed_hwm is None and result.inserted == 1
        complete = sync.run_once(store, storage, until=END)
        assert complete.status == "committed" and complete.committed_hwm == END
        assert complete.inserted == 0 and len(store.list_xml([sync.scope])) == 2
    assert [query.date_range.from_ for query in client.requests] == [START, START, LAST, LAST]
