from types import SimpleNamespace

import pytest

from ksef_client._invoice_export_state import ExportCheckpoint
from ksef_client.invoice_export_sync import InvoiceExportSync
from ksef_client.invoice_xml_storage import FileInvoiceXmlStore
from ksef_client.invoice_xml_types import InvoiceXmlKey
from ksef_client.operations import OperationState
from ksef_client.sqlite_store import SQLiteInvoiceSyncStore
from tests.test_invoice_export_package import END, HASH, START, XML, package
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
