import asyncio
import json
import os
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

from ksef_client import AsyncKsef, Ksef, KsefClientOptions
from ksef_client._invoice_export_state import ExportCheckpoint
from ksef_client.client import AsyncAuthenticatedClient, AuthenticatedClient
from ksef_client.clients.invoices import InvoicesClient
from ksef_client.exceptions import KsefDocumentValidationError, KsefSyncDataConflictError
from ksef_client.invoice_export_sync import (
    AsyncInvoiceExportSync,
    InvoiceExportSync,
    _local_files,
    _private_workspace,
)
from ksef_client.invoice_xml_storage import AsyncFileInvoiceXmlStore, FileInvoiceXmlStore
from ksef_client.invoice_xml_types import InvoiceXmlKey, KsefXmlIntegrityError, KsefXmlStorageError
from ksef_client.operations import ExportOperationError, OperationState
from ksef_client.sqlite_store import AsyncSQLiteInvoiceSyncStore, SQLiteInvoiceSyncStore
from tests.test_invoice_export_package import END, HASH, LAST, START, XML, package
from tests.test_invoice_sync import make_sync, row
from tests.test_invoice_xml_sync import NUMBER, NUMBER2, XmlServer

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
    sync = InvoiceExportSync(cast(Ksef, client), **arguments)
    database = tmp_path / "archive.db"
    with FileInvoiceXmlStore(tmp_path / "xml") as storage:
        options = dict(enqueue_xml=True, xml_storage_id=storage.storage_id)
        with SQLiteInvoiceSyncStore.open(database, **options) as store:
            first = sync.run_once(store, storage, until=END, max_documents=1)
            assert first.status == "importing" and first.imported == first.inserted == 1
            assert first.committed_hwm is None
            checkpoint = store._load_export(sync.scope, KEY)
            assert checkpoint is not None
            assert ExportCheckpoint.decode(checkpoint[1], KEY).inserted == 1
        sync = InvoiceExportSync(cast(Ksef, client), **arguments)
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
        InvoiceExportSync(cast(Ksef, client), state_key=KEY, **arguments).run_once(
            store, storage, until=END, max_documents=1
        )
        with pytest.raises(ValueError, match="unreadable export checkpoint"):
            InvoiceExportSync(cast(Ksef, client), state_key=b"x" * 32, **arguments).run_once(
                store, storage, until=END
            )
        assert client.downloads == 1 and len(client.requests) == 1


@pytest.mark.parametrize("finish_async", [False, True])
def test_async_import_resumes_the_same_archive_and_checkpoint_as_sync(
    tmp_path, monkeypatch, finish_async
):
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
            sync = AsyncInvoiceExportSync(cast(AsyncKsef, async_client), **args)
            result = await sync.run_once(store, storage, until=END, max_documents=1)
            assert result.status == "importing" and result.committed_hwm is None
            if finish_async:
                with pytest.raises(ValueError, match="shorten"):
                    await sync.run_once(store, storage, until=LAST)
                result = await sync.run_once(store, storage, until=END)
                assert result.status == "committed" and result.committed_hwm == END
                assert len(await store.list_xml([sync.scope])) == 2
                assert (await sync.run_once(store, storage, until=END)).status == "idle"

    async_client = AsyncClient(descriptor)
    asyncio.run(import_first())
    if finish_async:
        assert async_client.downloads == 1
        return
    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", Export)
    client = Client(descriptor)
    with (
        FileInvoiceXmlStore(folder) as storage,
        SQLiteInvoiceSyncStore.open(
            db, enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as store,
    ):
        sync = InvoiceExportSync(cast(Ksef, client), **args)
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
        cast(Ksef, client),
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


@pytest.mark.parametrize(
    "code,expected", [(210, "expired"), (420, "waiting_hwm"), (550, "retry_later"), (500, None)]
)
@pytest.mark.parametrize("asynchronous", [False, True])
def test_export_operation_failure_keeps_checkpoint(tmp_path, code, expected, asynchronous):
    def failure(state):
        return ExportOperationError(
            "rejected", state, SimpleNamespace(status=SimpleNamespace(code=code))
        )

    class Failure(Export):
        def download_to(self, destination, **kwargs):
            raise failure(self.state)

    class AsyncFailure(Export):
        async def download_to(self, destination, **kwargs):
            raise failure(self.state)

    class FailingClient(Client):
        def start(self, filters, **kwargs):
            return Failure(self, super().start(filters, **kwargs).state)

    class AsyncFailingClient(Client):
        async def start(self, filters, **kwargs):
            return AsyncFailure(self, super().start(filters, **kwargs).state)

    args = dict(
        namespace="test", sync_key="history", since=START, work_dir=tmp_path / "work", state_key=KEY
    )
    descriptor = package(tmp_path).package
    client = AsyncFailingClient(descriptor) if asynchronous else FailingClient(descriptor)

    async def run_async():
        async with (
            await AsyncFileInvoiceXmlStore.open(tmp_path / "xml") as storage,
            await AsyncSQLiteInvoiceSyncStore.open(
                tmp_path / "db", enqueue_xml=True, xml_storage_id=storage.storage_id
            ) as store,
        ):
            return await AsyncInvoiceExportSync(cast(AsyncKsef, client), **args).run_once(
                store, storage, until=END
            )

    def run_sync():
        with (
            FileInvoiceXmlStore(tmp_path / "xml") as storage,
            SQLiteInvoiceSyncStore.open(
                tmp_path / "db", enqueue_xml=True, xml_storage_id=storage.storage_id
            ) as store,
        ):
            return InvoiceExportSync(cast(Ksef, client), **args).run_once(store, storage, until=END)

    def run():
        return asyncio.run(run_async()) if asynchronous else run_sync()

    if expected is None:
        with pytest.raises(ExportOperationError):
            run()
    else:
        report = run()
        assert report.status == expected and report.committed_hwm is None
        if code == 550:
            assert run().status == "retry_later"
            assert len(client.requests) == 2
            assert client.requests[0] == client.requests[1]


@pytest.mark.parametrize("corrupt", ["metadata", "offset", "shorter-window", "different-start"])
def test_rejects_changed_state_or_package_before_advancing_hwm(tmp_path, monkeypatch, corrupt):
    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", Export)
    client = Client(package(tmp_path).package)
    args = dict(
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    sync = InvoiceExportSync(cast(Ksef, client), **args)
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "db", enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as store,
    ):
        sync.run_once(store, storage, until=END, max_documents=1)
        end = END
        if corrupt == "metadata":
            path = next((tmp_path / "work").glob("*/*/documents/_metadata.json"))
            raw = json.loads(path.read_bytes())
            raw["invoices"][0]["grossAmount"] = 10
            path.write_text(json.dumps(raw), encoding="utf-8")
        elif corrupt == "offset":
            saved = store._load_export(sync.scope, KEY)
            assert saved is not None
            revision, raw = saved
            state = replace(ExportCheckpoint.decode(raw, KEY), offset=3)
            store._commit_export(
                sync.scope, revision, state.encode(KEY), KEY, storage_id=storage.storage_id
            )
        elif corrupt == "shorter-window":
            end = LAST
        else:
            sync = InvoiceExportSync(cast(Ksef, client), **dict(args, since=LAST))
        if corrupt == "metadata":
            report = sync.run_once(store, storage, until=end)
            assert report.status == "retrying_package" and report.committed_hwm is None
            assert len(store.list_xml([sync.scope])) == 1
            assert sync.run_once(store, storage, until=end).committed_hwm == END
            assert client.downloads == 2 and len(client.requests) == 1
        else:
            with pytest.raises(ValueError):
                sync.run_once(store, storage, until=end)
            assert len(store.list_xml([sync.scope])) == 1


def test_export_rejects_invalid_configuration_and_local_descriptor(tmp_path, monkeypatch):
    descriptor = package(tmp_path).package
    args = dict(
        namespace="company", sync_key="history", since=START, work_dir=tmp_path, state_key=KEY
    )
    for override in (
        {"state_key": b"bad"},
        {"subject_type": "Subject2"},
        {"compression_type": "Zip"},
    ):
        with pytest.raises((ValueError, TypeError)):
            InvoiceExportSync(cast(Ksef, Client(descriptor)), **dict(args, **override))
    with pytest.raises(KsefDocumentValidationError, match="no package"):
        _local_files(tmp_path, None)
    monkeypatch.setattr("ksef_client.invoice_export_sync.EXPORT_MAX_ARCHIVE_ENTRIES", 1)
    with pytest.raises(KsefDocumentValidationError, match="too many files"):
        _local_files(tmp_path, descriptor)


@pytest.mark.skipif(os.name != "posix", reason="POSIX workspace permissions")
def test_public_export_workspace_is_rejected(tmp_path):
    folder = tmp_path / "public"
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    with pytest.raises(ValueError, match="must be private"):
        _private_workspace(folder)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_resume_published_package_before_descriptor_was_saved(tmp_path, monkeypatch, asynchronous):
    class InterruptedExport(Export):
        def download_to(self, destination, **kwargs):
            super().download_to(destination, **kwargs)
            raise InterruptedError("stopped after publication")

        def wait(self, **kwargs):
            return SimpleNamespace(package=self.owner.descriptor)

    class AsyncInterruptedExport(InterruptedExport):
        async def download_to(self, destination, **kwargs):
            return super().download_to(destination, **kwargs)

        async def wait(self, **kwargs):
            return super().wait(**kwargs)

    class InterruptedClient(Client):
        def start(self, filters, **kwargs):
            return InterruptedExport(self, super().start(filters, **kwargs).resume_state())

    class AsyncInterruptedClient(Client):
        async def start(self, filters, **kwargs):
            return AsyncInterruptedExport(self, super().start(filters, **kwargs).resume_state())

    options = dict(
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    descriptor = package(tmp_path).package
    if asynchronous:
        monkeypatch.setattr(
            "ksef_client.invoice_export_sync.AsyncExportOperation", AsyncInterruptedExport
        )
        client = AsyncInterruptedClient(descriptor)

        async def run():
            sync = AsyncInvoiceExportSync(cast(AsyncKsef, client), **options)
            async with (
                await AsyncFileInvoiceXmlStore.open(tmp_path / "xml") as xml,
                await AsyncSQLiteInvoiceSyncStore.open(
                    tmp_path / "db", enqueue_xml=True, xml_storage_id=xml.storage_id
                ) as store,
            ):
                with pytest.raises(InterruptedError):
                    await sync.run_once(store, xml, until=END)
                return await sync.run_once(store, xml, until=END)

        result = asyncio.run(run())
    else:
        monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", InterruptedExport)
        sync_client = InterruptedClient(descriptor)
        sync = InvoiceExportSync(cast(Ksef, sync_client), **options)
        with (
            FileInvoiceXmlStore(tmp_path / "xml") as xml,
            SQLiteInvoiceSyncStore.open(
                tmp_path / "db", enqueue_xml=True, xml_storage_id=xml.storage_id
            ) as store,
        ):
            with pytest.raises(InterruptedError):
                sync.run_once(store, xml, until=END)
            result = sync.run_once(store, xml, until=END)
    assert result.status == "committed" and result.committed_hwm == END
    completed_client = client if asynchronous else sync_client
    assert completed_client.downloads == len(completed_client.requests) == 1


def test_checkpoint_authentication_covers_scope_revision_and_payload(tmp_path):
    client = Client(package(tmp_path).package)
    sync = InvoiceExportSync(
        cast(Ksef, client),
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as xml,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "db", enqueue_xml=True, xml_storage_id=xml.storage_id
        ) as store,
    ):
        sync.run_once(store, xml, until=END)
        saved = store._load_export(sync.scope, KEY)
        assert saved is not None
        revision, raw = saved
        assert ExportCheckpoint.decode(raw, KEY).progress.committed_hwm == END
        other = replace(sync.scope, sync_key="other")
        with store.connection:
            store._execute("UPDATE invoice_export_progress SET sync_key='other'")
        with pytest.raises(KsefDocumentValidationError, match="unreadable export checkpoint"):
            store._load_export(other, KEY)
        with store.connection:
            store._execute(
                "UPDATE invoice_export_progress SET sync_key='history', revision=?", (revision + 1,)
            )
        with pytest.raises(KsefDocumentValidationError, match="unreadable export checkpoint"):
            store._load_export(sync.scope, KEY)
        blob = store._execute("SELECT state FROM invoice_export_progress").fetchone()[0]
        modified = blob[:32] + raw.replace(END.encode(), LAST.encode())
        assert modified != blob
        with store.connection:
            store._execute(
                "UPDATE invoice_export_progress SET revision=?,state=?", (revision, modified)
            )
        with pytest.raises(KsefDocumentValidationError, match="unreadable export checkpoint"):
            sync.run_once(store, xml, until=END)


def test_public_export_factories_bind_the_same_stream(tmp_path):
    options = KsefClientOptions(base_url="https://example.test/v2")
    client = Ksef(
        cast(AuthenticatedClient, None), options, context_type="Nip", context_value="test"
    )
    async_client = AsyncKsef(
        cast(AsyncAuthenticatedClient, None), options, context_type="Nip", context_value="test"
    )
    arguments = dict(
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    assert client.exports.sync_archive(**arguments).scope == (
        async_client.exports.sync_archive(**arguments).scope
    )


def test_export_matches_metadata_download_archive_for_same_corpus(tmp_path):
    numbers = (NUMBER, NUMBER2)
    server = XmlServer([row(number, date=LAST, hash_=HASH) for number in numbers])
    server.hwm = END
    server.reply = lambda request: httpx.Response(
        200, stream=httpx.ByteStream(XML), headers={"x-ms-meta-hash": HASH}
    )
    _, http = make_sync(server, since=START, subject_types=("Subject2",))
    metadata = InvoicesClient(http).sync_documents(
        namespace="company",
        sync_key="history",
        context_key="Nip:test",
        since=START,
        subject_types=("Subject2",),
    )
    export_client = Client(package(tmp_path).package)
    export = InvoiceExportSync(
        cast(Ksef, export_client),
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )

    try:
        with (
            FileInvoiceXmlStore(tmp_path / "metadata-xml") as xml,
            SQLiteInvoiceSyncStore.open(
                tmp_path / "metadata.db", enqueue_xml=True, xml_storage_id=xml.storage_id
            ) as store,
        ):
            assert metadata.run_once(store, xml).complete
            meta_scope = metadata.xml.scopes[0]
            metadata_archive = {
                entry["ksef_number"]: xml.read(
                    InvoiceXmlKey(
                        meta_scope.namespace,
                        meta_scope.environment,
                        meta_scope.context_key,
                        entry["ksef_number"],
                    ),
                    HASH,
                )
                for entry in store.list_xml([meta_scope])
            }
    finally:
        http.close()

    with (
        FileInvoiceXmlStore(tmp_path / "export-xml") as xml,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "export.db", enqueue_xml=True, xml_storage_id=xml.storage_id
        ) as store,
    ):
        assert export.run_once(store, xml, until=END).committed_hwm == END
        export_archive = {
            entry["ksef_number"]: xml.read(
                InvoiceXmlKey(
                    export.scope.namespace,
                    export.scope.environment,
                    export.scope.context_key,
                    entry["ksef_number"],
                ),
                HASH,
            )
            for entry in store.list_xml([export.scope])
        }

    assert export_archive == metadata_archive == dict.fromkeys(numbers, XML)
    assert len(server.calls) == 1 and server.downloads == len(numbers)
    assert len(export_client.requests) == export_client.downloads == 1


def test_export_requires_bound_storage_and_rolls_back_failed_receipt(tmp_path):
    client = Client(package(tmp_path).package)
    export = InvoiceExportSync(
        cast(Ksef, client),
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    with FileInvoiceXmlStore(tmp_path / "xml") as xml:
        with (
            SQLiteInvoiceSyncStore.open(tmp_path / "disabled.db") as store,
            pytest.raises(KsefXmlStorageError),
        ):
            export.run_once(store, xml, until=END)
        with SQLiteInvoiceSyncStore.open(
            tmp_path / "enabled.db", enqueue_xml=True, xml_storage_id=xml.storage_id
        ) as store:
            with pytest.raises(KsefXmlStorageError):
                store.validate_xml((export.scope,), "different-storage")
            with store.connection:
                store._execute(
                    "CREATE TEMP TRIGGER discard_ready BEFORE UPDATE OF status "
                    "ON invoice_xml_documents BEGIN SELECT RAISE(IGNORE); END"
                )
            with pytest.raises(KsefSyncDataConflictError):
                export.run_once(store, xml, until=END)
            saved = store._load_export(export.scope, KEY)
            assert saved is not None
            checkpoint = ExportCheckpoint.decode(saved[1], KEY)
            assert checkpoint.offset == 0 and checkpoint.progress.committed_hwm is None
            assert store._load_export(replace(export.scope, sync_key="other"), KEY) is None


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("damage", ["xml", "metadata", "fresh-xml", "fresh-metadata"])
def test_export_rebuilds_only_the_damaged_cache(tmp_path, monkeypatch, asynchronous, damage):
    class CachedExport(Export):
        def download_to(self, destination, **kwargs):
            files = super().download_to(destination, **kwargs)
            if self.owner.downloads == 1:
                if damage == "fresh-xml":
                    (destination / f"{NUMBER}.xml").write_bytes(b"<damaged/>")
                if damage == "fresh-metadata":
                    (destination / "_metadata.json").write_bytes(b"invalid JSON")
            return files

        def wait(self, **kwargs):
            return SimpleNamespace(package=self.owner.descriptor)

    class AsyncCachedExport(CachedExport):
        async def download_to(self, destination, **kwargs):
            return super().download_to(destination, **kwargs)

        async def wait(self, **kwargs):
            return super().wait(**kwargs)

    class CachedClient(Client):
        def start(self, filters, **kwargs):
            return CachedExport(self, super().start(filters, **kwargs).resume_state())

    class AsyncCachedClient(Client):
        async def start(self, filters, **kwargs):
            return AsyncCachedExport(self, super().start(filters, **kwargs).resume_state())

    options = dict(
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    descriptor = package(tmp_path).package

    async def invoke(call, *args, **kwargs):
        value = call(*args, **kwargs)
        return await value if asyncio.iscoroutine(value) else value

    async def exercise(sync, store, storage, client):
        if damage.startswith("fresh-"):
            error = KsefXmlIntegrityError if damage == "fresh-xml" else KsefDocumentValidationError
            with pytest.raises(error):
                await invoke(sync.run_once, store, storage, until=END)
        else:
            first = await invoke(sync.run_once, store, storage, until=END, max_documents=1)
            assert first.status == "importing"
            cached = next((tmp_path / "work").glob("*/*/documents"))
            if damage == "xml":
                (cached / f"{NUMBER2}.xml").write_bytes(b"<damaged/>")
            else:
                (cached / "_metadata.json").unlink()

        damaged = await invoke(sync.run_once, store, storage, until=END)
        assert damaged.status == "retrying_package" and damaged.committed_hwm is None
        repaired = await invoke(sync.run_once, store, storage, until=END)
        assert repaired.committed_hwm == END and repaired.inserted == 2
        assert client.downloads == 2 and len(client.requests) == 1

    if asynchronous:
        monkeypatch.setattr(
            "ksef_client.invoice_export_sync.AsyncExportOperation", AsyncCachedExport
        )

        async def run():
            client = AsyncCachedClient(descriptor)
            sync = AsyncInvoiceExportSync(cast(AsyncKsef, client), **options)
            async with (
                await AsyncFileInvoiceXmlStore.open(tmp_path / "xml") as storage,
                await AsyncSQLiteInvoiceSyncStore.open(
                    tmp_path / "db", enqueue_xml=True, xml_storage_id=storage.storage_id
                ) as store,
            ):
                await exercise(sync, store, storage, client)

        asyncio.run(run())
    else:
        monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", CachedExport)
        client = CachedClient(descriptor)
        sync = InvoiceExportSync(cast(Ksef, client), **options)
        with (
            FileInvoiceXmlStore(tmp_path / "xml") as storage,
            SQLiteInvoiceSyncStore.open(
                tmp_path / "db", enqueue_xml=True, xml_storage_id=storage.storage_id
            ) as store,
        ):
            asyncio.run(exercise(sync, store, storage, client))


def test_redownload_after_expiry_preserves_partial_import_at_same_boundary(tmp_path, monkeypatch):
    class Fragment(Export):
        def download_to(self, destination, **kwargs):
            if self.state.reference_number == "op-2" and self.owner.cancelled:
                raise ExportOperationError(
                    "rejected", self.state, SimpleNamespace(status=SimpleNamespace(code=550))
                )
            destination.mkdir()
            first = self.state.reference_number == "op-1"
            return package(
                destination,
                numbers=(NUMBER,) if first else (NUMBER2, NUMBER),
                truncated=self.state.reference_number != "op-4",
            )

    class Fragments(Client):
        cancelled = False

        def start(self, filters, **kwargs):
            self.requests.append(filters)
            state = OperationState(
                "export", self.environment, self.context_key, f"op-{len(self.requests)}"
            )
            return Fragment(self, state)

    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", Fragment)
    client = Fragments(package(tmp_path).package)
    sync = InvoiceExportSync(
        cast(Ksef, client),
        namespace="company",
        sync_key="history",
        since=START,
        work_dir=tmp_path / "work",
        state_key=KEY,
    )
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as xml,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "db", enqueue_xml=True, xml_storage_id=xml.storage_id
        ) as store,
    ):
        assert sync.run_once(store, xml, until=END).continuation == LAST
        assert sync.run_once(store, xml, until=END, max_documents=1).inserted == 1
        cached = next((tmp_path / "work").glob("*/*/documents"))
        (cached / f"{NUMBER}.xml").write_bytes(b"<damaged/>")
        assert sync.run_once(store, xml, until=END).status == "retrying_package"
        client.cancelled = True
        assert sync.run_once(store, xml, until=END).status == "retry_later"
        replayed = sync.run_once(store, xml, until=END)
        assert replayed.status == "truncated" and replayed.inserted == 0
        assert replayed.committed_hwm is None and replayed.continuation == LAST
        assert sync.run_once(store, xml, until=END).committed_hwm == END
        assert len(store.list_xml([sync.scope])) == 2
