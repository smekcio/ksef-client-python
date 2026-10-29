from __future__ import annotations

import asyncio
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from ksef_client import (
    FileInvoiceXmlStore,
    KsefSyncStoreError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
)
from ksef_client._sqlite_metadata import MetadataSQLiteStore
from tests.test_invoice_xml_sync import HASH, XML, call, environment


def test_closed_cleanup_cannot_remove_a_file_from_current_directory(tmp_path, monkeypatch):
    root, cwd = tmp_path / "storage", tmp_path / "working"
    cwd.mkdir()
    storage = FileInvoiceXmlStore(root)
    name = ".tmp-" + "c" * 32
    (root / name).write_bytes(b"stale")
    os.utime(root / name, (0, 0))
    (cwd / name).write_bytes(b"must remain untouched")
    storage.close()
    monkeypatch.chdir(cwd)
    with pytest.raises(KsefXmlStorageError):
        storage.cleanup_staging()
    assert (cwd / name).read_bytes() == b"must remain untouched"
    assert (root / name).read_bytes() == b"stale"


def test_failed_rollback_of_lease_conflict_is_a_store_failure(tmp_path, monkeypatch):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            claim = store.claim_xml(sync.xml.scopes, lease_seconds=120)
            receipt = storage.put_verified(claim.key, XML, HASH)
            store.fence_workers()
            original = store._execute

            def fail(sql, parameters=()):
                if sql == "ROLLBACK":
                    raise sqlite3.OperationalError("rollback unavailable")
                return original(sql, parameters)

            monkeypatch.setattr(store, "_execute", fail)
            with pytest.raises(KsefSyncStoreError) as caught:
                store.finish_xml(claim, receipt)
            assert caught.value.failure_scope == "store"
            assert caught.value.commit_outcome == "unknown"

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_validation_time_is_included_in_combined_budget(tmp_path, monkeypatch, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            original = store.validate_xml

            def slow_sync(*args):
                original(*args)
                time.sleep(0.03)

            async def slow_async(*args):
                await original(*args)
                await asyncio.sleep(0.03)

            def unexpected(*args, **kwargs):
                raise AssertionError("Metadata phase started after the total budget expired")

            monkeypatch.setattr(store, "validate_xml", slow_async if asynchronous else slow_sync)
            monkeypatch.setattr(sync.metadata, "run_once", unexpected)
            report = await call(sync.run_once, store, storage, time_budget=0.001)
            assert not report.metadata_complete and not report.complete
            assert report.xml.stop_reason == "time_budget" and server.downloads == 0

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_unrepresentable_retry_after_blocks_the_document(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            await call(sync.metadata.run_once, store)
            server.reply = lambda request: httpx.Response(
                429,
                stream=httpx.ByteStream(b"{}"),
                headers={"Retry-After": "9" * 400},
            )
            report = await call(sync.xml.run_once, store, storage, raise_on_error=False)
            assert report.blocked == 1 and report.claims == 1
            records = await call(store.list_xml, sync.xml.scopes)
            assert records[0]["last_reason"] == "invalid_retry_after"

    asyncio.run(run())


def test_migration_preserves_error_when_begin_never_started():
    class Connection(sqlite3.Connection):
        armed = False

        def executescript(self, sql):
            if self.armed and "BEGIN IMMEDIATE" in sql:
                raise sqlite3.OperationalError("original busy error")
            return super().executescript(sql)

    connection = sqlite3.connect(":memory:", factory=Connection)
    assert isinstance(connection, Connection)
    try:
        MetadataSQLiteStore(connection)
        connection.armed = True
        with pytest.raises(sqlite3.OperationalError, match="original busy error"):
            SQLiteInvoiceSyncStore.migrate_legacy_example(connection, xml_storage_id="files")
        assert not connection.in_transaction
    finally:
        connection.close()


def test_close_waits_for_publication_in_the_same_instance(tmp_path, monkeypatch):
    storage = FileInvoiceXmlStore(tmp_path)
    original = storage._open
    writing, release, closing = threading.Event(), threading.Event(), threading.Event()

    class Writer:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def write(self, data):
            writing.set()
            assert release.wait(10)
            return self.stream.write(data)

        def flush(self):
            return self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

        def __exit__(self, *exc):
            return self.stream.__exit__(*exc)

    def open_file(name, *, create=False):
        stream = original(name, create=create)
        return Writer(stream) if create else stream

    monkeypatch.setattr(storage, "_open", open_file)
    from ksef_client import InvoiceXmlKey
    from tests.test_invoice_xml_sync import NUMBER

    key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)

    def close():
        closing.set()
        storage.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        publication = pool.submit(storage.put_verified, key, XML, HASH)
        assert writing.wait(10)
        shutdown = pool.submit(close)
        assert closing.wait(10) and not shutdown.done()
        release.set()
        receipt = publication.result(timeout=10)
        shutdown.result(timeout=10)
    assert (tmp_path / receipt.object_key).read_bytes() == XML


def test_interrupted_queue_with_failed_rollback_preserves_interrupt(tmp_path, monkeypatch):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            claim = store.claim_xml(sync.xml.scopes, lease_seconds=120)
            receipt = storage.put_verified(claim.key, XML, HASH)
            original = store._execute

            def fail(sql, parameters=()):
                if sql.startswith("UPDATE invoice_xml_documents"):
                    raise KeyboardInterrupt
                if sql == "ROLLBACK":
                    raise sqlite3.OperationalError("rollback unavailable")
                return original(sql, parameters)

            monkeypatch.setattr(store, "_execute", fail)
            with pytest.raises(KeyboardInterrupt):
                store.finish_xml(claim, receipt)

    asyncio.run(run())


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory descriptors; Windows pins directories")
def test_cleanup_scans_the_open_directory_after_a_path_is_replaced(tmp_path):
    root, moved = tmp_path / "original", tmp_path / "moved"
    with FileInvoiceXmlStore(root) as storage:
        name = ".tmp-" + "d" * 32
        (root / name).write_bytes(b"fresh owned staging")
        root.rename(moved)
        root.mkdir()
        (root / name).write_bytes(b"old decoy outside the opened directory")
        os.utime(root / name, (0, 0))
        assert storage.cleanup_staging() == 0
        assert (moved / name).read_bytes() == b"fresh owned staging"
        assert (root / name).exists()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_cached_read_supports_the_same_size_controls_in_both_modes(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, _):
            await call(sync.metadata.run_once, store)
            claim = await call(store.claim_xml, sync.xml.scopes, lease_seconds=120)
            await call(storage.put_verified, claim.key, XML, HASH)
            assert await call(storage.read, claim.key, HASH, max_bytes=len(XML)) == XML
            with pytest.raises(KsefXmlStorageError):
                await call(storage.read, claim.key, HASH, max_bytes=1)

    asyncio.run(run())
