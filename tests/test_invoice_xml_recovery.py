from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from ksef_client import (
    CancellationToken,
    FileInvoiceXmlStore,
    InvoiceXmlKey,
    KsefRequestCancelledError,
    KsefSyncStoreError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
)
from tests.test_invoice_sync import make_sync
from tests.test_invoice_xml_sync import HASH, NUMBER, XML, XmlServer, call, environment


def test_fresh_process_restart_and_two_contenders(tmp_path):
    metadata, http = make_sync(XmlServer())
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "db", enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as store,
    ):
        metadata.run_once(store)
        scope = metadata.streams[0].scope
        storage.put_verified(
            InvoiceXmlKey(scope.namespace, scope.environment, scope.context_key, NUMBER),
            XML,
            HASH,
        )
        command = [
            sys.executable,
            "-I",
            str(Path(__file__).with_name("invoice_xml_worker.py")),
            str(tmp_path / "db"),
            str(tmp_path / "xml"),
        ]
        crashed = subprocess.run([*command, "crash"], capture_output=True, timeout=30)
        assert crashed.returncode == 71, crashed.stderr.decode()
        assert store.describe_xml([scope]).leased == 1
        store.fence_workers()
        children = [
            subprocess.Popen([*command, "recover"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(2)
        ]
        try:
            results = []
            for child in children:
                output, error = child.communicate(timeout=30)
                assert child.returncode == 0, error.decode()
                results.append(json.loads(output))
            assert sum(result["claimed"] for result in results) == 1
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()
        assert store.describe_xml([scope]).ready == 1
        assert store.list_xml([scope])[0]["attempts"] == 2
    http.close()


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("sql_prefix", ["UPDATE invoice_xml_documents", "COMMIT"])
def test_finish_fault_cannot_lose_published_document(tmp_path, after, sql_prefix):
    class FaultStore(SQLiteInvoiceSyncStore):
        armed = False

        def _execute(self, sql, parameters=()):
            hit = self.armed and sql.startswith(sql_prefix)
            if hit:
                self.armed = False
            if hit and not after:
                raise sqlite3.OperationalError("database-private-details")
            result = super()._execute(sql, parameters)
            if hit:
                raise sqlite3.OperationalError("database-private-details")
            return result

    async def run():
        async with environment(tmp_path, False) as (sync, old, storage, server):
            sync.metadata.run_once(old)
            claim = old.claim_xml(sync.xml.scopes, lease_seconds=120)
            receipt = storage.put_verified(claim.key, XML, HASH)
            store = FaultStore(old.connection, enqueue_xml=True, xml_storage_id=storage.storage_id)
            store.armed = True
            with pytest.raises(KsefSyncStoreError):
                store.finish_xml(claim, receipt)
            store.fence_workers()
            report = sync.xml.run_once(store, storage)
            assert report.ready == 1 and server.downloads == 0
            assert report.recovered == (not (after and sql_prefix == "COMMIT"))

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_cancel_after_claim_retains_task(tmp_path, asynchronous):
    async def run():
        cancel = CancellationToken()
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            await call(sync.metadata.run_once, store)
            original = server.reply

            def cancelling(request):
                cancel.cancel()
                return original(request)

            server.reply = cancelling
            with pytest.raises(KsefRequestCancelledError):
                await call(sync.xml.run_once, store, storage, cancellation=cancel)
            report = await call(store.describe_xml, sync.xml.scopes)
            assert report.ready == 0 and report.retry_wait == 1

    asyncio.run(run())


def test_no_clobber_and_symlink_paths(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks requires a platform privilege")
    with pytest.raises(KsefXmlStorageError):
        FileInvoiceXmlStore(link)
    with FileInvoiceXmlStore(outside) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        target = outside / key.object_key(HASH)
        secret = tmp_path / "secret"
        secret.write_bytes(XML)
        target.symlink_to(secret)
        with pytest.raises(KsefXmlStorageError):
            storage.inspect(key, HASH)
        assert secret.read_bytes() == XML


def test_staging_cleanup_preserves_documents(tmp_path):
    with FileInvoiceXmlStore(tmp_path) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        receipt = storage.put_verified(key, XML, HASH)
        stale = tmp_path / (".tmp-" + "a" * 32)
        stale.write_bytes(b"partial")
        os.utime(stale, (0, 0))
        assert storage.cleanup_staging() == 1
        assert storage.read(key, HASH) == XML
        assert (tmp_path / receipt.object_key).exists()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_interrupted_xml_body_never_publishes_partial_document(tmp_path, asynchronous):
    class BrokenStream(httpx.SyncByteStream, httpx.AsyncByteStream):
        closed = False

        def __iter__(self):
            yield XML[:10]
            raise httpx.ReadError("interrupted private response")

        async def __aiter__(self):
            yield XML[:10]
            raise httpx.ReadError("interrupted private response")

        def close(self):
            self.closed = True

        async def aclose(self):
            self.closed = True

    async def run():
        async with environment(tmp_path, asynchronous, max_failures=1) as (
            sync,
            store,
            storage,
            server,
        ):
            original = server.reply
            stream = BrokenStream()
            server.reply = lambda request: httpx.Response(200, stream=stream)
            report = await call(sync.run_once, store, storage, raise_on_error=False)
            assert report.xml.ready == 0 and report.xml.blocked == 1 and stream.closed
            assert not list((tmp_path / "xml").glob("*.xml"))
            server.reply = original
            await call(store.retry_blocked, sync.xml.scopes, reason="Connection repaired")
            assert (await call(sync.xml.run_once, store, storage)).ready == 1

    asyncio.run(run())


def test_partial_disk_write_preserves_queue_obligation(tmp_path, monkeypatch):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, server):
            original = storage._open

            class PartialWriter:
                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    self.stream.__enter__()
                    return self

                def write(self, data):
                    self.stream.write(data[: len(data) // 2])
                    raise OSError("Disk became unavailable")

                def __exit__(self, *exc):
                    return self.stream.__exit__(*exc)

            def fail_write(name, *, create=False):
                stream = original(name, create=create)
                return PartialWriter(stream) if create else stream

            monkeypatch.setattr(storage, "_open", fail_write)
            with pytest.raises(KsefXmlStorageError):
                sync.run_once(store, storage)
            assert store.describe_xml(sync.xml.scopes).leased == 1
            assert not list((tmp_path / "xml").glob("*.xml"))
            assert not list((tmp_path / "xml").glob(".tmp-*"))
            monkeypatch.setattr(storage, "_open", original)
            store.fence_workers()
            assert sync.xml.run_once(store, storage).ready == 1
            assert server.downloads == 2

    asyncio.run(run())
