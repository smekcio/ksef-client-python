from __future__ import annotations

import asyncio
import errno
import gc
import json
import os
import sqlite3
import subprocess
import sys
import time
import weakref
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from tools import verify_e2e_results as gate

from ksef_client import (
    ErrorCode,
    FileInvoiceXmlStore,
    InvoiceXmlKey,
    KsefSyncRunError,
    KsefXmlIntegrityError,
    KsefXmlRunError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
)
from ksef_client._sqlite_metadata import MetadataSQLiteStore
from ksef_client.exceptions import KsefHttpError
from ksef_client.invoice_xml_sync import _failure
from ksef_client.rate_limiting import KsefRateLimitWaitTimeout
from tests.test_invoice_sync import row
from tests.test_invoice_xml_sync import HASH, NUMBER, NUMBER2, XML, XmlServer, call, environment


def test_required_live_manifest_matches_approved_release_gate():
    assert gate.required_tests() == gate.REQUIRED
    assert (
        "tests/test_e2e_invoice_xml_sync.py::test_e2e_test_environment_invoice_xml_restart"
        in gate.REQUIRED
    )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_poisoned_document_does_not_starve_other_documents(tmp_path, asynchronous):
    async def run():
        bad_number = "not-a-ksef-number"
        server = XmlServer(
            [row(bad_number, hash_=HASH), row(NUMBER, hash_=HASH), row(NUMBER2, hash_=HASH)]
        )
        async with environment(tmp_path, asynchronous, server) as (sync, store, storage, _):
            await call(sync.metadata.run_once, store)
            scope = sync.xml.scopes[0]
            key = InvoiceXmlKey(scope.namespace, scope.environment, scope.context_key, NUMBER)
            (tmp_path / "xml" / key.object_key(HASH)).mkdir()
            report = await call(sync.xml.run_once, store, storage, raise_on_error=False)
            assert report.ready == 1 and report.blocked == 2 and server.downloads == 1
            assert dict(report.reason_counts).get("invalid_ksef_number") == 1
            assert sum(dict(report.reason_counts).values()) == 2
            assert report.to_dict()["reason_counts"] == report.reason_counts
            again = await call(sync.xml.run_once, store, storage, raise_on_error=False)
            assert again.claims == 0 and again.blocked == 2

    asyncio.run(run())


@pytest.mark.parametrize("corruption", ["number", "alias", "hash"])
def test_corrupt_persisted_number_is_quarantined_during_claim(tmp_path, corruption):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            store.connection.execute("PRAGMA foreign_keys=OFF")
            if corruption == "hash":
                store.connection.execute("UPDATE invoice_xml_documents SET expected_hash='invalid'")
            else:
                number = "bad" if corruption == "number" else NUMBER[:26] + "-" + NUMBER[26:]
                store.connection.execute(
                    "UPDATE invoice_xml_documents SET ksef_number=?", (number,)
                )
                store.connection.execute("UPDATE invoice_observations SET ksef_number=?", (number,))
            store.connection.commit()
            assert store.claim_xml(sync.xml.scopes) is None
            reason = "invalid_hash" if corruption == "hash" else "invalid_ksef_number"
            assert store.connection.execute(
                "SELECT status,last_reason FROM invoice_xml_documents"
            ).fetchone() == ("blocked", reason)

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_snapshot_contract_checked_before_download(tmp_path, monkeypatch, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            await call(sync.metadata.run_once, store)
            snapshot = await call(store.describe_xml, sync.xml.scopes)

            def broken(*args):
                return replace(snapshot, checkpoints=())

            async def broken_async(*args):
                return broken(*args)

            monkeypatch.setattr(store, "describe_xml", broken_async if asynchronous else broken)
            with pytest.raises(KsefXmlStorageError, match="invalid_report_checkpoints"):
                await call(sync.xml.run_once, store, storage)
            assert server.downloads == 0

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_early_budget_exit_still_raises_for_blocked_documents(tmp_path, monkeypatch, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, _):
            await call(sync.metadata.run_once, store)
            claim = await call(store.claim_xml, sync.xml.scopes)
            await call(store.defer_xml, claim, reason="forbidden", delay=1, blocked=True)
            original = store.validate_xml

            def slow(*args):
                original(*args)
                time.sleep(0.02)

            async def slow_async(*args):
                await original(*args)
                await asyncio.sleep(0.02)

            monkeypatch.setattr(store, "validate_xml", slow_async if asynchronous else slow)
            with pytest.raises(KsefXmlRunError) as caught:
                await call(sync.run_once, store, storage, time_budget=0.001)
            assert isinstance(caught.value, KsefSyncRunError)
            assert caught.value.xml_report.blocked == caught.value.report.xml.blocked == 1
            assert caught.value.code == ErrorCode.SYNC_RUN_FAILED

    asyncio.run(run())


def test_sqlite_row_factory_and_explicit_metadata_only_migration(tmp_path):
    async def run():
        connection = sqlite3.connect(tmp_path / "legacy")
        try:
            MetadataSQLiteStore(connection)
            connection.execute("CREATE TABLE application_data(value TEXT)")
            with pytest.raises(KsefXmlStorageError, match="explicitly migrate"):
                SQLiteInvoiceSyncStore(connection)
            SQLiteInvoiceSyncStore.migrate_legacy_example(connection)
            with FileInvoiceXmlStore(tmp_path / "other-xml") as files:
                store = SQLiteInvoiceSyncStore(
                    connection, enqueue_xml=True, xml_storage_id=files.storage_id
                )
                connection.row_factory = sqlite3.Row
                async with environment(tmp_path, False) as (sync, _, __, ___):
                    assert sync.run_once(store, files).complete
                    assert (
                        connection.execute(
                            "SELECT name FROM sqlite_master WHERE name='application_data'"
                        ).fetchone()[0]
                        == "application_data"
                    )
        finally:
            connection.close()

    asyncio.run(run())


@pytest.mark.parametrize("status", [408, 409, 425, 503, 507, 520, 522, 524])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_retry_wait_is_due_only_after_cooldown_and_exhausts_cycles(tmp_path, status, asynchronous):
    async def run():
        server = XmlServer()
        server.reply = lambda request: httpx.Response(
            status, stream=httpx.ByteStream(b"{}"), headers={"Retry-After": "300"}
        )
        async with environment(tmp_path, asynchronous, server, max_failures=3) as (
            sync,
            store,
            storage,
            _,
        ):
            await call(sync.metadata.run_once, store)
            for cycle in range(1, 4):
                report = await call(sync.xml.run_once, store, storage, raise_on_error=False)
                record = (await call(store.list_xml, sync.xml.scopes))[0]
                assert record["failures"] == cycle
                assert record["status"] == ("blocked" if cycle == 3 else "retry_wait")
                assert record["next_attempt_at"] >= time.time() + 290
                idle = await call(sync.xml.run_once, store, storage, raise_on_error=False)
                assert idle.claims == 0
                if cycle < 3:

                    def expire():
                        underlying = store._store if asynchronous else store
                        underlying.connection.execute(
                            "UPDATE invoice_xml_documents SET next_attempt_at=0"
                        )
                        underlying.connection.commit()

                    if asynchronous:
                        await asyncio.get_running_loop().run_in_executor(store._executor, expire)
                    else:
                        expire()
            assert report.blocked == 1 and server.downloads == 3

    asyncio.run(run())


def test_inspect_preserves_control_timeout(tmp_path, monkeypatch):
    import ksef_client.invoice_xml_storage as files

    with FileInvoiceXmlStore(tmp_path) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        storage.put_verified(key, XML, HASH)

        def timeout():
            raise KsefRateLimitWaitTimeout("deadline")

        monkeypatch.setattr(files, "check_control", timeout)
        with pytest.raises(KsefRateLimitWaitTimeout):
            storage.inspect(key, HASH)


def test_cleanup_finds_candidates_after_many_published_entries(tmp_path, monkeypatch):
    import ksef_client.invoice_xml_storage as files

    with FileInvoiceXmlStore(tmp_path) as storage:
        for index in range(1001):
            (tmp_path / f"{index}.xml").write_bytes(b"keep")
        temporary = tmp_path / (".tmp-" + "e" * 32)
        temporary.write_bytes(b"stale")
        os.utime(temporary, (0, 0))
        entries = sorted(os.scandir(tmp_path), key=lambda entry: entry.name.startswith(".tmp-"))

        class Scan:
            def __enter__(self):
                return iter(entries)

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(files.os, "scandir", lambda path: Scan())
        assert storage.cleanup_staging(max_entries=1) == 1
        assert not temporary.exists() and (tmp_path / "1000.xml").exists()


def test_read_and_publication_loser_do_not_trust_existing_bytes(tmp_path):
    with FileInvoiceXmlStore(tmp_path) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        receipt = storage.put_verified(key, XML, HASH)
        temporary = ".tmp-" + "f" * 32
        with storage._open(temporary, create=True) as output:
            output.write(b"different bytes must not overwrite")
        storage._publish(temporary, receipt.object_key)
        storage._unlink(temporary)
        assert storage.read(key, HASH) == XML
        with pytest.raises(KsefXmlIntegrityError):
            replace(receipt, sha256_base64="A" * 43 + "=").validate(key, HASH, storage.storage_id)
        (tmp_path / receipt.object_key).write_bytes(XML[:10])
        with pytest.raises(KsefXmlIntegrityError):
            storage.read(key, HASH)


def test_abandoned_storage_releases_real_os_resources(tmp_path):
    folder = tmp_path / "private"
    storage = FileInvoiceXmlStore(folder)
    reference = weakref.ref(storage)
    descriptor = storage._dir_fd
    if os.name == "nt":
        with pytest.raises(OSError):
            folder.rename(tmp_path / "renamed")
    del storage
    gc.collect()
    assert reference() is None
    if descriptor is not None:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF
    folder.rename(tmp_path / "renamed")


def test_base_package_import_does_not_require_sqlite_extension():
    root = Path(__file__).resolve().parents[1]
    program = """
import builtins
original = builtins.__import__
def restricted(name, *args, **kwargs):
    if name in {'sqlite3', '_sqlite3'}:
        raise ModuleNotFoundError('sqlite unavailable', name=name)
    return original(name, *args, **kwargs)
builtins.__import__ = restricted
import ksef_client
assert ksef_client.Ksef
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        env={**os.environ, "PYTHONPATH": str(root / "src")},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_queue_probes_use_due_indexes_without_materializing_observation_history(tmp_path):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            query, parameters = store._claim_query(sync.xml.scopes, time.time())
            plan = " ".join(
                str(row[-1])
                for row in store.connection.execute("EXPLAIN QUERY PLAN " + query, parameters)
            )
            assert "xml_claim_due" in plan and "xml_claim_expired" in plan
            assert "MATERIALIZE selected" not in plan and "CO-ROUTINE selected" not in plan
            assert store.claim_xml(sync.xml.scopes) is not None

    asyncio.run(run())


def test_canonical_identity_deduplicates_aliases_and_legacy_migration(tmp_path):
    alias = NUMBER[:26] + "-" + NUMBER[26:]
    canonical = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
    assert InvoiceXmlKey("tenant", "0" * 64, "ctx", alias) == canonical

    async def run():
        async with environment(tmp_path, False) as (sync, _, storage, server):
            connection = sqlite3.connect(tmp_path / "old-db")
            try:
                old = MetadataSQLiteStore(connection, enqueue_xml=True)
                server.rows = [row(alias, hash_=HASH), row(NUMBER, hash_=HASH)]
                sync.metadata.run_once(old)
                assert connection.execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == 2
                SQLiteInvoiceSyncStore.migrate_legacy_example(
                    connection, xml_storage_id=storage.storage_id
                )
                store = SQLiteInvoiceSyncStore(
                    connection, enqueue_xml=True, xml_storage_id=storage.storage_id
                )
                store.backfill_xml(sync.xml.scopes)
                report = sync.xml.run_once(store, storage)
                assert report.observed == report.ready == report.downloaded == 1
                assert (
                    connection.execute("SELECT ksef_number FROM invoices").fetchone()[0] == NUMBER
                )
            finally:
                connection.close()

    asyncio.run(run())


def test_v1_schema_upgrade_preserves_download_obligation_and_is_repeatable(tmp_path):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            connection = store.connection
            connection.execute("DROP INDEX xml_claim_due")
            connection.execute("DROP INDEX xml_claim_expired")
            connection.execute("UPDATE xml_store_meta SET version=1")
            connection.commit()
            with pytest.raises(KsefXmlStorageError, match="schema_migration_required"):
                SQLiteInvoiceSyncStore(connection)
            SQLiteInvoiceSyncStore.migrate_schema(connection)
            SQLiteInvoiceSyncStore.migrate_schema(connection)
            assert sync.xml.run_once(store, storage).ready == 1
            assert connection.execute("SELECT version FROM xml_store_meta").fetchone()[0] == 2
            connection.execute("BEGIN")
            with pytest.raises(ValueError):
                SQLiteInvoiceSyncStore.migrate_schema(connection)
            connection.rollback()

    asyncio.run(run())


def test_retry_after_for_unavailable_and_jitter_bounds(tmp_path, monkeypatch):
    async def run():
        server = XmlServer()
        server.reply = lambda request: httpx.Response(
            400,
            stream=httpx.ByteStream(
                json.dumps(
                    {"exception": {"exceptionDetailList": [{"exceptionCode": 21165}]}}
                ).encode()
            ),
            headers={"Retry-After": "86400", "Content-Type": "application/json"},
        )
        async with environment(tmp_path, False, server) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            assert sync.xml.run_once(store, storage).retry_wait == 1
            assert store.list_xml(sync.xml.scopes)[0]["next_attempt_at"] >= time.time() + 86390
            store.connection.execute("UPDATE invoice_xml_documents SET next_attempt_at=0")
            store.connection.commit()
            claim = store.claim_xml(sync.xml.scopes)
            error = KsefHttpError(503, "unavailable")
            monkeypatch.setattr("ksef_client.invoice_xml_sync.random.uniform", lambda a, b: a)
            low = _failure(error, claim, 12)["delay"]
            monkeypatch.setattr("ksef_client.invoice_xml_sync.random.uniform", lambda a, b: b)
            high = _failure(error, claim, 12)["delay"]
            assert low < high and high / low == pytest.approx(1.5)

    asyncio.run(run())


def test_permission_failure_is_local_but_io_failure_stops_the_store(tmp_path, monkeypatch):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            original = storage._open

            def unreadable(*args, **kwargs):
                raise PermissionError("untrusted path must not escape")

            monkeypatch.setattr(storage, "_open", unreadable)
            report = sync.xml.run_once(store, storage, raise_on_error=False)
            assert report.blocked == 1 and report.reason_counts == (
                ("stored_object_unreadable", 1),
            )
            store.retry_blocked(sync.xml.scopes, reason="permissions_fixed")

            def broken_disk(*args, **kwargs):
                raise OSError(errno.EIO, "private path")

            monkeypatch.setattr(storage, "_open", broken_disk)
            with pytest.raises(KsefXmlStorageError, match="storage_read_failed"):
                sync.xml.run_once(store, storage, raise_on_error=False)
            assert store.describe_xml(sync.xml.scopes).leased == 1
            monkeypatch.setattr(storage, "_open", original)

    asyncio.run(run())


def test_async_cancel_during_committed_claim_retains_work_and_close_is_repeatable(
    tmp_path, monkeypatch
):
    async def run():
        async with environment(tmp_path, True) as (sync, store, storage, _):
            await sync.metadata.run_once(store)
            original = store.claim_xml
            committed, release = asyncio.Event(), asyncio.Event()

            async def paused(*args, **kwargs):
                result = await original(*args, **kwargs)
                committed.set()
                await release.wait()
                return result

            monkeypatch.setattr(store, "claim_xml", paused)
            task = asyncio.create_task(sync.xml.run_once(store, storage))
            await asyncio.wait_for(committed.wait(), 10)
            task.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            report = await store.describe_xml(sync.xml.scopes)
            assert report.leased == report.observed == 1
            await store.fence_workers()
            monkeypatch.setattr(store, "claim_xml", original)
            assert (await sync.xml.run_once(store, storage)).ready == 1
            await store.close()
            await store.close()
            with pytest.raises(KsefXmlStorageError, match="store_closed"):
                await store.describe_xml(sync.xml.scopes)

    asyncio.run(run())
