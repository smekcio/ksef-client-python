from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ksef_client import (
    AsyncSQLiteInvoiceSyncStore,
    InvoiceSyncCheckpoint,
    KsefSyncConflictError,
    KsefSyncStoreError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
)
from ksef_client._sqlite_metadata import SCHEMA, MetadataSQLiteStore
from ksef_client.sqlite_store import XML_SCHEMA
from tests.test_invoice_sync import H1, Server, make_sync, row
from tests.test_invoice_xml_sync import HASH, NUMBER, XmlServer


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize(
    "statement", ["BEGIN IMMEDIATE", "SELECT d.namespace", "UPDATE invoice_xml_documents", "COMMIT"]
)
def test_claim_fault_rollback_or_durable_lease(tmp_path, after, statement):
    class FaultStore(SQLiteInvoiceSyncStore):
        armed = False

        def _execute(self, sql, parameters=()):
            hit = self.armed and statement in sql
            if hit:
                self.armed = False
            if hit and not after:
                raise sqlite3.OperationalError("private-db")
            result = super()._execute(sql, parameters)
            if hit:
                raise sqlite3.OperationalError("private-db")
            return result

    with FaultStore.open(tmp_path / "db", enqueue_xml=True, xml_storage_id="files") as store:
        assert isinstance(store, FaultStore)
        metadata, http = make_sync(XmlServer())
        try:
            metadata.run_once(store)
            store.armed = True
            with pytest.raises(KsefSyncStoreError):
                store.claim_xml([metadata.streams[0].scope], lease_seconds=120)
            persisted = after and statement == "COMMIT"
            report = store.describe_xml([metadata.streams[0].scope])
            assert report.leased == int(persisted)
            assert report.pending == int(not persisted)
        finally:
            http.close()


@pytest.mark.parametrize("interrupt", [False, True])
def test_metadata_rollback_failure_closes_connection(interrupt):
    class BrokenRollback(MetadataSQLiteStore):
        def _execute(self, sql, parameters=()):
            if sql.startswith("INSERT INTO sync_checkpoints"):
                raise KeyboardInterrupt if interrupt else sqlite3.OperationalError("private")
            if sql == "ROLLBACK":
                raise sqlite3.OperationalError("rollback unavailable")
            return super()._execute(sql, parameters)

    connection = sqlite3.connect(":memory:")
    store = BrokenRollback(connection)
    metadata, http = make_sync(Server())
    try:
        batch = metadata.streams[0].begin_cycle(None, until=H1)
        with pytest.raises(KeyboardInterrupt if interrupt else KsefSyncStoreError):
            store.commit(batch)
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
    finally:
        http.close()


def test_metadata_conflicting_revision_and_non_exception_interrupt(monkeypatch):
    metadata, http = make_sync(Server())
    connection = sqlite3.connect(":memory:")
    store = MetadataSQLiteStore(connection)
    try:
        first = metadata.streams[0].begin_cycle(None, until=H1)
        with pytest.raises(KsefSyncConflictError):
            store.commit(replace(first, expected_generation="old", expected_revision=1))
        data = first.next_checkpoint.to_dict()
        data["revision"] = 2
        with pytest.raises(KsefSyncConflictError):
            store.commit(replace(first, _checkpoint=InvoiceSyncCheckpoint.from_dict(data)))
        original = store._execute

        def interrupt(sql, parameters=()):
            if sql.startswith("INSERT INTO sync_checkpoints"):
                raise KeyboardInterrupt
            return original(sql, parameters)

        monkeypatch.setattr(store, "_execute", interrupt)
        with pytest.raises(KeyboardInterrupt):
            store.commit(first)
        assert not connection.in_transaction
    finally:
        connection.close()
        http.close()


def test_metadata_compare_and_swap_checks_update_rowcount(monkeypatch):
    metadata, http = make_sync(Server())
    connection = sqlite3.connect(":memory:")
    store = MetadataSQLiteStore(connection)
    try:
        stream = metadata.streams[0]
        begin = stream.begin_cycle(None, until=H1)
        cp = begin.confirm(store.commit(begin))
        page = stream.next_batch(cp)
        original = store._execute

        def no_match(sql, parameters=()):
            value = original(sql, parameters)
            return (
                SimpleNamespace(rowcount=0) if sql.startswith("UPDATE sync_checkpoints") else value
            )

        monkeypatch.setattr(store, "_execute", no_match)
        with pytest.raises(KsefSyncConflictError):
            store.commit(page)
        assert store.load(stream.scope) == cp
    finally:
        connection.close()
        http.close()


@pytest.mark.parametrize("legacy", [False, True])
def test_schema_creation_failures_roll_back(legacy):
    class Connection(sqlite3.Connection):
        fail = False

        def execute(self, sql, parameters=()):
            if self.fail and sql.startswith("INSERT INTO xml_store_meta"):
                raise sqlite3.OperationalError("schema write failed")
            return super().execute(sql, parameters)

    connection = sqlite3.connect(":memory:", factory=Connection)
    assert isinstance(connection, Connection)
    try:
        if legacy:
            MetadataSQLiteStore(connection)
        connection.fail = True
        with pytest.raises(sqlite3.OperationalError):
            if legacy:
                SQLiteInvoiceSyncStore.migrate_legacy_example(connection, xml_storage_id="files")
            else:
                SQLiteInvoiceSyncStore(connection)
        assert not connection.in_transaction
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='xml_store_meta'"
            ).fetchone()
            is None
        )
    finally:
        connection.close()


def test_binding_change_during_configuration_is_rejected():
    connection = sqlite3.connect(":memory:")
    try:
        SQLiteInvoiceSyncStore(connection)
        connection.executescript(
            "CREATE TRIGGER change_binding AFTER UPDATE OF storage_id "
            "ON xml_store_meta "
            "BEGIN UPDATE xml_store_meta SET storage_id='other'; END;"
        )
        with pytest.raises(KsefXmlStorageError):
            SQLiteInvoiceSyncStore(connection, enqueue_xml=True, xml_storage_id="files")
        assert connection.execute("SELECT storage_id FROM xml_store_meta").fetchone() == (None,)
    finally:
        connection.close()


def test_queue_rollback_failure_is_unknown_and_closes_connection(tmp_path):
    class BrokenRollback(SQLiteInvoiceSyncStore):
        armed = False

        def _execute(self, sql, parameters=()):
            if self.armed and ("SELECT d.namespace" in sql or sql == "ROLLBACK"):
                raise sqlite3.OperationalError("private")
            return super()._execute(sql, parameters)

    store = BrokenRollback.open(tmp_path / "db", enqueue_xml=True, xml_storage_id="files")
    assert isinstance(store, BrokenRollback)
    metadata, http = make_sync(Server([row(NUMBER, hash_=HASH)]))
    try:
        metadata.run_once(store)
        store.armed = True
        with pytest.raises(KsefSyncStoreError) as caught:
            store.claim_xml([metadata.streams[0].scope], lease_seconds=120)
        assert caught.value.commit_outcome == "unknown"
    finally:
        store.close()
        http.close()


def test_async_store_lifecycle_and_closed_guards(tmp_path):
    async def run():
        async with await AsyncSQLiteInvoiceSyncStore.open(tmp_path / "db") as store:
            assert store is not None
        with pytest.raises(KsefXmlStorageError):
            await store.describe_xml([])
        await store.close()

    asyncio.run(run())


@pytest.mark.parametrize("other", ["valid", "legacy", "version", "binding"])
def test_first_open_rechecks_schema_under_lock(other):
    class RacingConnection(sqlite3.Connection):
        lookups = 0

        def execute(self, sql, parameters=()):
            if sql == "SELECT name FROM sqlite_master WHERE type='table'":
                self.lookups += 1
                if self.lookups == 2:
                    # Model the competing initialization observed after acquiring
                    # the writer lock, using real SQLite DDL/constraints.
                    for statement in (SCHEMA + ("" if other == "legacy" else XML_SCHEMA)).split(
                        ";"
                    ):
                        if statement.strip():
                            super().execute(statement)
                    if other != "legacy":
                        super().execute(
                            "INSERT INTO xml_store_meta VALUES (1,?,?,?)",
                            (
                                99 if other == "version" else 2,
                                "epoch",
                                "bad" if other == "binding" else "files",
                            ),
                        )
            return super().execute(sql, parameters)

    connection = sqlite3.connect(":memory:", factory=RacingConnection)
    try:
        if other == "valid":
            store = SQLiteInvoiceSyncStore(connection, enqueue_xml=True, xml_storage_id="files")
            assert store.xml_storage_id == "files"
        else:
            with pytest.raises(KsefXmlStorageError):
                SQLiteInvoiceSyncStore(connection, enqueue_xml=True, xml_storage_id="files")
        assert not connection.in_transaction
    finally:
        connection.close()


def test_null_binding_and_full_legacy_shape_are_checked(tmp_path):
    metadata, http = make_sync(XmlServer())
    try:
        with SQLiteInvoiceSyncStore.open(
            tmp_path / "db", enqueue_xml=True, xml_storage_id="files"
        ) as store:
            metadata.run_once(store)
            scopes = [metadata.streams[0].scope]
            store.connection.execute("UPDATE xml_store_meta SET storage_id=NULL")
            store.connection.commit()
            with pytest.raises(KsefXmlStorageError):
                store.claim_xml(scopes, lease_seconds=120)
            for method, args, kwargs in (
                (store.backfill_xml, (scopes,), {"batch_size": 1001}),
                (store.retry_blocked, (scopes,), {"reason": "operator", "limit": 1001}),
                (
                    store.verify_ready,
                    (scopes, SimpleNamespace(storage_id="files")),
                    {"limit": 1001},
                ),
            ):
                store.connection.execute("UPDATE xml_store_meta SET storage_id='files'")
                store.connection.commit()
                with pytest.raises(ValueError):
                    method(*args, **kwargs)
    finally:
        http.close()
    connection = sqlite3.connect(":memory:")
    try:
        MetadataSQLiteStore(connection)
        connection.execute("DROP TABLE outbox")
        connection.execute("CREATE TABLE outbox(unknown TEXT)")
        with pytest.raises(KsefXmlStorageError):
            SQLiteInvoiceSyncStore.migrate_legacy_example(connection, xml_storage_id="files")
    finally:
        connection.close()


def test_legacy_metadata_adapter_requires_idle_connection():
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE example(value TEXT)")
        connection.execute("INSERT INTO example VALUES('active')")
        with pytest.raises(ValueError):
            MetadataSQLiteStore(connection)
    finally:
        connection.close()
