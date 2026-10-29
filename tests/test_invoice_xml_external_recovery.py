from __future__ import annotations

import asyncio
import errno
import sqlite3
from dataclasses import replace

import pytest

from ksef_client import (
    FileInvoiceXmlStore,
    InvoiceSyncCheckpoint,
    InvoiceXmlKey,
    KsefSyncDataConflictError,
    KsefXmlRunError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
)
from ksef_client._sqlite_metadata import SCHEMA
from ksef_client.rate_limiting import KsefRateLimitWaitTimeout
from tests.test_invoice_xml_sync import HASH, NUMBER, environment


def test_standalone_exception_shape_work_limit_and_foreign_snapshot(tmp_path, monkeypatch):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            report = sync.xml.run_once(store, storage, max_documents=1)
            assert report.stop_reason == "work_limit" and report.ready == 1
            assert KsefXmlRunError(report).xml_report is report
            snapshot = store.describe_xml(sync.xml.scopes)
            data = snapshot.checkpoints[0].to_dict()
            data["scope"]["sync_key"] = "foreign"
            foreign = InvoiceSyncCheckpoint.from_dict(data)
            monkeypatch.setattr(
                store, "describe_xml", lambda scopes: replace(snapshot, checkpoints=(foreign,))
            )
            with pytest.raises(KsefXmlStorageError, match="invalid_report_checkpoints"):
                sync.xml.run_once(store, storage)

    asyncio.run(run())


def test_invalid_storage_path_cleanup_error_and_read_error_preserve_categories(
    tmp_path, monkeypatch
):
    import ksef_client.invoice_xml_storage as files

    with pytest.raises(ValueError, match="must not be empty"):
        FileInvoiceXmlStore("")
    with FileInvoiceXmlStore(tmp_path) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)

        def failed_unlink(*args, **kwargs):
            raise OSError(errno.EIO, "untrusted file path")

        with monkeypatch.context() as patch:
            patch.setattr(files.os, "unlink", failed_unlink)
            with pytest.raises(KsefXmlStorageError, match="storage_cleanup_failed"):
                storage._unlink(".tmp-" + "a" * 32)

        for error, expected in (
            (KsefRateLimitWaitTimeout("deadline"), KsefRateLimitWaitTimeout),
            (OSError(errno.ELOOP, "symlink"), KsefXmlStorageError),
            (PermissionError("unreadable"), KsefXmlStorageError),
        ):

            def fail(*args, value=error, **kwargs):
                raise value

            monkeypatch.setattr(storage, "_open", fail)
            with pytest.raises(expected):
                storage.read(key, HASH)


def test_explicit_migration_rolls_back_partial_indexes_and_rejects_bad_rows(tmp_path):
    class Connection(sqlite3.Connection):
        fail = False

        def execute(self, sql, parameters=()):
            if self.fail and sql.startswith("CREATE INDEX xml_claim_expired"):
                raise sqlite3.OperationalError("injected index failure")
            return super().execute(sql, parameters)

    connection = sqlite3.connect(tmp_path / "db", factory=Connection)
    try:
        SQLiteInvoiceSyncStore(connection)
        for name in ("xml_claim_due", "xml_claim_expired"):
            connection.execute("DROP INDEX " + name)
        connection.execute("UPDATE xml_store_meta SET version=1")
        connection.commit()
        connection.fail = True
        with pytest.raises(sqlite3.OperationalError, match="injected index failure"):
            SQLiteInvoiceSyncStore.migrate_schema(connection)
        assert not connection.in_transaction
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='xml_claim_due'"
            ).fetchone()
            is None
        )
        assert connection.execute("SELECT version FROM xml_store_meta").fetchone()[0] == 1
        connection.fail = False
        SQLiteInvoiceSyncStore.migrate_schema(connection)
        connection.execute("UPDATE xml_store_meta SET version=99")
        connection.commit()
        with pytest.raises(KsefXmlStorageError, match="unsupported_schema"):
            SQLiteInvoiceSyncStore.migrate_schema(connection)
        connection.row_factory = lambda cursor, values: dict(
            zip((c[0] for c in cursor.description), values, strict=True)
        )
        with pytest.raises(ValueError, match="tuple rows or sqlite3.Row"):
            SQLiteInvoiceSyncStore(connection)
    finally:
        connection.close()


@pytest.mark.parametrize("conflict", [False, True])
def test_legacy_alias_migration_preserves_invalid_data_and_rolls_back_hash_conflict(
    tmp_path, conflict
):
    connection = sqlite3.connect(tmp_path / "legacy")
    try:
        connection.executescript(SCHEMA)
        alias = NUMBER[:26] + "-" + NUMBER[26:]
        scope = ("tenant", "0" * 64, "ctx")
        connection.execute("INSERT INTO invoices VALUES (?,?,?,?,?)", (*scope, "x" * 36, HASH))
        if conflict:
            connection.execute("INSERT INTO invoices VALUES (?,?,?,?,?)", (*scope, NUMBER, HASH))
            connection.execute(
                "INSERT INTO invoices VALUES (?,?,?,?,?)", (*scope, alias, "A" * 43 + "=")
            )
        connection.commit()
        if conflict:
            with pytest.raises(KsefSyncDataConflictError):
                SQLiteInvoiceSyncStore.migrate_legacy_example(connection)
            assert (
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name='xml_store_meta'"
                ).fetchone()
                is None
            )
            assert connection.execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == 3
        else:
            SQLiteInvoiceSyncStore.migrate_legacy_example(connection)
            assert connection.execute("SELECT ksef_number FROM invoices").fetchone()[0] == "x" * 36
    finally:
        connection.close()


def test_claim_quarantine_is_bounded_and_resumable(tmp_path):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            scope = sync.xml.scopes[0]
            prefix = (scope.namespace, scope.environment, scope.context_key)
            store.connection.execute("UPDATE invoice_xml_documents SET status='blocked'")
            for index in range(101):
                number = f"invalid-{index:04d}"
                store.connection.execute(
                    "INSERT INTO invoices VALUES (?,?,?,?,?)", (*prefix, number, HASH)
                )
                store.connection.execute(
                    "INSERT INTO invoice_observations VALUES (?,?,?,?,?,?,?)",
                    (*prefix, scope.sync_key, scope.stream_id, number, "{}"),
                )
                store.connection.execute(
                    "INSERT INTO invoice_xml_documents(namespace,environment,context_key,"
                    "ksef_number,expected_hash,created_at) VALUES (?,?,?,?,?,0)",
                    (*prefix, number, HASH),
                )
            store.connection.commit()
            assert store.claim_xml(sync.xml.scopes) is None
            assert store.describe_xml(sync.xml.scopes).pending == 1
            assert store.claim_xml(sync.xml.scopes) is None
            assert store.describe_xml(sync.xml.scopes).pending == 0

    asyncio.run(run())


def test_readiness_count_uses_document_identity_lookup(tmp_path, monkeypatch):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            original = store._execute
            plans: list[str] = []

            def execute(sql, parameters=()):
                if "SELECT COALESCE(d.status,'not_enqueued'),COUNT(*)" in sql:
                    plans.extend(
                        row[-1]
                        for row in store.connection.execute("EXPLAIN QUERY PLAN " + sql, parameters)
                    )
                return original(sql, parameters)

            monkeypatch.setattr(store, "_execute", execute)
            assert store.describe_xml(sync.xml.scopes).pending == 1
            assert any(
                "sqlite_autoindex_invoice_xml_documents_1" in plan and "ksef_number=?" in plan
                for plan in plans
            )
            assert not any("xml_claim_expired" in plan for plan in plans)

    asyncio.run(run())
