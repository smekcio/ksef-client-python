from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore

from ksef_client import (
    CancellationToken,
    InvoiceSyncCheckpoint,
    KsefInvalidSyncCheckpointError,
    KsefRateLimitWaitTimeout,
    KsefRequestCancelledError,
    KsefSyncConflictError,
    KsefSyncError,
    KsefSyncLimitError,
    KsefSyncStoreError,
    request_control,
)
from ksef_client.exceptions import KsefResponseLimitError
from ksef_client.invoice_search import InvoiceMetadataObservationPage
from ksef_client.invoice_sync import _commit_and_drain
from tests.test_invoice_sync import H1, H2, Server, database, make_sync, row


@pytest.mark.parametrize("at", range(1, 9))
@pytest.mark.parametrize("after", [False, True])
def test_sqlite_failure_at_each_statement_is_atomic(tmp_path, at, after):
    class FaultStore(SQLiteInvoiceSyncStore):
        calls = 0
        failure_at = None

        def _execute(self, sql, parameters=()):
            self.calls += 1
            fail = self.calls == self.failure_at
            if fail:
                self.failure_at = None
            if fail and not after:
                raise OSError("private-database-details")
            result = super()._execute(sql, parameters)
            if fail:
                raise OSError("private-database-details")
            return result

    server = Server([row()])
    sync, http = make_sync(server, since="2025-01-01T00:00:00Z")
    connection = sqlite3.connect(tmp_path / "sync.db", timeout=2)
    store = FaultStore(connection, enqueue_xml=True)
    stream = sync.streams[0]
    try:
        begin = stream.begin_cycle(None, until=H1)
        cp = begin.confirm(store.commit(begin))
        page = stream.next_batch(cp)
        store.calls, store.failure_at = 0, at
        with pytest.raises(KsefSyncStoreError) as caught:
            store.commit(page)
        assert caught.value.commit_outcome in {"not_started", "rolled_back", "unknown"}
        assert not connection.in_transaction
        loaded = store.load(stream.scope)
        assert loaded is not None
        persisted = loaded.last_commit_id == page.receipt.commit_id
        assert persisted == (after and at == 8)
        for table in ("invoices", "invoice_observations", "outbox"):
            assert connection.execute("SELECT count(*) FROM " + table).fetchone()[0] == int(
                persisted
            )
        assert loaded == (page.next_checkpoint if persisted else cp)
        # Replay after an uncertain committed result is rejected by CAS.
        if persisted:
            with pytest.raises(KsefSyncConflictError):
                store.commit(page)
    finally:
        http.close()
        connection.close()


def test_foreign_transaction_and_broken_load_are_not_missing(tmp_path):
    store = database(tmp_path)
    sync, http = make_sync(Server())
    try:
        batch = sync.streams[0].begin_cycle(None, until=H1)
        store.connection.execute("BEGIN")
        with pytest.raises(KsefSyncStoreError):
            store.commit(batch)
        with pytest.raises(ValueError):
            SQLiteInvoiceSyncStore(store.connection)
        store.connection.rollback()
        store.commit(batch)
        store.connection.execute("UPDATE sync_checkpoints SET checkpoint_json='broken'")
        store.connection.commit()
        with pytest.raises(KsefInvalidSyncCheckpointError):
            store.load(batch.scope)
        store.connection.close()
        with pytest.raises(KsefSyncStoreError):
            store.load(batch.scope)
    finally:
        http.close()
        store.connection.close()


def test_checkpoint_column_mismatch_and_tenant_isolation(tmp_path):
    store = database(tmp_path)
    sync, http = make_sync(Server())
    try:
        batch = sync.streams[0].begin_cycle(None, until=H1)
        store.commit(batch)
        assert store.load(replace(batch.scope, namespace="other")) is None
        assert store.load(replace(batch.scope, environment="a" * 64)) is None
        assert store.load(replace(batch.scope, context_key="other")) is None
        store.connection.execute("UPDATE sync_checkpoints SET revision=123")
        store.connection.commit()
        with pytest.raises(KsefSyncStoreError):
            store.load(batch.scope)
    finally:
        http.close()
        store.connection.close()


@pytest.mark.parametrize("phase", ["load", "http", "commit"])
@pytest.mark.parametrize("limit,reason", [(1.0, "step_time_budget"), (10.0, "time_budget")])
def test_cooperative_budget_reasons(tmp_path, monkeypatch, phase, limit, reason):
    import time

    from ksef_client.rate_limiting import RequestControl

    clock = [100.0]
    server = Server()
    sync, http = make_sync(server)
    store = database(tmp_path)
    original_load, original_commit = store.load, store.commit
    original_handle = server.handle

    def load(scope):
        cp = original_load(scope)
        if phase == "load":
            clock[0] += limit
        return cp

    def commit(batch):
        receipt = original_commit(batch)
        if phase == "commit":
            clock[0] += limit
        return receipt

    def handle(request):
        response = original_handle(request)
        if phase == "http":
            clock[0] += limit
        return response

    monkeypatch.setattr(store, "load", load)
    monkeypatch.setattr(store, "commit", commit)
    http._client._transport.handler = handle
    try:
        with monkeypatch.context() as context:
            context.setattr(time, "monotonic", lambda: clock[0])
            original_check = RequestControl.check
            original_remaining = RequestControl.remaining
            context.setattr(
                RequestControl,
                "check",
                lambda self, **kw: original_check(self, clock=lambda: clock[0]),
            )
            context.setattr(
                RequestControl,
                "remaining",
                lambda self, **kw: original_remaining(self, clock=lambda: clock[0]),
            )
            report = sync.run_once(
                store,
                time_budget=10,
                step_time_budget=20 if reason == "time_budget" else 1,
                raise_on_error=False,
            )
        assert report.streams[0].stop_reason == reason
        assert report.streams[0].status == "partial"
        if phase != "commit":
            assert report.streams[0].pages_committed == 0
    finally:
        http.close()
        store.connection.close()


def test_parent_deadline_and_cancellation_remain_fatal(tmp_path, monkeypatch):
    import time

    from ksef_client.rate_limiting import RequestControl

    sync, http = make_sync(Server())
    store = database(tmp_path)
    clock = [0.0]
    original = store.load

    def load(scope):
        value = original(scope)
        clock[0] += 1
        return value

    monkeypatch.setattr(store, "load", load)
    try:
        with monkeypatch.context() as context:
            context.setattr(time, "monotonic", lambda: clock[0])
            original_check = RequestControl.check
            original_remaining = RequestControl.remaining
            context.setattr(
                RequestControl,
                "check",
                lambda self, **kw: original_check(self, clock=lambda: clock[0]),
            )
            context.setattr(
                RequestControl,
                "remaining",
                lambda self, **kw: original_remaining(self, clock=lambda: clock[0]),
            )
            with request_control(deadline=1), pytest.raises(KsefRateLimitWaitTimeout):
                sync.run_once(store, time_budget=1, step_time_budget=1, raise_on_error=False)
        token = CancellationToken()
        token.cancel()
        with pytest.raises(KsefRequestCancelledError):
            sync.run_once(store, cancellation=token, raise_on_error=False)
    finally:
        http.close()
        store.connection.close()


@pytest.mark.parametrize(
    "error",
    [
        KsefSyncConflictError("conflict"),
        KsefSyncStoreError(operation="commit", commit_outcome="unknown", failure_scope="stream"),
    ],
)
def test_unconfirmed_progress_invalidates_cached_coverage(tmp_path, error):
    server, store = Server(), database(tmp_path)
    sync, http = make_sync(server)
    try:
        assert sync.run_once(store).complete
        previous = store.load(sync.streams[0].scope)

        class Fault:
            def load(self, scope):
                return store.load(scope)

            def commit(self, batch):
                raise error

        report = sync.run_once(Fault(), raise_on_error=False)
        result = report.streams[0]
        assert result.coverage is None and report.common_coverage is None
        assert result.observed_generation == previous.generation_id
        assert result.observed_revision == previous.revision
    finally:
        http.close()
        store.connection.close()


def test_fatal_isolation_invalid_store_values_and_programming_errors(tmp_path):
    sync, http = make_sync(Server())
    try:
        wrong = Mock(load=Mock(return_value="corrupt"))
        report = sync.run_once(wrong, raise_on_error=False)
        assert isinstance(report.streams[0].original_error, KsefInvalidSyncCheckpointError)
        cp = sync.streams[0].begin_cycle(None, until=H1).next_checkpoint
        wrong_scope = cp.to_dict()
        wrong_scope["scope"]["namespace"] = "other"
        wrong.load.return_value = InvoiceSyncCheckpoint.from_dict(wrong_scope)
        with pytest.raises(KsefSyncStoreError):
            sync.run_once(wrong, raise_on_error=False)
        with pytest.raises(ValueError):
            sync.describe([])
        assert not sync.describe({}).complete
        with pytest.raises(KsefInvalidSyncCheckpointError):
            sync.describe([wrong.load.return_value])
    finally:
        http.close()


def test_pull_idle_hwm_validation_and_response_limits(tmp_path):
    sync, http = make_sync(Server())
    store = database(tmp_path)
    try:
        assert sync.run_once(store).complete
        stream = sync.streams[0]
        cp = store.load(stream.scope)
        assert stream.next_batch(cp) is None
        active = stream.begin_cycle(cp, until=H2).next_checkpoint
        for hwm in (None, "bad", "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"):
            with pytest.raises(KsefSyncError):
                stream._advance(active, InvoiceMetadataObservationPage((), None, hwm))

        class TooBig:
            identity = SimpleNamespace(
                environment=stream.scope.environment, context_key=stream.scope.context_key
            )

            def validate_cursor(self, cursor):
                return None

            def observation_page(self, cursor):
                raise KsefResponseLimitError(limit_bytes=16)

        stream._search_factory = lambda *a, **kw: TooBig()
        with pytest.raises(KsefSyncLimitError) as caught:
            stream.next_batch(active)
        assert caught.value.limit_stage == "response_body"
        stream._search_factory = lambda *a, **kw: SimpleNamespace(
            identity=SimpleNamespace(environment="other", context_key=stream.scope.context_key)
        )
        with pytest.raises(KsefInvalidSyncCheckpointError):
            stream.next_batch(active)
    finally:
        http.close()
        store.connection.close()


def test_async_commit_failures_and_cancelled_failure_are_collected(tmp_path):
    async def run():
        sync, http = make_sync(Server(), asynchronous=True)
        batch = sync.streams[0].begin_cycle(None, until=H1)
        try:

            class Store:
                async def load(self, scope):
                    return None

                async def commit(self, batch):
                    raise OSError("private-database")

            with pytest.raises(KsefSyncStoreError):
                await sync.run_once(Store(), raise_on_error=False)
            entered, release = asyncio.Event(), asyncio.Event()

            class Slow(Store):
                async def commit(self, batch):
                    entered.set()
                    await release.wait()
                    raise OSError("private-database")

            task = asyncio.create_task(_commit_and_drain(Slow(), batch))
            await entered.wait()
            task.cancel()
            await asyncio.sleep(0)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            await http.aclose()

    asyncio.run(run())
