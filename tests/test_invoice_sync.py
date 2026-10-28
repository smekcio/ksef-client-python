from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import traceback
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import Mock

import httpx
import pytest
from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore

from ksef_client import (
    AsyncInvoiceSync,
    InvoiceSync,
    InvoiceSyncCheckpoint,
    InvoiceSyncCommitReceipt,
    KsefClientOptions,
    KsefInvalidSyncCheckpointError,
    KsefSyncConflictError,
    KsefSyncDataConflictError,
    KsefSyncRunError,
    KsefSyncStateError,
    KsefSyncStoreError,
)
from ksef_client import models as m
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient
from ksef_client.invoice_search import _date
from ksef_client.operations import environment_key

START = "2024-01-01T00:00:00Z"
H1 = "2026-01-01T00:00:00.1234567Z"
H2 = "2026-01-02T00:00:00.1234568Z"
HASH = base64.b64encode(b"a" * 32).decode()


def row(number="A", date="2025-01-01T00:00:00Z", hash_=HASH):
    return m.InvoiceMetadata(ksef_number=number, invoice_hash=hash_, permanent_storage_date=date)


def query(role="Subject1", start=START):
    return m.InvoiceQueryFilters(
        subject_type=m.InvoiceQuerySubjectType(role),
        date_range=m.InvoiceQueryDateRange(
            date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
            from_=start,
            restrict_to_permanent_storage_hwm_date=True,
        ),
    )


class Server:
    def __init__(self, rows=(), hwm=H1):
        self.rows, self.hwm, self.calls = list(rows), hwm, []
        self.forbidden = set()

    def handle(self, request):
        payload = json.loads(request.content)
        role, bounds = payload["subjectType"], payload["dateRange"]
        offset, size = int(request.url.params["pageOffset"]), int(request.url.params["pageSize"])
        self.calls.append((deepcopy(payload), offset, size))
        assert request.url.params["sortOrder"] == "Asc"
        assert bounds["restrictToPermanentStorageHwmDate"] is True
        assert (_date(bounds["to"])[0].date() - _date(bounds["from"])[0].date()).days <= 100
        if role in self.forbidden:
            return httpx.Response(
                403,
                stream=httpx.ByteStream(b'{"status":403}'),
                headers={"Content-Type": "application/json"},
            )
        hwm = min((bounds["to"], self.hwm), key=_date)
        selected = sorted(
            (
                r
                for r in self.rows
                if _date(bounds["from"]) <= _date(r.permanent_storage_date) <= _date(hwm)
            ),
            key=lambda r: _date(r.permanent_storage_date),
        )
        chunk = selected[offset * size : (offset + 1) * size]
        raw = json.dumps(
            {
                "invoices": [r.to_dict() for r in chunk],
                "hasMore": (offset + 1) * size < len(selected),
                "isTruncated": False,
                "permanentStorageHwmDate": hwm,
            }
        ).encode()
        return httpx.Response(
            200, stream=httpx.ByteStream(raw), headers={"Content-Type": "application/json"}
        )


def make_sync(server, *, asynchronous=False, **kwargs):
    options = KsefClientOptions(base_url="https://example.test/v2")
    http: Any = (AsyncBaseHttpClient if asynchronous else BaseHttpClient)(options)
    # Close the default client before replacing it (the async one has no opened connections).
    if not asynchronous:
        http.close()
    http._client = (httpx.AsyncClient if asynchronous else httpx.Client)(
        transport=httpx.MockTransport(server.handle)
    )
    api = (AsyncInvoicesClient if asynchronous else InvoicesClient)(http)
    params: dict[str, Any] = dict(
        namespace="tenant", sync_key="job", context_key="Nip:test", page_size=10
    )
    if "queries" not in kwargs:
        params.update(since=START, subject_types=("Subject1",))
    params.update(kwargs)
    return api.sync(**params), http


def database(tmp_path, *, autocommit=False):
    connection = sqlite3.connect(tmp_path / "sync.db", timeout=2)
    if autocommit:
        if not hasattr(connection, "autocommit"):
            connection.isolation_level = None
        else:
            connection.autocommit = True
    return SQLiteInvoiceSyncStore(connection, enqueue_xml=True)


@pytest.mark.parametrize("autocommit", [False, True])
def test_a_hwm_b_restart_real_sqlite(tmp_path, autocommit):
    server = Server([row()])
    store = database(tmp_path, autocommit=autocommit)
    sync, http = make_sync(server, subject_types=tuple(m.InvoiceQuerySubjectType))
    try:
        report = sync.run_once(store)
        assert report.complete and report.common_coverage.to == H1
        assert len(report.new_streams) == 4
        assert {r[0] for r in store.connection.execute("SELECT ksef_number FROM invoices")} == {"A"}
        assert (
            store.connection.execute("SELECT count(*) FROM invoice_observations").fetchone()[0] == 4
        )
        checkpoints = [store.load(s.scope) for s in sync.streams]
        assert all(cp.committed_hwm == H1 for cp in checkpoints)
        assert sync.describe(checkpoints).complete
    finally:
        http.close()
        store.connection.close()
    server.rows.append(row("B", H2))
    server.hwm = H2
    server.calls.clear()
    store = database(tmp_path, autocommit=autocommit)
    sync, http = make_sync(server, subject_types=tuple(m.InvoiceQuerySubjectType))
    try:
        report = sync.run_once(store)
        assert report.complete and not report.new_streams
        assert report.common_coverage.to == H2
        assert all(_date(call[0]["dateRange"]["from"]) == _date(H1) for call in server.calls)
        assert {r[0] for r in store.connection.execute("SELECT ksef_number FROM invoices")} == {
            "A",
            "B",
        }
        assert store.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 2
    finally:
        http.close()
        store.connection.close()


def test_restart_after_every_page_no_early_hwm(tmp_path):
    server = Server(
        [
            row(
                str(i),
                (datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(days=13 * i)).isoformat(),
            )
            for i in range(50)
        ]
    )
    store = database(tmp_path)
    sync, http = make_sync(server)
    calls = 0
    try:
        while True:
            report = sync.run_once(store, max_pages_per_stream=1)
            checkpoint = store.load(sync.streams[0].scope)
            checkpoint = InvoiceSyncCheckpoint.from_json(checkpoint.to_json())
            calls += 1
            if report.complete:
                assert checkpoint.committed_hwm == H1
                break
            assert checkpoint.committed_hwm is None
            assert report.streams[0].stop_reason == "work_limit"
            assert report.common_coverage is None
            store.connection.close()
            store = database(tmp_path)
        assert calls > 6
        assert {r[0] for r in store.connection.execute("SELECT ksef_number FROM invoices")} == {
            str(i) for i in range(50)
        }
    finally:
        http.close()
        store.connection.close()


def test_forbidden_role_does_not_block_healthy_increment(tmp_path):
    server = Server([row()])
    server.forbidden.add("Subject1")
    store = database(tmp_path)
    sync, http = make_sync(server, subject_types=("Subject1", "Subject2"))
    try:
        with pytest.raises(KsefSyncRunError) as caught:
            sync.run_once(store)
        report = caught.value.report
        assert [r.status for r in report.streams] == ["failed", "completed"]
        assert report.common_coverage is None
        server.rows.append(row("B", H2))
        server.hwm = H2
        report = sync.run_once(store, raise_on_error=False)
        assert [r.status for r in report.streams] == ["failed", "completed"]
        assert {r[0] for r in store.connection.execute("SELECT ksef_number FROM invoices")} == {
            "A",
            "B",
        }
    finally:
        http.close()
        store.connection.close()


def test_round_robin_and_configuration_identity(tmp_path):
    server, store = Server(), database(tmp_path)
    sync, http = make_sync(server, subject_types=("Subject1", "Subject2"))
    reordered, http2 = make_sync(server, subject_types=("Subject2", "Subject1", "Subject3"))
    changed, http3 = make_sync(server, since="2024-01-01T01:00:00+01:00")
    try:
        assert reordered.streams[0].scope == sync.streams[1].scope
        assert reordered.streams[1].scope == sync.streams[0].scope
        assert changed.streams[0].scope == sync.streams[0].scope
        report = sync.run_once(store, max_pages_per_stream=2)
        assert [c[0]["subjectType"] for c in server.calls] == [
            "Subject1",
            "Subject2",
            "Subject1",
            "Subject2",
        ]
        assert [r.pages_committed for r in report.streams] == [2, 2]
        assert sync.streams[0].scope.environment == environment_key(http.api_base_url)
    finally:
        for h in (http, http2, http3):
            h.close()
        store.connection.close()


def test_hash_conflicts_before_commit_and_between_jobs(tmp_path):
    stamp = "2025-01-01T00:00:00Z"
    server = Server([row("A", stamp), row("A", stamp, base64.b64encode(b"b" * 32).decode())])
    store = database(tmp_path)
    sync, http = make_sync(server, since="2025-01-01T00:00:00Z")
    try:
        report = sync.run_once(store, raise_on_error=False)
        assert isinstance(report.streams[0].original_error, KsefSyncDataConflictError)
        assert store.connection.execute("SELECT count(*) FROM invoices").fetchone()[0] == 0
        server.rows.pop()
        assert sync.run_once(store).complete
        server.rows[0] = row("A", stamp, base64.b64encode(b"c" * 32).decode())
        other, h2 = make_sync(server, sync_key="other-job", since="2025-01-01T00:00:00Z")
        try:
            report = other.run_once(store, raise_on_error=False)
            assert isinstance(report.streams[0].original_error, KsefSyncDataConflictError)
            assert not report.complete
            assert (
                store.connection.execute("SELECT invoice_hash FROM invoices").fetchone()[0] == HASH
            )
        finally:
            h2.close()
    finally:
        http.close()
        store.connection.close()


def test_pull_receipt_cas_recovery_and_fence(tmp_path):
    server, store = Server(), database(tmp_path)
    sync, http = make_sync(server)
    stream = sync.streams[0]
    try:
        batch = stream.begin_cycle(None, until=H1)
        checkpoint = batch.confirm(store.commit(batch))
        with pytest.raises(KsefSyncConflictError):
            store.commit(batch)
        with pytest.raises(KsefSyncStateError):
            stream.begin_cycle(checkpoint, until=H2)
        with pytest.raises(KsefInvalidSyncCheckpointError):
            stream.next_batch(None)
        bad = checkpoint.to_dict()
        bad["active"]["cursor"] = "broken"
        broken = InvoiceSyncCheckpoint.from_dict(bad)
        with pytest.raises(Exception, match="cursor"):
            stream.next_batch(broken)
        repaired = stream.restart_active(broken, reason="cursor_invalid", page_size=20)
        checkpoint = repaired.confirm(store.commit(repaired))
        assert checkpoint.active["cursor"] is None and checkpoint.active["page_size"] == 20
        stale = stream.next_batch(checkpoint)
        fence = stream.fence_after_restore(checkpoint, reason="backup_restored")
        checkpoint = fence.confirm(store.commit(fence))
        with pytest.raises(KsefSyncConflictError):
            store.commit(stale)
        replay = stream.restart_backfill(checkpoint, until=H2, reason="permissions_changed")
        checkpoint = replay.confirm(store.commit(replay))
        assert checkpoint.committed_hwm is None and checkpoint.active["from"] == START
        assert checkpoint.generation_id != fence.next_checkpoint.generation_id
        wrong = InvoiceSyncCommitReceipt(
            batch.scope,
            batch.receipt.generation_id,
            batch.receipt.revision + 1,
            batch.receipt.commit_id,
        )
        with pytest.raises(KsefSyncStoreError):
            batch.confirm(wrong)
    finally:
        http.close()
        store.connection.close()


@pytest.mark.parametrize(
    "params",
    [
        {"queries": []},
        {"subject_types": []},
        {"subject_types": ["Subject1", m.InvoiceQuerySubjectType.SUBJECT1]},
        {"subject_types": "Subject1"},
        {"queries": {}},
        {"queries": [query()], "since": START},
        {"since": "2024-01-01"},
        {"namespace": "\n"},
        {"sync_key": ""},
        {"context_key": "\x00"},
        {"page_size": True},
        {"window_days": 0},
        {"queries": [{}]},
    ],
)
def test_factory_rejects_invalid_before_io(params):
    http = Mock(api_base_url="https://example.test/v2")
    api = InvoicesClient(http)
    kwargs: dict[str, Any] = dict(namespace="n", sync_key="j", context_key="c")
    if "queries" not in params:
        kwargs["since"] = START
    kwargs.update(params)
    with pytest.raises((ValueError, TypeError)):
        api.sync(**kwargs)
    http.request.assert_not_called()
    http.request_json_limited.assert_not_called()


def test_store_exception_redaction_and_isolation(tmp_path):
    server = Server()
    sync, http = make_sync(server)
    try:

        class Failing:
            def load(self, scope):
                raise RuntimeError("secret-DSN-token")

        with pytest.raises(KsefSyncStoreError) as caught:
            sync.run_once(Failing(), raise_on_error=False)
        error = caught.value
        assert error.failure_scope == "store" and error.commit_outcome == "not_started"
        rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        assert "secret-DSN-token" not in str(error) + repr(error) + rendered + str(error.to_dict())
        assert "secret-DSN-token" in str(error.original_error)
        with pytest.raises(ValueError):
            KsefSyncStoreError(operation="load", commit_outcome="unknown")
    finally:
        http.close()


def test_async_parity_and_repeated_cancellation_drains_commit(tmp_path):
    async def run():
        server, store = Server([row()]), database(tmp_path)
        sync, http = make_sync(server, asynchronous=True)
        assert isinstance(sync, AsyncInvoiceSync)

        class AsyncStore:
            async def load(self, scope):
                return store.load(scope)

            async def commit(self, batch):
                return store.commit(batch)

        try:
            report = await sync.run_once(AsyncStore())
            assert report.complete and report.common_coverage is not None
            assert report.common_coverage.to == H1
            entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

            class SlowStore(AsyncStore):
                async def commit(self, batch):
                    entered.set()
                    await release.wait()
                    receipt = store.commit(batch)
                    finished.set()
                    return receipt

            task = asyncio.create_task(sync.run_once(SlowStore()))
            await entered.wait()
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            calls = len(server.calls)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert finished.is_set() and len(server.calls) == calls
        finally:
            await http.aclose()
            store.connection.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "params",
    [
        {"time_budget": True},
        {"time_budget": 0},
        {"time_budget": float("inf")},
        {"step_time_budget": -1},
        {"max_pages_per_stream": True},
        {"max_pages_per_stream": 0},
        {"raise_on_error": 1},
    ],
)
def test_run_parameter_validation(params):
    sync, http = make_sync(Server())
    try:
        with pytest.raises((ValueError, TypeError)):
            sync.run_once(Mock(), **params)
    finally:
        http.close()


def test_public_empty_coordinator_rejected():
    with pytest.raises(ValueError):
        InvoiceSync([])
