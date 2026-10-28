from __future__ import annotations

import asyncio
import base64
from dataclasses import replace

import pytest
from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore

from ksef_client import (
    KsefInvalidSyncCheckpointError,
    KsefSyncConflictError,
    KsefSyncDataConflictError,
    KsefSyncRunError,
    KsefSyncStoreError,
)
from tests.invoice_sync_store_harness import SQLiteHarness
from tests.test_invoice_sync import H1, H2, HASH, Server, make_sync, row

pytestmark = pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])


async def close_http(http, asynchronous):
    if asynchronous:
        await http.aclose()
    else:
        http.close()


@pytest.mark.parametrize("autocommit", [False, True])
@pytest.mark.parametrize("at", range(1, 9))
@pytest.mark.parametrize("after", [False, True])
def test_sqlite_failure_at_each_statement_is_atomic(tmp_path, asynchronous, autocommit, at, after):
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

    async def run():
        sync, http = make_sync(
            Server([row()]), since="2025-01-01T00:00:00Z", asynchronous=asynchronous
        )
        try:
            async with SQLiteHarness(
                tmp_path, asynchronous=asynchronous, autocommit=autocommit, store_type=FaultStore
            ) as store:
                stream = sync.streams[0]
                begin = stream.begin_cycle(None, until=H1)
                checkpoint = begin.confirm(await store.commit(begin))
                page = await store.next_batch(stream, checkpoint)

                def arm():
                    store.store.calls, store.store.failure_at = 0, at

                await store.call(arm)
                with pytest.raises(KsefSyncStoreError) as caught:
                    await store.commit(page)
                persisted = after and at == 8
                expected_outcome = (
                    "unknown"
                    if persisted
                    else ("not_started" if at == 1 and not after else "rolled_back")
                )
                assert caught.value.commit_outcome == expected_outcome
                assert caught.value.failure_scope == "store"
                assert "private-database-details" not in str(caught.value)
                assert not await store.call(lambda: store.store.connection.in_transaction)
                loaded = await store.load(stream.scope)
                assert loaded == (page.next_checkpoint if persisted else checkpoint)
                for table in ("invoices", "invoice_observations", "outbox"):
                    assert await store.sql("SELECT count(*) FROM " + table) == [(int(persisted),)]
                if persisted:
                    with pytest.raises(KsefSyncConflictError):
                        await store.commit(page)
                else:
                    # Explicit recovery after a confirmed rollback/not-started result.
                    assert page.confirm(await store.commit(page)) == page.next_checkpoint
                assert await store.load(stream.scope) == page.next_checkpoint
        finally:
            await close_http(http, asynchronous)

    asyncio.run(run())


@pytest.mark.parametrize("autocommit", [False, True])
def test_receipt_cas_fence_replay_isolation_and_hash_integrity(tmp_path, asynchronous, autocommit):
    async def run():
        server = Server([row()])
        sync, http = make_sync(server, since="2025-01-01T00:00:00Z", asynchronous=asynchronous)
        other, http2 = make_sync(
            server, since="2025-01-01T00:00:00Z", sync_key="other-job", asynchronous=asynchronous
        )
        try:
            async with SQLiteHarness(
                tmp_path, asynchronous=asynchronous, autocommit=autocommit
            ) as store:
                stream = sync.streams[0]
                assert await store.load(stream.scope) is None
                begin = stream.begin_cycle(None, until=H1)
                receipt = await store.commit(begin)
                assert receipt == begin.receipt
                checkpoint = begin.confirm(receipt)
                with pytest.raises(KsefSyncStoreError):
                    begin.confirm(replace(receipt, revision=receipt.revision + 1))
                with pytest.raises(KsefSyncConflictError):
                    await store.commit(begin)
                for changes in (
                    dict(namespace="other"),
                    dict(environment="a" * 64),
                    dict(context_key="other"),
                    dict(sync_key="other"),
                ):
                    assert await store.load(replace(stream.scope, **changes)) is None
                stale = await store.next_batch(stream, checkpoint)
                fence = stream.fence_after_restore(checkpoint, reason="backup_restored")
                checkpoint = fence.confirm(await store.commit(fence))
                assert checkpoint.generation_id != stale.expected_generation
                with pytest.raises(KsefSyncConflictError):
                    await store.commit(stale)
                assert (await store.run_once(sync)).complete
                checkpoint = await store.load(stream.scope)
                replay = stream.restart_backfill(checkpoint, until=H2, reason="permissions_changed")
                replay.confirm(await store.commit(replay))
                assert (await store.run_once(sync)).complete
                # Same document, second job: observations remain separate, outbox stays stable.
                assert (await store.run_once(other)).complete
                assert await store.sql("SELECT count(*) FROM invoices") == [(1,)]
                assert await store.sql("SELECT count(*) FROM invoice_observations") == [(2,)]
                assert await store.sql("SELECT count(*) FROM outbox") == [(1,)]
                assert await store.sql("SELECT invoice_hash FROM invoices") == [(HASH,)]
                server.rows = [row(hash_=base64.b64encode(b"b" * 32).decode())]
                conflict, http3 = make_sync(
                    server,
                    since="2025-01-01T00:00:00Z",
                    sync_key="conflicting-job",
                    asynchronous=asynchronous,
                )
                try:
                    report = await store.run_once(conflict, raise_on_error=False)
                    assert isinstance(report.streams[0].original_error, KsefSyncDataConflictError)
                    assert await store.sql("SELECT invoice_hash FROM invoices") == [(HASH,)]
                    assert await store.sql("SELECT count(*) FROM outbox") == [(1,)]
                finally:
                    await close_http(http3, asynchronous)
                await store.sql("UPDATE sync_checkpoints SET checkpoint_json='broken'")
                await store.call(store.store.connection.commit)
                with pytest.raises(KsefInvalidSyncCheckpointError):
                    await store.load(stream.scope)
                await store.call(store.store.connection.close)
                with pytest.raises(KsefSyncStoreError):
                    await store.load(stream.scope)
        finally:
            await close_http(http, asynchronous)
            await close_http(http2, asynchronous)

    asyncio.run(run())


@pytest.mark.parametrize(
    "operation,outcome",
    [
        ("load", "not_started"),
        ("commit", "not_started"),
        ("commit", "rolled_back"),
        ("commit", "committed"),
        ("commit", "unknown"),
    ],
)
@pytest.mark.parametrize("failure_scope", ["stream", "store"])
@pytest.mark.parametrize("raise_on_error", [False, True])
def test_store_failure_classification_table(
    tmp_path, asynchronous, operation, outcome, failure_scope, raise_on_error
):
    class FaultStore(SQLiteInvoiceSyncStore):
        armed = False

        def fault(self):
            self.armed = False
            return KsefSyncStoreError(
                operation=operation, commit_outcome=outcome, failure_scope=failure_scope
            )

        def load(self, scope):
            if self.armed and operation == "load" and scope == sync.streams[0].scope:
                raise self.fault()
            return super().load(scope)

        def commit(self, batch):
            if (
                self.armed
                and operation == "commit"
                and batch.observation_dicts
                and batch.scope == sync.streams[0].scope
            ):
                if outcome in {"committed", "unknown"}:
                    super().commit(batch)  # COMMIT succeeded; receipt was lost.
                elif outcome == "rolled_back":
                    self.connection.execute("BEGIN IMMEDIATE")
                    self.connection.execute("UPDATE invoices SET invoice_hash='rolled-back'")
                    self.connection.rollback()
                raise self.fault()
            return super().commit(batch)

    sync, http = make_sync(
        Server([row()]),
        since="2025-01-01T00:00:00Z",
        subject_types=("Subject1", "Subject2"),
        asynchronous=asynchronous,
    )

    async def run():
        try:
            async with SQLiteHarness(
                tmp_path, asynchronous=asynchronous, store_type=FaultStore
            ) as store:
                assert (await store.run_once(sync)).complete
                previous = await store.load(sync.streams[0].scope)
                # Swap only the synthetic server's data; keep the real persisted checkpoints.
                server = http._client._transport.handler.__self__
                server.rows.append(row("B", H2))
                server.hwm = H2
                await store.call(lambda: setattr(store.store, "armed", True))
                if failure_scope == "store":
                    with pytest.raises(KsefSyncStoreError) as caught:
                        await store.run_once(sync, raise_on_error=raise_on_error)
                    assert caught.value.failure_scope == "store"
                    assert caught.value.commit_outcome == outcome
                    return
                if raise_on_error:
                    with pytest.raises(KsefSyncRunError) as aggregate:
                        await store.run_once(sync, raise_on_error=True)
                    report = aggregate.value.report
                else:
                    report = await store.run_once(sync, raise_on_error=False)
                failed, healthy = report.streams
                assert [failed.status, healthy.status] == ["failed", "completed"]
                assert failed.coverage is None and report.common_coverage is None
                assert failed.original_error.failure_scope == failure_scope
                assert failed.original_error.commit_outcome == outcome
                assert healthy.coverage.to == H2
                loaded = await store.load(sync.streams[0].scope)
                assert loaded.committed_hwm == (
                    H2 if outcome in {"committed", "unknown"} else previous.committed_hwm
                )
                assert await store.sql("SELECT ksef_number FROM invoices ORDER BY ksef_number") == [
                    ("A",),
                    ("B",),
                ]
                # Never blindly retry the unconfirmed write; the next run loads durable state.
                assert (await store.run_once(sync)).complete
        finally:
            await close_http(http, asynchronous)

    asyncio.run(run())


@pytest.mark.parametrize("fault", ["stale_load", "wrong_receipt"])
@pytest.mark.parametrize("raise_on_error", [False, True])
def test_unconfirmed_write_requires_reload(tmp_path, asynchronous, fault, raise_on_error):
    class FaultStore(SQLiteInvoiceSyncStore):
        armed = False
        stale = None

        def load(self, scope):
            if self.armed and fault == "stale_load":
                self.armed = False
                return self.stale
            return super().load(scope)

        def commit(self, batch):
            receipt = super().commit(batch)
            if self.armed and fault == "wrong_receipt":
                self.armed = False
                return replace(receipt, revision=receipt.revision + 1)
            return receipt

    async def run():
        server = Server([row()])
        sync, http = make_sync(server, since="2025-01-01T00:00:00Z", asynchronous=asynchronous)
        try:
            async with SQLiteHarness(
                tmp_path, asynchronous=asynchronous, store_type=FaultStore
            ) as store:
                assert (await store.run_once(sync)).complete
                previous = await store.load(sync.streams[0].scope)
                if fault == "stale_load":
                    fence = sync.streams[0].fence_after_restore(previous, reason="backup_restored")
                    await store.commit(fence)
                server.calls.clear()

                def arm():
                    store.store.armed, store.store.stale = True, previous

                await store.call(arm)
                if raise_on_error:
                    with pytest.raises(KsefSyncRunError) as caught:
                        await store.run_once(sync)
                    report = caught.value.report
                else:
                    report = await store.run_once(sync, raise_on_error=False)
                result = report.streams[0]
                assert result.status == "failed" and result.coverage is None
                assert report.common_coverage is None and not server.calls
                assert isinstance(
                    result.original_error,
                    KsefSyncConflictError if fault == "stale_load" else KsefSyncStoreError,
                )
                # A durable load, not a receipt guess or unconditional retry, resolves the state.
                persisted = await store.load(sync.streams[0].scope)
                assert persisted.revision == previous.revision + 1
                assert (await store.run_once(sync)).complete
                assert await store.sql("SELECT count(*) FROM outbox") == [(1,)]
        finally:
            await close_http(http, asynchronous)

    asyncio.run(run())
