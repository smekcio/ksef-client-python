from __future__ import annotations

import asyncio
import base64
import json
import multiprocessing
import os
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore

from ksef_client import InvoiceSyncCheckpoint, KsefSyncConflictError, KsefSyncDataConflictError
from ksef_client.invoice_search import _date
from tests.test_invoice_sync import H1, H2, HASH, Server, database, make_sync, row


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("autocommit", [False, True])
def test_restart_after_every_page_no_early_hwm(tmp_path, mode, autocommit):
    worker = Path(__file__).with_name("invoice_sync_page_worker.py")
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    checkpoints, calls, pids = [], [], []
    cycle_to = None
    for _ in range(30):  # A broken cursor must fail, rather than loop without a bound.
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(worker),
                str(tmp_path),
                mode,
                "autocommit" if autocommit else "default",
            ],
            cwd=tmp_path,
            env=environment,
            check=True,
            timeout=30,
        )
        evidence = json.loads((tmp_path / "page.json").read_text(encoding="utf-8"))
        checkpoint = InvoiceSyncCheckpoint.from_json(evidence["checkpoint"])
        checkpoints.append(checkpoint)
        calls.append(evidence["wire"])
        pids.append(evidence["pid"])
        assert checkpoint.committed_hwm == (H1 if evidence["complete"] else None)
        if checkpoint.active is not None:
            if cycle_to is None:
                cycle_to = checkpoint.active["cycle_to"]
            assert checkpoint.active["cycle_to"] == cycle_to
        if len(checkpoints) > 1:
            previous = checkpoints[-2]
            assert checkpoint.generation_id == previous.generation_id
            assert checkpoint.revision == previous.revision + 1
        if environment.get("KSEF_TEST_INSTALLED") == "1":
            assert (
                Path(__file__).resolve().parents[1] / "src"
                not in Path(evidence["sdk_path"]).resolve().parents
            )
        if evidence["complete"]:
            break
    else:
        pytest.fail("Fresh-process pagination did not terminate")
    assert len(checkpoints) > 8
    assert cycle_to is not None
    assert os.getpid() not in pids  # OS may recycle a PID after an earlier child has exited.
    assert {call[1] for call in calls} >= {0, 1, 2}
    assert len({call[0]["dateRange"]["from"] for call in calls}) > 6
    assert checkpoints[-1].phase == "idle"
    assert all(_date(call[0]["dateRange"]["to"]) <= _date(cycle_to) for call in calls)
    connection = sqlite3.connect(tmp_path / "sync.db", timeout=2)
    try:
        expected = {str(i) for i in range(50)}
        assert {r[0] for r in connection.execute("SELECT ksef_number FROM invoices")} == expected
        assert {
            r[0] for r in connection.execute("SELECT ksef_number FROM invoice_observations")
        } == expected
        assert {r[0] for r in connection.execute("SELECT ksef_number FROM outbox")} == expected
    finally:
        connection.close()


def _race_worker(path, barrier, queue, mode, index):
    store = SQLiteInvoiceSyncStore(sqlite3.connect(path, timeout=5))
    digest = base64.b64encode(bytes([index]) * 32).decode()
    sync, http = make_sync(
        Server([row(hash_=digest)]),
        since="2025-01-01T00:00:00Z",
        sync_key=f"job-{index}" if mode == "hash" else "same-job",
    )
    try:
        stream = sync.streams[0]
        batch = stream.begin_cycle(None, until=H1)
        if mode == "hash":
            checkpoint = batch.confirm(store.commit(batch))
            batch = stream.next_batch(checkpoint)
        barrier.wait(timeout=20)
        try:
            store.commit(batch)
            queue.put("committed")
        except KsefSyncConflictError:
            queue.put("cas_conflict")
        except KsefSyncDataConflictError:
            queue.put("hash_conflict")
    finally:
        http.close()
        store.connection.close()


@pytest.mark.parametrize("mode,expected", [("init", "cas_conflict"), ("hash", "hash_conflict")])
def test_two_processes_contend_atomically(tmp_path, mode, expected):
    connection = sqlite3.connect(tmp_path / "sync.db", timeout=5)
    SQLiteInvoiceSyncStore(connection)
    connection.close()
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=_race_worker, args=(str(tmp_path / "sync.db"), barrier, queue, mode, i)
        )
        for i in range(2)
    ]
    try:
        for process in processes:
            process.start()
        results = sorted(queue.get(timeout=30) for _ in processes)
        for process in processes:
            process.join(timeout=5)
            assert process.exitcode == 0
        assert results == sorted(["committed", expected])
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        queue.close()
        queue.join_thread()
    connection = sqlite3.connect(tmp_path / "sync.db", timeout=5)
    try:
        assert connection.execute("SELECT count(*) FROM invoices").fetchone()[0] == int(
            mode == "hash"
        )
    finally:
        connection.close()


def test_hash_conflict_across_pages_and_fresh_adapter(tmp_path):
    stamp = "2025-01-01T00:00:00Z"
    server = Server(
        [row(str(i), stamp) for i in range(10)]
        + [row("0", stamp, base64.b64encode(b"b" * 32).decode())]
    )
    sync, http = make_sync(server, since=stamp)
    store = database(tmp_path)
    try:
        report = sync.run_once(store, max_pages_per_stream=1)
        assert report.streams[0].pages_committed == 1
        cp = store.load(sync.streams[0].scope)
        store.connection.close()
        store = database(tmp_path)
        other, h2 = make_sync(server, since=stamp, page_size=20, window_days=80)
        try:
            report = other.run_once(store, raise_on_error=False)
            assert isinstance(report.streams[0].original_error, KsefSyncDataConflictError)
            assert store.load(other.streams[0].scope) == cp
            assert server.calls[-1][1:] == (1, 10)
            assert {r[0] for r in store.connection.execute("SELECT ksef_number FROM invoices")} == {
                str(i) for i in range(10)
            }
        finally:
            h2.close()
    finally:
        http.close()
        store.connection.close()


def test_full_replay_keeps_outbox_idempotent(tmp_path):
    sync, http = make_sync(Server([row()]))
    store = database(tmp_path)
    try:
        assert sync.run_once(store).complete
        stream = sync.streams[0]
        cp = store.load(stream.scope)
        replay = stream.restart_backfill(cp, until=H2, reason="operator_replay")
        store.commit(replay)
        assert sync.run_once(store).complete
        assert store.connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == 1
        assert store.connection.execute("SELECT invoice_hash FROM invoices").fetchone()[0] == HASH
    finally:
        http.close()
        store.connection.close()


def test_async_adapter_owns_database_on_worker_thread(tmp_path):
    async def run():
        loop = asyncio.get_running_loop()
        main_thread = threading.get_ident()
        threads = set()
        sync, http = make_sync(Server([row()]), asynchronous=True)
        executor = ThreadPoolExecutor(max_workers=1)

        def create():
            return SQLiteInvoiceSyncStore(sqlite3.connect(tmp_path / "worker.db", timeout=5))

        store = await loop.run_in_executor(executor, create)

        def call(operation, argument):
            threads.add(threading.get_ident())
            return getattr(store, operation)(argument)

        class Adapter:
            async def load(self, scope):
                return await loop.run_in_executor(executor, call, "load", scope)

            async def commit(self, batch):
                return await loop.run_in_executor(executor, call, "commit", batch)

        try:
            assert (await sync.run_once(Adapter())).complete
            assert len(threads) == 1 and main_thread not in threads
        finally:
            await loop.run_in_executor(executor, store.connection.close)
            executor.shutdown(wait=True)
            await http.aclose()

    asyncio.run(run())
