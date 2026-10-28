"""Adversarial regressions from the independent second review pass."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import time
from contextlib import suppress
from copy import deepcopy
from dataclasses import replace
from typing import Any, cast

import httpx
import pytest
from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore

from ksef_client import (
    InvoiceSyncCheckpoint,
    KsefInvalidSyncCheckpointError,
    KsefSyncConflictError,
    KsefSyncError,
    KsefSyncLimitError,
    KsefSyncStateError,
    KsefSyncStoreError,
)
from ksef_client.invoice_sync import _commit_and_drain
from ksef_client.invoice_sync_state import utc_timestamp
from ksef_client.rate_limiting import RequestControl
from tests.test_invoice_sync import H1, Server, database, make_sync, query, row


@pytest.mark.parametrize("change", ["role", "filter", "start", "end", "size", "window", "order"])
def test_source_must_match_complete_scan_identity_before_http(change):
    server = Server()
    sync, http = make_sync(server)
    stream = sync.streams[0]
    original = stream._search_factory

    def wrong_source(payload, **kwargs):
        if change == "role":
            payload = replace(payload, subject_type=query("Subject2").subject_type)
        elif change == "filter":
            payload = replace(payload, invoice_number="other-filter")
        elif change == "start":
            payload = replace(payload, date_range=replace(payload.date_range, from_=H1))
        elif change == "end":
            payload = replace(
                payload, date_range=replace(payload.date_range, to="2025-12-31T00:00:00Z")
            )
        else:
            kwargs[
                {"size": "page_size", "window": "window_days", "order": "sort_order"}[change]
            ] = {"size": 20, "window": 99, "order": "Desc"}[change]
        return original(payload, **kwargs)

    try:
        checkpoint = stream.begin_cycle(None, until=H1).next_checkpoint
        stream._search_factory = wrong_source
        with pytest.raises(KsefInvalidSyncCheckpointError):
            stream.next_batch(checkpoint)
        assert not server.calls
    finally:
        http.close()


def test_pending_async_cancellation_prevents_starting_commit():
    async def run():
        sync, http = make_sync(Server(), asynchronous=True)
        calls = []

        class Store:
            async def load(self, scope):
                return None

            async def commit(self, batch):
                calls.append(batch)
                return batch.receipt

        async def cancelled_before_commit(batch):
            task = asyncio.current_task()
            assert task is not None
            task.cancel()
            await _commit_and_drain(Store(), batch)

        try:
            batch = sync.streams[0].begin_cycle(None, until=H1)
            with pytest.raises(asyncio.CancelledError):
                await asyncio.create_task(cancelled_before_commit(batch))
            assert not calls
        finally:
            await http.aclose()

    asyncio.run(run())


def test_unknown_nested_filter_is_not_silently_dropped():
    sync, http = make_sync(Server())
    try:
        from ksef_client.clients.invoices import InvoicesClient

        typed = replace(query(), amount=cast(Any, {"type": "Gross", "from": 1, "typo": 2}))
        with pytest.raises(ValueError):
            InvoicesClient(http).sync(namespace="n", sync_key="s", context_key="c", queries=[typed])
    finally:
        http.close()


@pytest.mark.parametrize("stamp", ["2024-01-01T00:00:00+01:60", "2024-01-01T00:00:00-00:99"])
def test_sync_timestamp_rejects_invalid_offset_minutes(stamp):
    with pytest.raises(ValueError):
        utc_timestamp(stamp)


def test_interrupt_rolls_back_owned_sqlite_transaction(tmp_path):
    class Interrupted(SQLiteInvoiceSyncStore):
        interrupt = False

        def _execute(self, sql, parameters=()):
            result = super()._execute(sql, parameters)
            if self.interrupt and sql.startswith("INSERT INTO invoices"):
                raise KeyboardInterrupt()
            return result

    store = Interrupted(sqlite3.connect(tmp_path / "sync.db", timeout=2))
    sync, http = make_sync(Server([row()]), since="2025-01-01T00:00:00Z")
    try:
        stream = sync.streams[0]
        batch = stream.begin_cycle(None, until=H1)
        cp = batch.confirm(store.commit(batch))
        store.interrupt = True
        page = stream.next_batch(cp)
        with pytest.raises(KeyboardInterrupt):
            store.commit(page)
        assert not store.connection.in_transaction
        assert store.load(stream.scope) == cp
        assert store.connection.execute("SELECT count(*) FROM invoices").fetchone()[0] == 0
    finally:
        store.connection.close()
        http.close()


def test_sqlite_load_rejects_foreign_transaction_and_closed_commit(tmp_path):
    store = database(tmp_path)
    sync, http = make_sync(Server())
    try:
        batch = sync.streams[0].begin_cycle(None, until=H1)
        store.connection.execute("BEGIN")
        with pytest.raises(KsefSyncStoreError):
            store.load(batch.scope)
        store.connection.rollback()
        store.connection.close()
        with pytest.raises(KsefSyncStoreError) as caught:
            store.commit(batch)
        assert caught.value.commit_outcome == "not_started"
    finally:
        store.connection.close()
        http.close()


def test_load_validation_is_part_of_step_budget(tmp_path, monkeypatch):
    sync, http = make_sync(Server())
    store = database(tmp_path)
    stream = sync.streams[0]
    store.commit(stream.begin_cycle(None, until=H1))
    clock = [100.0]
    calls: list[Any] = []
    original = stream._validate

    def slow_validation(checkpoint, **kwargs):
        original(checkpoint, **kwargs)
        if not calls:
            clock[0] += 2
        calls.append(checkpoint)

    monkeypatch.setattr(stream, "_validate", slow_validation)
    original_check, original_remaining = RequestControl.check, RequestControl.remaining
    try:
        with monkeypatch.context() as context:
            context.setattr(time, "monotonic", lambda: clock[0])
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
                store, time_budget=20, step_time_budget=1, max_pages_per_stream=1
            )
        assert report.streams[0].stop_reason == "step_time_budget"
        assert report.streams[0].pages_committed == 0
    finally:
        store.connection.close()
        http.close()


def test_future_history_of_one_role_does_not_abort_other_roles(tmp_path):
    sync, http = make_sync(
        Server(), queries=[query("Subject1", "2050-01-01T00:00:00Z"), query("Subject2")]
    )
    store = database(tmp_path)
    try:
        report = sync.run_once(store, raise_on_error=False)
        assert [item.status for item in report.streams] == ["failed", "completed"]
        assert isinstance(report.streams[0].original_error, KsefSyncStateError)
    finally:
        store.connection.close()
        http.close()


@pytest.mark.parametrize("origin", ["http", "store"])
def test_safe_report_never_copies_untrusted_exception_reason(tmp_path, origin):
    secret = "postgres://private:token@database/secret"
    server, store = Server(), database(tmp_path)
    sync, http = make_sync(server)

    class UntrustedStore:
        def load(self, scope):
            raise KsefSyncConflictError(secret)

        def commit(self, batch):
            raise AssertionError("Load must fail before commit")

    def handler(request):
        value = {"status": 403, "title": "Forbidden", "detail": "private", "reasonCode": secret}
        return httpx.Response(
            403,
            stream=httpx.ByteStream(json.dumps(value).encode()),
            headers={"Content-Type": "application/json"},
        )

    try:
        http._client._transport.handler = handler
        report = sync.run_once(
            UntrustedStore() if origin == "store" else store, raise_on_error=False
        )
        assert secret not in repr(report) + json.dumps(report.to_dict())
        assert report.streams[0].original_error is not None
    finally:
        store.connection.close()
        http.close()


def test_checkpoint_mutations_never_escape_as_builtin_errors():
    sync, http = make_sync(Server())
    try:
        base = sync.streams[0].begin_cycle(None, until=H1).next_checkpoint.to_dict()
        paths = []

        def walk(node, path=()):
            if isinstance(node, dict):
                for key, value in node.items():
                    paths.append(path + (key,))
                    walk(value, path + (key,))

        walk(base)
        mutations: tuple[Any, ...] = (
            None,
            True,
            False,
            0,
            1,
            1.5,
            "",
            [],
            {},
            [{}],
            {"unknown": 1},
        )
        for path in paths:
            for value in mutations:
                changed = deepcopy(base)
                node = changed
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
                try:
                    restored = InvoiceSyncCheckpoint.from_dict(changed)
                except KsefInvalidSyncCheckpointError:
                    continue
                assert InvoiceSyncCheckpoint.from_json(restored.to_json()) == restored
    finally:
        http.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("reason", ["response_redirect", "response_encoding", "unknown"])
def test_security_policy_rejection_is_not_reported_as_a_size_limit(asynchronous, reason):
    async def run():
        sync, http = make_sync(Server(), asynchronous=asynchronous)
        stream = sync.streams[0]
        original = stream._search_factory

        def factory(*args, **kwargs):
            search = original(*args, **kwargs)

            def reject(cursor):
                from ksef_client import KsefResponseLimitError

                raise KsefResponseLimitError(limit_bytes=16, reason_code=reason)

            async def async_reject(cursor):
                reject(cursor)

            search.observation_page = async_reject if asynchronous else reject
            return search

        try:
            cp = stream.begin_cycle(None, until=H1).next_checkpoint
            stream._search_factory = factory
            with pytest.raises(KsefSyncError) as caught:
                if asynchronous:
                    await stream.next_batch(cp)
                else:
                    stream.next_batch(cp)
            assert not isinstance(caught.value, KsefSyncLimitError)
            assert caught.value.reason_code == (
                reason if reason != "unknown" else "response_rejected"
            )
        finally:
            await http.aclose() if asynchronous else http.close()

    asyncio.run(run())


def test_safe_json_report_includes_individual_confirmed_coverage(tmp_path):
    sync, http = make_sync(Server())
    store = database(tmp_path)
    try:
        report = sync.run_once(store)
        assert report.common_coverage is not None
        assert report.to_dict()["streams"][0]["coverage"] == report.common_coverage.to_dict()
    finally:
        store.connection.close()
        http.close()


@pytest.mark.skipif(sys.platform != "linux", reason="CI process groups require Linux")
@pytest.mark.parametrize("exit_code", [0, 2])
def test_supervisor_reaps_children_after_the_phase_leader_exits(tmp_path, exit_code):
    import sys

    from tests.invoice_sync_supervisor import run_phases

    code = (
        "import subprocess,sys; from pathlib import Path; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "Path('child').write_text(str(p.pid)); sys.exit(" + str(exit_code) + ")"
    )
    if exit_code:
        with pytest.raises(RuntimeError):
            run_phases(
                [[sys.executable, "-c", code]],
                cwd=tmp_path,
                env=dict(os.environ),
                timeout=10,
                grace=0.1,
            )
    else:
        run_phases(
            [[sys.executable, "-c", code]],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=10,
            grace=0.1,
        )
    from tests.invoice_sync_supervisor import linux_process_running

    pid = int((tmp_path / "child").read_text())
    for _ in range(50):
        if not linux_process_running(pid):
            break
        time.sleep(0.01)
    assert not linux_process_running(pid)


@pytest.mark.parametrize("phase", ["body", "eof"])
def test_repeated_async_cancellation_still_finishes_response_cleanup(phase):
    async def run():
        sync, http = make_sync(Server(), asynchronous=True)
        entered, closing, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        class Stream(httpx.AsyncByteStream):
            closed = False

            async def __aiter__(self):
                yield b"x"
                entered.set()
                if phase == "body":
                    await asyncio.Event().wait()

            async def aclose(self):
                closing.set()
                await release.wait()
                self.closed = True

        stream = Stream()

        def handle(request):
            return httpx.Response(200, stream=stream)

        http._client._transport.handler = handle
        task = asyncio.create_task(http.request_json_limited("GET", "/x", max_bytes=100))
        try:
            await entered.wait()
            if phase == "body":
                task.cancel()
            await closing.wait()
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert stream.closed
        finally:
            release.set()
            if not task.done():
                task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            await http.aclose()

    asyncio.run(run())
