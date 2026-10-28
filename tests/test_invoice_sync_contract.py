from __future__ import annotations

import ast
import asyncio
import os
import sys
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest
from tools.generate_async_facade import Convert, generate

from ksef_client import (
    InvoiceSync,
    InvoiceSyncCheckpoint,
    KsefInvalidSyncCheckpointError,
    KsefRateLimitWaitTimeout,
    KsefSyncLimitError,
)
from ksef_client.async_facade import AsyncInvoices
from ksef_client.clients.invoices import InvoicesClient
from ksef_client.facade import Invoices
from ksef_client.invoice_sync import InvoiceSyncStream
from ksef_client.invoice_sync_state import _walk, utc_timestamp
from tests.invoice_sync_supervisor import linux_process_running, run_phases
from tests.test_invoice_sync import H1, Server, database, make_sync, query


def test_facade_sync_factory_stays_pure_and_generator_rejects_unknown_io():
    calls = []

    def factory(**kwargs):
        calls.append(kwargs)
        return "sync"

    owner = SimpleNamespace(
        context_key="private-context", api=SimpleNamespace(invoices=SimpleNamespace(sync=factory))
    )
    assert (
        Invoices(cast(Any, owner)).sync(namespace="n", sync_key="s", since="2024-01-01T00:00:00Z")
        == "sync"
    )
    assert calls[0]["context_key"] == "private-context"
    assert AsyncInvoices(cast(Any, owner)).sync(namespace="n", sync_key="s", since=H1) == "sync"
    tree = ast.parse(generate())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AsyncInvoices")
    factory_node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "sync")
    assert not any(isinstance(n, ast.Await) for n in ast.walk(factory_node))
    assert factory_node.returns is not None
    assert ast.unparse(factory_node.returns) == "AsyncInvoiceSync"
    with pytest.raises(ValueError, match="Unmapped"):
        Convert().visit(ast.parse("def unknown(self):\n    self.owner.api.invoices.unknown()"))


def test_report_safe_serialization_disjoint_coverage_and_spec_validation(tmp_path):
    server, store = Server(), database(tmp_path)
    sync, http = make_sync(server)
    try:
        report = sync.run_once(store)
        payload = report.to_dict()
        assert payload["complete"] and payload["common_coverage"]["to"] == H1
        assert "Nip:test" not in str(payload) and "tenant" not in str(payload)
        assert payload["streams"][0]["error_code"] is None
        cp = store.load(sync.streams[0].scope)
        assert cp is not None
        with pytest.raises(ValueError):
            InvoiceSyncStream(
                replace(cp.scope, stream_id="0" * 64),
                query(),
                lambda: None,
                page_size=10,
                window_days=100,
            )
        later, h2 = make_sync(server, since="2026-02-01T00:00:00Z")
        try:
            initial = (
                later.streams[0].begin_cycle(None, until="2026-03-01T00:00:00Z").next_checkpoint
            )
            data = initial.to_dict()
            data.update(phase="idle", active=None, committed_hwm="2026-03-01T00:00:00Z")
            later_cp = InvoiceSyncCheckpoint.from_dict(data)
            # Compare covers for distinct role specifications.
            q = query("Subject2", "2026-02-01T00:00:00Z")
            from ksef_client.invoice_sync_state import canonical_spec, spec_fingerprint

            spec = canonical_spec(q)
            scope = replace(later_cp.scope, stream_id=spec_fingerprint(spec))
            data.update(spec=spec, scope=scope.to_dict())
            later_cp = InvoiceSyncCheckpoint.from_dict(data)
            other = InvoiceSyncStream(
                scope, q, later.streams[0]._search_factory, page_size=10, window_days=100
            )
            both = InvoiceSync((sync.streams[0], other))
            assert both.describe((cp, later_cp)).common_coverage is None
        finally:
            h2.close()
    finally:
        http.close()
        store.connection.close()


def test_validation_extremes_and_unexpected_deadline(tmp_path):
    sync, http = make_sync(Server())
    store = database(tmp_path)
    try:
        with pytest.raises(ValueError):
            InvoicesClient(cast(Any, http)).sync(namespace="n", sync_key="s", context_key="c")
        with pytest.raises(ValueError):
            sync.run_once(store, time_budget=10**10000)
        with pytest.raises(ValueError):
            sync.streams[0].begin_cycle(None, until="2023-01-01T00:00:00Z")
        with pytest.raises(ValueError):
            KsefSyncLimitError(limit_stage="unknown", limit_bytes=1)
        with pytest.raises(ValueError):
            _walk({str(i): i for i in range(4)}, max_nodes=4)
        cp = sync.streams[0].begin_cycle(None, until=H1).next_checkpoint
        data = cp.to_dict()
        data["generation_id"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        with pytest.raises(KsefInvalidSyncCheckpointError):
            InvoiceSyncCheckpoint.from_dict(data)
        with pytest.raises(KsefInvalidSyncCheckpointError):
            InvoiceSyncCheckpoint(cast(Any, "wrong type"))
        with pytest.raises(KsefInvalidSyncCheckpointError):
            InvoiceSyncCheckpoint.from_json("\ud800")
        assert utc_timestamp("0001-01-01T00:00:00Z").startswith("0001-")

        class EarlyTimeout:
            def load(self, scope):
                raise KsefRateLimitWaitTimeout("not an expired SDK deadline")

            def commit(self, batch):
                raise AssertionError("Load must fail before commit")

        with pytest.raises(KsefRateLimitWaitTimeout):
            sync.run_once(EarlyTimeout(), raise_on_error=False)

        class CancelledStore:
            def load(self, scope):
                raise asyncio.CancelledError()

            def commit(self, batch):
                raise AssertionError("Load must fail before commit")

        with pytest.raises(asyncio.CancelledError):
            sync.run_once(CancelledStore())
    finally:
        http.close()
        store.connection.close()


def test_async_idle_and_bounded_limit():
    async def run():
        sync, http = make_sync(Server(), asynchronous=True)
        try:
            stream = sync.streams[0]
            cp = stream.begin_cycle(None, until=H1).next_checkpoint
            data = cp.to_dict()
            data.update(phase="idle", active=None, committed_hwm=H1)
            assert await stream.next_batch(InvoiceSyncCheckpoint.from_dict(data)) is None
            original = stream._search_factory

            def factory(*args, **kwargs):
                search = original(*args, **kwargs)

                async def too_big(cursor):
                    from ksef_client import KsefResponseLimitError

                    raise KsefResponseLimitError(limit_bytes=2)

                search.observation_page = too_big
                return search

            stream._search_factory = factory
            with pytest.raises(KsefSyncLimitError):
                await stream.next_batch(cp)
        finally:
            await http.aclose()

    asyncio.run(run())


def test_canonical_checkpoint_limit_after_unicode_expansion():
    import json

    from ksef_client.invoice_sync_state import MAX_CHECKPOINT_BYTES

    sync, http = make_sync(Server())
    try:
        data = sync.streams[0].begin_cycle(None, until=H1).next_checkpoint.to_dict()
        data["scope"]["context_key"] = "\u0105" * 4096
        data["active"]["cursor"] = "\\" * (2 * 1024 * 1024 - 10000)
        raw = json.dumps(data, ensure_ascii=False).encode()
        assert len(raw) <= MAX_CHECKPOINT_BYTES
        for action in (
            lambda: InvoiceSyncCheckpoint.from_dict(data),
            lambda: InvoiceSyncCheckpoint.from_json(raw),
        ):
            with pytest.raises(KsefInvalidSyncCheckpointError) as caught:
                action()
            assert caught.value.reason_code == "checkpoint_size_limit"
    finally:
        http.close()


def test_async_expected_store_error_remains_per_stream():
    from ksef_client import KsefSyncStoreError

    async def run():
        sync, http = make_sync(Server(), asynchronous=True)

        class Store:
            async def load(self, scope):
                raise KsefSyncStoreError(operation="load", failure_scope="stream")

            async def commit(self, batch):
                raise AssertionError("Load must fail before commit")

        try:
            report = await sync.run_once(Store(), raise_on_error=False)
            assert report.streams[0].status == "failed"
            assert report.to_dict()["streams"][0]["error_code"] == "sync_store_error"
        finally:
            await http.aclose()

    asyncio.run(run())


def test_coordinators_reject_streams_from_the_other_execution_mode():
    from ksef_client import AsyncInvoiceSync

    sync, http = make_sync(Server())
    asynchronous, async_http = make_sync(Server(), asynchronous=True)
    try:
        with pytest.raises(TypeError):
            InvoiceSync(cast(Any, asynchronous.streams))
        with pytest.raises(TypeError):
            AsyncInvoiceSync(cast(Any, sync.streams))
    finally:
        http.close()
        asyncio.run(async_http.aclose())


def test_live_poll_waits_for_hwm_and_preserves_other_failures():
    from ksef_client import KsefIncompletePaginationError
    from ksef_client.invoice_search import InvoiceMetadataObservationPage
    from tests.invoice_sync_live_worker import find_at_hwm
    from tests.test_invoice_sync import row

    class Scan:
        def __init__(self, reason=None):
            self.reason = reason

        def observation_page(self, cursor):
            if self.reason:
                raise KsefIncompletePaginationError(self.reason, last_cursor="private")
            return InvoiceMetadataObservationPage(
                (row(),) if cursor is None else (), "next" if cursor is None else None, H1
            )

    assert find_at_hwm(Scan("hwm_before_start"), "A") == (None, None)
    invoice, hwm = find_at_hwm(Scan(), "A")
    assert invoice.ksef_number == "A" and hwm == H1
    with pytest.raises(KsefIncompletePaginationError):
        find_at_hwm(Scan("repeated_page"), "A")


def test_live_wire_bounds_validate_windows_and_hwm_clipping():
    from ksef_client import models as m
    from tests.invoice_sync_live_worker import check_wire_bounds
    from tests.test_invoice_sync import row

    scan = replace(query().date_range, to=H1)
    wire = replace(
        query(),
        date_range=replace(
            query().date_range, from_="2025-01-01T00:00:00Z", to="2025-01-02T00:00:00Z"
        ),
    )
    response = m.QueryInvoicesMetadataResponse(
        invoices=[row()],
        has_more=False,
        is_truncated=False,
        permanent_storage_hwm_date="2025-01-01T12:00:00Z",
    )
    check_wire_bounds(scan, wire, response)
    with pytest.raises(AssertionError):
        check_wire_bounds(scan, replace(wire, date_range=replace(wire.date_range, to=H1)), response)
    with pytest.raises(AssertionError):
        check_wire_bounds(
            scan, wire, replace(response, invoices=[row(date="2025-01-01T12:00:00.0000001Z")])
        )


def test_supervisor_success_failure_and_shared_timeout(tmp_path):
    run_phases([[sys.executable, "-c", "pass"]] * 2, cwd=tmp_path, env=dict(os.environ), timeout=10)
    with pytest.raises(RuntimeError, match="private output withheld"):
        run_phases(
            [[sys.executable, "-c", "raise SystemExit(2)"]],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=10,
        )
    with pytest.raises(TimeoutError):
        run_phases(
            [[sys.executable, "-c", "import time; time.sleep(10)"]],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=0.2,
            grace=1,
        )
    with pytest.raises(TimeoutError):
        run_phases([[sys.executable, "-c", "pass"]], cwd=tmp_path, env=dict(os.environ), timeout=0)


@pytest.mark.skipif(sys.platform != "linux", reason="CI process-group watchdog runs on Linux")
def test_supervisor_kills_descendants_which_ignore_sigterm(tmp_path):
    import time

    code = (
        "import os,signal,subprocess,sys,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "p=subprocess.Popen([sys.executable,'-c',"
        "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)']); "
        "Path('pids').write_text(str(os.getpid())+' '+str(p.pid)); time.sleep(60)"
    )
    with pytest.raises(TimeoutError):
        run_phases(
            [[sys.executable, "-c", code]], cwd=tmp_path, env=dict(os.environ), timeout=1, grace=0.1
        )
    pids = (tmp_path / "pids").read_text().split()
    for _ in range(50):
        alive = [pid for pid in pids if linux_process_running(int(pid))]
        if not alive:
            break
        time.sleep(0.01)
    assert not alive
