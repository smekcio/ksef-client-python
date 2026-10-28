from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace
from typing import Any
from unittest.mock import Mock

import httpx
import pytest

from ksef_client import (
    InvoiceSyncCheckpoint,
    KsefInvalidSyncCheckpointError,
    KsefSyncError,
    KsefSyncStateError,
    KsefSyncStoreError,
)
from ksef_client import models as m
from ksef_client._json_bounds import check_json_structure
from ksef_client.invoice_search import _InvalidMetadataResponse
from ksef_client.invoice_sync_state import begin_cycle, make_batch
from ksef_client.rate_limiting import RequestControl
from tests.invoice_sync_store_harness import SQLiteHarness
from tests.test_invoice_sync import H1, H2, Server, make_sync, row


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_dense_metadata_page_fits_structural_budget_and_commits(tmp_path, asynchronous):
    # Match the benchmark's dense page: 250 invoices with 100 named third subjects each.
    thirds = [
        m.InvoiceMetadataThirdSubject.from_dict(
            {
                "identifier": {"type": "Nip", "value": "1234567890"},
                "role": 2,
                "name": "x" * 512,
            }
        )
        for _ in range(100)
    ]
    rows = [
        replace(
            row(f"invoice-{index:09}", "2025-01-01T00:00:00Z"),
            invoice_number="benchmark",
            third_subjects=thirds,
        )
        for index in range(250)
    ]

    async def run():
        hwm = "2025-01-01T00:00:02Z"
        sync, http = make_sync(
            Server(rows, hwm=hwm),
            asynchronous=asynchronous,
            since="2025-01-01T00:00:00Z",
            page_size=250,
        )
        try:
            async with SQLiteHarness(tmp_path, asynchronous=asynchronous) as store:
                report = await store.run_once(sync, max_pages_per_stream=1)
                assert report.complete and report.streams[0].coverage.to == hwm
                result = report.streams[0]
                assert result.pages_committed == 1 and result.records_delivered == 250
                count, metadata_bytes = (
                    await store.sql(
                        "SELECT count(*), sum(length(metadata_json)) FROM invoice_observations"
                    )
                )[0]
                assert count == 250 and metadata_bytes > 14_000_000
                stored = await store.sql("SELECT metadata_json FROM invoice_observations LIMIT 1")
                sample = json.loads(stored[0][0])
                assert len(sample["thirdSubjects"]) == 100
                assert sample["thirdSubjects"][-1]["name"] == "x" * 512
        finally:
            await http.aclose() if asynchronous else http.close()

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_slow_load_retains_verified_coverage(tmp_path, monkeypatch, asynchronous):
    async def run():
        sync, http = make_sync(
            Server(), asynchronous=asynchronous, subject_types=("Subject1", "Subject2")
        )
        clock = [100.0]
        try:
            async with SQLiteHarness(tmp_path, asynchronous=asynchronous) as store:
                assert (await store.run_once(sync)).complete
                previous = await store.load(sync.streams[0].scope)
                original_load = store.store.load

                def slow_load(scope):
                    cp = original_load(scope)
                    if scope == sync.streams[0].scope:
                        clock[0] += 2
                    return cp

                monkeypatch.setattr(store.store, "load", slow_load)
                check, remaining = RequestControl.check, RequestControl.remaining
                with monkeypatch.context() as context:
                    context.setattr(time, "monotonic", lambda: clock[0])
                    context.setattr(
                        RequestControl,
                        "check",
                        lambda self, **kw: check(self, clock=lambda: clock[0]),
                    )
                    context.setattr(
                        RequestControl,
                        "remaining",
                        lambda self, **kw: remaining(self, clock=lambda: clock[0]),
                    )
                    report = await store.run_once(sync, time_budget=10, step_time_budget=1)
                slow, healthy = report.streams
                assert slow.status == "partial" and slow.stop_reason == "step_time_budget"
                assert slow.coverage.to == H1 and report.common_coverage.to == H1
                assert slow.observed_revision == previous.revision
                assert slow.observed_generation == previous.generation_id
                assert slow.observed_at is not None and healthy.status == "completed"
        finally:
            await http.aclose() if asynchronous else http.close()

    asyncio.run(run())


def test_describe_identifies_new_scopes_and_exception_exports():
    from ksef_client import exceptions

    sync, http = make_sync(Server())
    try:
        assert sync.describe([None]).new_streams == (sync.streams[0].scope,)
        public = {
            name
            for name, value in vars(exceptions).items()
            if name.startswith("Ksef") and isinstance(value, type)
        }
        assert public <= set(exceptions.__all__)
    finally:
        http.close()


@pytest.mark.parametrize(
    "number",
    [float("inf"), -float("inf"), float("nan")],
    ids=["positive-infinity", "negative-infinity", "nan"],
)
def test_non_finite_metadata_is_invalid_not_oversized(number):
    sync, http = make_sync(Server())
    try:
        cp = sync.streams[0].begin_cycle(None, until=H1).next_checkpoint
        with pytest.raises(KsefSyncError) as caught:
            make_batch(cp, cp.to_dict(), observations=(replace(row(), gross_amount=number),))
        assert caught.value.reason_code == "invalid_metadata"
    finally:
        http.close()


def test_receipt_type_and_pure_transition_identity_are_fail_closed():
    sync, http = make_sync(Server())
    try:
        stream = sync.streams[0]
        batch = stream.begin_cycle(None, until=H1)
        cp = batch.next_checkpoint
        with pytest.raises(KsefSyncStoreError) as caught:
            batch.confirm(replace(batch.receipt, revision=2))
        assert caught.value.commit_outcome == "unknown"
        with pytest.raises(KsefInvalidSyncCheckpointError) as invalid:
            InvoiceSyncCheckpoint.from_json(bytearray(b"{}"))  # type: ignore[arg-type]
        assert invalid.value.reason_code == "invalid_checkpoint"
        data = cp.to_dict()
        data["scope"]["namespace"] = "another-tenant"
        with pytest.raises(KsefSyncStateError):
            make_batch(cp, data)
        idle = cp.to_dict()
        idle.update(phase="idle", active=None, committed_hwm=H1)
        idle = InvoiceSyncCheckpoint.from_dict(idle)
        with pytest.raises(KsefSyncStateError):
            begin_cycle(
                replace(stream.scope, namespace="another-tenant"),
                cp.spec,
                idle,
                until=H2,
                page_size=10,
                window_days=100,
            )
    finally:
        http.close()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_wrong_store_mode_is_a_clear_programming_error(asynchronous):
    async def run():
        server = Server()
        sync, http = make_sync(server, asynchronous=asynchronous)

        class AsyncStore:
            async def load(self, scope):
                return None

            async def commit(self, batch):
                raise AssertionError("No commit allowed")

        wrong = Mock(load=Mock(return_value=None), commit=Mock()) if asynchronous else AsyncStore()
        try:
            with pytest.raises(TypeError, match="store"):
                result = sync.run_once(wrong, raise_on_error=False)
                if asynchronous:
                    await result
            assert not server.calls
        finally:
            await http.aclose() if asynchronous else http.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "body",
    [
        b'{"x":["[{}]", "escaped\\"quote", "backslash\\\\", 1e99]}',
        json.dumps({"name": "a" * (1024 * 1024)}).encode(),
    ],
    ids=["escapes-and-scalars", "large-legal-string"],
)
def test_preflight_counts_structure_without_decoding_strings(body):
    check_json_structure(body, max_nodes=20, max_depth=3)
    assert isinstance(json.loads(body), dict)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("attack", ["nodes", "depth"])
def test_response_structure_rejected_before_json_loads(monkeypatch, asynchronous, attack):
    import ksef_client.clients.invoices as module

    body = b"[" + b"{}," * 500_001 + b"{}]" if attack == "nodes" else b"[" * 33 + b"0" + b"]" * 33

    class Http:
        api_base_url = "https://example.test/v2"

        def request_json_limited(self, *args, **kwargs):
            return httpx.Response(200, content=body)

    async def run():
        from tests.test_invoice_sync import query

        http: Any = Http()
        if asynchronous:
            original = http.request_json_limited

            async def request(*args, **kwargs):
                return original(*args, **kwargs)

            http.request_json_limited = request
        api: Any = (module.AsyncInvoicesClient if asynchronous else module.InvoicesClient)(http)
        decoder = Mock(side_effect=AssertionError("Decoder must not allocate the object graph"))
        monkeypatch.setattr(module.json, "loads", decoder)
        with pytest.raises(_InvalidMetadataResponse):
            result = api._query_invoice_metadata_observation_page(
                replace(
                    query(start="2025-12-31T00:00:00Z"),
                    date_range=replace(
                        query().date_range,
                        from_="2025-12-31T00:00:00Z",
                        to=H1,
                    ),
                ),
                page_offset=0,
                page_size=10,
                sort_order="Asc",
                expected_environment=http.api_base_url,
            )
            if asynchronous:
                await result
        decoder.assert_not_called()

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["missing", "denied", "timeout"])
def test_windows_supervisor_falls_back_to_process_kill(monkeypatch, failure):
    import subprocess
    from types import SimpleNamespace

    from tests import invoice_sync_supervisor as module

    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    error = (
        FileNotFoundError()
        if failure == "missing"
        else (
            PermissionError() if failure == "denied" else subprocess.TimeoutExpired("taskkill", 0.1)
        )
    )
    monkeypatch.setattr(module.subprocess, "run", Mock(side_effect=error))
    process = Mock(pid=1234, poll=Mock(return_value=None))
    module._stop(process, 0.1)
    process.kill.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=0.1)


@pytest.mark.parametrize("body", [b"\x00", b"]", b"{]", b'"unfinished', b"["])
def test_preflight_malformed_input_is_rejected(body):
    with pytest.raises(ValueError):
        check_json_structure(body, max_nodes=10, max_depth=3)


def test_preflight_exact_node_depth_budgets():
    body = b'{"x":[{}]}'
    check_json_structure(body, max_nodes=4, max_depth=3)
    with pytest.raises(ValueError, match="node"):
        check_json_structure(body, max_nodes=3, max_depth=3)
    with pytest.raises(ValueError, match="depth"):
        check_json_structure(body, max_nodes=4, max_depth=2)


def test_direct_checkpoint_limit_and_batch_count_fallback():
    from ksef_client.invoice_sync_state import MAX_CHECKPOINT_BYTES

    with pytest.raises(KsefInvalidSyncCheckpointError) as caught:
        InvoiceSyncCheckpoint(b"x" * (MAX_CHECKPOINT_BYTES + 1))
    assert caught.value.reason_code == "checkpoint_size_limit"
    sync, http = make_sync(Server())
    try:
        cp = sync.streams[0].begin_cycle(None, until=H1).next_checkpoint
        batch = make_batch(cp, cp.to_dict(), observations=(row(),))
        assert batch.observation_count == 1
        assert replace(batch, _record_count=None).observation_count == 1
    finally:
        http.close()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_error_response_structure_is_checked_before_decoding(monkeypatch, asynchronous):
    from ksef_client import KsefClientOptions
    from ksef_client.exceptions import KsefHttpError
    from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient
    from tests.test_bounded_http import Body

    body = b"[" * 33 + b"0" + b"]" * 33
    decoder = Mock(side_effect=AssertionError("Error JSON graph must not be allocated"))
    monkeypatch.setattr(httpx.Response, "json", decoder)

    async def run():
        client: Any = (AsyncBaseHttpClient if asynchronous else BaseHttpClient)(
            KsefClientOptions(base_url="https://example.test/v2"),
        )
        await client.aclose() if asynchronous else client.close()
        client._client = (httpx.AsyncClient if asynchronous else httpx.Client)(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    429,
                    headers={"Content-Type": "application/json"},
                    stream=Body([body]),
                )
            ),
        )
        try:
            with pytest.raises(KsefHttpError):
                response = client.request_json_limited("GET", "/x", max_bytes=4096)
                if asynchronous:
                    await response
            decoder.assert_not_called()
        finally:
            await client.aclose() if asynchronous else client.close()

    asyncio.run(run())


def test_store_validation_rejects_wrapped_awaitable_and_missing_operations():
    sync, http = make_sync(Server())
    try:
        with pytest.raises(TypeError, match="callable"):
            sync.run_once(object())

        async def load(scope):
            return None

        # Ordinary def wrappers returning a coroutine are legal in async, not sync.
        store = Mock(load=lambda scope: load(scope), commit=Mock())
        with pytest.raises(TypeError, match="synchronous"):
            sync.run_once(store)
    finally:
        http.close()


def test_invalid_hwm_and_cached_summary_do_not_parse_large_snapshot(monkeypatch):
    from ksef_client import invoice_sync_state as module

    sync, http = make_sync(Server())
    try:
        stream = sync.streams[0]
        cp = stream.begin_cycle(None, until=H1).next_checkpoint
        with pytest.raises(KsefSyncError) as caught:
            stream._advance(cp, Mock(next_cursor=None, permanent_storage_hwm_date="2026-01-01"))
        assert caught.value.reason_code == "invalid_hwm"
        monkeypatch.setattr(module, "_loads", Mock(side_effect=AssertionError("No reparse")))
        assert cp.scope == stream.scope and cp.phase == "active" and cp.revision == 1
        assert cp.generation_id and cp.last_commit_id and cp.committed_hwm is None
    finally:
        http.close()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_rate_capacity_failure_is_a_global_abort(tmp_path, asynchronous):
    from ksef_client import KsefRateLimitCapacityError

    async def run():
        server = Server()
        sync, http = make_sync(
            server, asynchronous=asynchronous, subject_types=("Subject1", "Subject2")
        )
        requests = []

        def fail(request):
            requests.append(json.loads(request.content)["subjectType"])
            raise KsefRateLimitCapacityError("Shared accounting limit reached")

        http._client._transport.handler = fail
        try:
            async with SQLiteHarness(tmp_path, asynchronous=asynchronous) as store:
                with pytest.raises(KsefRateLimitCapacityError):
                    await store.run_once(sync, raise_on_error=False)
                assert requests == ["Subject1"]
        finally:
            await http.aclose() if asynchronous else http.close()

    asyncio.run(run())
