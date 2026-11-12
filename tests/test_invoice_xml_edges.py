from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from dataclasses import replace
from typing import Any, cast
from unittest.mock import Mock

import httpx
import pytest

from ksef_client import (
    CancellationToken,
    FileInvoiceXmlStore,
    InvoiceXmlKey,
    KsefRequestCancelledError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
    request_control,
)
from ksef_client.invoice_xml_sync import AsyncInvoiceXmlSync, InvoiceXmlSync, _drive
from ksef_client.invoice_xml_types import positive
from ksef_client.sqlite_store import _selection
from tests.test_invoice_sync import Server, make_sync, row
from tests.test_invoice_xml_sync import HASH, NUMBER, XML, call, environment


@pytest.mark.parametrize("value", [0, -1, True, float("nan"), float("inf"), "1"])
def test_invalid_numeric_limits(value):
    with pytest.raises(ValueError):
        positive(value, "budget")


def test_identity_selection_and_variant_validation():
    with pytest.raises(ValueError):
        InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER, "unknown")
    with pytest.raises(ValueError):
        _selection([])
    sync, http = make_sync(Server())
    try:
        scope = sync.streams[0].scope
        with pytest.raises(ValueError):
            _selection([scope, replace(scope, namespace="other")])
    finally:
        http.close()


def test_worker_config_and_changed_source(tmp_path):
    metadata, http = make_sync(Server())
    try:
        from ksef_client.clients.invoices import InvoicesClient

        api = InvoicesClient(http)
        with pytest.raises(TypeError):
            InvoiceXmlSync(cast(Any, None), api)
        with pytest.raises(TypeError):
            AsyncInvoiceXmlSync(metadata, api)
        with pytest.raises(ValueError):
            api.xml_sync(metadata, lease_seconds=60)
        bad = replace(metadata.streams[0].scope, environment="0" * 64)
        original = metadata.streams[0]._scope
        metadata.streams[0]._scope = bad
        with pytest.raises(ValueError):
            api.xml_sync(metadata)
        metadata.streams[0]._scope = original
        worker = api.xml_sync(metadata)
        with (
            FileInvoiceXmlStore(tmp_path / "xml") as storage,
            SQLiteInvoiceSyncStore.open(tmp_path / "db") as store,
        ):
            with pytest.raises(KsefXmlStorageError):
                worker.run_once(store, storage)
            with pytest.raises(TypeError):
                worker.run_once(store, storage, raise_on_error=cast(Any, 1))
    finally:
        http.close()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_own_deadline_returns_partial_and_parent_deadline_escapes(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous, document_time_budget=0.01) as (
            sync,
            store,
            storage,
            server,
        ):
            await call(sync.metadata.run_once, store)
            original = server.reply

            def slow(request):
                time.sleep(0.025)
                return original(request)

            server.reply = slow
            report = await call(sync.xml.run_once, store, storage, time_budget=1)
            assert report.stop_reason in (None, "time_budget") and report.retry_wait == 1
            token = CancellationToken()
            token.cancel()
            with pytest.raises(KsefRequestCancelledError):
                await call(sync.xml.run_once, store, storage, cancellation=token)
            from ksef_client import KsefRateLimitWaitTimeout

            with request_control(timeout_seconds=0.01), pytest.raises(KsefRateLimitWaitTimeout):
                # Entry/claim checks must propagate a parent's deadline rather than
                # presenting its interruption as successful bounded work.
                time.sleep(0.02)
                await call(sync.xml.run_once, store, storage)

    asyncio.run(run())


def test_metadata_concurrent_change_invalidates_combined_completion(tmp_path):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            original = storage.put_verified

            def advance(*args):
                result = original(*args)
                sync.metadata.run_once(store)
                return result

            storage.put_verified = advance
            report = sync.run_once(store, storage)
            assert report.xml.ready == 1 and report.metadata_changed and not report.complete

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_metadata_failure_does_not_hide_xml_queue(tmp_path, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            await call(sync.metadata.run_once, store)
            server.forbidden.add("Subject1")
            from ksef_client import KsefXmlRunError

            with pytest.raises(KsefXmlRunError) as caught:
                await call(sync.run_once, store, storage)
            assert caught.value.report.xml.ready == 1
            assert caught.value.report.metadata.streams[0].status == "failed"

    asyncio.run(run())


def test_lease_lost_while_publishing_cannot_ack(tmp_path):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            original = storage.put_verified

            def fence(*args):
                receipt = original(*args)
                store.fence_workers()
                return receipt

            storage.put_verified = fence
            report = sync.run_once(store, storage, max_documents=1)
            assert report.xml.stop_reason == "lease_lost" and report.xml.pending == 1

    asyncio.run(run())


def test_store_input_guards_and_unsupported_version(tmp_path):
    with pytest.raises(ValueError):
        SQLiteInvoiceSyncStore.open(tmp_path / "bad", enqueue_xml=True)
    with SQLiteInvoiceSyncStore.open(
        tmp_path / "db", enqueue_xml=True, xml_storage_id="files"
    ) as store:
        metadata, http = make_sync(Server([row(NUMBER, hash_=HASH)]))
        try:
            metadata.run_once(store)
            scopes = [metadata.streams[0].scope]
            for limit in (0, 1001):
                with pytest.raises(ValueError):
                    store.list_xml(scopes, limit=limit)
            with pytest.raises(ValueError):
                store.retry_blocked(scopes, reason="")
            claim = store.claim_xml(scopes, lease_seconds=120)
            assert claim is not None
            with pytest.raises(ValueError):
                store.defer_xml(claim, reason="private-server-message", delay=0)
            store.connection.execute("UPDATE xml_store_meta SET version=99")
            store.connection.commit()
        finally:
            http.close()
    with pytest.raises(KsefXmlStorageError):
        SQLiteInvoiceSyncStore.open(tmp_path / "db")
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE example(value TEXT)")
    connection.execute("INSERT INTO example VALUES('active')")
    with pytest.raises(ValueError):
        SQLiteInvoiceSyncStore(connection)
    with pytest.raises(ValueError):
        SQLiteInvoiceSyncStore.migrate_legacy_example(connection, xml_storage_id="x")
    connection.close()


def test_file_size_receipt_and_identifier_are_validated(tmp_path):
    with FileInvoiceXmlStore(tmp_path / "xml") as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        storage.put_verified(key, XML, HASH)
        with pytest.raises(ValueError):
            storage.cleanup_staging(older_than=1)
    (tmp_path / "xml" / ".storage-id").write_text("invalid")
    with pytest.raises(KsefXmlStorageError):
        FileInvoiceXmlStore(tmp_path / "xml")


def test_bad_sync_async_adapter_modes_close_coroutines():
    async def later():
        return None

    actor = Mock()
    actor.operation = later

    def machine():
        yield ("store", "operation", (), {})

    with pytest.raises(TypeError):
        _drive(machine(), {"store": actor})


def test_public_facade_factories_sync_async(tmp_path):
    from ksef_client.async_facade import AsyncInvoices
    from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
    from ksef_client.facade import Invoices

    async def run():
        for asynchronous in (False, True):
            metadata, http = make_sync(Server(), asynchronous=asynchronous)
            try:
                api = (AsyncInvoicesClient if asynchronous else InvoicesClient)(http)
                owner = Mock(context_key="Nip:test", api=Mock(invoices=api))
                branch = (AsyncInvoices if asynchronous else Invoices)(owner)
                docs = branch.sync_documents(
                    namespace="tenant",
                    sync_key="job",
                    since="2024-01-01T00:00:00Z",
                    subject_types=("Subject1",),
                )
                assert docs.xml.scopes
                assert branch.xml_sync(metadata).scopes == docs.xml.scopes
                owner.context_key = "different"
                with pytest.raises(ValueError):
                    branch.xml_sync(metadata)
            finally:
                await call(http.aclose if asynchronous else http.close)

    asyncio.run(run())


def test_backfill_report_json():
    from ksef_client.invoice_xml_types import InvoiceXmlBackfillReport

    assert json.loads(json.dumps(InvoiceXmlBackfillReport(3, False).to_dict())) == {
        "processed": 3,
        "complete": False,
    }


@pytest.mark.parametrize("bad_scope", [False, True])
def test_malformed_claim_rejected_before_http(tmp_path, monkeypatch, bad_scope):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, server):
            sync.metadata.run_once(store)
            claim = store.claim_xml(sync.xml.scopes, lease_seconds=120)
            store.fence_workers()
            malformed = (
                replace(claim, key=replace(claim.key, namespace="other")) if bad_scope else "bad"
            )
            monkeypatch.setattr(store, "claim_xml", lambda *a, **k: malformed)
            with pytest.raises(KsefXmlStorageError):
                sync.xml.run_once(store, storage)
            assert server.downloads == 0

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_total_budget_exhausted_during_metadata(tmp_path, monkeypatch, asynchronous):
    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, _):
            initial = await call(sync.metadata.run_once, store)
            if asynchronous:

                async def async_slow(*args, **kwargs):
                    await asyncio.sleep(0.02)
                    return initial
            else:

                def sync_slow(*args, **kwargs):
                    time.sleep(0.02)
                    return initial

            callback = async_slow if asynchronous else sync_slow
            monkeypatch.setattr(sync.metadata, "run_once", callback)
            result = await call(sync.run_once, store, storage, time_budget=0.01)
            assert result.xml.stop_reason == "time_budget" and result.xml.pending == 1
            with pytest.raises(TypeError):
                await call(sync.run_once, store, storage, raise_on_error="invalid")

    asyncio.run(run())


def test_recovered_document_still_obeys_size_limit(tmp_path):
    async def run():
        async with environment(tmp_path, False, max_xml_bytes=1) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            claim = store.claim_xml(sync.xml.scopes, lease_seconds=120)
            storage.put_verified(claim.key, XML, HASH)
            store.fence_workers()
            report = sync.xml.run_once(store, storage, raise_on_error=False)
            assert report.blocked == 1 and report.recovered == 0

    asyncio.run(run())


def test_async_worker_rejects_sync_adapter(tmp_path):
    async def run():
        async with environment(tmp_path, True) as (sync, _, storage, _):
            store = Mock()
            store.validate_xml.return_value = None
            with pytest.raises(TypeError):
                await sync.xml.run_once(store, storage)

    asyncio.run(run())


def test_queue_failure_is_not_classified_as_document_http(tmp_path, monkeypatch):
    from ksef_client.exceptions import KsefHttpError

    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)

            def fail(*args, **kwargs):
                raise KsefHttpError(500, "queue backend failure")

            monkeypatch.setattr(store, "claim_xml", fail)
            with pytest.raises(KsefHttpError):
                sync.xml.run_once(store, storage)

    asyncio.run(run())


def test_overflow_budget_rejected():
    with pytest.raises(ValueError):
        positive(10**10000, "budget")


def test_availability_backoff_grows_without_exhausting_retries(tmp_path, monkeypatch):
    from ksef_client.exceptions import KsefHttpError
    from ksef_client.invoice_xml_sync import _failure

    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, _):
            sync.metadata.run_once(store)
            claim = store.claim_xml(sync.xml.scopes, lease_seconds=120)
            error = KsefHttpError(429, "rate limited")
            monkeypatch.setattr("ksef_client.invoice_xml_sync.random.uniform", lambda a, b: 1.2)
            first = _failure(error, claim, 12)
            later = _failure(error, replace(claim, attempts=20), 12)
            assert later["delay"] > first["delay"]
            assert later["delay"] == 3600 and not later["blocked"] and not later["failure"]

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_deadline_inside_http_retry_preserves_entire_server_cooldown(tmp_path, asynchronous):
    from ksef_client import RetryConfig

    async def run():
        async with environment(tmp_path, asynchronous, document_time_budget=0.02) as (
            sync,
            store,
            storage,
            server,
        ):
            await call(sync.metadata.run_once, store)
            sync.xml.client._http._options = replace(
                sync.xml.client._http._options, retry=RetryConfig(max_retries=1)
            )
            server.reply = lambda request: httpx.Response(
                429, stream=httpx.ByteStream(b"{}"), headers={"Retry-After": "86400"}
            )
            report = await call(sync.xml.run_once, store, storage)
            rows = await call(store.list_xml, sync.xml.scopes)
            assert report.retry_wait == 1 and report.errors == 1
            assert rows[0]["last_reason"] == "rate_limited"
            assert rows[0]["next_attempt_at"] >= time.time() + 86390

    asyncio.run(run())


def test_exhausted_run_budget_never_claims_work(tmp_path):
    async def run():
        async with environment(tmp_path, False) as (sync, store, storage, server):
            sync.metadata.run_once(store)
            report = sync.xml.run_once(store, storage, time_budget=1e-12)
            assert report.stop_reason == "time_budget"
            assert report.pending == 1 and report.claims == 0 and server.downloads == 0

    asyncio.run(run())
