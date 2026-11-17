from __future__ import annotations

import asyncio
import json
import sqlite3
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ksef_client import (
    AsyncFileInvoiceXmlStore,
    AsyncSQLiteInvoiceSyncStore,
    FileInvoiceXmlStore,
    KsefXmlIntegrityError,
    KsefXmlStorageError,
    SQLiteInvoiceSyncStore,
)
from ksef_client import sqlite_store as store_module
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.invoice_delivery import KsefInvoiceDeliveryLeaseLostError
from tests.test_invoice_sync import START, make_sync, row
from tests.test_invoice_xml_sync import HASH, NUMBER, NUMBER2, XML, XmlServer, call


def document_sync(api, sync_key="purchase", role="Subject2"):
    return api.sync_documents(
        namespace="company",
        sync_key=sync_key,
        context_key="Nip:test",
        since=START,
        subject_types=(role,),
    )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_same_invoice_is_delivered_once_per_consumer_across_streams(tmp_path, asynchronous):
    async def run():
        store_cls = AsyncSQLiteInvoiceSyncStore if asynchronous else SQLiteInvoiceSyncStore
        storage = (
            await AsyncFileInvoiceXmlStore.open(tmp_path / "xml")
            if asynchronous
            else FileInvoiceXmlStore(tmp_path / "xml")
        )
        path = tmp_path / "archive.db"
        options = {"enqueue_xml": True, "xml_storage_id": storage.storage_id}
        store = await call(store_cls.open, path, **options)
        other = await call(store_cls.open, path, **options)
        _, http = make_sync(XmlServer(), asynchronous=asynchronous)
        api = (AsyncInvoicesClient if asynchronous else InvoicesClient)(http)
        try:
            sync = document_sync(api)
            scope = sync.xml.scopes[0]
            with pytest.raises(ValueError, match="initialized Subject2"):
                await call(store.claim_invoice_delivery, scope, storage, consumer="import")
            await call(sync.metadata.run_once, store)
            assert (
                await call(store.claim_invoice_delivery, scope, storage, consumer="import")
            ) is None
            assert (await call(sync.xml.run_once, store, storage)).ready == 1
            if asynchronous:
                competing = await asyncio.gather(
                    store.claim_invoice_delivery(scope, storage, consumer="import"),
                    other.claim_invoice_delivery(scope, storage, consumer="import"),
                )
                (delivery,) = [item for item in competing if item is not None]
            else:
                delivery = store.claim_invoice_delivery(scope, storage, consumer="import")
                assert delivery is not None
            assert delivery.key.ksef_number == delivery.metadata.ksef_number == NUMBER
            assert delivery.xml == XML
            assert all(
                private not in repr(delivery) for private in (NUMBER, HASH, "Nip:test", "import")
            )
            assert (
                await call(other.claim_invoice_delivery, scope, storage, consumer="import")
            ) is None

            related = document_sync(api, sync_key="other-window")
            await call(related.metadata.run_once, other)
            assert (
                await call(
                    other.claim_invoice_delivery, related.xml.scopes[0], storage, consumer="import"
                )
            ) is None
            await call(other.acknowledge_invoice_delivery, delivery)
            await call(store.acknowledge_invoice_delivery, delivery)
            await call(other.close)
            other = await call(store_cls.open, path, **options)
            assert (
                await call(
                    other.claim_invoice_delivery, related.xml.scopes[0], storage, consumer="import"
                )
            ) is None
            independent = await call(
                other.claim_invoice_delivery, related.xml.scopes[0], storage, consumer="audit"
            )
            assert independent.event_id == delivery.event_id
            await call(other.retry_invoice_delivery, independent)
            retry = await call(store.claim_invoice_delivery, scope, storage, consumer="audit")
            assert retry.event_id == delivery.event_id
            assert retry.xml == XML
            with pytest.raises(KsefInvoiceDeliveryLeaseLostError):
                await call(other.retry_invoice_delivery, independent)
        finally:
            await call(other.close)
            await call(store.close)
            await call(storage.close)
            await call(http.aclose if asynchronous else http.close)

    asyncio.run(run())


def test_expired_and_fenced_attempts_cannot_ack_or_retry(tmp_path, monkeypatch):
    _, http = make_sync(XmlServer())
    path = tmp_path / "archive.db"
    sync = document_sync(InvoicesClient(http))
    scope = sync.xml.scopes[0]
    clock = [1000.0]
    monkeypatch.setattr(store_module, "time", SimpleNamespace(time=lambda: clock[0]))
    with FileInvoiceXmlStore(tmp_path / "xml") as storage:
        options = {"enqueue_xml": True, "xml_storage_id": storage.storage_id}
        with SQLiteInvoiceSyncStore.open(path, **options) as archive:
            sync.run_once(archive, storage)
            first = archive.claim_invoice_delivery(scope, storage, consumer="job", lease_seconds=2)
            assert first is not None and first.expires_at == 1002
        with SQLiteInvoiceSyncStore.open(path, **options) as archive:
            clock[0] = 1002
            for action in (archive.acknowledge_invoice_delivery, archive.retry_invoice_delivery):
                with pytest.raises(KsefInvoiceDeliveryLeaseLostError):
                    action(first)
            second = archive.claim_invoice_delivery(scope, storage, consumer="job")
            assert second is not None and second.event_id == first.event_id
            archive.fence_workers()
            third = archive.claim_invoice_delivery(scope, storage, consumer="job")
            assert third is not None and third.event_id == first.event_id
            with pytest.raises(KsefInvoiceDeliveryLeaseLostError):
                archive.acknowledge_invoice_delivery(second)
            archive.retry_invoice_delivery(third, delay_seconds=5)
            assert archive.claim_invoice_delivery(scope, storage, consumer="job") is None
            clock[0] += 5
            final = archive.claim_invoice_delivery(scope, storage, consumer="job")
            assert final is not None and final.event_id == first.event_id
            archive.acknowledge_invoice_delivery(final)
            with pytest.raises(KsefInvoiceDeliveryLeaseLostError):
                archive.retry_invoice_delivery(final)
    http.close()


def test_claim_rejects_ineligible_and_unverifiable_documents(tmp_path, monkeypatch):
    server = XmlServer([row(NUMBER2, hash_=HASH), row(NUMBER, hash_=HASH)])
    _, http = make_sync(server)
    api = InvoicesClient(http)
    db = tmp_path / "archive.db"
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            db, enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as archive,
    ):
        seller = document_sync(api, role="Subject1")
        seller.run_once(archive, storage)
        with pytest.raises(ValueError, match="Subject2"):
            archive.claim_invoice_delivery(seller.xml.scopes[0], storage, consumer="job")

        sync = document_sync(api)
        sync.run_once(archive, storage)
        scope = sync.xml.scopes[0]
        for invalid in ("", "job\\n", "x" * 65, None):
            with pytest.raises(ValueError, match="consumer"):
                archive.claim_invoice_delivery(scope, storage, consumer=cast(Any, invalid))
        with (
            FileInvoiceXmlStore(tmp_path / "other-xml") as other,
            pytest.raises(KsefXmlStorageError, match="storage_id_mismatch"),
        ):
            archive.claim_invoice_delivery(scope, other, consumer="job")
        with pytest.raises(KsefXmlStorageError, match="response_size_limit"):
            archive.claim_invoice_delivery(scope, storage, consumer="small", max_xml_bytes=1)

        hit = archive.claim_invoice_delivery(scope, storage, consumer="good")
        assert hit is not None
        for invalid_delay in (-1, 86_401, float("nan"), True, None):
            with pytest.raises(ValueError, match="delay_seconds"):
                archive.retry_invoice_delivery(hit, delay_seconds=cast(Any, invalid_delay))
        with monkeypatch.context() as m:
            m.setattr(storage, "read", lambda *args, **kwargs: b"bad")
            with pytest.raises(KsefXmlIntegrityError, match="stored_size_mismatch"):
                archive.claim_invoice_delivery(scope, storage, consumer="short")
            m.setattr(storage, "read", lambda *args, **kwargs: b"x" * len(XML))
            with pytest.raises(KsefXmlIntegrityError, match="hash_mismatch"):
                archive.claim_invoice_delivery(scope, storage, consumer="corrupt")

        with sqlite3.connect(db) as writer:
            writer.execute(
                "UPDATE invoice_xml_documents SET verified_at=0 WHERE ksef_number=?",
                (NUMBER2,),
            )
            writer.execute(
                "UPDATE invoice_observations SET metadata_json=? WHERE ksef_number=?",
                ('"tampered"', NUMBER2),
            )
        with pytest.raises(KsefXmlIntegrityError, match="invalid_delivery_metadata"):
            archive.claim_invoice_delivery(scope, storage, consumer="metadata")
        next_ = archive.claim_invoice_delivery(scope, storage, consumer="metadata")
        assert next_ is not None and next_.key.ksef_number == NUMBER

        with sqlite3.connect(db) as writer:
            writer.execute(
                "UPDATE invoice_observations SET metadata_json=? WHERE ksef_number=?",
                (json.dumps(row(NUMBER, hash_=HASH).to_dict()), NUMBER2),
            )
        with pytest.raises(KsefXmlIntegrityError, match="invalid_delivery_metadata"):
            archive.claim_invoice_delivery(scope, storage, consumer="wrong-document")
    http.close()


def test_long_unicode_scope_and_lease_expiration_during_read(tmp_path, monkeypatch):
    _, http = make_sync(XmlServer())
    context = "Nip:" + "\U0001f600" * 4000
    sync = InvoicesClient(http).sync_documents(
        namespace="company",
        sync_key="purchase",
        context_key=context,
        since=START,
        subject_types=("Subject2",),
    )
    scope = sync.xml.scopes[0]
    clock = [1000.0]
    monkeypatch.setattr(store_module, "time", SimpleNamespace(time=lambda: clock[0]))
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            tmp_path / "archive.db", enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as archive,
    ):
        sync.run_once(archive, storage)
        read = storage.read

        def slow_read(*args, **kwargs):
            xml = read(*args, **kwargs)
            clock[0] += 5
            return xml

        with monkeypatch.context() as m:
            m.setattr(storage, "read", slow_read)
            with pytest.raises(KsefInvoiceDeliveryLeaseLostError):
                archive.claim_invoice_delivery(scope, storage, consumer="job", lease_seconds=5)
        event = archive.claim_invoice_delivery(scope, storage, consumer="job")
        assert event is not None and len(event.event_id) == 64
        archive.retry_invoice_delivery(event)
        replay = archive.claim_invoice_delivery(scope, storage, consumer="job")
        assert replay is not None and replay.event_id == event.event_id
    http.close()


def test_corrupted_delivery_yields_to_later_ready_work_after_lease_expires(tmp_path, monkeypatch):
    _, http = make_sync(XmlServer([row(NUMBER2, hash_=HASH), row(NUMBER, hash_=HASH)]))
    sync = document_sync(InvoicesClient(http))
    scope = sync.xml.scopes[0]
    clock = [1000.0]
    monkeypatch.setattr(store_module, "time", SimpleNamespace(time=lambda: clock[0]))
    db = tmp_path / "archive.db"
    with (
        FileInvoiceXmlStore(tmp_path / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            db, enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as archive,
    ):
        sync.run_once(archive, storage)

        def write(metadata):
            with sqlite3.connect(db) as writer:
                writer.execute(
                    "UPDATE invoice_observations SET metadata_json=? WHERE ksef_number=?",
                    (metadata, NUMBER2),
                )

        metadata = row(NUMBER2, hash_=HASH).to_dict()
        for i, invalid in enumerate((float("nan"), "Infinity", 10**400)):
            write(json.dumps({**metadata, "grossAmount": invalid}))
            consumer = f"job-{i}"
            with pytest.raises(KsefXmlIntegrityError, match="invalid_delivery_metadata"):
                archive.claim_invoice_delivery(scope, storage, consumer=consumer, lease_seconds=10)
            clock[0] += 60
            healthy = archive.claim_invoice_delivery(scope, storage, consumer=consumer)
            assert healthy is not None and healthy.key.ksef_number == NUMBER
            archive.acknowledge_invoice_delivery(healthy)
            with pytest.raises(KsefXmlIntegrityError, match="invalid_delivery_metadata"):
                archive.claim_invoice_delivery(scope, storage, consumer=consumer, lease_seconds=10)
            clock[0] += 60
            write(json.dumps(metadata))
            repaired = archive.claim_invoice_delivery(scope, storage, consumer=consumer)
            assert repaired is not None and repaired.key.ksef_number == NUMBER2
            archive.acknowledge_invoice_delivery(repaired)
    http.close()
