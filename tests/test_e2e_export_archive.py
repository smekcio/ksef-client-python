"""Live TEST smoke for the public export archive synchronizer."""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

from ksef_client import (
    FileInvoiceXmlStore,
    InvoiceXmlKey,
    Ksef,
    KsefClientOptions,
    KsefEnvironment,
    RetryConfig,
    SQLiteInvoiceSyncStore,
    TokenCredentials,
)
from ksef_client import models as m
from ksef_client.request_control import request_control, wait_seconds
from ksef_client.utils.ksef_number import canonical_ksef_number
from tests.test_e2e_facade import _wait_for_invoice_at_hwm
from tests.test_e2e_token_flows import (
    _build_invoice_xml,
    _ensure_e2e_enabled,
    _load_test_token_config,
)

pytestmark = pytest.mark.e2e


def test_e2e_test_environment_export_archive_restart(tmp_path):
    _ensure_e2e_enabled()
    config = _load_test_token_config()
    assert config.token and config.context_type.casefold() == "nip"
    options = KsefClientOptions(
        base_url=config.base_url,
        retry=RetryConfig(
            max_retries=5, retryable_post_paths=frozenset({"/invoices/query/metadata"})
        ),
    )
    assert (
        options.normalized_base_url()
        == KsefClientOptions(base_url=KsefEnvironment.TEST.value).normalized_base_url()
    )
    since = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with Ksef.connect(
        options=options,
        credentials=TokenCredentials(config.token),
        context_type=config.context_type,
        context_value=config.context_value,
        timeout=360,
    ) as client:
        expected: dict[str, bytes] = {}
        with client.online_session() as session:
            for _ in range(2):
                invoice = session.send_invoice(
                    _build_invoice_xml(seller_nip=config.context_value, environment_name="archive")
                ).wait(timeout=360)
                assert invoice.ksef_number
                expected[canonical_ksef_number(invoice.ksef_number)] = b""
        assert len(expected) == 2
        filters = m.InvoiceQueryFilters(
            subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
            date_range=m.InvoiceQueryDateRange(
                date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                from_=since,
                restrict_to_permanent_storage_hwm_date=True,
            ),
        )
        for number in expected:
            _wait_for_invoice_at_hwm(client, filters, number)
            expected[number] = client.invoices.download(number)
        until = datetime.now(timezone.utc).isoformat()
        state_key = os.urandom(32)

        def archive():
            return client.exports.sync_archive(
                namespace="archive-smoke",
                sync_key="seller",
                since=since,
                state_key=state_key,
                subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
                work_dir=tmp_path / "work",
            )

        with (
            FileInvoiceXmlStore(tmp_path / "xml") as storage,
            SQLiteInvoiceSyncStore.open(
                tmp_path / "archive.db", enqueue_xml=True, xml_storage_id=storage.storage_id
            ) as store,
        ):
            first = archive()
            with request_control(timeout_seconds=900):
                while True:
                    report = first.run_once(store, storage, until=until, max_documents=1)
                    if report.status == "importing":
                        assert report.imported == 1
                        break
                    wait_seconds(30)

        with (
            FileInvoiceXmlStore(tmp_path / "xml") as storage,
            SQLiteInvoiceSyncStore.open(
                tmp_path / "archive.db", enqueue_xml=True, xml_storage_id=storage.storage_id
            ) as store,
        ):
            restored = archive()
            with request_control(timeout_seconds=900):
                while True:
                    report = restored.run_once(store, storage, until=until)
                    ready = {
                        row["ksef_number"]
                        for row in store.list_xml([restored.scope], limit=1000)
                        if row["status"] == "ready"
                    }
                    if expected.keys() <= ready and report.committed_hwm is not None:
                        break
                    wait_seconds(30)
            for number, content in expected.items():
                key = InvoiceXmlKey(
                    restored.scope.namespace, client.environment, client.context_key, number
                )
                digest = base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")
                assert storage.read(key, digest) == content
