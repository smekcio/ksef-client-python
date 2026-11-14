"""Live TEST smoke for the offline queue, restart, and per-invoice receipt."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import pytest

from ksef_client import Ksef, KsefClientOptions, KsefEnvironment, TokenCredentials
from ksef_client.exceptions import KsefHttpError
from ksef_client.offline_invoices import (
    OfflineInvoiceQueue,
    OfflineInvoiceStatus,
    SQLiteOfflineInvoiceStore,
)
from ksef_client.request_control import request_control, wait_seconds
from ksef_client.utils.ksef_number import canonical_ksef_number
from tests.test_e2e_token_flows import (
    _build_invoice_xml,
    _ensure_e2e_enabled,
    _load_test_token_config,
)

pytestmark = pytest.mark.e2e


def test_e2e_test_environment_offline_queue_restart_and_upo(tmp_path):
    _ensure_e2e_enabled()
    config = _load_test_token_config()
    assert config.token and config.context_type.casefold() == "nip"
    options = KsefClientOptions(base_url=config.base_url)
    assert (
        options.normalized_base_url()
        == KsefClientOptions(base_url=KsefEnvironment.TEST.value).normalized_base_url()
    )
    key = os.urandom(32)
    path = tmp_path / "offline.db"
    xml = _build_invoice_xml(seller_nip=config.context_value, environment_name="offline-queue")
    due_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    with SQLiteOfflineInvoiceStore.open(path, key=key) as store:
        queue = OfflineInvoiceQueue(
            store,
            options=options,
            context_type=config.context_type,
            context_value=config.context_value,
            namespace="offline-smoke",
        )
        staged = queue.enqueue(xml, due_at=due_at)
        invoice_hash = staged.progress.invoice_hash

    with Ksef.connect(
        options=options,
        credentials=TokenCredentials(config.token),
        context_type=config.context_type,
        context_value=config.context_value,
        timeout=360,
    ) as client:
        with SQLiteOfflineInvoiceStore.open(path, key=key) as store:
            worker = client.invoices.offline(store, namespace="offline-smoke")
            opened = worker.advance(invoice_hash)
            assert opened.progress.status is OfflineInvoiceStatus.SESSION_OPEN

        with SQLiteOfflineInvoiceStore.open(path, key=key) as store:
            worker = client.invoices.offline(store, namespace="offline-smoke")
            assert worker.status(invoice_hash) == opened
            sent = worker.advance(invoice_hash)
            assert sent.progress.status is OfflineInvoiceStatus.SUBMITTED
            assert sent.progress.session_reference == opened.progress.session_reference

        with SQLiteOfflineInvoiceStore.open(path, key=key) as store:
            worker = client.invoices.offline(store, namespace="offline-smoke")
            result = sent
            with request_control(timeout_seconds=600):
                while result.progress.status is not OfflineInvoiceStatus.COMPLETE:
                    try:
                        result = worker.advance(invoice_hash)
                    except KsefHttpError as error:
                        if result.progress.status is not OfflineInvoiceStatus.ACCEPTED or (
                            error.status_code not in {404, 409, 425}
                        ):
                            raise
                    assert result.progress.status in {
                        OfflineInvoiceStatus.SUBMITTED,
                        OfflineInvoiceStatus.ACCEPTED,
                        OfflineInvoiceStatus.COMPLETE,
                    }, "TEST did not accept the offline invoice"
                    if result.progress.status is not OfflineInvoiceStatus.COMPLETE:
                        wait_seconds(5)
            assert result.progress.ksef_number
            assert worker.read_xml(invoice_hash) == xml
            upo = ET.fromstring(worker.read_upo(invoice_hash))
            number = upo.findtext(".//{*}NumerKSeFDokumentu")
            assert number and canonical_ksef_number(number) == result.progress.ksef_number
            assert upo.findtext(".//{*}TrybWysylki") == "Offline"
