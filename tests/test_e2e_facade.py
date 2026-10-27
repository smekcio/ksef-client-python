"""Installed-wheel TEST facade flow, including streaming export and refreshed URLs."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from ksef_client import Ksef, KsefClientOptions, OperationState, RetryConfig, TokenCredentials
from ksef_client import models as m
from ksef_client.request_control import request_control, wait_seconds
from ksef_client.streaming_export import digest
from tests.test_e2e_token_flows import (
    _build_invoice_xml,
    _ensure_e2e_enabled,
    _load_test_token_config,
)

pytestmark = pytest.mark.e2e


def _wait_for_invoice_at_hwm(client, filters, expected, *, timeout=600, poll_interval=60):
    with request_control(timeout_seconds=timeout):
        while True:
            search = client.api.invoices.search_invoice_metadata(
                filters, context_key=client.context_key, page_size=100
            )
            if any(row.ksef_number == expected for row in search):
                return
            wait_seconds(poll_interval)


def test_e2e_test_environment_facade_streaming_export(tmp_path):
    _ensure_e2e_enabled()
    config = _load_test_token_config()
    assert config.token, "TEST token is required"
    options = KsefClientOptions(
        base_url=config.base_url,
        retry=RetryConfig(
            max_retries=5, retryable_post_paths=frozenset({"/invoices/query/metadata"})
        ),
    )
    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    with Ksef.connect(
        options=options,
        credentials=TokenCredentials(config.token),
        context_type=config.context_type,
        context_value=config.context_value,
        timeout=360,
    ) as client:
        with client.online_session() as session:
            invoice = session.send_invoice(
                _build_invoice_xml(seller_nip=config.context_value, environment_name="facade-test")
            ).wait(timeout=360)
        assert invoice.ksef_number
        session.wait(timeout=360)
        assert session.upo().wait(timeout=360).pages
        filters = m.InvoiceQueryFilters(
            subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
            date_range=m.InvoiceQueryDateRange(
                date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                from_=start.isoformat(),
                restrict_to_permanent_storage_hwm_date=True,
            ),
        )
        _wait_for_invoice_at_hwm(client, filters, invoice.ksef_number)
        operation = client.exports.start(filters)
        # Explicit roundtrip; private state never appears in subprocess arguments or logs.
        state = OperationState.from_dict(operation.resume_state().to_dict())
        restored = client.resume_operation(state)
        result = restored.download_to(tmp_path / "result", work_dir=tmp_path / "work", timeout=600)
        assert result.package.invoice_count >= 1
        assert result.metadata_path is not None
        # Verify this submission, not merely an unrelated invoice in the context.
        assert invoice.ksef_number in result.metadata_path.read_text(encoding="utf-8")
        expected = client.invoices.download(invoice.ksef_number)
        expected_hash = base64.b64encode(hashlib.sha256(expected).digest()).decode()
        assert any(
            digest(result.destination / name)[1] == expected_hash
            for name in result.files
            if name.lower().endswith(".xml")
        )
