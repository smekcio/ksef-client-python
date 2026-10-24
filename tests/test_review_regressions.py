"""Regression coverage for PR 105 bug and security review findings."""

import asyncio
import base64
import hashlib
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest

from ksef_client import KsefClientOptions, redact_sensitive
from ksef_client.services import workflows
from ksef_client.services.crypto import encrypt_aes_cbc_pkcs7, generate_iv, generate_symmetric_key
from ksef_client.utils.zip_utils import build_zip
from tests.test_invoice_search import filters, invoice, machine, response
from tests.test_services_workflows import RecordingHttp, _invoice_package


def test_overlap_can_span_more_than_two_duplicate_pages():
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    boundary = (start + timedelta(hours=3)).isoformat()
    rows = [invoice(i, (start + timedelta(seconds=i)).isoformat()) for i in range(9950)]
    rows.extend(invoice(i, boundary) for i in range(9950, 10543))
    walk = machine()
    state = walk.load(None)
    actual: list[str | None] = []
    while True:
        base = 9950 if state["request"]["dateRange"]["from"] == boundary else 0
        offset = state["offset"] * 10
        end = min(base + offset + 10, base + 10000)
        chunk = rows[base + offset : end]
        more = end < len(rows)
        page = walk.advance(state, response(chunk, more, more and offset + len(chunk) == 10000))
        actual.extend(item.ksef_number for item in page.items)
        if page.next_cursor is None:
            break
        state = walk.load(page.next_cursor)
    assert actual == [str(i) for i in range(10543)]


def test_desc_hwm_tracks_the_narrowed_historical_query():
    walk = machine(restricted=True, order="Desc")
    state = walk.load(None)
    state["offset"] = 999
    page = walk.advance(
        state,
        response(
            [invoice(i, "2026-10-01T02:00:00Z") for i in range(10)],
            True,
            True,
            hwm="2026-10-02T00:00:00Z",
        ),
    )
    state = walk.load(page.next_cursor)
    page = walk.advance(
        state,
        response([invoice(10, "2026-10-01T01:00:00Z")], hwm=state["request"]["dateRange"]["to"]),
    )
    assert [item.ksef_number for item in page.items] == ["10"]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_package_without_metadata_retains_optional_none(asynchronous):
    key, iv = generate_symmetric_key(), generate_iv()
    data = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
    digest = base64.b64encode(hashlib.sha256(data).digest()).decode()
    encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)
    if not asynchronous:
        workflow = workflows.ExportWorkflow(cast(Any, SimpleNamespace()), RecordingHttp())
        with patch.object(
            workflow._download_helper, "download_parts_with_hash", return_value=[(data, digest)]
        ):
            result = workflow.download_and_process_package(_invoice_package("u"), encryption)
    else:

        async def run():
            workflow = workflows.AsyncExportWorkflow(
                cast(Any, SimpleNamespace()), cast(Any, RecordingHttp())
            )
            with patch.object(
                workflow._download_helper,
                "download_parts_with_hash",
                AsyncMock(return_value=[(data, digest)]),
            ):
                return await workflow.download_and_process_package(
                    _invoice_package("u"), encryption
                )

        result = asyncio.run(run())
    assert result.metadata_raw is None


def test_dictionary_diagnostics_hide_proxy_credentials():
    options = KsefClientOptions(
        base_url="https://api-test.ksef.mf.gov.pl",
        proxy="https://DUMMY_USER:DUMMY_PASSWORD@proxy.example.invalid",
    )
    assert "DUMMY_PASSWORD" not in str(redact_sensitive(asdict(options)))


def test_health_messages_never_embed_credentialed_urls():
    from ksef_client.cli.sdk import adapters

    with patch.object(adapters, "get_tokens", return_value=None):
        result = adapters.run_health_check(
            profile="test",
            base_url="https://user:DUMMY_PASSWORD@example.invalid/?key=DUMMY_KEY",
            dry_run=True,
            check_auth=False,
            check_certs=False,
        )
    assert "DUMMY_PASSWORD" not in str(result)
    assert "DUMMY_KEY" not in str(result)


def test_generated_cursor_size_failure_preserves_replay(monkeypatch):
    import ksef_client.invoice_search as searches
    from ksef_client import KsefIncompletePaginationError

    walk = machine()
    state = walk.load(None)
    monkeypatch.setattr(searches, "MAX_CURSOR_BYTES", len(searches._dump(state)) + 20)
    with pytest.raises(KsefIncompletePaginationError, match="cursor_size_limit") as caught:
        walk.advance(state, response([invoice(1)], True))
    assert walk.load(caught.value.last_cursor)["offset"] == 0


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"dateRange": None},
        {"dateRange": {}},
        {"future_filter": "ignored"},
        {"amount": {"type": "Brutto", "typo": 1}},
    ],
)
def test_search_rejects_bad_or_lost_filters_before_http(asynchronous, payload):
    from unittest.mock import Mock

    from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient

    raw = filters().to_dict()
    if payload:
        raw.update(payload)
    else:
        raw.clear()
    http = SimpleNamespace(
        _options=KsefClientOptions(base_url="https://example.invalid"), request=Mock()
    )
    client = (AsyncInvoicesClient if asynchronous else InvoicesClient)(http)
    with pytest.raises(ValueError):
        client.search_invoice_metadata(
            cast(Any, SimpleNamespace(to_dict=lambda: raw)), context_key="test"
        )
    http.request.assert_not_called()


def test_nested_filter_lists_and_v1_cursor_migration():
    from ksef_client.clients.invoices import _serialize_search_filters
    from ksef_client.invoice_search import _dump
    from tests.test_invoice_search import filters

    raw = filters().to_dict()
    raw["currencyCodes"] = ["PLN", "EUR"]
    assert _serialize_search_filters(cast(Any, SimpleNamespace(to_dict=lambda: raw))) == raw
    walk = machine()
    state = walk.load(None)
    state.pop("last_page")
    assert walk.load(_dump(state))["last_page"] is None
    state["last_page"] = "invalid"
    from ksef_client import KsefInvalidPaginationCursorError

    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))


def test_missing_truncation_date_is_a_typed_sdk_validation_error():
    from ksef_client import KsefError
    from ksef_client.services.hwm import update_continuation_point

    with pytest.raises(KsefError) as caught:
        update_continuation_point({}, "Subject1", {"isTruncated": True})
    assert isinstance(caught.value, ValueError)


def test_search_machine_reports_missing_date_range_as_validation_error():
    from ksef_client.invoice_search import _MetadataMachine

    with pytest.raises(ValueError, match="dateRange"):
        _MetadataMachine({}, environment="test", context_key="test", page_size=10, sort_order="Asc")


def test_initial_oversized_state_fails_before_http(monkeypatch):
    from unittest.mock import Mock

    import ksef_client.invoice_search as searches
    from ksef_client import KsefPaginationError

    fetch = Mock()
    search = searches.InvoiceMetadataSearch(machine(), fetch)
    monkeypatch.setattr(searches, "MAX_CURSOR_BYTES", 10)
    with pytest.raises(KsefPaginationError, match="Search state"):
        search.page()
    fetch.assert_not_called()
