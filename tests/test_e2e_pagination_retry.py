"""Offline regressions for rate limiting in the required live cursor scenario."""

from __future__ import annotations

import io
import json
from contextlib import closing, redirect_stdout
from unittest.mock import Mock, patch

import httpx
import pytest

from ksef_client import KsefClient, KsefRateLimitError
from ksef_client.http import BaseHttpClient
from ksef_client.retry import should_retry_request
from tests.test_e2e_pagination import _CHILD, _metadata_options
from tests.test_invoice_search import filters, invoice, response


def test_metadata_retry_repeats_only_the_failed_page_and_honors_retry_after():
    options = _metadata_options("https://api-test.ksef.mf.gov.pl")
    http = BaseHttpClient(options)
    calls = Mock(
        side_effect=[
            httpx.Response(200, json=response([invoice(1)], True).to_dict()),
            httpx.Response(429, headers={"Retry-After": "65"}, json={"title": "limited"}),
            httpx.Response(200, json=response([invoice(2)]).to_dict()),
        ]
    )
    with (
        KsefClient(options, http_client=http) as client,
        patch.object(http._client, "request", calls),
        patch("ksef_client.http.time.sleep") as sleep,
    ):
        pages = list(client.invoices.search_invoice_metadata(filters(), context_key="test").pages())
    assert [item.ksef_number for page in pages for item in page.items] == ["1", "2"]
    assert [call.kwargs["params"]["pageOffset"] for call in calls.call_args_list] == [0, 1, 1]
    sleep.assert_called_once_with(65.0)


def test_metadata_retry_never_replays_invoice_submission():
    options = _metadata_options("https://api-test.ksef.mf.gov.pl")
    calls = Mock(return_value=httpx.Response(429, json={"title": "limited"}))
    with (
        closing(BaseHttpClient(options)) as http,
        patch.object(http._client, "request", calls),
        patch("ksef_client.http.time.sleep") as sleep,
        pytest.raises(KsefRateLimitError),
    ):
        http.request("POST", "/sessions/online/session/invoices", json={})
    assert calls.call_count == 1
    sleep.assert_not_called()


def test_cursor_child_has_the_same_bounded_read_only_retry(monkeypatch):
    payload = {
        "installed": False,
        "url": "https://api-test.ksef.mf.gov.pl",
        "token": "DUMMY_TOKEN",
        "filters": filters().to_dict(),
        "context": "test",
        "cursor": "DUMMY_CURSOR",
    }
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    search = client.invoices.search_invoice_metadata.return_value
    search.items.return_value = [invoice(2)]
    factory = Mock(return_value=client)
    output = io.StringIO()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    with patch("ksef_client.KsefClient", factory), redirect_stdout(output):
        exec(_CHILD, {})
    options = factory.call_args.args[0]
    assert options == _metadata_options(payload["url"])
    assert options.retry.max_retries == 5
    assert should_retry_request("POST", "/invoices/query/metadata", 429, options.retry)
    assert not should_retry_request("POST", "/sessions/online/session/invoices", 429, options.retry)
    search.items.assert_called_once_with("DUMMY_CURSOR")
    assert json.loads(output.getvalue()) == ["2"]
