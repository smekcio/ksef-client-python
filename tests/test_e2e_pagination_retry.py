"""Offline regressions for rate limiting in the required live cursor scenario."""

from __future__ import annotations

import io
import json
from contextlib import closing, redirect_stdout
from unittest.mock import Mock, call, patch

import httpx
import pytest

from ksef_client import KsefClient, KsefRateLimitError
from ksef_client.exceptions import KsefAuthenticationError
from ksef_client.http import BaseHttpClient
from ksef_client.retry import should_retry_request
from tests.test_e2e_pagination import _CHILD, _metadata_options
from tests.test_e2e_token_flows import (
    _poll_metadata_until_contains,
    _with_rate_limit_retry,
)
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


def test_e2e_rate_limit_retry_honors_retry_after(monkeypatch):
    monkeypatch.setenv("KSEF_E2E_RATE_LIMIT_RETRIES", "2")
    call_operation = Mock(
        side_effect=[
            KsefRateLimitError(429, "Too Many Requests", retry_after=12),
            "ok",
        ]
    )

    with patch("tests.test_e2e_token_flows.time.sleep") as sleep:
        assert _with_rate_limit_retry(call_operation) == "ok"

    sleep.assert_called_once_with(12.0)


def test_e2e_rate_limit_retry_caps_retry_after(monkeypatch):
    monkeypatch.setenv("KSEF_E2E_RATE_LIMIT_RETRIES", "2")
    monkeypatch.setenv("KSEF_E2E_RATE_LIMIT_MAX_SLEEP_SECONDS", "5")
    call_operation = Mock(
        side_effect=[
            KsefRateLimitError(429, "Too Many Requests", retry_after=900),
            "ok",
        ]
    )

    with patch("tests.test_e2e_token_flows.time.sleep") as sleep:
        assert _with_rate_limit_retry(call_operation) == "ok"

    sleep.assert_called_once_with(5.0)


def test_e2e_rate_limit_retry_uses_bounded_exponential_backoff(monkeypatch):
    monkeypatch.setenv("KSEF_E2E_RATE_LIMIT_RETRIES", "4")
    monkeypatch.setenv("KSEF_E2E_RATE_LIMIT_SLEEP_SECONDS", "2")
    monkeypatch.setenv("KSEF_E2E_RATE_LIMIT_MAX_SLEEP_SECONDS", "5")
    call_operation = Mock(
        side_effect=[
            KsefRateLimitError(429, "Too Many Requests"),
            KsefRateLimitError(429, "Too Many Requests"),
            KsefRateLimitError(429, "Too Many Requests"),
            "ok",
        ]
    )

    with patch("tests.test_e2e_token_flows.time.sleep") as sleep:
        assert _with_rate_limit_retry(call_operation) == "ok"

    assert sleep.call_args_list == [call(2.0), call(4.0), call(5.0)]


def test_metadata_poll_refreshes_access_token_after_401(monkeypatch):
    monkeypatch.setenv("KSEF_E2E_METADATA_MAX_ATTEMPTS", "2")
    client = Mock()
    query = Mock(
        side_effect=[
            KsefAuthenticationError(401, "API error"),
            [invoice(2)],
        ]
    )
    refresh = Mock(return_value="new-access-token")

    with patch("tests.test_e2e_token_flows._query_invoice_metadata", query):
        invoices = _poll_metadata_until_contains(
            client,
            access_token="expired-access-token",
            subject_type="Subject1",
            expected_ksef_number="2",
            refresh_access_token=refresh,
        )

    assert invoices == [invoice(2)]
    refresh.assert_called_once_with()
    assert query.call_args_list[0].kwargs["access_token"] == "expired-access-token"
    assert query.call_args_list[1].kwargs["access_token"] == "new-access-token"
