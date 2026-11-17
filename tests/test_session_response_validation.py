"""Check original wire types before a session observation can authorize a retry."""

from __future__ import annotations

import asyncio
import inspect
import json

import httpx
import pytest

from ksef_client.clients.sessions import AsyncSessionsClient, SessionsClient
from ksef_client.exceptions import KsefDocumentValidationError
from ksef_client.http import HttpResponse
from tests.test_clients import DummyAsyncHttp, DummyHttp

SESSION = {
    "status": {"code": 200, "description": "processed"},
    "dateCreated": "2026-11-17T21:00:00Z",
    "dateUpdated": "2026-11-17T22:00:00.0000001+00:00",
    "invoiceCount": 1,
}
INVOICE = {"status": {"code": 550}, "referenceNumber": "invoice-1", "ordinalNumber": 1}


def call(method, *args, **kwargs):
    result = method(*args, strict=True, **kwargs)
    return asyncio.run(result) if inspect.iscoroutine(result) else result


def client(body, asynchronous):
    response = HttpResponse(200, httpx.Headers(), body)
    if asynchronous:
        async_http = DummyAsyncHttp(response)
        return async_http, AsyncSessionsClient(async_http)
    http = DummyHttp(response)
    return http, SessionsClient(http)


@pytest.mark.parametrize("asynchronous", [True, False])
def test_typed_session_reads_bound_transport_and_preserve_evidence(asynchronous):
    http, sessions = client(json.dumps(SESSION).encode(), asynchronous)
    assert call(sessions.get_session_status, "session-1", access_token="test").invoice_count == 1
    assert http.last_request_kwargs["max_bytes"] == 1024 * 1024
    http, sessions = client(json.dumps(INVOICE).encode(), asynchronous)
    assert call(sessions.get_session_invoice_status, "session-1", "invoice-1").status.code == 550
    assert http.last_request_kwargs["expected_status"] == {200}

    body = json.dumps({"invoices": [INVOICE], "continuationToken": ""}).encode()
    http, sessions = client(body, asynchronous)
    page = call(sessions.get_session_invoices, "session-1", continuation_token="next", page_size=10)
    assert [row.ordinal_number for row in page.invoices] == [1]
    assert page.continuation_token == ""
    assert http.last_request_kwargs["max_bytes"] == 16 * 1024 * 1024
    assert http.last_request_kwargs["params"] == {"pageSize": 10}
    assert http.last_request_kwargs["headers"] == {"x-continuation-token": "next"}


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        ("get_session_invoices", {}),
        ("get_session_invoices", {"invoices": None}),
        ("get_session_invoices", {"invoices": [INVOICE, "broken"]}),
        ("get_session_invoices", {"invoices": [{"status": {"code": 550.9}}]}),
        ("get_session_invoices", {"invoices": [{**INVOICE, "ordinalNumber": True}]}),
        ("get_session_invoices", {"invoices": [{**INVOICE, "referenceNumber": 10}]}),
        ("get_session_invoices", {"invoices": [{**INVOICE, "referenceNumber": "X" * 37}]}),
        ("get_session_invoices", {"invoices": [{**INVOICE, "invoiceFileName": "x" * 129}]}),
        ("get_session_invoices", {"invoices": [{**INVOICE, "invoiceHash": "x" * 45}]}),
        ("get_session_invoices", {"invoices": [], "continuationToken": False}),
        ("get_session_status", {**SESSION, "successfulInvoiceCount": False}),
        ("get_session_status", {**SESSION, "invoiceCount": 0.5}),
        ("get_session_status", {**SESSION, "dateUpdated": None}),
        ("get_session_status", {**SESSION, "dateUpdated": "unchanged but invalid"}),
        ("get_session_status", {**SESSION, "dateCreated": "2026-11-17T22:00:00"}),
        ("get_session_status", {**SESSION, "status": {"code": "440"}}),
        ("get_session_status", []),
        ("get_session_status", {"status": []}),
    ],
)
def test_malformed_observation_is_never_converted_to_a_typed_result(method, payload):
    _, sessions = client(json.dumps(payload).encode(), False)
    with pytest.raises(KsefDocumentValidationError, match="Invalid KSeF session status response"):
        call(getattr(sessions, method), "session-1")


def test_duplicate_json_key_and_page_row_limit_are_checked_before_conversion():
    _, sessions = client(b'{"invoices":[],"invoices":[]}', False)
    with pytest.raises(KsefDocumentValidationError):
        call(sessions.get_session_invoices, "session-1")
    _, sessions = client(json.dumps({"invoices": [INVOICE] * 11}).encode(), False)
    for size in (None, 10):
        with pytest.raises(KsefDocumentValidationError):
            call(sessions.get_session_invoices, "session-1", page_size=size)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_strict_reads_validate_route_and_cursor_before_transport(asynchronous):
    http, sessions = client(b"", asynchronous)
    with pytest.raises(ValueError, match="reference"):
        call(sessions.get_session_invoice_status, "session-1", "invalid invoice")
    with pytest.raises(ValueError, match="token"):
        call(sessions.get_session_invoices, "session-1", continuation_token="invalid token")
    for size in (9, 1001):
        with pytest.raises(ValueError, match="page_size"):
            call(sessions.get_session_invoices, "session-1", page_size=size)
    assert http.last_request_args is None
