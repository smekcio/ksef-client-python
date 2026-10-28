from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import Mock

import httpx
import pytest

from ksef_client import (
    KsefClientOptions,
    KsefRateLimitWaitTimeout,
    KsefResponseLimitError,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitValues,
    request_control,
)
from ksef_client._bounded_http import FRAME, PENDING, make_policy
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.exceptions import KsefHttpError, KsefIncompletePaginationError
from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient
from ksef_client.token_manager import (
    AsyncTokenManager,
    AsyncTokenRefreshingHttpClient,
    TokenManager,
    TokenRefreshingHttpClient,
)
from tests.test_bounded_http import Body
from tests.test_invoice_sync import H1, Server, make_sync, query


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        b"no-json",
        b'{"invoices":[],"invoices":[]}',
        b'{"invoices":NaN}',
        b'{"invoices":{}}',
        json.dumps({"invoices": [{}] * 11}).encode(),
        b"[]",
    ],
)
def test_strict_observation_decoder(asynchronous, body):
    async def run():
        sync, http = make_sync(Server(), asynchronous=asynchronous)

        def handler(request):
            return httpx.Response(200, stream=Body([body]))

        http._client._transport.handler = handler
        try:
            stream = sync.streams[0]
            cp = stream.begin_cycle(None, until=H1).next_checkpoint
            with pytest.raises(KsefIncompletePaginationError) as caught:
                if asynchronous:
                    await stream.next_batch(cp)
                else:
                    stream.next_batch(cp)
            assert caught.value.reason_code == "invalid_response"
        finally:
            await http.aclose() if asynchronous else http.close()

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_source_environment_change_before_http(asynchronous):
    http = Mock(api_base_url="https://changed.test/v2")
    api: Any = (AsyncInvoicesClient if asynchronous else InvoicesClient)(http)

    async def run():
        with pytest.raises(ValueError):
            result = api._query_invoice_metadata_observation_page(
                query(),
                page_offset=0,
                page_size=10,
                sort_order="Asc",
                expected_environment="https://original.test/v2",
            )
            if asynchronous:
                await result

    asyncio.run(run())
    http.request_json_limited.assert_not_called()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("second", [200, 401])
def test_limited_reactive_refresh_once_with_nested_auth(asynchronous, second):
    options = KsefClientOptions(base_url="https://example.test/v2")
    requests, refreshes = [], []

    def handler(request):
        requests.append((request.url.path, request.headers.get("Authorization")))
        if request.url.path.endswith("auth"):
            return httpx.Response(200, stream=Body([b"refresh response larger than limit"]))
        count = sum(p.endswith("metadata") for p, _ in requests)
        return httpx.Response(
            401 if count == 1 else second,
            stream=Body([b"{}"]),
            headers={"Content-Type": "application/json"},
        )

    async def run():
        async def refresh(token):
            refreshes.append(token)
            await client.request("POST", "/auth", skip_auth=True)
            from ksef_client.models import TokenInfo

            return TokenInfo("new", "2099-01-01T00:00:00Z")

        manager = AsyncTokenManager("old", "refresh", refresh_handler=refresh)
        client = AsyncTokenRefreshingHttpClient(options, manager)
        await client.aclose()
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            await client.request_json_limited("POST", "/invoices/query/metadata", max_bytes=2)
        finally:
            await client.aclose()

    def run_sync():
        def refresh(token):
            refreshes.append(token)
            client.request("POST", "/auth", skip_auth=True)
            from ksef_client.models import TokenInfo

            return TokenInfo("new", "2099-01-01T00:00:00Z")

        manager = TokenManager("old", "refresh", refresh_handler=refresh)
        client = TokenRefreshingHttpClient(options, manager)
        client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        try:
            client.request_json_limited("POST", "/invoices/query/metadata", max_bytes=2)
        finally:
            client.close()

    if second == 401:
        with pytest.raises(KsefHttpError):
            asyncio.run(run()) if asynchronous else run_sync()
    else:
        asyncio.run(run()) if asynchronous else run_sync()
    assert refreshes == ["refresh"]
    assert requests == [
        ("/v2/invoices/query/metadata", "Bearer old"),
        ("/v2/auth", None),
        ("/v2/invoices/query/metadata", "Bearer new"),
    ]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("broken", [False, True])
def test_429_cooldown_survives_body_failure(asynchronous, broken):
    budget: Any = RateLimitBudget(
        RateLimitPolicy({"invoice_metadata": RateLimitValues(per_minute=100)})
    )
    original_defer = budget.defer
    budget.defer = Mock(side_effect=original_defer)
    options = KsefClientOptions(
        base_url="https://example.test/v2",
        rate_limit_budget=budget,
        rate_limit_context_key="context",
    )

    class Broken(Body):
        def __iter__(self):
            raise httpx.ReadError("private")
            yield b""

        async def __aiter__(self):
            raise httpx.ReadError("private")
            yield b""

    body = Broken([]) if broken else Body([b"too large"])

    def handler(request):
        return httpx.Response(429, headers={"Retry-After": "30"}, stream=body)

    async def run():
        client = AsyncBaseHttpClient(options)
        await client.aclose()
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            await client.request_json_limited("POST", "/invoices/query/metadata", max_bytes=2)
        finally:
            await client.aclose()

    def run_sync():
        client = BaseHttpClient(options)
        client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        try:
            client.request_json_limited("POST", "/invoices/query/metadata", max_bytes=2)
        finally:
            client.close()

    with pytest.raises(KsefHttpError if broken else KsefResponseLimitError):
        asyncio.run(run()) if asynchronous else run_sync()
    assert budget.defer.call_count == 1 and budget.defer.call_args.args[-1] == 30
    assert body.closed


def test_real_slow_http_checks_deadline_without_filling_large_chunk():
    stopped = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.end_headers()
            try:
                while not stopped.is_set():
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.005)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = BaseHttpClient(KsefClientOptions(base_url=f"http://127.0.0.1:{server.server_port}/v2"))
    try:
        start = time.monotonic()
        with (
            request_control(timeout_seconds=0.08),
            pytest.raises((KsefRateLimitWaitTimeout, KsefHttpError)),
        ):
            client.request_json_limited("GET", "/x", max_bytes=200000)
        assert time.monotonic() - start < 1
    finally:
        stopped.set()
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_async_concurrent_nested_frames_and_no_marker_leak():
    async def run():
        client = AsyncBaseHttpClient(KsefClientOptions(base_url="https://example.test/v2"))
        await client.aclose()

        async def handler(request):
            await asyncio.sleep(0)
            return httpx.Response(
                200,
                stream=Body(
                    [
                        b"{}"
                        if request.url.path.endswith("small")
                        else b"a much larger ordinary response"
                    ]
                ),
            )

        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            small, large = await asyncio.gather(
                client.request_json_limited("GET", "/small", max_bytes=2),
                client.request("GET", "/large"),
            )
            assert small.content == b"{}" and len(large.content) > 2
            # An inherited pending marker from another task is not consumed as its own policy.
            marker = PENDING.set(make_policy(client, "/small", 2))
            try:
                result = await asyncio.create_task(client.request("GET", "/large"))
                assert len(result.content) > 2
            finally:
                PENDING.reset(marker)
            assert FRAME.get() is None and PENDING.get() is None
        finally:
            await client.aclose()

    asyncio.run(run())
