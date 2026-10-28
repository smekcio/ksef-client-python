from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError

import httpx
import pytest

from ksef_client import KsefClientOptions
from ksef_client._bounded_http import FRAME, PENDING
from ksef_client.exceptions import KsefHttpError, KsefResponseLimitError
from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient


class Body(httpx.SyncByteStream, httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    def __iter__(self):
        yield from self.chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(0)
            yield chunk

    def close(self):
        self.closed = True

    async def aclose(self):
        self.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "status,headers,chunks,limit,error",
    [
        (200, {}, [b"{}"], 2, None),
        (200, {"Content-Length": "3"}, [b"{}"], 2, KsefResponseLimitError),
        (200, {"Content-Length": "bad"}, [b"abc"], 2, KsefResponseLimitError),
        (200, {"Content-Length": "9" * 100}, [], 2, KsefResponseLimitError),
        (200, {"Content-Encoding": "gzip"}, [], 20, KsefResponseLimitError),
        (302, {"Location": "https://other.test/"}, [], 20, KsefResponseLimitError),
        (401, {}, [b"{}"], 20, KsefHttpError),
        (429, {}, [b"{}"], 20, KsefHttpError),
    ],
)
def test_bounded_receive(asynchronous, status, headers, chunks, limit, error):
    body = Body(chunks)
    calls = []

    def handle(request):
        calls.append(request)
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(status, headers=headers, stream=body)

    options = KsefClientOptions(
        base_url="https://example.test/v2",
        follow_redirects=True,
        custom_headers={"accept-encoding": "gzip"},
    )

    async def run():
        client = AsyncBaseHttpClient(options)
        await client._client.aclose()
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        try:
            result = await client.request_json_limited("GET", "/x", max_bytes=limit)
            assert result.content == b"{}"
        finally:
            await client.aclose()

    def sync():
        client = BaseHttpClient(options)
        client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handle))
        try:
            result = client.request_json_limited("GET", "/x", max_bytes=limit)
            assert result.content == b"{}"
        finally:
            client.close()

    if error:
        with pytest.raises(error):
            asyncio.run(run()) if asynchronous else sync()
    else:
        asyncio.run(run()) if asynchronous else sync()
    assert len(calls) == 1
    assert body.closed
    assert FRAME.get() is None and PENDING.get() is None


@pytest.mark.parametrize("asynchronous", [False, True])
def test_nested_request_does_not_inherit_policy(asynchronous):
    options = KsefClientOptions(base_url="https://example.test/v2")
    targets = []

    def handler(request):
        targets.append(str(request.url))
        return httpx.Response(
            200,
            stream=Body(
                [b"{}" if request.url.path.endswith("x") else b"auth body larger than two bytes"]
            ),
        )

    class Client(BaseHttpClient):
        def _resolve_request_token(self, **kwargs):
            if not kwargs["skip_auth"]:
                self.request("POST", "/auth", skip_auth=True)
            return None

    class AsyncClient(AsyncBaseHttpClient):
        async def _resolve_request_token(self, **kwargs):
            if not kwargs["skip_auth"]:
                await self.request("POST", "/auth", skip_auth=True)
            return None

    async def run():
        client = AsyncClient(options)
        await client.aclose()
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            await client.request_json_limited("GET", "/x", max_bytes=2)
        finally:
            await client.aclose()

    if asynchronous:
        asyncio.run(run())
    else:
        client = Client(options)
        client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        try:
            client.request_json_limited("GET", "/x", max_bytes=2)
        finally:
            client.close()
    assert targets == ["https://example.test/v2/auth", "https://example.test/v2/x"]


def test_frozen_configuration_and_validation():
    client = BaseHttpClient(KsefClientOptions(base_url="https://example.test/v2"))
    try:
        with pytest.raises(FrozenInstanceError):
            client._options.base_url = "https://other.test"  # type: ignore[misc]
        for limit in (True, 0, -1, 1.0):
            with pytest.raises(ValueError):
                client.request_json_limited("GET", "/x", max_bytes=limit)
        with pytest.raises(AttributeError):
            client.api_base_url = "https://other.test"  # type: ignore[misc]
    finally:
        client.close()
