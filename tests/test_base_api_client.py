import unittest
from unittest.mock import AsyncMock

import httpx

from ksef_client.clients.base import BaseApiClient, AsyncBaseApiClient
from ksef_client.http import HttpResponse


class DummyHttp:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls = []

    def request(self, *args, **kwargs) -> HttpResponse:
        self.calls.append((args, kwargs))
        return self.response


class DummyAsyncHttp:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls = []

    async def request(self, *args, **kwargs) -> HttpResponse:
        self.calls.append((args, kwargs))
        return self.response


class BaseApiClientTests(unittest.TestCase):
    def test_request_json_with_content(self):
        response = HttpResponse(200, httpx.Headers({"Content-Type": "application/json"}), b"{\"ok\": true}")
        client = BaseApiClient(DummyHttp(response))
        result = client._request_json("GET", "/path")
        self.assertEqual(result, {"ok": True})

    def test_request_json_empty(self):
        response = HttpResponse(204, httpx.Headers(), b"")
        client = BaseApiClient(DummyHttp(response))
        self.assertIsNone(client._request_json("GET", "/path"))

    def test_request_bytes_and_raw(self):
        response = HttpResponse(200, httpx.Headers(), b"data")
        client = BaseApiClient(DummyHttp(response))
        self.assertEqual(client._request_bytes("GET", "/path"), b"data")
        raw = client._request_raw("GET", "/path")
        self.assertIs(raw, response)


class AsyncBaseApiClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_request_json(self):
        response = HttpResponse(200, httpx.Headers({"Content-Type": "application/json"}), b"{\"ok\": true}")
        client = AsyncBaseApiClient(DummyAsyncHttp(response))
        result = await client._request_json("GET", "/path")
        self.assertEqual(result, {"ok": True})

    async def test_async_request_bytes_raw(self):
        response = HttpResponse(200, httpx.Headers(), b"data")
        client = AsyncBaseApiClient(DummyAsyncHttp(response))
        self.assertEqual(await client._request_bytes("GET", "/path"), b"data")
        raw = await client._request_raw("GET", "/path")
        self.assertIs(raw, response)

    async def test_async_request_json_empty(self):
        response = HttpResponse(204, httpx.Headers(), b"")
        client = AsyncBaseApiClient(DummyAsyncHttp(response))
        self.assertIsNone(await client._request_json("GET", "/path"))


if __name__ == "__main__":
    unittest.main()
