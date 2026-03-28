import unittest
from typing import Any

import httpx

from ksef_client.clients.base import (
    AsyncBaseApiClient,
    BaseApiClient,
    _serialize_json_payload,
    _validate_model_list_payload,
    _validate_model_payload,
)
from ksef_client.http import HttpResponse


class DummyHttp:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def request(self, *args, **kwargs) -> HttpResponse:
        self.calls.append((args, kwargs))
        return self.response


class DummyAsyncHttp:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    async def request(self, *args, **kwargs) -> HttpResponse:
        self.calls.append((args, kwargs))
        return self.response


class JsonPayload:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        _ = omit_none
        return dict(self._payload)


class ParsedModel:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ParsedModel":
        return cls(data)


class BaseApiClientTests(unittest.TestCase):
    def test_payload_helpers(self):
        self.assertIsNone(_serialize_json_payload(None))
        self.assertEqual(_serialize_json_payload({"ok": True}), {"ok": True})
        self.assertEqual(_serialize_json_payload(JsonPayload({"x": 1})), {"x": 1})
        self.assertEqual(_validate_model_payload({"ok": True}, path="/path"), {"ok": True})
        self.assertEqual(
            _validate_model_list_payload([{"ok": True}], path="/path"),
            [{"ok": True}],
        )
        with self.assertRaises(TypeError):
            _validate_model_payload([], path="/path")
        with self.assertRaises(TypeError):
            _validate_model_list_payload({"ok": True}, path="/path")
        with self.assertRaises(TypeError):
            _validate_model_list_payload([{"ok": True}, "bad"], path="/path")

    def test_request_json_with_content(self):
        response = HttpResponse(
            200, httpx.Headers({"Content-Type": "application/json"}), b'{"ok": true}'
        )
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

    def test_request_model_helpers(self):
        response = HttpResponse(
            200, httpx.Headers({"Content-Type": "application/json"}), b'{"ok": true}'
        )
        http = DummyHttp(response)
        client = BaseApiClient(http)

        parsed = client._request_model(
            "POST",
            "/path",
            response_model=ParsedModel,
            json=JsonPayload({"hello": "world"}),
            access_token="access",
            refresh_token="refresh",
            skip_auth=True,
            expected_status={200},
        )
        self.assertEqual(parsed.payload, {"ok": True})
        self.assertEqual(http.calls[0][1]["json"], {"hello": "world"})
        self.assertEqual(http.calls[0][1]["access_token"], "access")
        self.assertEqual(http.calls[0][1]["refresh_token"], "refresh")
        self.assertTrue(http.calls[0][1]["skip_auth"])
        self.assertEqual(http.calls[0][1]["expected_status"], {200})

        optional = client._request_optional_model("GET", "/path", response_model=ParsedModel)
        self.assertIsNotNone(optional)
        assert optional is not None
        self.assertEqual(optional.payload, {"ok": True})

    def test_request_optional_model_none_and_invalid_payload(self):
        client = BaseApiClient(DummyHttp(HttpResponse(204, httpx.Headers(), b"")))
        self.assertIsNone(
            client._request_optional_model("GET", "/path", response_model=ParsedModel)
        )

        invalid_client = BaseApiClient(
            DummyHttp(HttpResponse(200, httpx.Headers({"Content-Type": "application/json"}), b"[]"))
        )
        with self.assertRaises(TypeError):
            invalid_client._request_model("GET", "/path", response_model=ParsedModel)

    def test_request_model_list(self):
        response = HttpResponse(
            200,
            httpx.Headers({"Content-Type": "application/json"}),
            b'[{"a": 1}, {"b": 2}]',
        )
        client = BaseApiClient(DummyHttp(response))
        parsed = client._request_model_list("GET", "/path", response_model=ParsedModel)
        self.assertEqual([item.payload for item in parsed], [{"a": 1}, {"b": 2}])

        invalid_client = BaseApiClient(
            DummyHttp(
                HttpResponse(
                    200,
                    httpx.Headers({"Content-Type": "application/json"}),
                    b'["bad"]',
                )
            )
        )
        with self.assertRaises(TypeError):
            invalid_client._request_model_list("GET", "/path", response_model=ParsedModel)


class AsyncBaseApiClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_request_json(self):
        response = HttpResponse(
            200, httpx.Headers({"Content-Type": "application/json"}), b'{"ok": true}'
        )
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

    async def test_async_request_model_helpers(self):
        response = HttpResponse(
            200, httpx.Headers({"Content-Type": "application/json"}), b'{"ok": true}'
        )
        http = DummyAsyncHttp(response)
        client = AsyncBaseApiClient(http)

        parsed = await client._request_model(
            "POST",
            "/path",
            response_model=ParsedModel,
            json=JsonPayload({"hello": "world"}),
            access_token="access",
            refresh_token="refresh",
            skip_auth=True,
            expected_status={200},
        )
        self.assertEqual(parsed.payload, {"ok": True})
        self.assertEqual(http.calls[0][1]["json"], {"hello": "world"})
        self.assertEqual(http.calls[0][1]["access_token"], "access")
        self.assertEqual(http.calls[0][1]["refresh_token"], "refresh")
        self.assertTrue(http.calls[0][1]["skip_auth"])
        self.assertEqual(http.calls[0][1]["expected_status"], {200})

        optional = await client._request_optional_model(
            "GET", "/path", response_model=ParsedModel
        )
        self.assertIsNotNone(optional)
        assert optional is not None
        self.assertEqual(optional.payload, {"ok": True})

    async def test_async_request_optional_model_none_and_invalid_payload(self):
        client = AsyncBaseApiClient(DummyAsyncHttp(HttpResponse(204, httpx.Headers(), b"")))
        self.assertIsNone(
            await client._request_optional_model("GET", "/path", response_model=ParsedModel)
        )

        invalid_client = AsyncBaseApiClient(
            DummyAsyncHttp(
                HttpResponse(200, httpx.Headers({"Content-Type": "application/json"}), b"[]")
            )
        )
        with self.assertRaises(TypeError):
            await invalid_client._request_model("GET", "/path", response_model=ParsedModel)

    async def test_async_request_model_list(self):
        response = HttpResponse(
            200,
            httpx.Headers({"Content-Type": "application/json"}),
            b'[{"a": 1}, {"b": 2}]',
        )
        client = AsyncBaseApiClient(DummyAsyncHttp(response))
        parsed = await client._request_model_list("GET", "/path", response_model=ParsedModel)
        self.assertEqual([item.payload for item in parsed], [{"a": 1}, {"b": 2}])

        invalid_client = AsyncBaseApiClient(
            DummyAsyncHttp(
                HttpResponse(
                    200,
                    httpx.Headers({"Content-Type": "application/json"}),
                    b'["bad"]',
                )
            )
        )
        with self.assertRaises(TypeError):
            await invalid_client._request_model_list("GET", "/path", response_model=ParsedModel)


if __name__ == "__main__":
    unittest.main()
