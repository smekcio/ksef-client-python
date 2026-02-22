import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx

from ksef_client.config import KsefClientOptions
from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError
from ksef_client.http import (
    AsyncBaseHttpClient,
    BaseHttpClient,
    HttpResponse,
    _host_allowed,
    _merge_headers,
    _validate_presigned_url_security,
)


class HttpTests(unittest.TestCase):
    def test_merge_headers(self):
        base = {"a": "1"}
        merged = _merge_headers(base, {"b": "2"})
        self.assertEqual(merged, {"a": "1", "b": "2"})
        self.assertEqual(_merge_headers(base, None), base)

    def test_base_http_request_and_headers(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", Mock(return_value=response)) as request_mock:
            resp = client.request("GET", "/path", json={"a": 1})
            self.assertIsInstance(resp, HttpResponse)
            self.assertEqual(resp.json(), {"ok": True})

            _, kwargs = request_mock.call_args
            self.assertIn("Authorization", kwargs["headers"])
            self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
            self.assertTrue(kwargs["url"].endswith("/v2/path"))

        with patch.object(client._client, "close") as close_mock:
            client.close()
            close_mock.assert_called_once()

    def test_custom_headers_applied(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            custom_headers={"X-Custom": "value", "Accept": "application/xml"},
        )
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", Mock(return_value=response)) as request_mock:
            client.request("GET", "/path")
            _, kwargs = request_mock.call_args
            self.assertEqual(kwargs["headers"]["X-Custom"], "value")
            self.assertEqual(kwargs["headers"]["Accept"], "application/xml")

    def test_httpx_client_init_proxy_and_redirects(self):
        with patch("ksef_client.http.httpx.Client") as mocked:
            options = KsefClientOptions(
                base_url="https://api-test.ksef.mf.gov.pl",
                proxy="http://proxy.local:8080",
                follow_redirects=True,
            )
            BaseHttpClient(options)
            _, kwargs = mocked.call_args
            self.assertEqual(kwargs["proxy"], "http://proxy.local:8080")
            self.assertTrue(kwargs["follow_redirects"])

    def test_refresh_token_overrides_access(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", Mock(return_value=response)) as request_mock:
            client.request("POST", "https://example.com/refresh", refresh_token="refresh")
            _, kwargs = request_mock.call_args
            self.assertIn("Authorization", kwargs["headers"])
            self.assertIn("refresh", kwargs["headers"]["Authorization"])

    def test_raise_for_status_rate_limit(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(429, headers={"Retry-After": "5"}, json={"error": "limit"})
        with self.assertRaises(KsefRateLimitError) as ctx:
            client._raise_for_status(response)
        self.assertEqual(ctx.exception.retry_after, "5")

    def test_raise_for_status_api_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(400, json={"error": "bad"})
        with self.assertRaises(KsefApiError):
            client._raise_for_status(response)

    def test_raise_for_status_http_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(500, content=b"boom", headers={"Content-Type": "text/plain"})
        with self.assertRaises(KsefHttpError):
            client._raise_for_status(response)

    def test_raise_for_status_invalid_json(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            400, content=b"not-json", headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(KsefHttpError):
            client._raise_for_status(response)

    def test_expected_status_mismatch(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(400, json={"error": "bad"})
        with (
            patch.object(client._client, "request", Mock(return_value=response)),
            self.assertRaises(KsefApiError),
        ):
            client.request("GET", "/path", expected_status={200})

    def test_default_status_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(400, json={"error": "bad"})
        with (
            patch.object(client._client, "request", Mock(return_value=response)),
            self.assertRaises(KsefApiError),
        ):
            client.request("GET", "/path")

    def test_skip_auth_presigned_url_accepts_valid_https(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", Mock(return_value=response)) as request_mock:
            client.request("GET", "https://files.example.com/upload", skip_auth=True)
            _, kwargs = request_mock.call_args
            self.assertEqual(kwargs["url"], "https://files.example.com/upload")
            self.assertNotIn("Authorization", kwargs["headers"])

    def test_skip_auth_presigned_url_rejects_http_when_strict(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        with self.assertRaisesRegex(ValueError, "https is required"):
            client.request("GET", "http://files.example.com/upload", skip_auth=True)

    def test_skip_auth_presigned_url_allows_http_when_not_strict(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            strict_presigned_url_validation=False,
        )
        client = BaseHttpClient(options)
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", Mock(return_value=response)) as request_mock:
            client.request("GET", "http://files.example.com/upload", skip_auth=True)
            _, kwargs = request_mock.call_args
            self.assertEqual(kwargs["url"], "http://files.example.com/upload")

    def test_skip_auth_presigned_url_rejects_localhost_and_loopback(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        with self.assertRaisesRegex(ValueError, "localhost"):
            client.request("GET", "https://localhost/upload", skip_auth=True)
        with self.assertRaisesRegex(ValueError, "loopback"):
            client.request("GET", "https://127.0.0.1/upload", skip_auth=True)

    def test_skip_auth_presigned_url_rejects_private_ip_by_default(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        with self.assertRaisesRegex(ValueError, "private, link-local, and reserved IP"):
            client.request("GET", "https://10.1.2.3/upload", skip_auth=True)

    def test_skip_auth_presigned_url_allows_private_ip_when_opted_in(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            allow_private_network_presigned_urls=True,
        )
        client = BaseHttpClient(options)
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", Mock(return_value=response)) as request_mock:
            client.request("GET", "https://10.1.2.3/upload", skip_auth=True)
            _, kwargs = request_mock.call_args
            self.assertEqual(kwargs["url"], "https://10.1.2.3/upload")

    def test_skip_auth_presigned_url_allowlist_exact_and_subdomain(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            allowed_presigned_hosts=["uploads.example.com"],
        )
        client = BaseHttpClient(options)
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", Mock(return_value=response)):
            client.request("GET", "https://uploads.example.com/path", skip_auth=True)
            client.request("GET", "https://sub.uploads.example.com/path", skip_auth=True)

    def test_skip_auth_presigned_url_allowlist_rejects_other_hosts(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            allowed_presigned_hosts=["uploads.example.com"],
        )
        client = BaseHttpClient(options)
        with self.assertRaisesRegex(ValueError, "allowed_presigned_hosts"):
            client.request("GET", "https://other.example.com/path", skip_auth=True)

    def test_host_allowed_skips_empty_and_ip_allowlist_entries(self):
        self.assertTrue(
            _host_allowed(
                "sub.uploads.example.com",
                ["", "10.0.0.1", "uploads.example.com"],
            )
        )

    def test_validate_presigned_url_security_rejects_missing_host(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        with self.assertRaisesRegex(ValueError, "host is missing"):
            _validate_presigned_url_security(options, "https:///no-host")


class AsyncHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_request(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options, access_token="token")
        response = httpx.Response(200, json={"ok": True})
        with patch.object(client._client, "request", AsyncMock(return_value=response)):
            resp = await client.request("GET", "/path", json={"a": 1})
            self.assertEqual(resp.json(), {"ok": True})

        with patch.object(client._client, "aclose", AsyncMock()) as aclose_mock:
            await client.aclose()
            aclose_mock.assert_called_once()

    async def test_async_httpx_client_init_proxy_and_redirects(self):
        with patch("ksef_client.http.httpx.AsyncClient") as mocked:
            options = KsefClientOptions(
                base_url="https://api-test.ksef.mf.gov.pl",
                proxy="http://proxy.local:8080",
                follow_redirects=True,
            )
            AsyncBaseHttpClient(options)
            _, kwargs = mocked.call_args
            self.assertEqual(kwargs["proxy"], "http://proxy.local:8080")
            self.assertTrue(kwargs["follow_redirects"])

    async def test_async_expected_status(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options)
        response = httpx.Response(400, json={"error": "bad"})
        with (
            patch.object(client._client, "request", AsyncMock(return_value=response)),
            self.assertRaises(KsefApiError),
        ):
            await client.request("GET", "/path", expected_status={200})

    async def test_async_default_status_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options)
        response = httpx.Response(400, json={"error": "bad"})
        with (
            patch.object(client._client, "request", AsyncMock(return_value=response)),
            self.assertRaises(KsefApiError),
        ):
            await client.request("GET", "/path")

    async def test_async_refresh_token(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options, access_token="token")
        response = httpx.Response(200, json={"ok": True})
        with patch.object(
            client._client, "request", AsyncMock(return_value=response)
        ) as request_mock:
            await client.request("POST", "/path", refresh_token="refresh")
            _, kwargs = request_mock.call_args
            self.assertIn("refresh", kwargs["headers"]["Authorization"])

    async def test_async_raise_for_status_paths(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options)
        response_invalid = httpx.Response(
            400, content=b"not-json", headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(KsefHttpError):
            client._raise_for_status(response_invalid)

        response_rate = httpx.Response(429, headers={"Retry-After": "1"}, json={"error": "limit"})
        with self.assertRaises(KsefRateLimitError):
            client._raise_for_status(response_rate)

        response_http = httpx.Response(500, content=b"boom", headers={"Content-Type": "text/plain"})
        with self.assertRaises(KsefHttpError):
            client._raise_for_status(response_http)

    async def test_async_skip_auth_presigned_validation_rejects_localhost(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options)
        with self.assertRaisesRegex(ValueError, "localhost"):
            await client.request("GET", "https://localhost/upload", skip_auth=True)


if __name__ == "__main__":
    unittest.main()
