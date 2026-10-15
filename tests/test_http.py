import asyncio
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import httpx

from ksef_client import models
from ksef_client.config import KsefClientOptions
from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError
from ksef_client.http import (
    MAX_RETRY_AFTER_SECONDS,
    AsyncBaseHttpClient,
    BaseHttpClient,
    HttpResponse,
    _host_allowed,
    _is_json_content_type,
    _loggable_url,
    _merge_headers,
    _parse_api_problem,
    _parse_retry_after,
    _validate_presigned_url_security,
)


class HttpTests(unittest.TestCase):
    def test_is_json_content_type(self):
        self.assertTrue(_is_json_content_type("application/json"))
        self.assertTrue(_is_json_content_type("application/problem+json"))
        self.assertTrue(_is_json_content_type("application/vnd.api+json; charset=utf-8"))
        self.assertFalse(_is_json_content_type("text/plain"))

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

    def test_request_rejects_json_and_data_together(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        with patch.object(client._client, "request", Mock()) as request_mock:
            with self.assertRaisesRegex(ValueError, "either json or data"):
                client.request("POST", "/path", json={"a": 1}, data=b"RAW")
            request_mock.assert_not_called()

    def test_system_warning_handler_receives_response_header(self):
        warnings: list[str] = []
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            system_warning_handler=warnings.append,
        )
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200, headers={"X-System-Warning": "future warning"})
        with patch.object(client._client, "request", Mock(return_value=response)):
            client.request("GET", "/path")
        self.assertEqual(warnings, ["future warning"])

    def test_system_warning_handler_is_optional(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200, headers={"X-System-Warning": "future warning"})
        with patch.object(client._client, "request", Mock(return_value=response)):
            client.request("GET", "/path")

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
        self.assertEqual(ctx.exception.retry_after, 5)
        self.assertEqual(ctx.exception.retry_after_raw, "5")

    def test_raise_for_status_legacy_rate_limit_problem(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            429,
            headers={"Retry-After": "5"},
            json={
                "status": {
                    "code": 429,
                    "description": "Too Many Requests",
                    "details": ["Retry later."],
                }
            },
        )
        with self.assertRaises(KsefRateLimitError) as ctx:
            client._raise_for_status(response)
        self.assertEqual(ctx.exception.retry_after, 5)
        assert isinstance(ctx.exception.problem, models.TooManyRequestsResponse)
        self.assertEqual(ctx.exception.problem.status["code"], 429)

    def test_raise_for_status_unknown_rate_limit_problem(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            429,
            headers={"Retry-After": "5"},
            json={"error": "limit"},
        )
        with self.assertRaises(KsefRateLimitError) as ctx:
            client._raise_for_status(response)
        self.assertEqual(ctx.exception.retry_after, 5)
        assert isinstance(ctx.exception.problem, models.UnknownApiProblem)
        self.assertEqual(ctx.exception.problem.status, 429)

    def test_raise_for_status_api_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(400, json={"error": "bad"})
        with self.assertRaises(KsefApiError):
            client._raise_for_status(response)

    def test_raise_for_status_problem_json_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            403,
            headers={"Content-Type": "application/problem+json"},
            json={
                "title": "Forbidden",
                "status": 403,
                "detail": "Missing permissions",
                "reasonCode": "missing-permissions",
                "timestamp": "2026-04-13T10:00:00Z",
            },
        )
        with self.assertRaises(KsefApiError) as ctx:
            client._raise_for_status(response)
        assert isinstance(ctx.exception.response_body, dict)
        self.assertEqual(ctx.exception.response_body["reasonCode"], "missing-permissions")
        assert ctx.exception.problem is not None
        assert isinstance(ctx.exception.problem, models.ForbiddenProblemDetails)
        self.assertEqual(ctx.exception.problem.reason_code, "missing-permissions")

    def test_raise_for_status_bad_request_problem_details(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            400,
            headers={"Content-Type": "application/problem+json"},
            json={
                "title": "Bad Request",
                "status": 400,
                "instance": "/tokens",
                "detail": "Request is invalid.",
                "errors": [
                    {
                        "code": 21405,
                        "description": "Validation error.",
                        "details": ["Field X is required."],
                    }
                ],
                "timestamp": "2026-04-13T10:00:00Z",
                "traceId": "trace-400",
            },
        )
        with self.assertRaises(KsefApiError) as ctx:
            client._raise_for_status(response)
        assert isinstance(ctx.exception.problem, models.BadRequestProblemDetails)
        self.assertEqual(ctx.exception.problem.errors[0].code, 21405)

    def test_raise_for_status_problem_rate_limit(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            429,
            headers={"Retry-After": "5", "Content-Type": "application/problem+json"},
            json={
                "title": "Too Many Requests",
                "status": 429,
                "instance": "/invoices/exports",
                "detail": "Retry later.",
                "timestamp": "2026-04-13T10:00:00Z",
                "traceId": "trace-429",
            },
        )
        with self.assertRaises(KsefRateLimitError) as ctx:
            client._raise_for_status(response)
        self.assertEqual(ctx.exception.retry_after, 5)
        assert isinstance(ctx.exception.problem, models.TooManyRequestsProblemDetails)
        self.assertEqual(ctx.exception.problem.trace_id, "trace-429")

    def test_raise_for_status_gone_problem(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            410,
            headers={"Content-Type": "application/problem+json"},
            json={
                "title": "Gone",
                "status": 410,
                "instance": "/auth/ref-1",
                "detail": "Operation expired.",
                "timestamp": "2026-04-13T10:00:00Z",
                "traceId": "trace-410",
            },
        )
        with self.assertRaises(KsefApiError) as ctx:
            client._raise_for_status(response)
        assert isinstance(ctx.exception.problem, models.GoneProblemDetails)
        self.assertEqual(ctx.exception.problem.status, 410)

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

    def test_loggable_url_strips_credentials_and_query(self):
        self.assertEqual(
            _loggable_url("https://user:SECRET@api-test.ksef.mf.gov.pl/v2/x?sig=SECRET#frag"),
            "https://api-test.ksef.mf.gov.pl/v2/x",
        )
        self.assertEqual(
            _loggable_url("https://storage.example.com/part?sv=1&sig=SECRET"),
            "https://storage.example.com/part",
        )
        self.assertEqual(_loggable_url("https://host:8443/a/b"), "https://host:8443/a/b")
        self.assertEqual(_loggable_url("https://[::1]:8443/a"), "https://[::1]:8443/a")
        self.assertEqual(_loggable_url("/relative/path?x=1"), "/relative/path")

    def test_skip_auth_presigned_url_rejects_credentials_in_url(self):
        """Userinfo nie może wyciec do logu diagnostycznego."""
        self.assertNotIn(
            "pw", _loggable_url("https://user:pw@uploads.example.com/x?sig=SECRET")
        )
        self.assertEqual(
            _loggable_url("https://user:pw@uploads.example.com/x?sig=SECRET"),
            "https://uploads.example.com/x",
        )

    def test_skip_auth_presigned_url_rejects_ipv4_mapped_loopback(self):
        """`[::ffff:127.0.0.1]` to loopback — nawet przy zgodzie na sieci prywatne."""
        for allow_private in (False, True):
            options = KsefClientOptions(
                base_url="https://api-test.ksef.mf.gov.pl",
                allow_private_network_presigned_urls=allow_private,
            )
            with self.assertRaisesRegex(ValueError, "loopback"):
                _validate_presigned_url_security(options, "https://[::ffff:127.0.0.1]/x")

        default_options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        with self.assertRaisesRegex(ValueError, "private, link-local"):
            _validate_presigned_url_security(
                default_options, "https://[::ffff:169.254.169.254]/x"
            )

    def test_skip_auth_presigned_url_rejects_ambiguous_numeric_hosts(self):
        """Zapisy, które resolvery rozumieją jako IP, a `ipaddress` już nie."""
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        for host in ("2130706433", "0x7f000001", "127.1", "0177.0.0.1"):
            with self.assertRaisesRegex(ValueError, "ambiguous numeric host"):
                _validate_presigned_url_security(options, f"https://{host}/x")

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

    def test_parse_retry_after_variants(self):
        self.assertIsNone(_parse_retry_after(None))
        self.assertIsNone(_parse_retry_after("   "))
        self.assertEqual(_parse_retry_after("5"), 5)
        self.assertIsNone(_parse_retry_after("bad"))
        parsed_http_date = _parse_retry_after("Wed, 01 Jan 2099 00:00:00 GMT")
        self.assertIsNotNone(parsed_http_date)
        assert parsed_http_date is not None
        self.assertGreater(parsed_http_date, 0)

    def test_parse_retry_after_assigns_utc_to_naive_http_date(self):
        with patch(
            "ksef_client.http.parsedate_to_datetime",
            return_value=datetime(2099, 1, 1, 0, 0, 0),
        ):
            parsed_http_date = _parse_retry_after("Wed, 01 Jan 2099 00:00:00")
        self.assertIsNotNone(parsed_http_date)
        assert parsed_http_date is not None
        self.assertGreater(parsed_http_date, 0)

    def test_parse_retry_after_is_capped_and_never_negative(self):
        self.assertEqual(_parse_retry_after("31536000"), MAX_RETRY_AFTER_SECONDS)
        self.assertEqual(_parse_retry_after("-5"), 0)
        self.assertEqual(
            _parse_retry_after("Wed, 01 Jan 2099 00:00:00 GMT"),
            MAX_RETRY_AFTER_SECONDS,
        )
        with patch(
            "ksef_client.http.parsedate_to_datetime",
            return_value=datetime(2000, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        ):
            self.assertEqual(_parse_retry_after("Sat, 01 Jan 2000 00:00:00 GMT"), 0)

    def test_rate_limit_error_caps_retry_after_but_keeps_the_raw_header(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            429,
            headers={"Retry-After": "31536000"},
            json={"error": "limit"},
        )
        with self.assertRaises(KsefRateLimitError) as ctx:
            client._raise_for_status(response)
        self.assertEqual(ctx.exception.retry_after, MAX_RETRY_AFTER_SECONDS)
        self.assertEqual(ctx.exception.retry_after_raw, "31536000")

    def test_parse_api_problem_variants(self):
        self.assertIsNone(_parse_api_problem(400, []))

        exception_problem = _parse_api_problem(400, {"exception": {}})
        self.assertIsInstance(exception_problem, models.ExceptionResponse)

        bad_request = _parse_api_problem(
            400,
            {
                "title": "Bad Request",
                "status": 400,
                "instance": "/tokens",
                "detail": "Request is invalid.",
                "errors": [{"code": 21405, "description": "Validation error."}],
                "timestamp": "2026-04-13T10:00:00Z",
                "traceId": "trace-400",
            },
        )
        self.assertIsInstance(bad_request, models.BadRequestProblemDetails)

        forbidden = _parse_api_problem(
            403,
            {
                "title": "Forbidden",
                "status": 403,
                "detail": "Missing permissions",
                "reasonCode": "missing-permissions",
                "timestamp": "2026-04-13T10:00:00Z",
            },
        )
        self.assertIsInstance(forbidden, models.ForbiddenProblemDetails)

        unauthorized = _parse_api_problem(
            401,
            {
                "title": "Unauthorized",
                "status": 401,
                "detail": "Missing bearer token",
                "timestamp": "2026-04-13T10:00:00Z",
            },
        )
        self.assertIsInstance(unauthorized, models.UnauthorizedProblemDetails)

        rate_limit_problem = _parse_api_problem(
            429,
            {
                "title": "Too Many Requests",
                "status": 429,
                "instance": "/invoices/exports",
                "detail": "Retry later.",
                "timestamp": "2026-04-13T10:00:00Z",
                "traceId": "trace-429",
            },
        )
        self.assertIsInstance(rate_limit_problem, models.TooManyRequestsProblemDetails)

        legacy_rate_limit_problem = _parse_api_problem(
            429,
            {
                "status": {
                    "code": 429,
                    "description": "Too Many Requests",
                    "details": ["Retry later."],
                }
            },
        )
        self.assertIsInstance(legacy_rate_limit_problem, models.TooManyRequestsResponse)

        unknown_rate_limit_problem = _parse_api_problem(429, {"error": "limit"})
        self.assertIsInstance(unknown_rate_limit_problem, models.UnknownApiProblem)

        gone_problem = _parse_api_problem(
            410,
            {
                "title": "Gone",
                "status": 410,
                "instance": "/auth/ref-1",
                "detail": "Operation expired.",
                "timestamp": "2026-04-13T10:00:00Z",
                "traceId": "trace-410",
            },
        )
        self.assertIsInstance(gone_problem, models.GoneProblemDetails)

        unknown = _parse_api_problem(400, {"title": "Bad", "detail": "x"})
        self.assertIsInstance(unknown, models.UnknownApiProblem)
        self.assertIsNotNone(unknown)
        assert unknown is not None
        self.assertEqual(unknown.title, "Bad")

        raw_unknown = _parse_api_problem(400, {"error": "bad"})
        self.assertIsInstance(raw_unknown, models.UnknownApiProblem)
        self.assertIsNotNone(raw_unknown)
        assert raw_unknown is not None
        self.assertEqual(raw_unknown.status, 400)

        invalid_status_unknown = _parse_api_problem(400, {"title": "Bad", "status": "oops"})
        self.assertIsInstance(invalid_status_unknown, models.UnknownApiProblem)
        self.assertIsNotNone(invalid_status_unknown)
        assert invalid_status_unknown is not None
        self.assertEqual(invalid_status_unknown.status, 400)

        parse_error_unknown = _parse_api_problem(
            403,
            {
                "title": "Forbidden",
                "status": 403,
                "detail": "Missing permissions",
                "reasonCode": ["invalid-type"],
            },
        )
        self.assertIsInstance(parse_error_unknown, models.UnknownApiProblem)
        self.assertIsNotNone(parse_error_unknown)
        assert parse_error_unknown is not None
        self.assertEqual(parse_error_unknown.title, "Forbidden")

        self.assertIsNone(_parse_api_problem(400, {}))

    def test_raise_for_status_rate_limit_http_date(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options)
        response = httpx.Response(
            429,
            headers={"Retry-After": "Wed, 01 Jan 2099 00:00:00 GMT"},
            json={"error": "limit"},
        )
        with self.assertRaises(KsefRateLimitError) as ctx:
            client._raise_for_status(response)
        self.assertIsNotNone(ctx.exception.retry_after)
        assert ctx.exception.retry_after is not None
        self.assertGreater(ctx.exception.retry_after, 0)


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

    async def test_async_request_rejects_json_and_data_together(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options)
        with patch.object(client._client, "request", AsyncMock()) as request_mock:
            with self.assertRaisesRegex(ValueError, "either json or data"):
                await client.request("POST", "/path", json={"a": 1}, data=b"RAW")
            request_mock.assert_not_called()

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

        response_problem = httpx.Response(
            401,
            headers={"Content-Type": "application/problem+json"},
            json={
                "title": "Unauthorized",
                "status": 401,
                "detail": "Missing bearer token",
                "timestamp": "2026-04-13T10:00:00Z",
            },
        )
        with self.assertRaises(KsefApiError):
            client._raise_for_status(response_problem)

    async def test_async_skip_auth_presigned_validation_rejects_localhost(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options)
        with self.assertRaisesRegex(ValueError, "localhost"):
            await client.request("GET", "https://localhost/upload", skip_auth=True)

    async def test_async_request_absolute_url_without_skip_auth(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options, access_token="token")
        response = httpx.Response(200, json={"ok": True})
        with patch.object(
            client._client, "request", AsyncMock(return_value=response)
        ) as request_mock:
            await client.request("GET", "https://files.example.com/upload")
            _, kwargs = request_mock.call_args
            self.assertEqual(kwargs["url"], "https://files.example.com/upload")
            self.assertIn("Authorization", kwargs["headers"])

    async def test_async_skip_auth_presigned_url_accepts_valid_https(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options, access_token="token")
        response = httpx.Response(200, json={"ok": True})
        with patch.object(
            client._client, "request", AsyncMock(return_value=response)
        ) as request_mock:
            await client.request("GET", "https://files.example.com/upload", skip_auth=True)
            _, kwargs = request_mock.call_args
            self.assertEqual(kwargs["url"], "https://files.example.com/upload")
            self.assertNotIn("Authorization", kwargs["headers"])


class RedirectHandlingTests(unittest.TestCase):
    """3xx nie może być traktowane jak sukces.

    `httpx` nie podąża za przekierowaniami (`follow_redirects=False`), więc treść
    odpowiedzi 3xx to strona pośrednika albo puste ciało — przyjmowanie jej jako
    sukcesu zapisywało PUSTY plik UPO/faktury i raportowało sukces.
    """

    def test_sync_redirect_without_expected_status_is_an_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(302, headers={"Location": "https://example.com/login"})
        with (
            patch.object(client._client, "request", Mock(return_value=response)),
            self.assertRaises(KsefHttpError),
        ):
            client.request("GET", "/path")

    def test_sync_redirect_is_accepted_when_explicitly_expected(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(302, headers={"Location": "https://example.com/x"})
        with patch.object(client._client, "request", Mock(return_value=response)):
            result = client.request("GET", "/path", expected_status={302})
            self.assertEqual(result.status_code, 302)

    def test_sync_2xx_is_still_a_success(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        for status_code in (200, 201, 202, 204):
            response = httpx.Response(status_code)
            with patch.object(client._client, "request", Mock(return_value=response)):
                self.assertEqual(client.request("GET", "/path").status_code, status_code)


class AsyncRedirectHandlingTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_redirect_is_an_error(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncBaseHttpClient(options, access_token="token")
        response = httpx.Response(307, headers={"Location": "https://example.com/x"})
        with (
            patch.object(client._client, "request", AsyncMock(return_value=response)),
            self.assertRaises(KsefHttpError),
        ):
            await client.request("GET", "/path")


class VerboseLoggingTests(unittest.TestCase):
    """`-v/--verbose` ma realny efekt: żądania trafiają do logu bez sekretów."""

    def test_request_is_logged_without_query_parameters(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200)
        with (
            patch.object(client._client, "request", Mock(return_value=response)),
            self.assertLogs("ksef_client.http", level="DEBUG") as captured,
        ):
            client.request("GET", "https://storage.example.com/package?sig=SEKRET")

        joined = "\n".join(captured.output)
        assert "-> 200" in joined
        assert "storage.example.com/package" in joined
        assert "SEKRET" not in joined, "podpis presigned URL nie może trafiać do logu"

    def test_relative_path_is_logged_without_the_query(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200)
        with (
            patch.object(client._client, "request", Mock(return_value=response)),
            self.assertLogs("ksef_client.http", level="DEBUG") as captured,
        ):
            client.request("GET", "/invoices?secret=SEKRET")

        joined = "\n".join(captured.output)
        assert "/invoices" in joined
        assert "SEKRET" not in joined

    def test_loggable_url_handles_a_relative_path(self):
        from ksef_client.http import _loggable_url

        assert _loggable_url("invoices/1?sig=SEKRET") == "invoices/1"
        assert (
            _loggable_url("https://host.example/path?sig=SEKRET")
            == "https://host.example/path"
        )


class PresignedUrlRedirectTests(unittest.TestCase):
    """Presigned URL nie może podążać za przekierowaniem.

    Walidacja `_validate_presigned_url_security` dotyczy wyłącznie adresu
    początkowego, a przy `skip_auth` nie ma nagłówka `Authorization` — podążenie
    za przekierowaniem wykonałoby żądanie pod adres wskazany przez serwer (także
    do sieci wewnętrznej) i zwróciło jego treść jako wynik.
    """

    def test_skip_auth_never_follows_redirects(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl", follow_redirects=True
        )
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(302, headers={"Location": "http://169.254.169.254/secret"})
        request_mock = Mock(return_value=response)
        with (
            patch.object(client._client, "request", request_mock),
            self.assertRaises(KsefHttpError),
        ):
            client.request("GET", "https://storage.example.com/presigned?x=1", skip_auth=True)

        self.assertFalse(request_mock.call_args.kwargs["follow_redirects"])

    def test_authenticated_request_keeps_the_option(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl", follow_redirects=True
        )
        client = BaseHttpClient(options, access_token="token")
        response = httpx.Response(200)
        request_mock = Mock(return_value=response)
        with patch.object(client._client, "request", request_mock):
            client.request("GET", "/path")

        self.assertTrue(request_mock.call_args.kwargs["follow_redirects"])

    def test_async_skip_auth_never_follows_redirects(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl", follow_redirects=True
        )
        client = AsyncBaseHttpClient(options, access_token="token")
        response = httpx.Response(302, headers={"Location": "http://169.254.169.254/secret"})
        request_mock = AsyncMock(return_value=response)

        async def _run() -> None:
            with (
                patch.object(client._client, "request", request_mock),
                self.assertRaises(KsefHttpError),
            ):
                await client.request(
                    "GET", "https://storage.example.com/presigned?x=1", skip_auth=True
                )

        asyncio.run(_run())
        self.assertFalse(request_mock.call_args.kwargs["follow_redirects"])


if __name__ == "__main__":
    unittest.main()
