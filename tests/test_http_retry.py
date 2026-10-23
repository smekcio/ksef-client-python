from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from ksef_client.config import KsefClientOptions
from ksef_client.exceptions import KsefHttpError, KsefRateLimitError
from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient
from ksef_client.retry import RetryConfig

BASE_URL = "https://api-test.ksef.mf.gov.pl"


def _options(*, retry: RetryConfig | None = None) -> KsefClientOptions:
    return KsefClientOptions(base_url=BASE_URL, retry=retry)


def _response(status_code: int, *, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers=headers or {},
        json={"title": "status", "status": status_code},
    )


# --- kompatybilność: brak konfiguracji = dokładnie jedno żądanie ----------


def test_without_retry_config_single_attempt_and_raise() -> None:
    client = BaseHttpClient(_options(), access_token="token")
    request = Mock(return_value=_response(429, headers={"Retry-After": "1"}))

    with patch.object(client._client, "request", request), pytest.raises(KsefRateLimitError):
        client.request("GET", "/invoices/query/metadata")

    assert request.call_count == 1


def test_without_retry_config_success_unchanged() -> None:
    client = BaseHttpClient(_options(), access_token="token")
    request = Mock(return_value=httpx.Response(200, json={"ok": True}))

    with patch.object(client._client, "request", request):
        response = client.request("GET", "/x")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert request.call_count == 1


def test_max_retries_zero_means_single_attempt() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig(max_retries=0)), access_token="token")
    request = Mock(return_value=_response(429, headers={"Retry-After": "1"}))

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep") as sleep,pytest.raises(KsefRateLimitError)
    ):
        client.request("GET", "/x")

    assert request.call_count == 1
    sleep.assert_not_called()


# --- retry sync -----------------------------------------------------------


def test_retries_429_with_retry_after_and_succeeds() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(
        side_effect=[
            _response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep") as sleep,
    ):
        response = client.request("GET", "/x")

    assert response.status_code == 200
    assert request.call_count == 2
    sleep.assert_called_once_with(2.0)


def test_retries_until_budget_exhausted_then_raises_last_error() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig(max_retries=2)), access_token="token")
    request = Mock(return_value=_response(503))

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep"),pytest.raises(KsefHttpError) as excinfo
    ):
        client.request("GET", "/x")

    assert excinfo.value.status_code == 503
    assert request.call_count == 3  # pierwsza próba + 2 ponowienia


def test_uses_exponential_backoff_without_retry_after() -> None:
    config = RetryConfig(base_delay_ms=100, jitter_ratio=0.0, max_retries=2)
    client = BaseHttpClient(_options(retry=config), access_token="token")
    request = Mock(
        side_effect=[
            _response(502),
            _response(502),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.random.random", return_value=0.5),
        patch("ksef_client.http.time.sleep") as sleep,
    ):
        client.request("GET", "/x")

    assert [call.args[0] for call in sleep.call_args_list] == pytest.approx([0.1, 0.2])


def test_retry_after_larger_than_ceiling_is_capped() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(
        side_effect=[
            _response(429, headers={"Retry-After": "999999"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep") as sleep,
    ):
        client.request("GET", "/x")

    sleep.assert_called_once_with(300.0)


def test_post_is_not_retried_by_default() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(return_value=_response(503))

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep") as sleep,pytest.raises(KsefHttpError)
    ):
        client.request("POST", "/sessions/online")

    assert request.call_count == 1
    sleep.assert_not_called()


def test_allowlisted_post_path_is_retried() -> None:
    config = RetryConfig(retryable_post_paths=frozenset({"/invoices/query/metadata"}))
    client = BaseHttpClient(_options(retry=config), access_token="token")
    request = Mock(side_effect=[_response(503), httpx.Response(200, json={"ok": True})])

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep"),
    ):
        response = client.request("POST", "/invoices/query/metadata")

    assert response.status_code == 200
    assert request.call_count == 2


def test_delete_is_retried() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(side_effect=[_response(503), httpx.Response(204)])

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep"),
    ):
        response = client.request("DELETE", "/auth/sessions/current", expected_status={204})

    assert response.status_code == 204
    assert request.call_count == 2


def test_presigned_put_is_retried() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(side_effect=[_response(503), httpx.Response(200)])

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep"),
    ):
        response = client.request(
            "PUT",
            "https://storage.example.com/part?sig=secret",
            data=b"payload",
            skip_auth=True,
        )

    assert response.status_code == 200
    assert request.call_count == 2


def test_transport_error_is_not_retried() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(side_effect=httpx.ConnectError("boom"))

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep") as sleep,pytest.raises(KsefHttpError) as excinfo
    ):
        client.request("GET", "/x")

    assert excinfo.value.status_code == 0
    assert request.call_count == 1
    sleep.assert_not_called()


def test_non_retryable_status_is_not_retried() -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(return_value=_response(400))

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep") as sleep,pytest.raises(KsefHttpError)
    ):
        client.request("GET", "/x")

    assert request.call_count == 1
    sleep.assert_not_called()


def test_retry_log_does_not_leak_presigned_query(caplog: pytest.LogCaptureFixture) -> None:
    client = BaseHttpClient(_options(retry=RetryConfig()), access_token="token")
    request = Mock(side_effect=[_response(503), httpx.Response(200)])

    with (
        patch.object(client._client, "request", request),
        patch("ksef_client.http.time.sleep"),
        caplog.at_level(logging.DEBUG, logger="ksef_client.http"),
    ):
        client.request(
            "PUT", "https://storage.example.com/part?sig=secret", data=b"x", skip_auth=True
        )

    assert "sig=secret" not in caplog.text


# --- retry async ----------------------------------------------------------

ASYNC_BASE_URL = BASE_URL


def _async_options(*, retry: RetryConfig | None = None) -> KsefClientOptions:
    return KsefClientOptions(base_url=ASYNC_BASE_URL, retry=retry)


def test_async_without_retry_config_single_attempt() -> None:
    async def scenario() -> None:
        client = AsyncBaseHttpClient(_async_options(), access_token="token")
        request = AsyncMock(return_value=_response(429, headers={"Retry-After": "1"}))

        with (
            patch.object(client._client, "request", request),
            pytest.raises(KsefRateLimitError),
        ):
            await client.request("GET", "/x")

        assert request.call_count == 1
        await client.aclose()

    asyncio.run(scenario())


def test_async_retries_429_and_succeeds() -> None:
    async def scenario() -> None:
        client = AsyncBaseHttpClient(_async_options(retry=RetryConfig()), access_token="token")
        request = AsyncMock(
            side_effect=[
                _response(429, headers={"Retry-After": "1"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )

        with (
            patch.object(client._client, "request", request),
            patch("ksef_client.http.asyncio.sleep", new_callable=AsyncMock) as sleep,
        ):
            response = await client.request("GET", "/x")

        assert response.status_code == 200
        assert request.call_count == 2
        sleep.assert_awaited_once_with(1.0)
        await client.aclose()

    asyncio.run(scenario())


def test_async_post_is_not_retried_by_default() -> None:
    async def scenario() -> None:
        client = AsyncBaseHttpClient(_async_options(retry=RetryConfig()), access_token="token")
        request = AsyncMock(return_value=_response(503))

        with (
            patch.object(client._client, "request", request),
            patch("ksef_client.http.asyncio.sleep", new_callable=AsyncMock) as sleep,
            pytest.raises(KsefHttpError),
        ):
            await client.request("POST", "/sessions/online")

        assert request.call_count == 1
        sleep.assert_not_awaited()
        await client.aclose()

    asyncio.run(scenario())


def test_async_budget_exhaustion_raises_last_error() -> None:
    async def scenario() -> None:
        client = AsyncBaseHttpClient(
            _async_options(retry=RetryConfig(max_retries=1)), access_token="token"
        )
        request = AsyncMock(return_value=_response(504))

        with (
            patch.object(client._client, "request", request),
            patch("ksef_client.http.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(KsefHttpError) as excinfo,
        ):
            await client.request("GET", "/x")

        assert excinfo.value.status_code == 504
        assert request.call_count == 2
        await client.aclose()

    asyncio.run(scenario())


def test_async_presigned_put_is_retried() -> None:
    async def scenario() -> None:
        client = AsyncBaseHttpClient(_async_options(retry=RetryConfig()), access_token="token")
        request = AsyncMock(side_effect=[_response(503), httpx.Response(200)])

        with (
            patch.object(client._client, "request", request),
            patch("ksef_client.http.asyncio.sleep", new_callable=AsyncMock),
        ):
            response = await client.request(
                "PUT",
                "https://storage.example.com/part?sig=secret",
                data=b"payload",
                skip_auth=True,
            )

        assert response.status_code == 200
        assert request.call_count == 2
        await client.aclose()

    asyncio.run(scenario())


def test_async_transport_error_is_not_retried() -> None:
    async def scenario() -> None:
        client = AsyncBaseHttpClient(_async_options(retry=RetryConfig()), access_token="token")
        request = AsyncMock(side_effect=httpx.ConnectError("boom"))

        with (
            patch.object(client._client, "request", request),
            patch("ksef_client.http.asyncio.sleep", new_callable=AsyncMock) as sleep,
            pytest.raises(KsefHttpError),
        ):
            await client.request("GET", "/x")

        assert request.call_count == 1
        sleep.assert_not_awaited()
        await client.aclose()

    asyncio.run(scenario())
