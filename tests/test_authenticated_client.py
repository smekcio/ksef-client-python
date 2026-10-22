from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from ksef_client import AsyncAuthenticatedClient, AuthenticatedClient
from ksef_client.client import AsyncKsefClient, KsefClient
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.config import KsefClientOptions
from ksef_client.exceptions import KsefHttpError
from ksef_client.models import AuthenticationTokensResponse, TokenInfo
from ksef_client.services.workflows import AuthResult
from ksef_client.token_manager import (
    AsyncTokenManager,
    AsyncTokenRefreshingHttpClient,
    TokenManager,
    TokenRefreshingHttpClient,
)

BASE_URL = "https://api-test.ksef.mf.gov.pl"
FAR_FUTURE = "2099-01-01T00:00:00+00:00"


def _options() -> KsefClientOptions:
    return KsefClientOptions(base_url=BASE_URL)


def _tokens() -> AuthenticationTokensResponse:
    return AuthenticationTokensResponse(
        access_token=TokenInfo("access", FAR_FUTURE),
        refresh_token=TokenInfo("refresh", FAR_FUTURE),
    )


def _auth_result() -> AuthResult:
    return AuthResult(
        reference_number="ref-1",
        authentication_token="auth-token",
        tokens=_tokens(),
    )


def _unauthorized() -> httpx.Response:
    return httpx.Response(
        401,
        json={"title": "Unauthorized", "status": 401, "detail": "token expired"},
    )


def _request_mock(*responses: httpx.Response) -> Mock:
    return Mock(side_effect=list(responses))


# --- wstrzykiwanie tokena -------------------------------------------------


def test_authenticated_client_injects_token_into_requests() -> None:
    client = AuthenticatedClient(_options(), TokenManager("token-1"))
    request = _request_mock(httpx.Response(204))

    with patch.object(client._http._client, "request", request):
        client.auth.revoke_current_session()

    headers = request.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer token-1"
    assert isinstance(client.http_client, TokenRefreshingHttpClient)


def test_explicit_access_token_wins_over_manager() -> None:
    client = AuthenticatedClient(_options(), TokenManager("manager-token"))
    request = _request_mock(httpx.Response(204))

    with patch.object(client._http._client, "request", request):
        client.auth.revoke_current_session("explicit-token")

    headers = request.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer explicit-token"


def test_skip_auth_request_does_not_get_token() -> None:
    client = AuthenticatedClient(_options(), TokenManager("manager-token"))
    request = _request_mock(
        httpx.Response(200, json={"challenge": "c", "timestamp": "t", "timestampMs": 1})
    )

    with patch.object(client._http._client, "request", request):
        client.auth.get_challenge()

    headers = request.call_args.kwargs["headers"]
    assert "Authorization" not in headers


def test_plain_client_without_token_sends_no_authorization() -> None:
    client = KsefClient(_options())
    request = _request_mock(httpx.Response(204))

    with patch.object(client._http._client, "request", request):
        client.auth.revoke_current_session()

    headers = request.call_args.kwargs["headers"]
    assert "Authorization" not in headers


# --- 401 → refresh → retry ------------------------------------------------


def test_401_refreshes_token_and_retries_once() -> None:
    refreshed: list[str] = []

    def handler(refresh_token: str) -> TokenInfo:
        refreshed.append(refresh_token)
        return TokenInfo("fresh-token", FAR_FUTURE)

    client = AuthenticatedClient(
        _options(), TokenManager("stale-token", "refresh-token", refresh_handler=handler)
    )
    request = _request_mock(_unauthorized(), httpx.Response(204))

    with patch.object(client._http._client, "request", request):
        client.auth.revoke_current_session()

    assert request.call_count == 2
    assert refreshed == ["refresh-token"]
    assert request.call_args_list[1].kwargs["headers"]["Authorization"] == "Bearer fresh-token"


def test_second_401_after_refresh_is_raised() -> None:
    refreshed: list[str] = []

    def handler(refresh_token: str) -> TokenInfo:
        refreshed.append(refresh_token)
        return TokenInfo("fresh-token", FAR_FUTURE)

    client = AuthenticatedClient(
        _options(), TokenManager("stale-token", "refresh-token", refresh_handler=handler)
    )
    request = _request_mock(_unauthorized(), _unauthorized())

    with (
        patch.object(client._http._client, "request", request),
        pytest.raises(KsefHttpError) as excinfo,
    ):
        client.auth.revoke_current_session()

    assert excinfo.value.status_code == 401
    assert request.call_count == 2
    assert refreshed == ["refresh-token"]


def test_401_with_explicit_token_does_not_refresh() -> None:
    refreshed: list[str] = []

    def handler(refresh_token: str) -> TokenInfo:
        refreshed.append(refresh_token)
        return TokenInfo("fresh-token", FAR_FUTURE)

    client = AuthenticatedClient(
        _options(), TokenManager("manager-token", "refresh-token", refresh_handler=handler)
    )
    request = _request_mock(_unauthorized())

    with patch.object(client._http._client, "request", request), pytest.raises(KsefHttpError):
        client.auth.revoke_current_session("explicit-token")

    assert request.call_count == 1
    assert refreshed == []


def test_non_401_error_does_not_refresh() -> None:
    refreshed: list[str] = []

    def handler(refresh_token: str) -> TokenInfo:
        refreshed.append(refresh_token)
        return TokenInfo("fresh-token", FAR_FUTURE)

    client = AuthenticatedClient(
        _options(), TokenManager("token", "refresh-token", refresh_handler=handler)
    )
    request = _request_mock(
        httpx.Response(
            403,
            json={
                "title": "Forbidden",
                "status": 403,
                "detail": "no access",
                "reasonCode": "missing-permission",
            },
        )
    )

    with (
        patch.object(client._http._client, "request", request),
        pytest.raises(KsefHttpError) as excinfo,
    ):
        client.auth.revoke_current_session()

    assert excinfo.value.status_code == 403
    assert refreshed == []
    assert request.call_count == 1


def test_401_without_refresh_token_raises_original_error() -> None:
    client = AuthenticatedClient(_options(), TokenManager("stale-token"))
    request = _request_mock(_unauthorized())

    with (
        patch.object(client._http._client, "request", request),
        pytest.raises(KsefHttpError) as excinfo,
    ):
        client.auth.revoke_current_session()

    assert excinfo.value.status_code == 401
    assert request.call_count == 1


# --- fabryki i walidacja --------------------------------------------------


def test_from_auth_result_builds_manager_and_binds_auth_client() -> None:
    client = AuthenticatedClient.from_auth_result(_options(), _auth_result())

    assert isinstance(client.http_client, TokenRefreshingHttpClient)
    assert client.token_manager.can_refresh is True
    assert client.token_manager.snapshot().has_refresh_token is True


def test_from_auth_result_passes_on_refresh_callback() -> None:
    received: list[TokenInfo] = []
    auth_result = _auth_result()
    auth_result = AuthResult(
        reference_number=auth_result.reference_number,
        authentication_token=auth_result.authentication_token,
        tokens=AuthenticationTokensResponse(
            access_token=TokenInfo("access", "2020-01-01T00:00:00+00:00"),
            refresh_token=TokenInfo("refresh", FAR_FUTURE),
        ),
    )

    client = AuthenticatedClient.from_auth_result(
        _options(), auth_result, on_refresh=received.append
    )
    refresh_request = _request_mock(
        httpx.Response(
            200, json={"accessToken": {"token": "new-access", "validUntil": FAR_FUTURE}}
        )
    )

    with patch.object(client._http._client, "request", refresh_request):
        token = client.token_manager.get_access_token()

    assert token == "new-access"
    assert [info.token for info in received] == ["new-access"]
    # refresh idzie przez endpoint z jawnym refresh_token (brak rekurencji providera)
    sent_headers = refresh_request.call_args.kwargs["headers"]
    assert sent_headers["Authorization"] == "Bearer refresh"


def test_client_rejects_access_token_and_http_client_together() -> None:
    with pytest.raises(ValueError, match="either access_token or http_client"):
        KsefClient(_options(), "token", http_client=Mock())

    with pytest.raises(ValueError, match="either access_token or http_client"):
        AsyncKsefClient(_options(), "token", http_client=Mock())


@pytest.mark.parametrize(
    "method",
    [
        InvoicesClient.get_invoice,
        InvoicesClient.query_invoice_metadata,
        AsyncInvoicesClient.get_invoice,
    ],
)
def test_loosened_methods_accept_missing_access_token(method: object) -> None:
    signature = inspect.signature(method)  # type: ignore[arg-type]

    assert signature.parameters["access_token"].default is None


def test_positional_token_call_still_works_after_loosening() -> None:
    client = KsefClient(_options())
    request = _request_mock(httpx.Response(204))

    with patch.object(client._http._client, "request", request):
        client.auth.revoke_session("ref-1", "positional-token")

    headers = request.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer positional-token"


# --- async ----------------------------------------------------------------


def test_async_authenticated_client_injects_token() -> None:
    async def scenario() -> None:
        client = AsyncAuthenticatedClient(_options(), AsyncTokenManager("token-1"))
        request = AsyncMock(return_value=httpx.Response(204))

        with patch.object(client._http._client, "request", request):
            await client.auth.revoke_current_session()

        headers = request.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer token-1"
        assert isinstance(client.http_client, AsyncTokenRefreshingHttpClient)
        await client.aclose()

    asyncio.run(scenario())


def test_async_401_refreshes_and_retries() -> None:
    async def scenario() -> None:
        refreshed: list[str] = []

        async def handler(refresh_token: str) -> TokenInfo:
            refreshed.append(refresh_token)
            return TokenInfo("fresh-token", FAR_FUTURE)

        client = AsyncAuthenticatedClient(
            _options(),
            AsyncTokenManager("stale-token", "refresh-token", refresh_handler=handler),
        )
        request = AsyncMock(side_effect=[_unauthorized(), httpx.Response(204)])

        with patch.object(client._http._client, "request", request):
            await client.auth.revoke_current_session()

        assert request.call_count == 2
        assert refreshed == ["refresh-token"]
        assert request.call_args_list[1].kwargs["headers"]["Authorization"] == "Bearer fresh-token"
        await client.aclose()

    asyncio.run(scenario())


def test_async_explicit_token_wins_over_manager() -> None:
    async def scenario() -> None:
        client = AsyncAuthenticatedClient(_options(), AsyncTokenManager("manager-token"))
        request = AsyncMock(return_value=httpx.Response(204))

        with patch.object(client._http._client, "request", request):
            await client.auth.revoke_current_session("explicit-token")

        headers = request.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer explicit-token"
        await client.aclose()

    asyncio.run(scenario())


def test_async_non_401_error_does_not_refresh() -> None:
    async def scenario() -> None:
        refreshed: list[str] = []

        async def handler(refresh_token: str) -> TokenInfo:
            refreshed.append(refresh_token)
            return TokenInfo("fresh-token", FAR_FUTURE)

        client = AsyncAuthenticatedClient(
            _options(),
            AsyncTokenManager("token", "refresh-token", refresh_handler=handler),
        )
        request = AsyncMock(
            return_value=httpx.Response(
                403,
                json={
                    "title": "Forbidden",
                    "status": 403,
                    "detail": "no access",
                    "reasonCode": "missing-permission",
                },
            )
        )

        with (
            patch.object(client._http._client, "request", request),
            pytest.raises(KsefHttpError),
        ):
            await client.auth.revoke_current_session()

        assert refreshed == []
        assert request.call_count == 1
        await client.aclose()

    asyncio.run(scenario())


def test_async_from_auth_result_builds_manager() -> None:
    async def scenario() -> None:
        client = AsyncAuthenticatedClient.from_auth_result(_options(), _auth_result())

        assert isinstance(client.http_client, AsyncTokenRefreshingHttpClient)
        assert client.token_manager.can_refresh is True
        await client.aclose()

    asyncio.run(scenario())
