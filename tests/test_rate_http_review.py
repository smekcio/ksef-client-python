"""Independent regression probes for budget integration and token freshness."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from ksef_client.config import KsefClientOptions
from ksef_client.exceptions import KsefHttpError, KsefRateLimitError
from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient
from ksef_client.models import TokenInfo
from ksef_client.rate_limit_routing import canonical_rate_limit_environment
from ksef_client.rate_limiting import (
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitScope,
    RateLimitValues,
)
from ksef_client.token_manager import (
    AsyncTokenManager,
    AsyncTokenRefreshingHttpClient,
    TokenManager,
    TokenRefreshingHttpClient,
)

BASE = "https://api-test.ksef.mf.gov.pl"


class Clock:
    def __init__(self):
        self._now = 0.0
        self._lock = threading.Lock()

    def __call__(self):
        with self._lock:
            return self._now

    def sleep(self, seconds):
        with self._lock:
            self._now += seconds

    async def asleep(self, seconds):
        self.sleep(seconds)
        await asyncio.sleep(0)

    def utc(self):
        return datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=self())


def budget(clock, *, global_limit=None, metadata_limit=None, anonymous_limit=None):
    return RateLimitBudget(
        RateLimitPolicy(
            {
                "global": global_limit or RateLimitValues(),
                "invoice_metadata": metadata_limit or RateLimitValues(),
                "anonymous": anonymous_limit or RateLimitValues(),
            }
        ),
        clock=clock,
        sleep=clock.sleep,
        async_sleep=clock.asleep,
        poll_interval=1,
    )


def options(limiter, *, context="Nip:DUMMY_A", url=BASE):
    return KsefClientOptions(
        base_url=url, rate_limit_budget=limiter, rate_limit_context_key=context
    )


def test_sync_thread_and_async_share_global_quota_across_url_and_context_aliases():
    clock = Clock()
    limiter = budget(clock, global_limit=RateLimitValues(per_second=1))
    first = BaseHttpClient(options(limiter))
    second = AsyncBaseHttpClient(
        options(
            limiter,
            context="Nip:DUMMY_B",
            url="https://API-TEST.KSEF.MF.GOV.PL.:443/api/v2",
        )
    )
    instants: list[float] = []

    def wire(*args, **kwargs):
        instants.append(clock())
        return httpx.Response(200, json={})

    async def run():
        try:
            with (
                patch.object(first._client, "request", Mock(side_effect=wire)),
                ThreadPoolExecutor(max_workers=1) as executor,
            ):
                executor.submit(first.request, "POST", "/invoices/query/metadata").result()
            with patch.object(second._client, "request", AsyncMock(side_effect=wire)):
                await second.request("POST", "/invoices/query/metadata")
        finally:
            first.close()
            await second.aclose()

    asyncio.run(run())
    assert len(instants) == 2
    assert instants[1] - instants[0] >= 1


@pytest.mark.parametrize("asynchronous", [False, True])
def test_managed_token_is_resampled_after_a_long_budget_wait(asynchronous):
    clock = Clock()
    limiter = budget(clock, metadata_limit=RateLimitValues(per_minute=1))
    scope = RateLimitScope(canonical_rate_limit_environment(BASE), "Nip:DUMMY_A")
    limiter.acquire(scope, ("global", "invoice_metadata")).commit()
    authorizations = []

    def refresh(_token):
        return TokenInfo(
            token="DUMMY_FRESH", valid_until=(clock.utc() + timedelta(seconds=10)).isoformat()
        )

    refreshed = Mock(side_effect=refresh)

    def wire(*args, **kwargs):
        authorizations.append(kwargs["headers"].get("Authorization"))
        return httpx.Response(200, json={})

    if not asynchronous:
        manager = TokenManager(
            "DUMMY_OLD",
            "DUMMY_REFRESH",
            access_token_valid_until=clock.utc() + timedelta(seconds=10),
            refresh_margin_seconds=0,
            refresh_handler=refreshed,
            clock=clock.utc,
        )
        client = TokenRefreshingHttpClient(options(limiter), manager)
        try:
            with patch.object(client._client, "request", Mock(side_effect=wire)):
                client.request("POST", "/invoices/query/metadata")
        finally:
            client.close()
    else:

        async def run():
            manager = AsyncTokenManager(
                "DUMMY_OLD",
                "DUMMY_REFRESH",
                access_token_valid_until=clock.utc() + timedelta(seconds=10),
                refresh_margin_seconds=0,
                refresh_handler=refreshed,
                clock=clock.utc,
            )
            client = AsyncTokenRefreshingHttpClient(options(limiter), manager)
            try:
                with patch.object(client._client, "request", AsyncMock(side_effect=wire)):
                    await client.request("POST", "/invoices/query/metadata")
            finally:
                await client.aclose()

        asyncio.run(run())
    assert clock() >= 60
    assert authorizations == ["Bearer DUMMY_FRESH"]
    refreshed.assert_called_once_with("DUMMY_REFRESH")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_shared_cooldown_respects_retry_after_longer_than_legacy_retry_cap(asynchronous):
    clock = Clock()
    limiter = budget(clock)
    responses = [
        httpx.Response(429, headers={"Retry-After": "3600"}, json={"title": "limited"}),
        httpx.Response(200, json={}),
    ]
    if not asynchronous:
        client = BaseHttpClient(options(limiter))
        try:
            with patch.object(client._client, "request", Mock(side_effect=responses)):
                with pytest.raises(KsefRateLimitError):
                    client.request("POST", "/invoices/query/metadata")
                client.request("POST", "/invoices/query/metadata")
        finally:
            client.close()
    else:

        async def run():
            client = AsyncBaseHttpClient(options(limiter))
            try:
                with patch.object(client._client, "request", AsyncMock(side_effect=responses)):
                    with pytest.raises(KsefRateLimitError):
                        await client.request("POST", "/invoices/query/metadata")
                    await client.request("POST", "/invoices/query/metadata")
            finally:
                await client.aclose()

        asyncio.run(run())
    assert clock() >= 3600


@pytest.mark.parametrize("asynchronous", [False, True])
def test_refresh_and_business_admissions_charge_only_at_physical_wires(asynchronous):
    clock = Clock()
    limiter = budget(
        clock,
        global_limit=RateLimitValues(per_hour=1),
        metadata_limit=RateLimitValues(per_hour=1),
        anonymous_limit=RateLimitValues(per_hour=1),
    )
    scope = RateLimitScope(canonical_rate_limit_environment(BASE), "Nip:DUMMY_A")
    limiter.acquire(scope, ("global", "invoice_metadata")).commit()
    wires = []

    def wire(*args, **kwargs):
        wires.append((clock(), kwargs["url"], kwargs["headers"].get("Authorization")))
        return httpx.Response(200, json={})

    if not asynchronous:

        def refresh(token):
            client.request("POST", "/auth/token/refresh", refresh_token=token)
            return TokenInfo(
                token="DUMMY_FRESH",
                valid_until=(clock.utc() + timedelta(hours=2)).isoformat(),
            )

        manager = TokenManager(
            "DUMMY_OLD",
            "DUMMY_REFRESH",
            access_token_valid_until=clock.utc() + timedelta(seconds=10),
            refresh_margin_seconds=0,
            refresh_handler=refresh,
            clock=clock.utc,
        )
        client = TokenRefreshingHttpClient(options(limiter), manager)
        try:
            with patch.object(client._client, "request", Mock(side_effect=wire)):
                client.request("POST", "/invoices/query/metadata")
                client.request("POST", "/auth/challenge", skip_auth=True)
        finally:
            client.close()
    else:

        async def run():
            async def refresh(token):
                await client.request("POST", "/auth/token/refresh", refresh_token=token)
                return TokenInfo(
                    token="DUMMY_FRESH",
                    valid_until=(clock.utc() + timedelta(hours=2)).isoformat(),
                )

            manager = AsyncTokenManager(
                "DUMMY_OLD",
                "DUMMY_REFRESH",
                access_token_valid_until=clock.utc() + timedelta(seconds=10),
                refresh_margin_seconds=0,
                refresh_handler=refresh,
                clock=clock.utc,
            )
            client = AsyncTokenRefreshingHttpClient(options(limiter), manager)
            try:
                with patch.object(client._client, "request", AsyncMock(side_effect=wire)):
                    await client.request("POST", "/invoices/query/metadata")
                    await client.request("POST", "/auth/challenge", skip_auth=True)
            finally:
                await client.aclose()

        asyncio.run(run())

    assert [instant for instant, _, _ in wires] == [3600, 7200, 10800]
    assert [url.removeprefix(BASE + "/v2") for _, url, _ in wires] == [
        "/auth/token/refresh",
        "/invoices/query/metadata",
        "/auth/challenge",
    ]
    assert [auth for _, _, auth in wires] == [
        "Bearer DUMMY_REFRESH",
        "Bearer DUMMY_FRESH",
        None,
    ]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_admission_does_not_repeat_refresh_when_valid_lifetime_is_shorter_than_margin(
    asynchronous,
):
    clock = Clock()
    limiter = budget(clock)
    refreshed = Mock(
        return_value=TokenInfo(
            token="DUMMY_FRESH", valid_until=(clock.utc() + timedelta(seconds=10)).isoformat()
        )
    )

    def wire(*args, **kwargs):
        assert kwargs["headers"]["Authorization"] == "Bearer DUMMY_FRESH"
        return httpx.Response(200, json={})

    if not asynchronous:
        manager = TokenManager(
            "DUMMY_OLD",
            "DUMMY_REFRESH",
            access_token_valid_until=clock.utc() + timedelta(seconds=1),
            refresh_handler=refreshed,
            clock=clock.utc,
        )
        client = TokenRefreshingHttpClient(options(limiter), manager)
        try:
            with patch.object(client._client, "request", Mock(side_effect=wire)):
                client.request("POST", "/invoices/query/metadata")
        finally:
            client.close()
    else:

        async def run():
            manager = AsyncTokenManager(
                "DUMMY_OLD",
                "DUMMY_REFRESH",
                access_token_valid_until=clock.utc() + timedelta(seconds=1),
                refresh_handler=refreshed,
                clock=clock.utc,
            )
            client = AsyncTokenRefreshingHttpClient(options(limiter), manager)
            try:
                with patch.object(client._client, "request", AsyncMock(side_effect=wire)):
                    await client.request("POST", "/invoices/query/metadata")
            finally:
                await client.aclose()

        asyncio.run(run())

    refreshed.assert_called_once_with("DUMMY_REFRESH")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_proactive_refresh_401_is_not_retried_as_a_business_401(asynchronous):
    clock = Clock()
    limiter = budget(clock)
    response = httpx.Response(401, json={"title": "invalid refresh token"})
    if not asynchronous:

        def refresh(token):
            client.request("POST", "/auth/token/refresh", refresh_token=token)
            raise AssertionError("Rejected refresh must not produce a new access token")

        manager = TokenManager(
            "DUMMY_OLD",
            "DUMMY_REFRESH",
            access_token_valid_until=clock.utc(),
            refresh_handler=refresh,
            clock=clock.utc,
        )
        client = TokenRefreshingHttpClient(options(limiter), manager)
        try:
            with patch.object(client._client, "request", Mock(return_value=response)) as wire:
                with pytest.raises(KsefHttpError) as caught:
                    client.request("POST", "/invoices/query/metadata")
                assert caught.value.status_code == 401
                wire.assert_called_once()
                assert wire.call_args.kwargs["url"].endswith("/auth/token/refresh")
        finally:
            client.close()
    else:

        async def run():
            async def refresh(token):
                await client.request("POST", "/auth/token/refresh", refresh_token=token)
                raise AssertionError("Rejected refresh must not produce a new access token")

            manager = AsyncTokenManager(
                "DUMMY_OLD",
                "DUMMY_REFRESH",
                access_token_valid_until=clock.utc(),
                refresh_handler=refresh,
                clock=clock.utc,
            )
            client = AsyncTokenRefreshingHttpClient(options(limiter), manager)
            try:
                with patch.object(
                    client._client, "request", AsyncMock(return_value=response)
                ) as wire:
                    with pytest.raises(KsefHttpError) as caught:
                        await client.request("POST", "/invoices/query/metadata")
                    assert caught.value.status_code == 401
                    wire.assert_awaited_once()
                    assert wire.call_args.kwargs["url"].endswith("/auth/token/refresh")
            finally:
                await client.aclose()

        asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_token_current_check_never_waits_for_a_refresh_lock(asynchronous):
    clock = Clock()
    if not asynchronous:
        manager = TokenManager("DUMMY_ACCESS", clock=clock.utc)
        client = TokenRefreshingHttpClient(options(budget(clock)), manager)
        try:
            with manager._lock:
                assert not client._request_token_is_current(
                    "DUMMY_ACCESS", access_token=None, refresh_token=None, skip_auth=False
                )
            assert client._request_token_is_current(
                "DUMMY_ACCESS", access_token=None, refresh_token=None, skip_auth=False
            )
        finally:
            client.close()
    else:

        async def run():
            manager = AsyncTokenManager("DUMMY_ACCESS", clock=clock.utc)
            client = AsyncTokenRefreshingHttpClient(options(budget(clock)), manager)
            try:
                async with manager._lock:
                    assert not await client._request_token_is_current(
                        "DUMMY_ACCESS", access_token=None, refresh_token=None, skip_auth=False
                    )
                assert await client._request_token_is_current(
                    "DUMMY_ACCESS", access_token=None, refresh_token=None, skip_auth=False
                )
            finally:
                await client.aclose()

        asyncio.run(run())
