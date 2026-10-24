from __future__ import annotations

import asyncio
import math
import threading
import time
from contextlib import closing
from dataclasses import replace
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from ksef_client import (
    CancellationToken,
    KsefClientOptions,
    KsefRateLimitWaitTimeout,
    KsefRequestCancelledError,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitValues,
    RetryConfig,
    request_control,
)
from ksef_client.exceptions import KsefRateLimitError
from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient, _budget_retry_after
from ksef_client.request_control import (
    current_request_control,
    wait_seconds,
    wait_seconds_async,
)

URL = "https://api-test.ksef.mf.gov.pl"
PATH = "/invoices/query/metadata"


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    async def async_sleep(self, seconds):
        self.sleep(seconds)
        await asyncio.sleep(0)


def options(groups=None):
    clock = Clock()
    budget = RateLimitBudget(
        RateLimitPolicy(groups or {"invoice_metadata": RateLimitValues(per_minute=2)}),
        clock=clock,
        sleep=clock.sleep,
        async_sleep=clock.async_sleep,
    )
    return KsefClientOptions(
        base_url=URL, rate_limit_budget=budget, rate_limit_context_key="Nip:DUMMY"
    ), clock


def test_budget_options_are_explicit_and_validated():
    opts, _ = options()
    cases: list[tuple[dict[str, Any], type[Exception]]] = [
        ({"rate_limit_budget": object()}, TypeError),
        ({"rate_limit_context_key": None}, ValueError),
        ({"rate_limit_context_key": "x" * 4097}, ValueError),
        ({"rate_limit_egress_key": ""}, ValueError),
        ({"rate_limit_egress_key": "x" * 4097}, ValueError),
        ({"follow_redirects": True}, ValueError),
    ]
    for changed, error in cases:
        with pytest.raises(error):
            replace(opts, **changed)
    assert KsefClientOptions(base_url=URL, follow_redirects=True).rate_limit_budget is None
    assert "DUMMY" not in repr(opts)


def test_retry_accounts_each_wire_attempt_and_never_replays_a_prefix():
    opts, clock = options()
    opts = replace(opts, retry=RetryConfig(max_retries=1, retryable_post_paths=frozenset({PATH})))
    calls = Mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "1"}, json={"title": "limited"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    with (
        closing(BaseHttpClient(opts)) as client,
        patch.object(client._client, "request", calls),
        patch("ksef_client.http.time.sleep", clock.sleep),
    ):
        assert client.request("POST", PATH).status_code == 200
    assert calls.call_count == 2
    assert clock.now == pytest.approx(1)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_429_cooldown_does_not_retry_invoice_submission(asynchronous):
    opts, _ = options({"invoice_send": RateLimitValues(per_minute=10)})
    path = "/sessions/online/DUMMY/invoices"
    if not asynchronous:
        with closing(BaseHttpClient(opts)) as client:
            wire = Mock(return_value=httpx.Response(429, json={"title": "limited"}))
            with patch.object(client._client, "request", wire), pytest.raises(KsefRateLimitError):
                client.request("POST", path, json={})
            assert wire.call_count == 1
    else:

        async def run():
            client = AsyncBaseHttpClient(opts)
            try:
                wire = AsyncMock(return_value=httpx.Response(429, json={"title": "limited"}))
                with (
                    patch.object(client._client, "request", wire),
                    pytest.raises(KsefRateLimitError),
                ):
                    await client.request("POST", path, json={})
                assert wire.call_count == 1
            finally:
                await client.aclose()

        asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_429_cooldown_survives_a_failing_system_warning_hook(asynchronous):
    opts, clock = options({"invoice_metadata": RateLimitValues()})
    warning_hook = Mock(side_effect=RuntimeError("Warning hook failed"))
    opts = replace(opts, system_warning_handler=warning_hook)
    responses = [
        httpx.Response(429, headers={"Retry-After": "5", "X-System-Warning": "maintenance"}),
        httpx.Response(200),
    ]
    if not asynchronous:
        with closing(BaseHttpClient(opts)) as client:
            wire = Mock(side_effect=responses)
            with patch.object(client._client, "request", wire):
                with pytest.raises(RuntimeError, match="Warning hook failed"):
                    client.request("POST", PATH)
                assert client.request("POST", PATH).status_code == 200
                assert wire.call_count == 2
    else:

        async def run():
            client = AsyncBaseHttpClient(opts)
            try:
                wire = AsyncMock(side_effect=responses)
                with patch.object(client._client, "request", wire):
                    with pytest.raises(RuntimeError, match="Warning hook failed"):
                        await client.request("POST", PATH)
                    assert (await client.request("POST", PATH)).status_code == 200
                    assert wire.call_count == 2
            finally:
                await client.aclose()

        asyncio.run(run())
    warning_hook.assert_called_once_with("maintenance")
    assert clock.now == pytest.approx(5)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_control_bounds_wire_timeout_and_is_optional(asynchronous):
    opts = KsefClientOptions(base_url=URL)
    if not asynchronous:
        with closing(BaseHttpClient(opts)) as client:
            wire = Mock(return_value=httpx.Response(200))
            with patch.object(client._client, "request", wire):
                client.request("GET", "/limits/context")
                assert "timeout" not in wire.call_args.kwargs
                with request_control(timeout_seconds=5):
                    client.request("GET", "/limits/context")
                    assert 0 < wire.call_args.kwargs["timeout"] <= 5
                with request_control(cancellation=CancellationToken()):
                    client.request("GET", "/limits/context")
                    assert "timeout" not in wire.call_args.kwargs
    else:

        async def run():
            client = AsyncBaseHttpClient(opts)
            try:
                wire = AsyncMock(return_value=httpx.Response(200))
                with patch.object(client._client, "request", wire):
                    with request_control(timeout_seconds=5):
                        await client.request("GET", "/limits/context")
                    assert 0 < wire.call_args.kwargs["timeout"] <= 5
            finally:
                await client.aclose()

        asyncio.run(run())


def test_control_nesting_preserves_parent_deadline_and_cancellation():
    parent, child = CancellationToken(), threading.Event()
    assert current_request_control() is None
    with request_control(timeout_seconds=10, cancellation=parent) as outer:
        with request_control(timeout_seconds=20, cancellation=child) as inner:
            assert inner.deadline == outer.deadline
            child.set()
            with pytest.raises(KsefRequestCancelledError):
                inner.check()
        with request_control() as inherited:
            assert inherited.cancellation is parent
            parent.cancel()
            with pytest.raises(KsefRequestCancelledError):
                inherited.check()
    assert current_request_control() is None


@pytest.mark.parametrize(
    "value",
    [True, "bad", math.inf, math.nan, 10**10000],
    ids=["bool", "text", "inf", "nan", "huge"],
)
def test_control_rejects_nonfinite_and_hostile_timeout_values(value):
    with pytest.raises(ValueError), request_control(timeout_seconds=value):
        pass


def test_control_rejects_negative_and_expired_deadlines():
    with pytest.raises(ValueError), request_control(timeout_seconds=-1):
        pass
    with pytest.raises(KsefRateLimitWaitTimeout), request_control(deadline=time.monotonic() - 1):
        pass


def test_retry_wait_can_be_cancelled_without_repeating_the_request():
    token = CancellationToken()
    opts = KsefClientOptions(base_url=URL, retry=RetryConfig())
    with closing(BaseHttpClient(opts)) as client:
        wire = Mock(return_value=httpx.Response(429, headers={"Retry-After": "5"}))
        with (
            patch.object(client._client, "request", wire),
            patch("ksef_client.http.time.sleep", lambda seconds: token.cancel()),
            pytest.raises(KsefRequestCancelledError),
            request_control(cancellation=token),
        ):
            client.request("GET", "/limits/context")
        assert wire.call_count == 1


def test_control_wait_helpers_keep_async_tasks_responsive_and_stop_at_deadline():
    with request_control(timeout_seconds=1):
        wait_seconds(0)
        wait_seconds(0.001)

    async def run():
        with request_control(timeout_seconds=0.01), pytest.raises(KsefRateLimitWaitTimeout):
            await wait_seconds_async(10)
        token = CancellationToken()
        with request_control(cancellation=token):
            task = asyncio.create_task(wait_seconds_async(10))
            await asyncio.sleep(0)
            token.cancel()
            with pytest.raises(KsefRequestCancelledError):
                await task
        await wait_seconds_async(0)
        with request_control():
            await wait_seconds_async(0)

    asyncio.run(run())


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, 1),
        ("", 1),
        ("bad", 1),
        ("0", 0),
        ("3600", 3600),
        ("Wed, 01 Jan 2020 00:00:00 GMT", 0),
        ("Wed, 01 Jan 2099 00:00:00", None),
    ],
)
def test_shared_cooldown_parser_keeps_server_wait(value, expected):
    parsed = _budget_retry_after(value)
    assert parsed == expected if expected is not None else parsed > 3600


def test_unrepresentable_server_cooldown_is_explicit():
    with pytest.raises(KsefRateLimitWaitTimeout):
        _budget_retry_after("9" * 400)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("failure", ["freshness", "cancelled_before_wire"])
def test_unused_admission_is_refunded_when_preparation_fails(asynchronous, failure):
    opts, clock = options({"invoice_metadata": RateLimitValues(per_minute=1)})
    token = CancellationToken()

    def freshness(*args, **kwargs):
        if failure == "freshness":
            raise RuntimeError("DUMMY freshness provider failure")
        token.cancel()
        return True

    error = RuntimeError if failure == "freshness" else KsefRequestCancelledError
    if not asynchronous:
        with closing(BaseHttpClient(opts)) as client:
            wire = Mock(return_value=httpx.Response(200))
            with (
                patch.object(client._client, "request", wire),
                patch.object(client, "_request_token_is_current", side_effect=freshness),
                request_control(cancellation=token),
                pytest.raises(error),
            ):
                client.request("POST", PATH)
            wire.assert_not_called()
            with patch.object(client._client, "request", wire):
                client.request("POST", PATH)
            assert wire.call_count == 1
    else:

        async def run():
            client = AsyncBaseHttpClient(opts)
            try:
                wire = AsyncMock(return_value=httpx.Response(200))
                with (
                    patch.object(client._client, "request", wire),
                    patch.object(
                        client, "_request_token_is_current", AsyncMock(side_effect=freshness)
                    ),
                    request_control(cancellation=token),
                    pytest.raises(error),
                ):
                    await client.request("POST", PATH)
                wire.assert_not_called()
                with patch.object(client._client, "request", wire):
                    await client.request("POST", PATH)
                assert wire.call_count == 1
            finally:
                await client.aclose()

        asyncio.run(run())
    assert clock.now == 0


def test_external_storage_is_not_charged_to_ksef_budget():
    opts, clock = options(
        {"global": RateLimitValues(per_minute=1), "invoice_metadata": RateLimitValues()}
    )
    opts = replace(opts, allowed_presigned_hosts=["storage.example.com"])
    with closing(BaseHttpClient(opts)) as client:
        wire = Mock(return_value=httpx.Response(200))
        with patch.object(client._client, "request", wire):
            for _ in range(2):
                client.request("GET", "https://storage.example.com/DUMMY", skip_auth=True)
            client.request("POST", PATH)
        assert wire.call_count == 3
    assert clock.now == 0
