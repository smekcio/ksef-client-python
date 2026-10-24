from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from typing import Any, cast

import pytest

from ksef_client.models import EffectiveApiRateLimits
from ksef_client.rate_limiting import (
    CancellationToken,
    KsefRateLimitCapacityError,
    KsefRateLimitWaitTimeout,
    KsefRequestCancelledError,
    RateLimitAdmission,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitScope,
    RateLimitValues,
    RequestControl,
)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.waits: list[float] = []

    def __call__(self):
        return self.now

    def sleep(self, delay):
        assert delay > 0
        self.waits.append(delay)
        self.now += delay

    async def asleep(self, delay):
        self.sleep(delay)
        await asyncio.sleep(0)


def scope(context="Nip:DUMMY_CONTEXT", *, ip="egress-a", environment="test"):
    return RateLimitScope(environment, context, ip)


def budget(clock, **kwargs):
    policy = kwargs.pop("policy", RateLimitPolicy({"invoice_metadata": RateLimitValues(2, 3, 4)}))
    return RateLimitBudget(
        policy, clock=clock, sleep=clock.sleep, async_sleep=clock.asleep, poll_interval=1, **kwargs
    )


def test_all_three_rolling_windows_and_boundary_admission():
    clock = Clock()
    limiter = budget(clock)
    times = []
    for _ in range(5):
        limiter.acquire(scope(), "invoice_metadata")
        times.append(clock.now)
    assert times == [0, 0, 1, 60, 3600]
    assert all(delay <= 1 for delay in clock.waits)


def test_context_and_egress_isolation_but_global_is_per_ip():
    clock = Clock()
    limiter = budget(
        clock,
        policy=RateLimitPolicy(
            {
                "global": RateLimitValues(per_second=1),
                "invoice_metadata": RateLimitValues(per_second=1),
            }
        ),
    )
    limiter.acquire(scope("A"), "invoice_metadata")
    limiter.acquire(scope("B", ip="egress-b"), "invoice_metadata")
    limiter.acquire(scope("B", environment="demo"), "invoice_metadata")
    assert clock.now == 0
    limiter.acquire(scope("B"), ("global", "invoice_metadata", "global"))
    assert clock.now == 1
    isolated = budget(clock)
    isolated.acquire(scope("A"), ("global", "invoice_metadata"))
    isolated.acquire(scope("B"), "invoice_metadata")
    assert clock.now == 1


def test_anonymous_is_per_ip_and_other_templates_have_separate_counters():
    clock = Clock()
    limiter = budget(
        clock,
        policy=RateLimitPolicy(
            {
                "anonymous": RateLimitValues(per_second=1),
                "other": RateLimitValues(per_second=1),
            }
        ),
    )
    limiter.acquire(scope("A"), "anonymous")
    limiter.acquire(scope("B"), "anonymous")
    assert clock.now == 1
    limiter.acquire(scope("A"), "other:GET /tokens")
    limiter.acquire(scope("A"), "other:GET /tokens/{referenceNumber}")
    assert clock.now == 1
    limiter.acquire(scope("A"), "other:GET /tokens")
    assert clock.now == 2


def test_server_effective_limits_and_unlimited_sentinel_are_preserved():
    raw = {
        model_field.metadata.get("json_key", model_field.name): {
            "perSecond": 10,
            "perMinute": -1,
            "perHour": -1,
        }
        for model_field in fields(EffectiveApiRateLimits)
    }
    effective = EffectiveApiRateLimits.from_dict(raw)
    policy = RateLimitPolicy.from_effective_limits(effective)
    assert policy.groups["global"] == RateLimitValues(10, None, None)
    assert policy.groups["invoice_metadata"].windows() == ((1.0, 10),)
    raw["invoiceMetadata"]["perSecond"] = 1
    assert policy.groups["invoice_metadata"].per_second == 10
    with pytest.raises(TypeError):
        policy.groups["other"] = RateLimitValues(1)  # type: ignore[index]
    with pytest.raises(TypeError):
        RateLimitPolicy.from_effective_limits(cast(Any, {}))
    with pytest.raises(ValueError, match="Incomplete"):
        RateLimitPolicy.from_effective_limits(replace(effective, invoice_metadata=cast(Any, None)))


@pytest.mark.parametrize("value", [True, 0, -2, 1.5, float("inf"), 2**31])
def test_invalid_limits_are_rejected(value):
    with pytest.raises(ValueError):
        RateLimitValues(per_second=value)


def test_unlimited_budget_has_no_unbounded_history():
    clock = Clock()
    limiter = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues(-1, -1, -1)}))
    for _ in range(1000):
        limiter.acquire(scope(), "other")
    assert limiter._history == 0 and limiter._buckets == {}


def test_deadline_does_not_consume_quota_and_cancellation_is_safe():
    clock = Clock()
    limiter = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues(per_second=1)}))
    limiter.acquire(scope(), "other")
    with pytest.raises(KsefRateLimitWaitTimeout):
        limiter.acquire(scope(), "other", control=RequestControl(deadline=0.25))
    assert clock.now == 0.25 and limiter._history == 1
    token = CancellationToken()
    token.cancel()
    assert token.is_cancelled and token.cancelled and token.wait(0)
    assert "cancelled=True" in repr(token)
    with pytest.raises(KsefRequestCancelledError):
        limiter.acquire(scope(), "other", control=RequestControl(cancellation=token))
    assert limiter._history == 1
    clock.now = 1
    limiter.acquire(scope(), "other")
    assert limiter._history == 1


def test_cancel_during_synchronous_wait_does_not_reserve_a_slot():
    clock = Clock()
    token = threading.Event()

    def sleep(delay):
        clock.sleep(delay)
        token.set()

    limiter = RateLimitBudget(
        RateLimitPolicy({"other": RateLimitValues(per_second=1)}), clock=clock, sleep=sleep
    )
    limiter.acquire(scope(), "other")
    with pytest.raises(KsefRequestCancelledError):
        limiter.acquire(scope(), "other", control=RequestControl(cancellation=token))
    assert limiter._history == 1


def test_async_uses_the_same_budget_and_never_blocks_the_loop():
    async def run():
        clock = Clock()
        limiter = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues(per_second=1)}))
        limiter.acquire(scope(), "other")
        await limiter.acquire_async(scope(), "other")
        assert clock.now == 1
        token = CancellationToken()

        async def sleep(delay):
            clock.sleep(delay)
            token.cancel()
            await asyncio.sleep(0)

        limiter._async_sleep = sleep
        with pytest.raises(KsefRequestCancelledError):
            await limiter.acquire_async(
                scope(), "other", control=RequestControl(cancellation=token)
            )
        assert limiter._history == 1
        limiter.acquire(scope(), "other")
        started = asyncio.Event()

        async def blocked_sleep(delay):
            started.set()
            await asyncio.sleep(100)

        limiter._async_sleep = blocked_sleep
        pending = asyncio.create_task(limiter.acquire_async(scope(), "other"))
        await started.wait()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert limiter._history == 1

    asyncio.run(run())


def test_two_thousand_thread_and_async_callers_share_atomic_accounting():
    clock = Clock()
    limiter = budget(
        clock,
        policy=RateLimitPolicy(
            {
                "global": RateLimitValues(per_minute=2000),
                "other": RateLimitValues(per_minute=2000),
            }
        ),
    )

    async def run():
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(limiter.acquire, scope(), "other") for _ in range(1000)]
            await asyncio.gather(*(limiter.acquire_async(scope(), "other") for _ in range(1000)))
            for future in futures:
                future.result()
        assert limiter._history == 4000
        with pytest.raises(KsefRateLimitWaitTimeout):
            await limiter.acquire_async(scope(), "other", control=RequestControl(deadline=0))
        assert limiter._history == 4000

    asyncio.run(run())


def test_capacity_never_evicts_active_scopes_and_reclaims_expired_ones():
    clock = Clock()
    limiter = budget(clock, max_scopes=1)
    limiter.acquire(scope("A"), "invoice_metadata")
    with pytest.raises(KsefRateLimitCapacityError):
        limiter.acquire(scope("B"), "invoice_metadata")
    assert len(limiter._buckets) == 1
    clock.now = 3600
    limiter.acquire(scope("B"), "invoice_metadata")
    assert len(limiter._buckets) == 1


def test_capacity_is_atomic_across_groups_and_counts_all_windows():
    clock = Clock()
    limiter = budget(
        clock,
        max_history=2,
        policy=RateLimitPolicy(
            {
                "global": RateLimitValues(per_second=5),
                "other": RateLimitValues(per_second=5, per_minute=5),
            }
        ),
    )
    with pytest.raises(KsefRateLimitCapacityError):
        limiter.acquire(scope(), "other")
    assert limiter._history == 0 and not limiter._buckets
    limiter = budget(
        clock,
        max_buckets=1,
        policy=RateLimitPolicy(
            {
                "other": RateLimitValues(per_second=5),
            }
        ),
    )
    limiter.defer(scope(), "other:GET /a", 5)
    with pytest.raises(KsefRateLimitCapacityError):
        limiter.acquire(scope(), "other:GET /b")
    clock.now = 5
    limiter.acquire(scope(), "other:GET /b")
    assert len(limiter._buckets) == 1


def test_shared_cooldown_extends_without_charging_and_can_be_unlimited():
    clock = Clock()
    limiter = budget(
        clock,
        policy=RateLimitPolicy(
            {
                "global": RateLimitValues(),
                "other": RateLimitValues(),
            }
        ),
    )
    limiter.defer(scope("A"), "other", 0)
    assert not limiter._buckets
    limiter.defer(scope("A"), "other", 0.2)
    limiter.defer(scope("A"), "other", 0.5)
    limiter.acquire(scope("B"), "other")
    assert clock.now == 0.5 and limiter._history == 0 and not limiter._buckets
    limiter.defer(scope(), "other", 1)
    assert "active_buckets=2" in repr(limiter)
    assert "DUMMY_CONTEXT" not in repr(limiter)
    assert "DUMMY_CONTEXT" not in repr(scope())
    assert "groups" not in repr(limiter.policy)


@pytest.mark.parametrize("value", [-1, float("nan"), True])
def test_invalid_cooldown(value):
    with pytest.raises(ValueError):
        budget(Clock()).defer(scope(), "invoice_metadata", value)


def test_long_retry_after_is_retained_without_uninterruptible_waiting():
    clock = Clock()
    limiter = budget(clock)
    limiter.defer(scope(), "invoice_metadata", 86401)
    assert next(iter(limiter._buckets.values())).cooldown == 86401
    with pytest.raises(KsefRateLimitWaitTimeout):
        limiter.acquire(scope(), "invoice_metadata", control=RequestControl(deadline=0.25))
    assert clock.now == 0.25 and limiter._history == 0
    clock = Clock()
    clock.now = 1e308
    limiter = budget(clock)
    with pytest.raises(ValueError, match="finite"):
        limiter.defer(scope(), "invoice_metadata", 1e308)
    assert not limiter._buckets


@pytest.mark.parametrize("groups", [[], ["missing"], [True], ["x" * 513], ["other"] * 129, [""]])
def test_bad_endpoint_groups_fail_before_charging(groups):
    limiter = budget(Clock())
    with pytest.raises(ValueError):
        limiter.acquire(scope(), groups)
    assert not limiter._buckets


def test_global_without_custom_policy_is_optional_but_cannot_be_the_only_group():
    limiter = budget(Clock())
    with pytest.raises(ValueError):
        limiter.acquire(scope(), "global")
    with pytest.raises(TypeError):
        limiter.acquire(cast(Any, "scope"), "invoice_metadata")


@pytest.mark.parametrize(
    "data", [{}, {"": RateLimitValues()}, {"x": None}, {True: RateLimitValues()}]
)
def test_bad_policy(data):
    with pytest.raises(ValueError):
        RateLimitPolicy(data)


@pytest.mark.parametrize(
    "kwargs", [{"context_key": ""}, {"environment": 1}, {"client_ip": "x" * 4097}]
)
def test_invalid_scope(kwargs):
    data = {"environment": "test", "context_key": "ctx", "client_ip": "ip"}
    data.update(kwargs)
    with pytest.raises(ValueError):
        RateLimitScope(**data)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"policy": None},
        {"poll_interval": 0},
        {"poll_interval": 2},
        {"poll_interval": float("nan")},
        {"max_scopes": True},
        {"max_history": 0},
        {"max_buckets": -1},
        {"sleep": None},
    ],
)
def test_invalid_budget_configuration(kwargs):
    data: dict[str, Any] = {"policy": RateLimitPolicy({"other": RateLimitValues()})}
    data.update(kwargs)
    with pytest.raises((ValueError, TypeError)):
        RateLimitBudget(**data)


def test_control_validation_remaining_and_clock_regression():
    assert RequestControl().remaining() is None
    RequestControl().check()
    with pytest.raises(TypeError):
        RequestControl(cancellation=cast(Any, object()))
    with pytest.raises(ValueError):
        RequestControl(deadline=float("inf"))
    with pytest.raises(ValueError):
        RequestControl(deadline=2**5000)
    with pytest.raises(ValueError):
        RequestControl(deadline=cast(Any, True))
    with pytest.raises(ValueError):
        RequestControl(deadline=1).remaining(clock=lambda: float("nan"))
    clock = Clock()
    limiter = budget(clock)
    limiter.acquire(scope(), "invoice_metadata")
    clock.now = -1
    with pytest.raises(ValueError, match="monotonic"):
        limiter.acquire(scope(), "invoice_metadata")


def test_control_and_policy_replacement_cannot_corrupt_accounting():
    limiter = budget(Clock())
    with pytest.raises(AttributeError):
        cast(Any, limiter).policy = RateLimitPolicy({"other": RateLimitValues()})
    with pytest.raises(TypeError, match="RequestControl"):
        limiter.acquire(scope(), "invoice_metadata", control=cast(Any, object()))

    async def run():
        with pytest.raises(TypeError, match="RequestControl"):
            await limiter.acquire_async(scope(), "invoice_metadata", control=cast(Any, object()))

    asyncio.run(run())


def test_admission_commit_and_cancel_are_idempotent_and_safe_to_represent():
    clock = Clock()
    limiter = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues(10, 10, 10)}))
    first = limiter.acquire(scope(), "other")
    second = limiter.acquire(scope(), "other")
    assert isinstance(first, RateLimitAdmission) and limiter._history == 6
    assert repr(first) == "RateLimitAdmission(state=pending)"
    assert "DUMMY_CONTEXT" not in repr(first)
    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(lambda _: first.cancel(), range(200)))
    first.commit()
    assert limiter._history == 3 and "cancelled" in repr(first)
    second.commit()
    second.commit()
    second.cancel()
    assert limiter._history == 3 and "committed" in repr(second)
    assert all(
        list(history) == [0]
        for _, history in next(iter(limiter._buckets.values())).windows.values()
    )


def test_cancel_old_admission_never_removes_recreated_bucket_newer_counts():
    clock = Clock()
    limiter = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues(per_second=1)}))
    old = limiter.acquire(scope("A"), "other")
    clock.now = 2
    current = limiter.acquire(scope("A"), "other")
    old.cancel()
    assert limiter._history == 1
    assert next(iter(limiter._buckets.values())).windows[1.0][1][0] == 2
    current.cancel()
    assert limiter._history == 0 and not limiter._buckets
    old = limiter.acquire(scope("A"), "other")
    clock.now = 4
    limiter._max_scopes = 1
    limiter.acquire(scope("B"), "other")
    old.cancel()  # The previous key no longer exists after capacity collection.
    assert limiter._history == 1 and len(limiter._buckets) == 1


def test_cancel_refunds_only_the_windows_where_its_debit_is_still_retained():
    clock = Clock()
    limiter = budget(
        clock,
        policy=RateLimitPolicy(
            {
                "global": RateLimitValues(10, 10, 10),
                "other": RateLimitValues(10, 10, 10),
            }
        ),
    )
    old = limiter.acquire(scope(), "other")
    clock.now = 2
    current = limiter.acquire(scope(), "other")
    assert limiter._history == 10  # Old per-second debit expired in both groups.
    old.cancel()
    assert limiter._history == 6
    assert all(
        list(history) == [2]
        for bucket in limiter._buckets.values()
        for _, history in bucket.windows.values()
    )
    current.cancel()
    assert limiter._history == 0 and not limiter._buckets


def test_refund_releases_accounting_capacity_without_clearing_shared_cooldown():
    clock = Clock()
    limiter = budget(
        clock,
        max_history=3,
        policy=RateLimitPolicy(
            {
                "other": RateLimitValues(10, 10, 10),
            }
        ),
    )
    receipt = limiter.acquire(scope(), "other")
    with pytest.raises(KsefRateLimitCapacityError):
        limiter.acquire(scope(), "other")
    limiter.defer(scope(), "other", 5)
    receipt.cancel()
    assert limiter._history == 0
    assert next(iter(limiter._buckets.values())).cooldown == 5
    limiter.acquire(scope(), "other")
    assert clock.now == 5 and limiter._history == 3


def test_async_admission_receipts_can_be_refunded_before_commit():
    async def run():
        clock = Clock()
        limiter = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues(per_second=1)}))
        receipt = await limiter.acquire_async(scope(), "other")
        assert isinstance(receipt, RateLimitAdmission)
        receipt.cancel()
        retry = await limiter.acquire_async(scope(), "other")
        assert clock.now == 0 and limiter._history == 1
        retry.commit()
        retry.cancel()
        assert limiter._history == 1
        unlimited = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues()}))
        free = await unlimited.acquire_async(scope(), "other")
        free.cancel()
        assert unlimited._history == 0

    asyncio.run(run())


def test_monotonic_clock_need_not_have_a_positive_epoch():
    clock = Clock()
    clock.now = -50
    limiter = budget(clock, policy=RateLimitPolicy({"other": RateLimitValues(per_second=1)}))
    limiter.acquire(scope(), "other")
    limiter.acquire(scope(), "other")
    assert clock.now == -49
