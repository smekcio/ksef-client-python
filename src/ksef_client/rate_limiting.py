"""Opt-in, process-local rate budgets shared by synchronous and asynchronous clients.

One injected budget coordinates threads and event loops. It does not coordinate
other processes, applications or hosts. Global and anonymous quotas are keyed by
environment/IP; protected endpoint quotas additionally include application context.
No access token is used as a budget key. Admission is atomic across all counters.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields
from itertools import islice
from types import MappingProxyType
from typing import Protocol

from .exceptions import ErrorCode, KsefError
from .models import EffectiveApiRateLimits


class KsefRateLimitWaitTimeout(KsefError, TimeoutError):
    """The request deadline expired before a rate budget became available."""

    code = ErrorCode.RATE_LIMITED


class KsefRequestCancelledError(KsefError):
    """Cooperative cancellation prevented admission of a pending request."""


class KsefRateLimitCapacityError(KsefError):
    """Accounting reached its configured memory bound; admission failed closed."""

    code = ErrorCode.RATE_LIMITED


class CancellationSignal(Protocol):
    def is_set(self) -> bool: ...


class CancellationToken:
    """Thread-safe cooperative cancellation, also readable by async waiters."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    @property
    def is_cancelled(self) -> bool:
        return self.is_set()

    @property
    def cancelled(self) -> bool:
        return self.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def __repr__(self) -> str:
        return f"CancellationToken(cancelled={self.is_set()})"


def _finite_number(value: float, name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be finite")
    try:
        number = float(value)
    except OverflowError:
        raise ValueError(f"{name} must be finite") from None
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite")
    return number


@dataclass(frozen=True)
class RequestControl:
    """An absolute monotonic deadline and/or an Event-compatible cancellation signal."""

    deadline: float | None = None
    cancellation: CancellationSignal | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.deadline is not None:
            object.__setattr__(self, "deadline", _finite_number(self.deadline, "deadline"))
        if self.cancellation is not None and not callable(
            getattr(self.cancellation, "is_set", None)
        ):
            raise TypeError("cancellation must provide is_set()")

    def remaining(self, *, clock: Callable[[], float] = time.monotonic) -> float | None:
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - _finite_number(clock(), "clock"))

    def check(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        if self.cancellation is not None and self.cancellation.is_set():
            raise KsefRequestCancelledError("Request was cancelled")
        if self.deadline is not None and self.remaining(clock=clock) == 0:
            raise KsefRateLimitWaitTimeout(
                "Request deadline expired while waiting for a rate budget"
            )


@dataclass(frozen=True)
class RateLimitValues:
    """Rolling one-second, one-minute and one-hour quotas; None/-1 means unlimited."""

    per_second: int | None = None
    per_minute: int | None = None
    per_hour: int | None = None

    def __post_init__(self) -> None:
        for name in ("per_second", "per_minute", "per_hour"):
            value = getattr(self, name)
            if value is None:
                continue
            if type(value) is not int or value == 0 or value < -1 or value > 2**31 - 1:
                raise ValueError("Rate limits must be positive int32 values, None or -1")
            if value == -1:
                object.__setattr__(self, name, None)

    def windows(self) -> tuple[tuple[float, int], ...]:
        return tuple(
            (window, value)
            for window, value in (
                (1.0, self.per_second),
                (60.0, self.per_minute),
                (3600.0, self.per_hour),
            )
            if value is not None
        )


@dataclass(frozen=True)
class RateLimitPolicy:
    """Explicit endpoint-group quotas; server values may be loaded without defaults.

    Keys use SDK snake_case names (``invoice_metadata``, ``invoice_export``,
    ``global``). ``other:METHOD /canonical-template`` has a separate counter
    using the values configured for ``other``. Omitting global is an explicit
    custom policy; when present, it is automatically charged on every admission.
    """

    groups: Mapping[str, RateLimitValues] = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.groups, Mapping) or not 1 <= len(self.groups) <= 128:
            raise ValueError("Rate policy requires between 1 and 128 endpoint groups")
        copied = dict(self.groups)
        if any(
            type(name) is not str
            or not name
            or len(name) > 256
            or not isinstance(value, RateLimitValues)
            for name, value in copied.items()
        ):
            raise ValueError("Invalid rate policy endpoint group")
        object.__setattr__(self, "groups", MappingProxyType(copied))

    @classmethod
    def from_effective_limits(cls, limits: EffectiveApiRateLimits) -> RateLimitPolicy:
        """Use GET /rate-limits response, including the API's -1 unlimited sentinel."""
        if not isinstance(limits, EffectiveApiRateLimits):
            raise TypeError("Expected EffectiveApiRateLimits")
        values = {}
        for model_field in fields(EffectiveApiRateLimits):
            current = getattr(limits, model_field.name)
            try:
                values[model_field.name.rstrip("_")] = RateLimitValues(
                    current.per_second, current.per_minute, current.per_hour
                )
            except AttributeError:
                raise ValueError("Incomplete effective API rate limits") from None
        return cls(values)


@dataclass(frozen=True)
class RateLimitScope:
    """Application-supplied scope. client_ip identifies a shared outbound-IP budget.

    The default IP label conservatively shares quotas in this process. Applications
    with multiple known egress IPs can provide separate labels. No IP discovery or
    authentication is performed; context_key must describe the authenticated context.
    """

    environment: str = field(repr=False)
    context_key: str = field(repr=False)
    client_ip: str = field(default="default", repr=False)

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or not value.strip() or len(value) > 4096
            for value in (self.environment, self.context_key, self.client_ip)
        ):
            raise ValueError("Rate scope requires bounded environment, context and IP identifiers")

    def key(self, *, per_ip: bool) -> str:
        identity = ["ip", self.environment, self.client_ip]
        if not per_ip:
            identity = ["context", self.environment, self.client_ip, self.context_key]
        return hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()


class _Bucket:
    def __init__(self, limits: RateLimitValues) -> None:
        self.windows = {period: (maximum, deque[float]()) for period, maximum in limits.windows()}
        self.cooldown = -math.inf

    def prune(self, now: float) -> int:
        removed = 0
        for period, (_, history) in self.windows.items():
            while history and history[0] <= now - period:
                history.popleft()
                removed += 1
        return removed

    def active(self, now: float) -> bool:
        return self.cooldown > now or any(history for _, history in self.windows.values())

    def delay(self, now: float) -> float:
        delay = max(0.0, self.cooldown - now)
        for period, (maximum, history) in self.windows.items():
            if len(history) >= maximum:
                delay = max(delay, history[0] + period - now)
        return delay


class RateLimitAdmission:
    """A charged admission which can be refunded before the wire attempt.

    Call ``commit()`` immediately before executing the HTTP request. If preparation
    must block again (for example, refreshing a token), call ``cancel()`` first and
    acquire a fresh admission afterwards. Both methods are idempotent; committed
    attempts remain charged even when the transport fails. Ignoring the receipt
    also retains the charge until its ordinary rolling-window expiry.
    """

    __slots__ = ("_budget", "_timestamp", "_keys", "_status")

    def __init__(
        self, budget: RateLimitBudget, timestamp: float, keys: tuple[tuple[str, str], ...]
    ) -> None:
        self._budget, self._timestamp, self._keys = budget, timestamp, keys
        self._status = "pending"

    def __repr__(self) -> str:
        with self._budget._lock:
            return f"RateLimitAdmission(state={self._status})"

    def commit(self) -> None:
        """Retain the debit irrevocably for an attempt about to reach the wire."""
        with self._budget._lock:
            if self._status == "pending":
                self._status = "committed"

    def cancel(self) -> None:
        """Refund this admission only; cancellation after commit has no effect."""
        with self._budget._lock:
            if self._status != "pending":
                return
            # Mark first: if an external KeyboardInterrupt interrupts cleanup,
            # a repeated cancellation must not refund another same-time debit.
            # A partial refund then only leaves conservative accounting behind.
            self._status = "cancelled"
            for key in self._keys:
                bucket = self._budget._buckets.get(key)
                if bucket is None:
                    continue
                for _, history in bucket.windows.values():
                    try:
                        history.remove(self._timestamp)
                    except ValueError:
                        # A later admission may already have expired this window.
                        # Never remove a newer timestamp in its place.
                        continue
                    self._budget._history -= 1
                now = self._budget._last_now
                if now is not None and not bucket.active(now):
                    del self._budget._buckets[key]


class RateLimitBudget:
    """Exact rolling-window accounting shared by threads and event loops.

    Waiting does not reserve quota and native asyncio cancellation is propagated.
    Admission uses a short thread lock; async waiting never blocks the event loop.
    ``max_history`` bounds all retained timestamp slots (across all rolling windows),
    ``max_scopes`` bounds active IP/context keys, and ``max_buckets`` bounds counters.
    Active accounting is never evicted to make room: resource exhaustion fails closed.
    Waiting is cooperative, checked at most every poll_interval seconds (default .05).
    """

    def __init__(
        self,
        policy: RateLimitPolicy,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        async_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        poll_interval: float = 0.05,
        max_scopes: int = 256,
        max_history: int = 100000,
        max_buckets: int = 4096,
    ) -> None:
        if not isinstance(policy, RateLimitPolicy):
            raise TypeError("policy must be a RateLimitPolicy")
        self._poll_interval = _finite_number(poll_interval, "poll_interval")
        if not 0 < self._poll_interval <= 1:
            raise ValueError("poll_interval must be in (0, 1]")
        if any(
            type(value) is not int or value <= 0 for value in (max_scopes, max_history, max_buckets)
        ):
            raise ValueError("Rate accounting bounds must be positive integers")
        if not all(callable(value) for value in (clock, sleep, async_sleep)):
            raise TypeError("clock and wait functions must be callable")
        self._policy = policy
        self._clock, self._sleep, self._async_sleep = clock, sleep, async_sleep
        self._max_scopes, self._max_history, self._max_buckets = (
            max_scopes,
            max_history,
            max_buckets,
        )
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._history = 0
        self._last_now: float | None = None

    @property
    def policy(self) -> RateLimitPolicy:
        """Immutable policy snapshot; replacing limits requires a new shared budget."""
        return self._policy

    def __repr__(self) -> str:
        with self._lock:
            return (
                f"RateLimitBudget(active_buckets={len(self._buckets)}, timestamps={self._history})"
            )

    def _now(self) -> float:
        now = _finite_number(self._clock(), "clock")
        if self._last_now is not None and now < self._last_now:
            raise ValueError("Budget clock must be monotonic")
        self._last_now = now
        return now

    def _resolve(
        self, scope: RateLimitScope, groups: str | Iterable[str]
    ) -> list[tuple[tuple[str, str], RateLimitValues]]:
        if not isinstance(scope, RateLimitScope):
            raise TypeError("scope must be a RateLimitScope")
        names = [groups] if isinstance(groups, str) else list(islice(groups, 129))
        if not names or len(names) > 128:
            raise ValueError("Require between 1 and 128 endpoint groups")
        if "global" in self.policy.groups and "global" not in names:
            names.insert(0, "global")
        result = []
        seen = set()
        for name in names:
            if type(name) is not str or not name or len(name) > 512:
                raise ValueError("Invalid endpoint group")
            if name in seen:
                continue
            seen.add(name)
            policy_name = "other" if name.startswith("other:") else name
            values = self.policy.groups.get(policy_name)
            if values is None:
                if name == "global":
                    continue
                raise ValueError("No rate policy for endpoint group")
            result.append(((scope.key(per_ip=name in {"global", "anonymous"}), name), values))
        if not result:
            raise ValueError("No configured endpoint group")
        return result

    def _prune(self, key: tuple[str, str], now: float) -> _Bucket | None:
        bucket = self._buckets.get(key)
        if bucket is not None:
            self._history -= bucket.prune(now)
            if not bucket.active(now):
                del self._buckets[key]
                return None
        return bucket

    def _capacity(self, keys: list[tuple[str, str]], slots: int, now: float) -> None:
        # Cold counters are collected before testing bounds, never active counters.
        for key in list(self._buckets):
            self._prune(key, now)
        combined = set(self._buckets) | set(keys)
        if (
            len(combined) > self._max_buckets
            or len({key[0] for key in combined}) > self._max_scopes
            or self._history + slots > self._max_history
        ):
            raise KsefRateLimitCapacityError("Rate budget accounting capacity exceeded")

    def _attempt(
        self,
        descriptors: list[tuple[tuple[str, str], RateLimitValues]],
        control: RequestControl | None,
    ) -> float | RateLimitAdmission:
        with self._lock:
            now = self._now()
            if control is not None:
                control.check(clock=lambda: now)
            delay = 0.0
            for key, _ in descriptors:
                bucket = self._prune(key, now)
                if bucket is not None:
                    delay = max(delay, bucket.delay(now))
            if delay > 0:
                return delay
            charged = [(key, value) for key, value in descriptors if value.windows()]
            slots = sum(len(value.windows()) for _, value in charged)
            self._capacity([key for key, _ in charged], slots, now)
            for key, values in charged:
                bucket = self._buckets.setdefault(key, _Bucket(values))
                for _, history in bucket.windows.values():
                    history.append(now)
            self._history += slots
            return RateLimitAdmission(self, now, tuple(key for key, _ in charged))

    def _wait_time(self, delay: float, control: RequestControl | None) -> float:
        wait = min(delay, self._poll_interval)
        if control is not None:
            control.check(clock=self._clock)
            remaining = control.remaining(clock=self._clock)
            if remaining is not None:
                wait = min(wait, remaining)
        return wait

    def acquire(
        self,
        scope: RateLimitScope,
        groups: str | Iterable[str],
        *,
        control: RequestControl | None = None,
    ) -> RateLimitAdmission:
        if control is not None and not isinstance(control, RequestControl):
            raise TypeError("control must be a RequestControl")
        descriptors = self._resolve(scope, groups)
        while True:
            admission = self._attempt(descriptors, control)
            if isinstance(admission, RateLimitAdmission):
                return admission
            self._sleep(self._wait_time(admission, control))

    async def acquire_async(
        self,
        scope: RateLimitScope,
        groups: str | Iterable[str],
        *,
        control: RequestControl | None = None,
    ) -> RateLimitAdmission:
        if control is not None and not isinstance(control, RequestControl):
            raise TypeError("control must be a RequestControl")
        descriptors = self._resolve(scope, groups)
        while True:
            admission = self._attempt(descriptors, control)
            if isinstance(admission, RateLimitAdmission):
                return admission
            await self._async_sleep(self._wait_time(admission, control))

    def defer(self, scope: RateLimitScope, groups: str | Iterable[str], seconds: float) -> None:
        """Share the complete finite Retry-After pause; this does not retry a request.

        Long server pauses are retained without shortening them. Acquisition still
        checks cancellation/deadlines at each short polling interval.
        """
        pause = _finite_number(seconds, "cooldown")
        if pause < 0:
            raise ValueError("cooldown must be non-negative")
        descriptors = self._resolve(scope, groups)
        with self._lock:
            now = self._now()
            if pause == 0:
                return
            expires = _finite_number(now + pause, "cooldown expiry")
            self._capacity([key for key, _ in descriptors], 0, now)
            for key, values in descriptors:
                bucket = self._buckets.setdefault(key, _Bucket(values))
                bucket.cooldown = max(bucket.cooldown, expires)


__all__ = [
    "CancellationToken",
    "RequestControl",
    "RateLimitValues",
    "RateLimitPolicy",
    "RateLimitScope",
    "RateLimitBudget",
    "RateLimitAdmission",
    "KsefRateLimitWaitTimeout",
    "KsefRequestCancelledError",
    "KsefRateLimitCapacityError",
]
