from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CircuitBreakerState:
    failures: int = 0
    is_open: bool = False
    opened_at_monotonic: float | None = None


@dataclass(frozen=True)
class CircuitBreakerPolicy:
    failure_threshold: int = 5
    open_seconds: int = 30

    def __post_init__(self) -> None:
        if self.failure_threshold <= 0:
            raise ValueError("failure_threshold must be > 0")
        if self.open_seconds <= 0:
            raise ValueError("open_seconds must be > 0")


def record_success(state: CircuitBreakerState) -> None:
    state.failures = 0
    state.is_open = False
    state.opened_at_monotonic = None


def record_failure(
    state: CircuitBreakerState,
    policy: CircuitBreakerPolicy,
    *,
    now_monotonic: float,
) -> None:
    if now_monotonic < 0:
        raise ValueError("now_monotonic must be >= 0")
    state.failures += 1
    if state.failures >= policy.failure_threshold:
        state.is_open = True
        state.opened_at_monotonic = now_monotonic


def is_circuit_open(
    state: CircuitBreakerState,
    policy: CircuitBreakerPolicy,
    *,
    now_monotonic: float,
) -> bool:
    if now_monotonic < 0:
        raise ValueError("now_monotonic must be >= 0")
    if not state.is_open:
        return False
    if state.opened_at_monotonic is None:
        return True
    if now_monotonic - state.opened_at_monotonic >= float(policy.open_seconds):
        record_success(state)
        return False
    return True
