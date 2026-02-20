from __future__ import annotations

import pytest

from ksef_client.cli.policies.circuit_breaker import (
    CircuitBreakerPolicy,
    CircuitBreakerState,
    is_circuit_open,
    record_failure,
    record_success,
)


def test_circuit_breaker_defaults() -> None:
    state = CircuitBreakerState()
    policy = CircuitBreakerPolicy()
    assert state.failures == 0
    assert policy.failure_threshold == 5
    assert state.opened_at_monotonic is None


def test_circuit_breaker_validation() -> None:
    with pytest.raises(ValueError):
        CircuitBreakerPolicy(failure_threshold=0)
    with pytest.raises(ValueError):
        CircuitBreakerPolicy(open_seconds=0)


def test_circuit_breaker_state_transitions() -> None:
    state = CircuitBreakerState()
    policy = CircuitBreakerPolicy(failure_threshold=2, open_seconds=5)

    record_failure(state, policy, now_monotonic=10.0)
    assert state.failures == 1
    assert state.is_open is False

    record_failure(state, policy, now_monotonic=12.0)
    assert state.failures == 2
    assert state.is_open is True
    assert state.opened_at_monotonic == 12.0

    assert is_circuit_open(state, policy, now_monotonic=13.0) is True
    assert is_circuit_open(state, policy, now_monotonic=18.0) is False
    assert state.failures == 0
    assert state.opened_at_monotonic is None

    record_success(state)
    assert state.is_open is False


def test_circuit_breaker_invalid_monotonic_values() -> None:
    state = CircuitBreakerState()
    policy = CircuitBreakerPolicy()
    with pytest.raises(ValueError):
        record_failure(state, policy, now_monotonic=-1)
    with pytest.raises(ValueError):
        is_circuit_open(state, policy, now_monotonic=-1)


def test_circuit_breaker_non_open_and_open_without_timestamp() -> None:
    policy = CircuitBreakerPolicy()
    state = CircuitBreakerState()
    assert is_circuit_open(state, policy, now_monotonic=1.0) is False

    state.is_open = True
    state.opened_at_monotonic = None
    assert is_circuit_open(state, policy, now_monotonic=2.0) is True
