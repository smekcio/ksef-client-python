from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ksef_client.cli.policies.retry import (
    RetryPolicy,
    compute_retry_delay_seconds,
    parse_retry_after,
    should_retry,
)


def test_should_retry() -> None:
    assert should_retry(429)
    assert not should_retry(400)


def test_retry_policy_validation() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(max_retries=-1)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay_ms=0)
    with pytest.raises(ValueError):
        RetryPolicy(jitter_ratio=2.0)


def test_parse_retry_after_seconds_and_date() -> None:
    assert parse_retry_after("3") == 3.0
    assert parse_retry_after("bad") is None
    assert parse_retry_after(None) is None
    assert parse_retry_after("   ") is None

    http_date = (datetime.now(timezone.utc) + timedelta(seconds=2)).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    parsed = parse_retry_after(http_date)
    assert parsed is not None
    assert parsed >= 0.0


def test_compute_retry_delay_seconds() -> None:
    policy = RetryPolicy(max_retries=3, base_delay_ms=100, jitter_ratio=0.2)
    assert compute_retry_delay_seconds(1, policy, random_value=0.5) == 0.1
    assert compute_retry_delay_seconds(2, policy, random_value=0.5) == 0.2
    assert compute_retry_delay_seconds(1, policy, retry_after="4") == 4.0

    with pytest.raises(ValueError):
        compute_retry_delay_seconds(0, policy)
    with pytest.raises(ValueError):
        compute_retry_delay_seconds(1, policy, random_value=2.0)


def test_parse_retry_after_naive_datetime(monkeypatch) -> None:
    naive = datetime(2099, 1, 1, 0, 0, 0)
    monkeypatch.setattr("ksef_client.cli.policies.retry.parsedate_to_datetime", lambda _: naive)
    parsed = parse_retry_after("Wed, 01 Jan 2099 00:00:00")
    assert parsed is not None
    assert parsed >= 0.0
