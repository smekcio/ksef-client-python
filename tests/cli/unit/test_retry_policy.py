from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ksef_client.cli.policies.retry import (
    RetryPolicy,
    compute_retry_delay_seconds,
    parse_retry_after,
    should_retry,
)
from ksef_client.http import MAX_RETRY_AFTER_SECONDS, RETRYABLE_STATUS_CODES


def test_should_retry() -> None:
    assert should_retry(429)
    assert not should_retry(400)


@pytest.mark.parametrize("status_code", [429, 502, 503, 504])
def test_should_retry_covers_every_retryable_status(status_code: int) -> None:
    """Zbiór kodów musi być spójny z warstwą HTTP (`RETRYABLE_STATUS_CODES`)."""
    assert status_code in RETRYABLE_STATUS_CODES
    assert should_retry(status_code)


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 410, 500, 501])
def test_should_retry_rejects_the_other_statuses(status_code: int) -> None:
    assert not should_retry(status_code)


def test_server_requested_delay_wins_over_the_backoff() -> None:
    """Nagłówek `Retry-After: 30` (także z 503) daje 30 s, a nie 0,25 s backoffu."""
    policy = RetryPolicy(max_retries=3, base_delay_ms=250, jitter_ratio=0.2)
    assert compute_retry_delay_seconds(1, policy, retry_after="30") == 30.0
    assert compute_retry_delay_seconds(1, policy, retry_after=None, random_value=0.5) == 0.25


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


def test_retry_after_is_capped_like_the_http_layer() -> None:
    policy = RetryPolicy(max_retries=3, base_delay_ms=100, jitter_ratio=0.2)
    assert parse_retry_after("31536000") == float(MAX_RETRY_AFTER_SECONDS)
    assert compute_retry_delay_seconds(1, policy, retry_after="31536000") == float(
        MAX_RETRY_AFTER_SECONDS
    )
    assert parse_retry_after("-5") is None

    far_future = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    assert parse_retry_after(far_future) == float(MAX_RETRY_AFTER_SECONDS)

    in_the_past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    assert parse_retry_after(in_the_past) == 0.0


def test_parse_retry_after_naive_datetime(monkeypatch) -> None:
    naive = datetime(2099, 1, 1, 0, 0, 0)
    monkeypatch.setattr("ksef_client.cli.policies.retry.parsedate_to_datetime", lambda _: naive)
    parsed = parse_retry_after("Wed, 01 Jan 2099 00:00:00")
    assert parsed is not None
    assert parsed >= 0.0
