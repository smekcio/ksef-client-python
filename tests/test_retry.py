from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from ksef_client.config import KsefClientOptions
from ksef_client.http import MAX_RETRY_AFTER_SECONDS, RETRYABLE_STATUS_CODES
from ksef_client.retry import (
    MAX_RETRY_DELAY_MS,
    RetryConfig,
    compute_retry_delay_seconds,
    parse_retry_after_seconds,
    should_retry_request,
)

# --- RetryConfig ----------------------------------------------------------


def test_retry_config_defaults_are_valid_and_conservative() -> None:
    config = RetryConfig()

    assert config.max_retries == 3
    assert config.base_delay_ms == 250
    assert config.jitter_ratio == 0.2
    assert config.max_delay_ms == 30_000
    assert config.retryable_methods == frozenset({"GET", "PUT", "DELETE"})
    assert config.retryable_post_paths == frozenset()


def test_retry_config_normalizes_method_names() -> None:
    config = RetryConfig(retryable_methods=frozenset({"get", " Put "}))

    assert config.retryable_methods == frozenset({"GET", "PUT"})


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_retries": -1},
        {"base_delay_ms": 0},
        {"base_delay_ms": -5},
        {"jitter_ratio": -0.1},
        {"jitter_ratio": 1.1},
        {"base_delay_ms": 1000, "max_delay_ms": 999},
        {"retryable_methods": frozenset({""})},
    ],
)
def test_retry_config_rejects_invalid_values(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        RetryConfig(**overrides)  # type: ignore[arg-type]


def test_retry_config_allows_disabling_delay_cap() -> None:
    assert RetryConfig(base_delay_ms=5000, max_delay_ms=None).max_delay_ms is None


def test_retry_config_allows_zero_retries() -> None:
    assert RetryConfig(max_retries=0).max_retries == 0


def test_retry_config_rejects_excessive_retries() -> None:
    with pytest.raises(ValueError, match="max_retries"):
        RetryConfig(max_retries=101)

    assert RetryConfig(max_retries=100).max_retries == 100


# --- parse_retry_after_seconds -------------------------------------------


def test_parse_retry_after_returns_none_without_header() -> None:
    assert parse_retry_after_seconds(None) is None
    assert parse_retry_after_seconds("") is None
    assert parse_retry_after_seconds("   ") is None


def test_parse_retry_after_parses_seconds() -> None:
    assert parse_retry_after_seconds("30") == 30.0
    assert parse_retry_after_seconds(" 12 ") == 12.0
    assert parse_retry_after_seconds("0") == 0.0


def test_parse_retry_after_caps_large_seconds() -> None:
    assert parse_retry_after_seconds("999999") == float(MAX_RETRY_AFTER_SECONDS)


def test_parse_retry_after_parses_http_date() -> None:
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=42), usegmt=True)

    assert parse_retry_after_seconds(future) == pytest.approx(42.0, abs=5.0)


def test_parse_retry_after_caps_http_date_in_the_far_future() -> None:
    future = format_datetime(datetime.now(timezone.utc) + timedelta(days=30), usegmt=True)

    assert parse_retry_after_seconds(future) == float(MAX_RETRY_AFTER_SECONDS)


def test_parse_retry_after_returns_zero_for_past_date() -> None:
    past = format_datetime(datetime.now(timezone.utc) - timedelta(days=1), usegmt=True)

    assert parse_retry_after_seconds(past) == 0.0


def test_parse_retry_after_returns_none_for_garbage() -> None:
    assert parse_retry_after_seconds("not-a-date") is None
    assert parse_retry_after_seconds("-5") is None


def test_parse_retry_after_accepts_naive_http_date() -> None:
    naive = datetime(2099, 1, 1, 0, 0, 0)

    assert parse_retry_after_seconds(naive.strftime("%a, %d %b %Y %H:%M:%S")) is not None


# --- compute_retry_delay_seconds -----------------------------------------


def test_compute_retry_delay_uses_exponential_backoff() -> None:
    config = RetryConfig(base_delay_ms=250, jitter_ratio=0.0)

    assert compute_retry_delay_seconds(1, config, random_value=0.5) == 0.25
    assert compute_retry_delay_seconds(2, config, random_value=0.5) == 0.5
    assert compute_retry_delay_seconds(3, config, random_value=0.5) == 1.0


def test_compute_retry_delay_applies_jitter_bounds() -> None:
    config = RetryConfig(base_delay_ms=1000, jitter_ratio=0.2)

    assert compute_retry_delay_seconds(1, config, random_value=0.0) == pytest.approx(0.8)
    assert compute_retry_delay_seconds(1, config, random_value=1.0) == pytest.approx(1.2)
    assert compute_retry_delay_seconds(1, config, random_value=0.5) == pytest.approx(1.0)


def test_compute_retry_delay_respects_max_delay_cap() -> None:
    config = RetryConfig(base_delay_ms=1000, jitter_ratio=0.0, max_delay_ms=1500)

    assert compute_retry_delay_seconds(3, config, random_value=0.5) == 1.5


def test_compute_retry_delay_without_cap_grows() -> None:
    config = RetryConfig(base_delay_ms=1000, jitter_ratio=0.0, max_delay_ms=None)

    assert compute_retry_delay_seconds(3, config, random_value=0.5) == 4.0


def test_compute_retry_delay_prefers_retry_after() -> None:
    config = RetryConfig(base_delay_ms=250, jitter_ratio=0.0)

    assert compute_retry_delay_seconds(1, config, retry_after="30") == 30.0


def test_compute_retry_delay_ignores_unparseable_retry_after() -> None:
    config = RetryConfig(base_delay_ms=250, jitter_ratio=0.0)

    assert compute_retry_delay_seconds(1, config, retry_after="?", random_value=0.5) == 0.25


@pytest.mark.parametrize("attempt", [0, -1])
def test_compute_retry_delay_rejects_non_positive_attempt(attempt: int) -> None:
    with pytest.raises(ValueError):
        compute_retry_delay_seconds(attempt, RetryConfig())


@pytest.mark.parametrize("random_value", [-0.1, 1.1])
def test_compute_retry_delay_rejects_random_value_out_of_range(random_value: float) -> None:
    with pytest.raises(ValueError):
        compute_retry_delay_seconds(1, RetryConfig(), random_value=random_value)


# --- should_retry_request -------------------------------------------------


def test_retryable_statuses_are_shared_with_http_layer() -> None:
    assert frozenset({429, 502, 503, 504}) == RETRYABLE_STATUS_CODES


@pytest.mark.parametrize("status_code", [429, 502, 503, 504])
def test_should_retry_request_accepts_retryable_statuses(status_code: int) -> None:
    assert should_retry_request("GET", "/x", status_code, RetryConfig()) is True


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 410, 500, 501])
def test_should_retry_request_rejects_other_statuses(status_code: int) -> None:
    assert should_retry_request("GET", "/x", status_code, RetryConfig()) is False


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "get", " delete "])
def test_should_retry_request_allows_safe_methods(method: str) -> None:
    assert should_retry_request(method, "/x", 503, RetryConfig()) is True


def test_should_retry_request_never_retries_post_by_default() -> None:
    assert should_retry_request("POST", "/invoices/query/metadata", 503, RetryConfig()) is False


def test_should_retry_request_retries_allowlisted_post_path() -> None:
    config = RetryConfig(retryable_post_paths=frozenset({"/invoices/query/metadata"}))

    assert should_retry_request("POST", "/invoices/query/metadata", 503, config) is True
    assert should_retry_request("POST", "/invoices/query/metadata/extra", 503, config) is False


def test_should_retry_request_does_not_retry_post_on_absolute_url() -> None:
    config = RetryConfig(retryable_post_paths=frozenset({"/invoices/query/metadata"}))

    assert should_retry_request("POST", "https://storage.example.com/x", 503, config) is False


def test_should_retry_request_rejects_method_outside_allowlist() -> None:
    assert should_retry_request("PATCH", "/x", 503, RetryConfig()) is False


def test_compute_retry_delay_does_not_overflow_for_huge_attempt() -> None:
    # Wcześniej `2 ** attempt` przepełniał float przy dużym max_retries.
    config = RetryConfig(base_delay_ms=250, jitter_ratio=0.0, max_delay_ms=None)

    assert compute_retry_delay_seconds(5000, config, random_value=0.5) == MAX_RETRY_DELAY_MS / 1000


def test_retry_config_accepts_max_delay_at_safety_ceiling() -> None:
    assert RetryConfig(max_delay_ms=MAX_RETRY_DELAY_MS).max_delay_ms == MAX_RETRY_DELAY_MS


def test_retry_config_rejects_max_delay_above_safety_ceiling() -> None:
    with pytest.raises(ValueError, match="max_delay_ms"):
        RetryConfig(max_delay_ms=MAX_RETRY_DELAY_MS + 1)


def test_post_in_retryable_methods_is_still_not_retried() -> None:
    config = RetryConfig(retryable_methods=frozenset({"GET", "POST"}))

    assert should_retry_request("POST", "/sessions/online/invoices", 503, config) is False
    assert should_retry_request("GET", "/x", 503, config) is True


def test_options_reject_non_retry_config() -> None:
    with pytest.raises(TypeError, match="RetryConfig"):
        KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl", retry="oops")  # type: ignore[arg-type]
