from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 3
    base_delay_ms: int = 250
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.base_delay_ms <= 0:
            raise ValueError("base_delay_ms must be > 0")
        if not (0 <= self.jitter_ratio <= 1):
            raise ValueError("jitter_ratio must be in range [0, 1]")


def should_retry(status_code: int) -> bool:
    return status_code in {429, 502, 503, 504}


def parse_retry_after(retry_after: str | None) -> float | None:
    if retry_after is None:
        return None
    value = retry_after.strip()
    if value == "":
        return None

    if value.isdigit():
        return max(0.0, float(value))

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0.0, (parsed.astimezone(timezone.utc) - now).total_seconds())


def compute_retry_delay_seconds(
    attempt: int,
    policy: RetryPolicy,
    *,
    retry_after: str | None = None,
    random_value: float = 0.5,
) -> float:
    if attempt <= 0:
        raise ValueError("attempt must be > 0")
    if not (0 <= random_value <= 1):
        raise ValueError("random_value must be in range [0, 1]")

    retry_after_seconds = parse_retry_after(retry_after)
    if retry_after_seconds is not None:
        return retry_after_seconds

    base = float(policy.base_delay_ms) * (2 ** (attempt - 1))
    jitter_factor = 1 + ((random_value * 2 - 1) * policy.jitter_ratio)
    effective_ms = max(0.0, base * jitter_factor)
    return effective_ms / 1000.0
