"""HTTP options for live invoice scenarios, honoring server cooldowns in full."""

from __future__ import annotations

import time
from dataclasses import fields

from ksef_client import (
    KsefClientOptions,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitValues,
    RetryConfig,
)
from ksef_client.models import EffectiveApiRateLimits


def live_options(base_url: str, context_type: str, context_value: str) -> KsefClientOptions:
    # No guessed TEST quotas: empty windows only retain server-supplied cooldowns.
    # Cover all endpoint groups used by auth, session finalization and invoices.
    policy = RateLimitPolicy(
        {item.name.rstrip("_"): RateLimitValues() for item in fields(EffectiveApiRateLimits)}
    )
    return KsefClientOptions(
        base_url=base_url,
        retry=RetryConfig(
            max_retries=5, retryable_post_paths=frozenset({"/invoices/query/metadata"})
        ),
        rate_limit_budget=RateLimitBudget(policy, clock=time.monotonic, sleep=time.sleep),
        rate_limit_context_key=f"{context_type}:{context_value}",
    )
