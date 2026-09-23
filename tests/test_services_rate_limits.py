"""Semantyka grup limitów API KSeF (KSeF API 2.8.0+)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ksef_client import models as m
from ksef_client.services import (
    INACTIVE_RATE_LIMIT_GROUPS,
    SESSION_CLOSE_GROUPS,
    RateLimitGroup,
    get_rate_limit,
    iter_rate_limits,
)

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = ROOT / "specs" / "ksef-openapi.snapshot.json"

_LIMIT = {"perSecond": 10, "perMinute": 30, "perHour": 120}


@pytest.fixture
def effective_limits() -> m.EffectiveApiRateLimits:
    """Buduje odpowiedź GET /rate-limits na podstawie kontraktu OpenAPI."""
    spec = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    properties = spec["components"]["schemas"]["EffectiveApiRateLimits"]["properties"]
    payload = {}
    for json_key in properties:
        payload[json_key] = dict(_LIMIT)
    payload["onlineSessionClose"] = {"perSecond": 20, "perMinute": 60, "perHour": 240}
    payload["batchSessionClose"] = {"perSecond": 20, "perMinute": 40, "perHour": 120}
    return m.EffectiveApiRateLimits.from_dict(payload)


def test_rate_limit_groups_cover_openapi_schema() -> None:
    """Każda grupa limitów z OpenAPI musi mieć odpowiednik w RateLimitGroup."""
    spec = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    properties = set(spec["components"]["schemas"]["EffectiveApiRateLimits"]["properties"])
    assert {group.value for group in RateLimitGroup} == properties


def test_session_close_groups_have_dedicated_higher_limits(
    effective_limits: m.EffectiveApiRateLimits,
) -> None:
    """Od 2.8.0 zamykanie sesji ma osobne, wyższe limity niż otwieranie."""
    online = get_rate_limit(effective_limits, RateLimitGroup.ONLINE_SESSION_CLOSE)
    batch = get_rate_limit(effective_limits, RateLimitGroup.BATCH_SESSION_CLOSE)
    assert online is not None and batch is not None
    assert (online.per_second, online.per_minute, online.per_hour) == (20, 60, 240)
    assert (batch.per_second, batch.per_minute, batch.per_hour) == (20, 40, 120)


def test_iter_rate_limits_reads_every_group(
    effective_limits: m.EffectiveApiRateLimits,
) -> None:
    infos = iter_rate_limits(effective_limits)
    assert {info.group for info in infos} == set(RateLimitGroup)


def test_global_group_is_marked_inactive() -> None:
    """`global` opisuje przyszłe limity per IP - mechanizm jest wyłączony."""
    assert RateLimitGroup.GLOBAL in INACTIVE_RATE_LIMIT_GROUPS
    assert RateLimitGroup.INVOICE_SEND not in INACTIVE_RATE_LIMIT_GROUPS


def test_global_field_roundtrips_through_json_key(
    effective_limits: m.EffectiveApiRateLimits,
) -> None:
    """`global` koliduje ze słowem kluczowym Pythona - klucz JSON musi zostać `global`."""
    payload = effective_limits.to_dict()
    assert "global" in payload
    assert "global_" not in payload


def test_get_rate_limit_accepts_string_and_enum(
    effective_limits: m.EffectiveApiRateLimits,
) -> None:
    by_enum = get_rate_limit(effective_limits, RateLimitGroup.INVOICE_SEND)
    by_str = get_rate_limit(effective_limits, "invoiceSend")
    assert by_enum is not None and by_str is not None
    assert by_enum == by_str
    assert by_enum.as_dict() == {"perSecond": 10, "perMinute": 30, "perHour": 120}


def test_session_close_groups_constant_matches_enum() -> None:
    assert {
        RateLimitGroup.ONLINE_SESSION_CLOSE,
        RateLimitGroup.BATCH_SESSION_CLOSE,
    } == SESSION_CLOSE_GROUPS
