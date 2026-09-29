"""Testy wspólnej konwersji nazw z kontraktu OpenAPI na atrybuty modeli."""

from __future__ import annotations

import dataclasses

import pytest

from ksef_client.models import EffectiveApiRateLimits
from ksef_client.services.rate_limits import RateLimitGroup, _attribute_name
from ksef_client.utils.naming import to_snake_case


@pytest.mark.parametrize(
    ("contract_name", "expected"),
    [
        ("invoiceSend", "invoice_send"),
        ("invoiceExportStatus", "invoice_export_status"),
        ("batchSessionClose", "batch_session_close"),
        ("KodWaluty", "kod_waluty"),
        ("other", "other"),
        ("global", "global"),
        ("onlineSession", "online_session"),
    ],
)
def test_to_snake_case_handles_contract_names(contract_name: str, expected: str) -> None:
    assert to_snake_case(contract_name) == expected


def test_every_rate_limit_group_maps_to_real_model_field() -> None:
    """Refaktor na wspólny util nie może zepsuć mapowania grup na atrybuty modelu."""
    field_names = {field.name for field in dataclasses.fields(EffectiveApiRateLimits)}

    for group in RateLimitGroup:
        assert _attribute_name(group) in field_names, group


def test_global_maps_to_trailing_underscore() -> None:
    """`global` jest słowem kluczowym Pythona, więc model używa `global_`."""
    assert _attribute_name(RateLimitGroup.GLOBAL) == "global_"
    assert _attribute_name(RateLimitGroup.ANONYMOUS) == "anonymous"
