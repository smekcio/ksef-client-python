"""Spójność słowników walut między OpenAPI KSeF a schematem XSD FA(3).

Test pilnuje, że rozjazd list walut nie przejdzie niezauważony przy kolejnym
wydaniu API — dokładnie tak, jak przeszedł przy API 2.8.0, które dodało do
OpenAPI kody ``CNH``, ``VED``, ``XTS``, ``ZWG`` i ``SLE`` nieobecne w schemacie
FA(3).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ksef_client.documents.fa3 import (
    fa3_xsd_currency_codes,
    known_openapi_only_currency_codes,
    openapi_currency_codes,
    openapi_only_currency_codes,
    validate_fa3_currency,
)
from ksef_client.documents.fa3.currency import Fa3CurrencyMismatchError

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = ROOT / "specs" / "ksef-openapi.snapshot.json"


def test_fa3_xsd_currency_codes_are_loaded() -> None:
    codes = fa3_xsd_currency_codes()
    assert len(codes) > 100, "TKodWaluty powinien zawierać pełny słownik walut"
    assert "PLN" in codes
    assert "EUR" in codes


def test_openapi_currency_codes_match_committed_snapshot() -> None:
    """Enum CurrencyCode musi odpowiadać zatwierdzonemu kontraktowi OpenAPI."""
    spec = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    expected = set(spec["components"]["schemas"]["CurrencyCode"]["enum"])
    assert openapi_currency_codes() == expected


def test_known_currency_mismatches_are_still_the_only_ones() -> None:
    """Rozjazd OpenAPI vs XSD nie może się rozszerzyć bez świadomej decyzji.

    Jeśli ten test padnie, KSeF dodało walutę do OpenAPI bez odpowiednika w
    schemacie FA(3). Należy wtedy ocenić wpływ i zaktualizować
    ``_KNOWN_OPENAPI_ONLY_CURRENCIES`` razem z dokumentacją.
    """
    actual = openapi_only_currency_codes()
    known = known_openapi_only_currency_codes()
    assert actual == known, (
        "Zmienił się zbiór walut obecnych w OpenAPI, ale nieobsługiwanych przez "
        f"schemat FA(3). Nowe/zmienione kody: {sorted(actual ^ known)}"
    )


@pytest.mark.parametrize("currency", sorted(known_openapi_only_currency_codes()))
def test_openapi_only_currency_is_rejected_with_explanatory_message(
    currency: str,
) -> None:
    with pytest.raises(Fa3CurrencyMismatchError) as ctx:
        validate_fa3_currency(currency)

    message = str(ctx.value)
    assert currency in message
    assert "OpenAPI" in message
    assert "FA(3)" in message


@pytest.mark.parametrize("currency", ["PLN", "EUR", "USD", "GBP", "CHF"])
def test_supported_currency_passes_validation(currency: str) -> None:
    validate_fa3_currency(currency)


def test_unknown_currency_is_rejected() -> None:
    with pytest.raises(Fa3CurrencyMismatchError):
        validate_fa3_currency("XYZ")


def test_empty_currency_is_rejected() -> None:
    with pytest.raises(Fa3CurrencyMismatchError):
        validate_fa3_currency("")
