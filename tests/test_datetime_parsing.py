"""Regresje parsowania znaczników czasu: małe ``z`` oraz ułamki sekund.

``normalize_api_timestamp`` obcina końcówkę ``("Z", "z")`` — małe ``z`` jest
poprawnym oznaczeniem UTC w ISO-8601 i tak samo musi być przyjmowane. Do tej pory
pokryty był wyłącznie wariant z dużym ``Z``
(``tests/test_api_contract_regressions.py::TestApiTimestampParsing::test_z_suffix_is_accepted``),
więc gałąź ``"z"`` nie miała żadnego testu. Ten plik domyka tę lukę, w tym
przypadek najtrudniejszy: 7-cyfrowy ułamek sekundy, którego
``datetime.fromisoformat`` nie przyjmuje na Pythonie 3.10.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ksef_client.utils.datetime_parsing import (
    normalize_api_timestamp,
    parse_api_datetime,
    try_parse_api_datetime,
)

#: Ten sam znacznik co w regresjach API, ale z małym ``z`` i 7 cyframi ułamka.
LOWER_Z_WITH_FRACTION = "2025-10-11T12:23:56.0154302z"
#: Wariant z małym ``z`` bez ułamka sekundy — sprawdza samo obcięcie końcówki.
LOWER_Z_WITHOUT_FRACTION = "2025-10-11T12:23:56z"

EXPECTED = datetime(2025, 10, 11, 12, 23, 56, 15430, tzinfo=timezone.utc)
MILLISECOND_PRECISION = datetime(2025, 10, 11, 12, 23, 56, 15000, tzinfo=timezone.utc)
SECOND_PRECISION = datetime(2025, 10, 11, 12, 23, 56, tzinfo=timezone.utc)


class TestLowercaseZSuffix:
    """Małe ``z`` musi dawać ten sam wynik co ``Z`` i jawne ``+00:00``."""

    def test_normalize_replaces_lowercase_z_with_utc_offset(self) -> None:
        assert normalize_api_timestamp(LOWER_Z_WITH_FRACTION) == "2025-10-11T12:23:56.015430+00:00"
        assert normalize_api_timestamp(LOWER_Z_WITHOUT_FRACTION) == "2025-10-11T12:23:56+00:00"

    def test_seven_digit_fraction_with_lowercase_z_is_parsed(self) -> None:
        parsed = parse_api_datetime(LOWER_Z_WITH_FRACTION)
        assert parsed == EXPECTED
        assert parsed.tzinfo is timezone.utc

    def test_lowercase_z_matches_uppercase_z_and_explicit_offset(self) -> None:
        assert parse_api_datetime("2025-10-11T12:23:56.0154302Z") == EXPECTED
        assert parse_api_datetime("2025-10-11T12:23:56.0154302+00:00") == EXPECTED
        assert parse_api_datetime(LOWER_Z_WITH_FRACTION) == EXPECTED

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # Dłuższy ułamek jest obcinany do mikrosekund (bez zaokrąglania).
            ("2025-10-11T12:23:56.0154302z", EXPECTED),
            # Krótszy ułamek jest dopełniany zerami — 5 cyfr też działa na 3.10.
            ("2025-10-11T12:23:56.01543z", EXPECTED),
            # 3 cyfry (milisekundy) — najkrótszy ułamek spotykany w API.
            ("2025-10-11T12:23:56.015z", MILLISECOND_PRECISION),
            # Bez ułamka — liczy się wyłącznie końcówka ``z``.
            (LOWER_Z_WITHOUT_FRACTION, SECOND_PRECISION),
        ],
    )
    def test_fraction_lengths_with_lowercase_z(self, value: str, expected: datetime) -> None:
        assert parse_api_datetime(value) == expected

    def test_try_variant_accepts_lowercase_z(self) -> None:
        assert try_parse_api_datetime(LOWER_Z_WITH_FRACTION) == EXPECTED
        assert try_parse_api_datetime("2025-10-11T12:23:56.0154302q") is None
