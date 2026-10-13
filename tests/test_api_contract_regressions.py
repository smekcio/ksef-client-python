"""Regresje z finalnego przeglądu API i dokumentacji (runda 3).

Każdy test odpowiada znalezisku, którego dowód pochodzi ze snapshotu OpenAPI,
dokumentacji MF albo oficjalnych próbek FA(3). Testy mają nieść regułę, nie
tylko pilnować implementacji.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ksef_client.utils.datetime_parsing import (
    normalize_api_timestamp,
    parse_api_datetime,
    try_parse_api_datetime,
)

#: Znacznik, jaki zwraca API KSeF — 7 cyfr części ułamkowej.
KSEF_TIMESTAMP = "2025-10-11T12:23:56.0154302+00:00"
#: Ten sam znacznik z ``Z`` zamiast offsetu.
KSEF_TIMESTAMP_Z = "2025-10-11T12:23:56.0154302Z"
#: Okno ważności certyfikatu z oficjalnego przykładu API (7 cyfr ułamka).
CERT_VALID_FROM = "2024-07-11T12:23:56.0154302+00:00"
CERT_VALID_TO_EXPIRED = "2025-07-11T12:23:56.0154302+00:00"
CERT_VALID_TO_FUTURE = "2028-07-11T12:23:56.0154302+00:00"
CERT_VALID_FROM_OLDER = "2020-07-11T12:23:56.0154302+00:00"
CERT_VALID_FROM_NEWER = "2026-07-11T12:23:56.0154302+00:00"
CERT_VALID_TO_2030 = "2030-07-11T12:23:56.0154302+00:00"


class TestApiTimestampParsing:
    """`datetime.fromisoformat` na Pythonie 3.10 odrzuca 7 cyfr ułamka."""

    def test_seven_digit_fraction_is_parsed(self):
        parsed = parse_api_datetime(KSEF_TIMESTAMP)
        assert parsed == datetime(2025, 10, 11, 12, 23, 56, 15430, tzinfo=timezone.utc)

    def test_z_suffix_is_accepted(self):
        assert parse_api_datetime(KSEF_TIMESTAMP_Z) == parse_api_datetime(KSEF_TIMESTAMP)

    def test_naive_timestamp_is_treated_as_utc(self):
        parsed = parse_api_datetime("2026-01-01T00:00:00")
        assert parsed.tzinfo is timezone.utc

    def test_offset_is_normalised_to_utc(self):
        parsed = parse_api_datetime("2026-01-01T12:00:00+02:00")
        assert parsed.hour == 10

    def test_normalize_is_idempotent_and_keeps_microseconds(self):
        once = normalize_api_timestamp(KSEF_TIMESTAMP)
        assert once == "2025-10-11T12:23:56.015430+00:00"
        assert normalize_api_timestamp(once) == once

    def test_try_variant_returns_none_for_junk(self):
        assert try_parse_api_datetime("nie-data") is None
        assert try_parse_api_datetime(None) is None
        assert try_parse_api_datetime("") is None
        assert try_parse_api_datetime(KSEF_TIMESTAMP) is not None

    def test_parse_variant_raises_for_junk(self):
        with pytest.raises(ValueError):
            parse_api_datetime("nie-data")


class TestTimestampNormalisationIsVersionUniform:
    """Ułamek sekundy musi być sprowadzany do 6 cyfr niezależnie od długości."""

    def test_short_fraction_is_padded(self):
        from ksef_client.utils.datetime_parsing import parse_api_datetime

        assert parse_api_datetime("2026-01-01T00:00:00.1234+00:00").microsecond == 123400
        assert parse_api_datetime("2026-01-01T00:00:00.12+00:00").microsecond == 120000

    def test_long_fraction_is_truncated(self):
        from ksef_client.utils.datetime_parsing import parse_api_datetime

        assert parse_api_datetime("2026-01-01T00:00:00.123456789+00:00").microsecond == 123456

    def test_helper_is_exported_from_utils(self):
        from ksef_client.utils import parse_api_datetime, try_parse_api_datetime

        assert parse_api_datetime("2026-01-01T00:00:00Z").year == 2026
        assert try_parse_api_datetime("nie-data") is None
