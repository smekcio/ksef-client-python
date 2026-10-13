"""Regresje z finalnego przeglądu API i dokumentacji (runda 3).

Każdy test odpowiada znalezisku, którego dowód pochodzi ze snapshotu OpenAPI,
dokumentacji MF albo oficjalnych próbek FA(3). Testy mają nieść regułę, nie
tylko pilnować implementacji.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import pytest

from ksef_client.http import HttpResponse
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


class TestCertificateValidity:
    """Wygasły certyfikat nie może przejść filtra ważności."""

    def _cert(self, valid_from: str, valid_to: str):
        from ksef_client import models as m

        return m.PublicKeyCertificate(
            certificate="cert",
            usage=[m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION],
            valid_from=valid_from,
            valid_to=valid_to,
        )

    def test_expired_certificate_with_seven_digit_dates_is_rejected(self):
        from ksef_client.clients.security import _is_current_certificate

        now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        expired = self._cert(CERT_VALID_FROM, CERT_VALID_TO_EXPIRED)
        assert _is_current_certificate(expired, now) is False

    def test_current_certificate_with_seven_digit_dates_is_accepted(self):
        from ksef_client.clients.security import _is_current_certificate

        now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        current = self._cert(CERT_VALID_FROM, CERT_VALID_TO_FUTURE)
        assert _is_current_certificate(current, now) is True

    def test_unparseable_valid_to_is_not_treated_as_valid(self):
        from ksef_client.clients.security import _is_current_certificate

        now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        broken = self._cert(CERT_VALID_FROM, "to-nie-data")
        assert _is_current_certificate(broken, now) is False

    def test_unparseable_valid_from_is_not_treated_as_valid(self):
        """Symetria do `validTo`: nieparsowalne `validFrom` też odrzuca certyfikat.

        Bez tego strażnika `_is_current_certificate` uznawał certyfikat o złej
        dacie początkowej za aktualny, a `_select_public_key_certificate` mógł go
        wybrać (klucz sortowania `(False, datetime.min)` przegrywa tylko z
        parsowalnymi datami).
        """
        from ksef_client.clients.security import _is_current_certificate

        now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        broken = self._cert("to-nie-data", CERT_VALID_TO_FUTURE)
        assert _is_current_certificate(broken, now) is False

        from ksef_client import models as m
        from ksef_client.clients.security import _select_public_key_certificate

        with pytest.raises(ValueError, match="Missing KSeF public certificate"):
            _select_public_key_certificate(
                [broken], m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION, now=now
            )

    def test_newest_certificate_wins_with_seven_digit_dates(self):
        from ksef_client import models as m
        from ksef_client.clients.security import _select_public_key_certificate

        now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        older = self._cert(CERT_VALID_FROM_OLDER, CERT_VALID_TO_2030)
        newer = self._cert(CERT_VALID_FROM_NEWER, CERT_VALID_TO_2030)
        selected = _select_public_key_certificate(
            [older, newer], m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION, now=now
        )
        assert selected.valid_from == newer.valid_from


class TestHwmContinuationPoint:
    """Kolejność z dokumentacji MF: obcięta paczka → `LastPermanentStorageDate`."""

    def _update(self, payload: dict):
        from ksef_client.services.hwm import update_continuation_point

        points: dict[str, str | None] = {}
        update_continuation_point(points, "seller", payload)
        return points

    def test_truncated_package_resumes_from_last_permanent_storage_date(self):
        points = self._update(
            {
                "isTruncated": True,
                "lastPermanentStorageDate": "2025-05-01T00:00:00+00:00",
                "permanentStorageHwmDate": "2025-05-10T00:00:00+00:00",
                "invoices": [],
            }
        )
        assert points["seller"] == "2025-05-01T00:00:00+00:00"

    def test_stable_package_uses_server_watermark(self):
        points = self._update(
            {
                "isTruncated": False,
                "permanentStorageHwmDate": "2025-05-10T00:00:00+00:00",
                "invoices": [],
            }
        )
        assert points["seller"] == "2025-05-10T00:00:00+00:00"

    def test_seven_digit_timestamps_sort_chronologically(self):
        from ksef_client.services.hwm import _permanent_storage_date_sort_key

        earlier = "2025-09-25T10:00:00.0000000+00:00"
        later = "2025-09-25T11:00:00.0000000+00:00"
        assert _permanent_storage_date_sort_key(later) > _permanent_storage_date_sort_key(
            earlier
        )

    def test_mixed_offsets_compare_by_instant(self):
        from ksef_client.services.hwm import _get_latest_invoice_permanent_storage_date

        # 12:00+02:00 to 10:00Z, czyli WCZEŚNIEJ niż 11:00Z.
        payload = {
            "invoices": [
                {"permanentStorageDate": "2025-09-25T12:00:00.0000000+02:00"},
                {"permanentStorageDate": "2025-09-25T11:00:00.0000000+00:00"},
            ]
        }
        assert (
            _get_latest_invoice_permanent_storage_date(payload)
            == "2025-09-25T11:00:00.0000000+00:00"
        )


class TestCollectiveIdentifierDatetime:
    """Zakres dat zapytania musi przyjąć format zwracany przez API."""

    def test_seven_digit_bound_is_accepted(self):
        from ksef_client.utils.collective_identifier import require_query_date_range

        start, end = require_query_date_range(KSEF_TIMESTAMP, "2025-10-12T12:23:56.0154302+00:00")
        assert start.startswith("2025-10-11")
        assert end.startswith("2025-10-12")

    def test_junk_bound_is_reported(self):
        from ksef_client.utils.collective_identifier import require_query_date_range

        with pytest.raises(ValueError, match="(?i)invalid"):
            require_query_date_range("nie-data", KSEF_TIMESTAMP)


class TestInvoiceRangeDatetime:
    """Granice zakresu faktur muszą być parsowalne i porównywane jak w API."""

    def test_seven_digit_bound_is_parsed(self):
        from ksef_client.clients.invoices import _parse_invoice_range_datetime

        assert _parse_invoice_range_datetime(KSEF_TIMESTAMP) is not None

    def test_local_timestamp_gets_warsaw_offset(self):
        from ksef_client.clients.invoices import _normalize_datetime_without_offset

        assert _normalize_datetime_without_offset("2026-01-01T00:00:00").endswith("+01:00")
        assert _normalize_datetime_without_offset("2026-07-01T00:00:00").endswith("+02:00")

    def test_explicit_offset_is_left_untouched(self):
        from ksef_client.clients.invoices import _normalize_datetime_without_offset

        for value in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+05:00"):
            assert _normalize_datetime_without_offset(value) == value

    def test_documented_100_day_window_boundary(self):
        from ksef_client.clients.invoices import _normalize_invoice_date_range_payload

        # Sufit setnego dnia jest przyjmowany (KSeF liczy dni kalendarzowe UTC).
        accepted = _normalize_invoice_date_range_payload(
            {"dateRange": {"from": "2026-01-01T00:00:00Z", "to": "2026-04-11T23:59:59Z"}}
        )
        assert accepted["dateRange"]["to"] == "2026-04-11T23:59:59Z"
        with pytest.raises(ValueError, match="100 days"):
            _normalize_invoice_date_range_payload(
                {"dateRange": {"from": "2026-01-01T00:00:00Z", "to": "2026-04-12T00:00:00Z"}}
            )

    def test_seven_digit_bounds_pass_the_guard(self):
        from ksef_client.clients.invoices import _normalize_invoice_date_range_payload

        payload = _normalize_invoice_date_range_payload(
            {
                "dateRange": {
                    "from": "2025-10-11T12:23:56.0154302+00:00",
                    "to": "2025-12-01T12:23:56.0154302+00:00",
                }
            }
        )
        assert payload["dateRange"]["from"].startswith("2025-10-11")


class _RecordingHttp:
    """Minimalny transport zapisujący nagłówki każdego żądania."""

    def __init__(self) -> None:
        import httpx

        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self._response = HttpResponse(200, httpx.Headers(), b"<UPO/>")

    def request(self, method: str, path: str, **kwargs: Any) -> HttpResponse:
        self.requests.append((method, path, dict(kwargs.get("headers") or {})))
        return self._response


class _AsyncRecordingHttp(_RecordingHttp):
    async def request(self, method: str, path: str, **kwargs: Any) -> HttpResponse:  # type: ignore[override]
        return super().request(method, path, **kwargs)


class TestUpoAcceptHeader:
    """Snapshot deklaruje `application/xml` jako jedyny typ odpowiedzi UPO.

    Kontrakt: `GET /sessions/{ref}/invoices/{invoiceRef}/upo`,
    `GET /sessions/{ref}/invoices/ksef/{ksefNumber}/upo` oraz
    `GET /sessions/{ref}/upo/{upoRef}` zwracają wyłącznie XML, więc bez
    nagłówka `Accept` serwer może zwrócić 406. Test przechodzi przez WSZYSTKIE
    sześć metod (sync i async), a nie przez dopasowanie tekstu źródła.
    """

    def test_sync_upo_downloads_request_xml(self):
        from ksef_client.clients.sessions import SessionsClient

        http = _RecordingHttp()
        client = SessionsClient(http)
        client.get_session_invoice_upo_by_ref("ref", "inv", access_token="t")
        client.get_session_invoice_upo_by_ksef(
            "ref", "1234567890-20260101-AAAAAA-BBBBBB-01", access_token="t"
        )
        client.get_session_upo("ref", "upo", access_token="t")
        assert [path for _m, path, _h in http.requests] == [
            "/sessions/ref/invoices/inv/upo",
            "/sessions/ref/invoices/ksef/1234567890-20260101-AAAAAA-BBBBBB-01/upo",
            "/sessions/ref/upo/upo",
        ]
        for method, path, headers in http.requests:
            assert method == "GET" and headers == {"Accept": "application/xml"}, path

    def test_async_upo_downloads_request_xml(self):
        from ksef_client.clients.sessions import AsyncSessionsClient

        http = _AsyncRecordingHttp()
        client = AsyncSessionsClient(http)

        async def _run() -> None:
            await client.get_session_invoice_upo_by_ref("ref", "inv", access_token="t")
            await client.get_session_invoice_upo_by_ksef("ref", "ksef", access_token="t")
            await client.get_session_upo("ref", "upo", access_token="t")

        asyncio.run(_run())
        assert len(http.requests) == 3
        for method, path, headers in http.requests:
            assert method == "GET" and headers == {"Accept": "application/xml"}, path


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


class TestCliCertificateValidity:
    """CLI miał DWIE własne kopie błędu naprawionego w `clients.security`."""

    CERT_FROM_EXPIRED = "2020-07-11T12:23:56.0154302+00:00"
    CERT_TO_EXPIRED = "2025-07-11T12:23:56.0154302+00:00"
    CERT_FROM_CURRENT = "2026-07-11T12:23:56.0154302+00:00"
    CERT_TO_CURRENT = "2030-07-11T12:23:56.0154302+00:00"

    def _cert(self, valid_from: str, valid_to: str, certificate: str = "cert"):
        return {
            "usage": ["SymmetricKeyEncryption"],
            "certificate": certificate,
            "validFrom": valid_from,
            "validTo": valid_to,
        }

    @staticmethod
    def _now():
        from datetime import datetime, timezone

        return datetime(2027, 1, 1, tzinfo=timezone.utc)

    def test_adapters_reject_an_expired_certificate(self):
        from ksef_client.cli.sdk.adapters import _is_current_certificate

        expired = self._cert(self.CERT_FROM_EXPIRED, self.CERT_TO_EXPIRED)
        current = self._cert(self.CERT_FROM_CURRENT, self.CERT_TO_CURRENT)
        assert _is_current_certificate(expired, self._now()) is False
        assert _is_current_certificate(current, self._now()) is True

    def test_adapters_reject_unparseable_bounds(self):
        from ksef_client.cli.sdk.adapters import _is_current_certificate

        broken_to = self._cert(self.CERT_FROM_CURRENT, "to-nie-data")
        broken_from = self._cert("od-nie-data", self.CERT_TO_CURRENT)
        assert _is_current_certificate(broken_to, self._now()) is False
        assert _is_current_certificate(broken_from, self._now()) is False

    def test_adapters_select_the_newest_valid_certificate(self):
        from ksef_client.cli.sdk.adapters import _select_certificate

        expired = self._cert(self.CERT_FROM_EXPIRED, self.CERT_TO_EXPIRED, "EXPIRED")
        current = self._cert(self.CERT_FROM_CURRENT, self.CERT_TO_CURRENT, "CURRENT")
        selected = _select_certificate([expired, current], "SymmetricKeyEncryption")
        assert selected.certificate == "CURRENT"

    def test_adapters_report_missing_usage(self):
        from ksef_client.cli.errors import CliError
        from ksef_client.cli.sdk.adapters import _select_certificate

        expired = self._cert(self.CERT_FROM_EXPIRED, self.CERT_TO_EXPIRED)
        with pytest.raises(CliError, match="Missing KSeF public certificate"):
            _select_certificate([expired], "SymmetricKeyEncryption")

    def test_auth_manager_rejects_an_expired_certificate(self):
        from ksef_client.cli.auth.manager import _is_current_certificate

        expired = self._cert(self.CERT_FROM_EXPIRED, self.CERT_TO_EXPIRED)
        current = self._cert(self.CERT_FROM_CURRENT, self.CERT_TO_CURRENT)
        assert _is_current_certificate(expired, self._now()) is False
        assert _is_current_certificate(current, self._now()) is True
        # Obie granice są sprawdzane niezależnie: nieparsowalne `validTo`
        # przy parsowalnym `validFrom` też musi odrzucić certyfikat.
        assert _is_current_certificate(self._cert("od-nie-data", "tez-zle"), self._now()) is False
        broken_to = self._cert(self.CERT_FROM_CURRENT, "zle")
        assert _is_current_certificate(broken_to, self._now()) is False

    def test_auth_manager_selects_the_newest_valid_certificate(self):
        from ksef_client.cli.auth.manager import _select_certificate

        expired = self._cert(self.CERT_FROM_EXPIRED, self.CERT_TO_EXPIRED, "EXPIRED")
        current = self._cert(self.CERT_FROM_CURRENT, self.CERT_TO_CURRENT, "CURRENT")
        selected = _select_certificate([expired, current], "SymmetricKeyEncryption")
        assert selected.certificate == "CURRENT"

    def test_sort_key_is_none_safe(self):
        from datetime import datetime, timezone

        from ksef_client import models as m
        from ksef_client.clients.security import _certificate_sort_key

        broken = m.PublicKeyCertificate(certificate="c", valid_from="nie-data")
        assert _certificate_sort_key(broken) == (
            False,
            datetime.min.replace(tzinfo=timezone.utc),
        )
