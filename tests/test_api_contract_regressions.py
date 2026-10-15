"""Regresje z finalnego przeglądu API i dokumentacji (runda 3).

Każdy test odpowiada znalezisku, którego dowód pochodzi ze snapshotu OpenAPI,
dokumentacji MF albo oficjalnych próbek FA(3). Testy mają nieść regułę, nie
tylko pilnować implementacji.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from decimal import Decimal
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


class TestDecimalAcceptance:
    """`Decimal` nie może wymagać dodatkowej konwersji, a `str` musi działać."""

    def test_discount_is_per_unit_like_the_official_sample(self):
        from ksef_client.documents.fa3 import (
            BasicInvoiceBuilder,
            Discount,
            InvoiceParty,
            VatClass,
        )

        builder = BasicInvoiceBuilder(invoice_number="FV/D")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line(
            "zamrażarka",
            quantity="20",
            unit_net_price="1000",
            tax=VatClass.standard_23(),
            discount=Discount.amount(Decimal("100")),
        )
        xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
        # `FA_3_Przykład_4.xml`: 20 × (1000 − 100) = 18000, nie 20 × 1000 − 100.
        assert "<P_10>100</P_10>" in xml
        assert "<P_11>18000.00</P_11>" in xml

    def test_percent_discount_applies_to_the_unit_price(self):
        from ksef_client.documents.fa3 import (
            BasicInvoiceBuilder,
            Discount,
            InvoiceParty,
            VatClass,
        )

        builder = BasicInvoiceBuilder(invoice_number="FV/D2")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line(
            "Usługa",
            quantity="2",
            unit_net_price="100",
            tax=VatClass.standard_23(),
            discount=Discount.percent("10"),
        )
        xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
        assert "<P_10>10</P_10>" in xml
        assert "<P_11>180.00</P_11>" in xml

    def test_order_line_discount_uses_the_same_per_unit_semantics(self):
        """Ten sam obiekt `Discount` musi znaczyć to samo w pozycji zamówienia."""
        from ksef_client.documents.fa3 import (
            AdvanceInvoiceBuilder,
            Discount,
            InvoiceParty,
            VatClass,
        )

        builder = AdvanceInvoiceBuilder(invoice_number="ZAL/D")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        builder.order(total_gross="1000")
        builder.order_line(
            "Pozycja",
            quantity="20",
            unit_net_price="50",
            tax=VatClass.standard_23(),
            discount=Discount.amount("5"),
        )
        invoice = builder.build()
        assert invoice.order is not None
        line = invoice.order.lines[0]
        # 20 × 5 = 100 (obniżka na jednostkę), a nie 5 zł łącznie.
        assert line.discount_amount == Decimal("100.00")
        assert line.effective_net_amount == Decimal("900.00")


class TestFa3SchemaContract:
    """Reguły schematu FA(3) potwierdzone oficjalnymi próbkami MF."""

    @staticmethod
    def _seller():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")

    @staticmethod
    def _buyer():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")

    def _correction_builder(self, invoice_number: str):
        from datetime import date

        from ksef_client.documents.fa3 import (
            CorrectionInvoiceBuilder,
            CorrectionType,
            VatClass,
        )

        builder = CorrectionInvoiceBuilder(invoice_number=invoice_number)
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        builder.corrects_invoice(
            number="FV/1",
            issue_date=date(2026, 2, 15),
            reason="zmiana danych",
            correction_type=CorrectionType.OTHER,
        )
        return builder

    def test_corrected_seller_requires_an_address(self):
        """`Podmiot1K/Adres` jest w schemacie wymagane (minOccurs=1)."""
        from ksef_client.documents.fa3 import InvoiceParty

        builder = self._correction_builder("FK/1")
        builder.corrected_seller(InvoiceParty.polish_company(nip="2222222222", name="Stary"))
        with pytest.raises(ValueError, match="(?i)adres"):
            builder.build()

    def test_corrected_seller_with_address_is_accepted(self):
        from ksef_client.documents.fa3 import InvoiceParty

        builder = self._correction_builder("FK/2")
        builder.corrected_seller(
            InvoiceParty.polish_company(nip="2222222222", name="Stary", address="ul. Stara 1")
        )
        xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
        assert "<Podmiot1K>" in xml and "<Adres>" in xml

    def test_margin_line_has_no_rate_or_net_amounts(self):
        """Oficjalny `FA_3_Przykład_8.xml`: brak `P_9A`, `P_11`, `P_12`."""
        from ksef_client.documents.fa3 import BasicInvoiceBuilder, TaxCategory

        builder = BasicInvoiceBuilder(invoice_number="FV/M")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line(
            "samochód używany",
            quantity="1",
            unit_net_price=Decimal("15000"),
            tax=TaxCategory.margin(),
            unit_gross_price=Decimal("15000"),
            gross_amount=Decimal("15000"),
        )
        xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
        row = xml.split("<FaWiersz>", 1)[1].split("</FaWiersz>", 1)[0]
        assert "<P_9A>" not in row
        assert "<P_11>" not in row
        assert "<P_12>" not in row
        assert "<P_9B>" in row and "<P_11A>" in row

    def test_correction_can_have_no_rows(self):
        """Art. 106j ust. 3: korekta zbiorcza nie zawiera `FaWiersz`."""
        from datetime import date

        from ksef_client.documents.fa3 import CorrectionInvoiceBuilder, CorrectionReference

        builder = CorrectionInvoiceBuilder(invoice_number="FK/3")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.corrects_many(
            (
                CorrectionReference("FV/2026/01/1", date(2026, 1, 15)),
                CorrectionReference("FV/2026/02/1", date(2026, 2, 15)),
            ),
            reason="rabat",
            correction_type="2",
        )
        builder.corrected_period("pierwsze półrocze 2026")
        errors = builder.build().validate().errors
        assert not errors, [issue.message for issue in errors]

    def test_attachment_row_must_have_a_cell(self):
        """`Wiersz` wymaga co najmniej jednego `WKom`."""
        from dataclasses import replace

        from ksef_client.documents.fa3 import BasicInvoiceBuilder
        from ksef_client.documents.fa3.domain import (
            Attachment,
            AttachmentBlock,
            AttachmentTable,
        )

        builder = BasicInvoiceBuilder(invoice_number="FV/T")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        invoice = replace(
            builder.build(),
            attachment=Attachment(
                (
                    AttachmentBlock(
                        header="H",
                        metadata=(("K", "V"),),
                        tables=(AttachmentTable(headers=("A", "B"), rows=(("x", "y"), ())),),
                    ),
                )
            ),
        )
        errors = invoice.validate().errors
        assert any("komórki" in issue.message for issue in errors), [
            issue.message for issue in errors
        ]

    def test_settlement_with_unsupported_proportion_is_rejected(self):
        """SDK nie wyprowadza proporcji `P_13_x` z pełnej wartości zamówienia."""
        from datetime import date

        from ksef_client.documents.fa3 import (
            SettlementInvoiceBuilder,
            VatClass,
        )

        builder = SettlementInvoiceBuilder(invoice_number="ROZ/1")
        builder.issued_on(date(2026, 3, 1))
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line(
            "Dostawa 8%", quantity="1", unit_net_price="307500", tax=VatClass.reduced_8()
        )
        builder.settles_advance(ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01")
        builder.remaining_to_pay(Decimal("307635"))
        with pytest.raises(ValueError, match="(?i)proporcj|pozostałej"):
            builder.build()


class TestRemainingBranches:
    """Gałęzie wprowadzone przez poprawki muszą być wykonywane przez testy."""

    @staticmethod
    def _seller():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")

    @staticmethod
    def _buyer():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")

    def test_line_without_discount_has_zero_unit_discount(self):
        from ksef_client.documents.fa3 import BasicInvoiceBuilder

        builder = BasicInvoiceBuilder(invoice_number="FV/ND")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        line = builder.build().lines[0]
        assert line.discount_unit_amount == Decimal("0.00")
        assert line.discount_amount == Decimal("0.00")

    def test_gross_with_advances_includes_advance_payments(self):
        from ksef_client.documents.fa3 import AdvanceInvoiceBuilder, VatClass

        builder = AdvanceInvoiceBuilder(invoice_number="ZAL/1")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.advance_payment(amount="123", tax=VatClass.standard_23())
        invoice = builder.build()
        assert invoice.line_gross_total == Decimal("0.00")
        assert invoice.gross_with_advances == Decimal("123.00")

    def test_non_settlement_kind_skips_the_proportion_check(self):
        from ksef_client.documents.fa3 import BasicInvoiceBuilder

        builder = BasicInvoiceBuilder(invoice_number="FV/PROP")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        assert builder.build()._validate_settlement_proportion() == []

    def test_settlement_without_amount_due_skips_the_proportion_check(self):
        from datetime import date

        from ksef_client.documents.fa3 import SettlementInvoiceBuilder

        builder = SettlementInvoiceBuilder(invoice_number="ROZ/2")
        builder.issued_on(date(2026, 3, 1))
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line("Dostawa", quantity="1", unit_net_price="100")
        builder.settles_advance(ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01")
        assert builder.build()._validate_settlement_proportion() == []

    def test_serializer_rejects_corrected_seller_without_address(self):
        """Warstwa XML broni się niezależnie od walidacji domenowej."""
        from dataclasses import replace
        from datetime import date

        from ksef_client.documents.fa3 import (
            CorrectionInvoiceBuilder,
            CorrectionType,
            InvoiceParty,
            VatClass,
        )
        from ksef_client.documents.fa3.xml import FA3XmlValidationError, invoice_to_xml

        builder = CorrectionInvoiceBuilder(invoice_number="FK/4")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        builder.corrects_invoice(
            number="FV/1",
            issue_date=date(2026, 2, 15),
            reason="zmiana",
            correction_type=CorrectionType.OTHER,
        )
        # Najpierw budujemy dokument POPRAWNIE (z adresem)…
        builder.corrected_seller(
            InvoiceParty.polish_company(nip="2222222222", name="Stary", address="ul. Stara 1")
        )
        invoice = builder.build()
        # …a potem odbieramy adres, żeby sprawdzić samą warstwę XML przy
        # wyłączonej walidacji domenowej (`validate=False`).
        broken = replace(
            invoice,
            corrected_seller=InvoiceParty.polish_company(nip="2222222222", name="Stary"),
        )
        with pytest.raises(FA3XmlValidationError, match="(?i)adres"):
            invoice_to_xml(broken, validate=False)

    def test_corrected_seller_guard_fires_before_the_facet_layer(self):
        """Strażnik z `xml.py` musi działać także przy wyłączonych fasetach.

        Sam `match="(?i)adres"` spełnia również komunikat warstwy faset
        (`brak wymaganego elementu Adres w Podmiot1K`), więc usunięcie strażnika
        z serializatora przechodziło na zielono. Tutaj wyłączamy fasety, żeby
        sprawdzić dokładnie tę warstwę.
        """
        from dataclasses import replace
        from datetime import date

        from ksef_client.documents.fa3 import (
            CorrectionInvoiceBuilder,
            CorrectionType,
            InvoiceParty,
            VatClass,
        )
        from ksef_client.documents.fa3.xml import FA3XmlValidationError, invoice_to_xml

        builder = CorrectionInvoiceBuilder(invoice_number="FK/5")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        builder.corrects_invoice(
            number="FV/1",
            issue_date=date(2026, 2, 15),
            reason="zmiana",
            correction_type=CorrectionType.OTHER,
        )
        builder.corrected_seller(
            InvoiceParty.polish_company(nip="2222222222", name="Stary", address="ul. Stara 1")
        )
        invoice = builder.build()
        broken = replace(
            invoice,
            corrected_seller=InvoiceParty.polish_company(nip="2222222222", name="Stary"),
        )
        with pytest.raises(FA3XmlValidationError, match="korekta danych sprzedawcy"):
            invoice_to_xml(broken, validate=False, facets=False)


class TestPurchaserIdentification:
    """GEN-20 / P2-16 broszury MF: polski NIP nabywcy trafia wyłącznie w `NIP`.

    Schemat przyjmuje `KodUE=PL`/`KodKraju=PL`, więc XSD tego nie wychwyci —
    a KSeF **nie udostępni faktury nabywcy**, jeśli NIP nie będzie w `NIP`.
    """

    @staticmethod
    def _seller():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")

    @staticmethod
    def _party(identifier, name="Nabywca"):
        from ksef_client.documents.fa3 import Address, InvoiceParty

        return InvoiceParty(name=name, identifier=identifier, address=Address.polish("ul. B 2"))

    def _valid_invoice(self):
        from ksef_client.documents.fa3 import (
            BasicInvoiceBuilder,
            PartyIdentifier,
        )

        builder = BasicInvoiceBuilder(invoice_number="FV/GEN20")
        builder.seller(self._seller())
        builder.buyer(self._party(PartyIdentifier.polish_nip("2222222222")))
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        return builder.build()

    def _invoice_with_buyer(self, buyer):
        from dataclasses import replace

        return replace(self._valid_invoice(), buyer=buyer)

    def test_polish_nip_in_kodue_is_rejected(self):
        from ksef_client.documents.fa3 import PartyIdentifier

        invoice = self._invoice_with_buyer(
            self._party(PartyIdentifier.eu_vat("PL", "1111111111"))
        )
        messages = [issue.message for issue in invoice.validate().errors]
        assert any("GEN-20" in message for message in messages), messages
        # `build()` też nie przepuszcza takiego dokumentu (walidacja domenowa).
        with pytest.raises(ValueError, match="GEN-20"):
            invoice.to_xml()

    def test_polish_nip_in_nrid_is_rejected(self):
        from ksef_client.documents.fa3 import PartyIdentifier

        invoice = self._invoice_with_buyer(
            self._party(PartyIdentifier.foreign("1111111111", country_code="PL"))
        )
        with pytest.raises(ValueError, match="GEN-20"):
            invoice.to_xml()

    def test_corrected_buyer_is_checked_too(self):
        from datetime import date

        from ksef_client.documents.fa3 import (
            CorrectionInvoiceBuilder,
            CorrectionType,
            InvoiceParty,
            PartyIdentifier,
            VatClass,
        )

        builder = CorrectionInvoiceBuilder(invoice_number="FK/GEN20")
        builder.seller(self._seller())
        builder.buyer(self._party(PartyIdentifier.polish_nip("2222222222")))
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        builder.corrects_invoice(
            number="FV/1",
            issue_date=date(2026, 2, 15),
            reason="zmiana",
            correction_type=CorrectionType.OTHER,
        )
        builder.corrected_buyer(
            InvoiceParty(
                name="Stary nabywca",
                identifier=PartyIdentifier.eu_vat("PL", "1111111111"),
            )
        )
        with pytest.raises(ValueError, match="GEN-20"):
            builder.build()

    def test_foreign_vat_identifier_is_still_accepted(self):
        from ksef_client.documents.fa3 import PartyIdentifier

        invoice = self._invoice_with_buyer(
            self._party(PartyIdentifier.eu_vat("DE", "123456789"), "Firma DE")
        )
        assert not [issue for issue in invoice.validate().errors if "GEN-20" in issue.message]
        assert invoice.to_xml(xsd_validate=True)

    def test_third_party_identifier_is_not_covered_by_gen20(self):
        """Reguła dotyczy nabywcy (Podmiot2); Podmiot3 ma własne role."""
        from ksef_client.documents.fa3 import (
            BasicInvoiceBuilder,
            PartyIdentifier,
            ThirdPartyRole,
        )

        builder = BasicInvoiceBuilder(invoice_number="FV/P3")
        builder.seller(self._seller())
        builder.buyer(self._party(PartyIdentifier.polish_nip("2222222222")))
        builder.add_party(
            self._party(PartyIdentifier.eu_vat("PL", "1111111111"), "Odbiorca"),
            ThirdPartyRole.RECIPIENT,
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        invoice = builder.build()
        assert not [issue for issue in invoice.validate().errors if "GEN-20" in issue.message]


class TestTaxpayerPrefix:
    """`Podmiot1/PrefiksPodatnika` ma w schemacie `fixed="PL"` (S:2137)."""

    @staticmethod
    def _seller(prefix=None):
        from dataclasses import replace

        from ksef_client.documents.fa3 import InvoiceParty

        party = InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        return replace(party, taxpayer_prefix=prefix) if prefix else party

    @staticmethod
    def _buyer():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")

    def _invoice(self, prefix=None):
        from ksef_client.documents.fa3 import BasicInvoiceBuilder

        builder = BasicInvoiceBuilder(invoice_number="FV/PREF")
        builder.seller(self._seller(prefix))
        builder.buyer(self._buyer())
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        return builder.build()

    def _invoice_with_prefix(self, prefix):
        from dataclasses import replace

        invoice = self._invoice()
        return replace(invoice, seller=replace(invoice.seller, taxpayer_prefix=prefix))

    def test_seller_prefix_other_than_pl_is_rejected(self):
        from ksef_client.documents.fa3.xml import FA3XmlValidationError

        invoice = self._invoice_with_prefix("DE")
        messages = [issue.message for issue in invoice.validate().errors]
        assert any("'PL'" in message for message in messages), messages
        # Warstwa faset (domyślna) też musi to wyłapać — inaczej dokument
        # wychodzi z SDK i dopiero KSeF go odrzuca.
        with pytest.raises(FA3XmlValidationError, match="stałą wartość"):
            invoice.to_xml(validate=False)

    def test_seller_prefix_pl_is_accepted(self):
        invoice = self._invoice("PL")
        assert not [issue for issue in invoice.validate().errors if "prefix" in issue.message]
        assert invoice.to_xml(xsd_validate=True)

    def test_corrected_seller_prefix_is_not_constrained_by_the_schema(self):
        """`Podmiot1K/PrefiksPodatnika` nie ma `fixed` — nie wolno odrzucać."""
        from datetime import date

        from ksef_client.documents.fa3 import (
            CorrectionInvoiceBuilder,
            CorrectionType,
            InvoiceParty,
            VatClass,
        )

        builder = CorrectionInvoiceBuilder(invoice_number="FK/PREF")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        builder.corrects_invoice(
            number="FV/1",
            issue_date=date(2026, 2, 15),
            reason="zmiana",
            correction_type=CorrectionType.OTHER,
        )
        builder.corrected_seller(
            InvoiceParty.polish_company(
                nip="2222222222", name="Stary", address="ul. Stara 1"
            )
        )
        invoice = builder.build()
        from dataclasses import replace as _replace

        corrected_seller = invoice.corrected_seller
        assert corrected_seller is not None
        invoice = _replace(
            invoice,
            corrected_seller=_replace(corrected_seller, taxpayer_prefix="DE"),
        )
        assert not [issue for issue in invoice.validate().errors if "prefix" in issue.message]
        xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
        assert "<Podmiot1K>" in xml and "<PrefiksPodatnika>DE</PrefiksPodatnika>" in xml


class TestSimplifiedInvoice:
    """Faktura uproszczona (art. 106e ust. 5 pkt 3) może nie mieć nazwy nabywcy.

    Oficjalny `FA_3_Przykład_15/16.xml` ma `Podmiot2` złożony z samego `NIP`
    (bez `Nazwa` i bez `Adres`) — `TPodmiot2` trzyma `Nazwa` w
    `<xsd:sequence minOccurs="0">`, właśnie dla tego przypadku.
    """

    @staticmethod
    def _seller():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")

    def _build(self, *, simplified: bool, buyer_name: str = ""):
        from ksef_client.documents.fa3 import (
            BasicInvoiceBuilder,
            InvoiceParty,
            PartyIdentifier,
            SimplifiedInvoiceBuilder,
            VatClass,
        )

        builder = (
            SimplifiedInvoiceBuilder(invoice_number="FV/UPR")
            if simplified
            else BasicInvoiceBuilder(invoice_number="FV/VAT")
        )
        builder.seller(self._seller())
        builder.buyer(
            InvoiceParty(name=buyer_name, identifier=PartyIdentifier.polish_nip("2222222222"))
        )
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        return builder

    def test_simplified_invoice_without_buyer_name_matches_the_official_shape(self):
        invoice = self._build(simplified=True).build()
        assert not invoice.validate().errors
        xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
        assert "<Podmiot2>" in xml
        buyer_section = xml.split("<Podmiot2>", 1)[1].split("</Podmiot2>", 1)[0]
        assert "<NIP>2222222222</NIP>" in buyer_section
        assert "<Nazwa>" not in buyer_section
        assert "<Adres>" not in buyer_section

    def test_regular_invoice_still_requires_the_buyer_name(self):
        """Bez nazwy nabywcy buduje się wyłącznie faktura uproszczona."""
        builder = self._build(simplified=False)
        with pytest.raises(ValueError, match="nazwa jest wymagana"):
            builder.build()


class TestAdvanceInvoiceKsefNumber:
    """`NrKSeFFaZaliczkowej` ma ten sam typ `TNumerKSeF` co pole korygowane."""

    @staticmethod
    def _builder(invoice_number: str):
        from ksef_client.documents.fa3 import AdvanceInvoiceBuilder, InvoiceParty, VatClass

        builder = AdvanceInvoiceBuilder(invoice_number=invoice_number)
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        return builder

    def test_bogus_advance_ksef_number_is_rejected(self):
        from ksef_client.documents.fa3.xml import FA3XmlValidationError

        builder = self._builder("ZAL/1")
        builder.settles_advance(ksef_number="X" * 35)
        with pytest.raises(FA3XmlValidationError, match="nie pasuje do formatu"):
            builder.build().to_xml()

    def test_valid_advance_ksef_number_is_accepted(self):
        builder = self._builder("ZAL/2")
        builder.settles_advance(ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01")
        assert builder.build().to_xml(xsd_validate=True)


class TestCountryCodeDictionary:
    """`KodKraju` jest 254-wartościowym słownikiem, nie dowolnym dwuznakiem."""

    def test_unknown_country_code_is_rejected(self):
        from ksef_client.documents.fa3 import (
            Address,
            BasicInvoiceBuilder,
            InvoiceParty,
            PartyIdentifier,
        )
        from ksef_client.documents.fa3.xml import FA3XmlValidationError

        builder = BasicInvoiceBuilder(invoice_number="FV/KRAJ")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty(
                name="Nabywca",
                identifier=PartyIdentifier.polish_nip("2222222222"),
                address=Address.foreign("XX", "Somewhere 1"),
            )
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        with pytest.raises(FA3XmlValidationError, match="słownika TKodKraju"):
            builder.build().to_xml()

    def test_country_dictionary_matches_the_schema(self):
        """Słownik w tabeli to komplet 254 kodów z `KodyKrajow_v10-0E.xsd`."""
        from ksef_client.documents.fa3.validation import ELEMENT_FACETS

        entry = ELEMENT_FACETS["KodKraju"]
        assert entry.facet.allowed is not None
        assert len(entry.facet.allowed) == 254
        assert {"PL", "DE", "GB", "XI"} <= entry.facet.allowed


class TestVerificationLinkInputValidation:
    """Segmenty KOD I/KOD II muszą być dokładnie takie, jakich wymaga KSeF."""

    @staticmethod
    def _service():
        from ksef_client.config import KsefClientOptions, KsefEnvironment
        from ksef_client.services.verification_link import VerificationLinkService

        return VerificationLinkService(KsefClientOptions(base_url=KsefEnvironment.TEST.value))

    def test_context_identifier_type_is_normalised(self):
        from ksef_client.services.verification_link import _normalize_context_identifier_type

        assert _normalize_context_identifier_type("nip") == "Nip"
        assert _normalize_context_identifier_type("NIP") == "Nip"
        assert _normalize_context_identifier_type(" internalId ") == "InternalId"
        assert _normalize_context_identifier_type("nipVatUe") == "NipVatUe"
        assert _normalize_context_identifier_type("PeppolId") == "PeppolId"

    def test_unknown_context_identifier_type_is_reported(self):
        from ksef_client.services.verification_link import _normalize_context_identifier_type

        with pytest.raises(ValueError, match="Unsupported context identifier type"):
            _normalize_context_identifier_type("nip-vat")

    def test_invoice_url_uses_the_contracted_date_format(self):
        from datetime import date

        service = self._service()
        assert "/invoice/123/01-02-2026/" in service.build_invoice_verification_url(
            "123", "01-02-2026", "YQ=="
        )
        assert "/invoice/123/01-02-2026/" in service.build_invoice_verification_url(
            "123", date(2026, 2, 1), "YQ=="
        )
        # ISO-8601 jest wygodnym wejściem i musi zostać przekonwertowany.
        assert "/invoice/123/01-02-2026/" in service.build_invoice_verification_url(
            "123", "2026-02-01", "YQ=="
        )

    def test_malformed_invoice_date_is_reported(self):
        service = self._service()
        for value in ("2026/02/01", "1 lutego 2026", "01.02.2026"):
            with pytest.raises(ValueError, match="Invalid invoice issue date"):
                service.build_invoice_verification_url("123", value, "YQ==")


class TestArchiveEntryNames:
    """`build_zip` musi być równie ostrożny jak `build_tar_gz`."""

    def test_zip_sanitises_entry_names(self):
        from ksef_client.utils.zip_utils import build_zip, unzip_bytes_safe

        with pytest.raises(ValueError, match="unsafe segments"):
            build_zip({"../evil.xml": b"x"})
        payload = build_zip({"sub/faktura.xml": b"<xml/>"})
        assert unzip_bytes_safe(payload) == {"sub/faktura.xml": b"<xml/>"}

    def test_zip_rejects_names_colliding_after_normalisation(self):
        from ksef_client.utils.zip_utils import build_zip

        with pytest.raises(ValueError, match="duplicated after normalisation"):
            build_zip({"a//b.xml": b"x", "a/b.xml": b"y"})

    def test_unzip_reads_each_entry_and_rejects_duplicates(self):
        import io
        import warnings
        import zipfile

        from ksef_client.utils.zip_utils import unzip_bytes_safe

        buffer = io.BytesIO()
        with warnings.catch_warnings():
            # `zipfile` ostrzega o powtórzonej nazwie — tworzymy ją celowo.
            warnings.simplefilter("ignore")
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("faktura.xml", b"FIRST")
                archive.writestr("faktura.xml", b"SECOND")
        with pytest.raises(ValueError, match="duplicate entry name"):
            unzip_bytes_safe(buffer.getvalue())

    def test_untar_rejects_duplicate_entries(self):
        import io
        import tarfile

        from ksef_client.utils.zip_utils import untar_gz_bytes_safe

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for payload in (b"FIRST", b"SECOND"):
                info = tarfile.TarInfo(name="faktura.xml")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        with pytest.raises(ValueError, match="duplicate entry name"):
            untar_gz_bytes_safe(buffer.getvalue())

    def test_batch_part_size_is_the_decimal_limit(self):
        """KSeF: „Maksymalny dozwolony rozmiar części ... to 100MB" (dziesiętnie)."""
        from ksef_client.utils.zip_utils import MAX_BATCH_PART_SIZE_BYTES, split_bytes

        assert MAX_BATCH_PART_SIZE_BYTES == 100_000_000
        oversized = b"x" * (MAX_BATCH_PART_SIZE_BYTES + 1)
        parts = split_bytes(oversized)
        assert len(parts) == 2
        assert max(len(part) for part in parts) <= MAX_BATCH_PART_SIZE_BYTES


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

    def test_cli_invoice_sort_normalises_seven_digit_timestamps(self):
        from ksef_client.cli.sdk.adapters import (
            _is_iso_datetime,
            _normalize_invoice_sort_value,
        )

        value = "2025-09-25T13:48:26.8700925+02:00"
        assert _normalize_invoice_sort_value(value) == "2025-09-25T11:48:26.870092+00:00"
        assert _is_iso_datetime(value) is True
        assert _is_iso_datetime("nie-data") is False


def _tax_buckets(xml: str) -> tuple[Decimal, Decimal]:
    """Suma `P_13_x`/`P_14_x` oraz `P_15` z wygenerowanego dokumentu."""
    from xml.etree import ElementTree as ET

    from ksef_client.documents.fa3.xml import FA3_NAMESPACE

    root = ET.fromstring(xml)
    fa = root.find(f"{{{FA3_NAMESPACE}}}Fa")
    assert fa is not None
    buckets = Decimal("0")
    for child in fa:
        tag = child.tag.rsplit("}", 1)[-1]
        if (tag.startswith("P_13_") or tag.startswith("P_14_")) and not tag.endswith("W"):
            buckets += Decimal(child.text or "0")
    p15 = fa.find(f"{{{FA3_NAMESPACE}}}P_15")
    return buckets, Decimal(p15.text or "0") if p15 is not None else Decimal("0")


class TestTaxSummaryIdentity:
    """`P_15 = ΣP_13_x + ΣP_14_x` musi zachodzić dla każdego rodzaju faktury.

    Zapłata częściowa trafia do XML jako `ZaliczkaCzesciowa`/`P_15Z`, a schemat
    opisuje `P_15` jako kwotę ZAWIERAJĄCĄ `P_15Z`. Pominięcie jej w koszykach
    (tak działo się dla `KOR_ZAL` po zawężeniu podsumowania do `ZAL`) dawało
    dokument bez podstawy opodatkowania dla tej części kwoty.
    """

    @staticmethod
    def _seller():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")

    @staticmethod
    def _buyer():
        from ksef_client.documents.fa3 import InvoiceParty

        return InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")

    def test_advance_correction_with_payment_keeps_the_identity(self):
        from datetime import date

        from ksef_client.documents.fa3 import FA3Invoice, VatClass

        builder = FA3Invoice.advance_correction("KOR_ZAL/1")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.advance_payment(amount="20000", tax=VatClass.standard_23())
        builder.corrects_invoice(
            number="ZAL/1", issue_date=date(2026, 1, 1), reason="korekta zaliczki"
        )
        builder.corrected_advance_state("30000")
        buckets, p15 = _tax_buckets(builder.build().to_xml().decode("utf-8"))
        assert buckets == p15 == Decimal("20000.00")

    def test_advance_invoice_keeps_the_identity(self):
        from ksef_client.documents.fa3 import AdvanceInvoiceBuilder, VatClass

        builder = AdvanceInvoiceBuilder(invoice_number="ZAL/1")
        builder.seller(self._seller())
        builder.buyer(self._buyer())
        builder.advance_payment(amount="12300", tax=VatClass.standard_23())
        buckets, p15 = _tax_buckets(builder.build().to_xml().decode("utf-8"))
        assert buckets == p15 == Decimal("12300.00")


class TestOrderLineDiscountIdentity:
    """`ZamowienieWiersz` nie ma pola rabatu, więc `P_9AZ` musi być ceną po rabacie."""

    def test_unit_price_after_discount_keeps_the_schema_identity(self):
        from ksef_client.documents.fa3 import (
            AdvanceInvoiceBuilder,
            Discount,
            InvoiceParty,
            VatClass,
        )

        builder = AdvanceInvoiceBuilder(invoice_number="FZ/RABAT")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.order(total_gross="22140")
        builder.order_line(
            "pozycja zamowienia",
            quantity="20",
            unit_net_price="1000",
            tax=VatClass.standard_23(),
            discount=Discount.amount("100"),
        )
        xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
        row = xml.split("<ZamowienieWiersz>", 1)[1].split("</ZamowienieWiersz>", 1)[0]
        # `FA_3_Przykład_29.xml`: P_8BZ × P_9AZ = P_11NettoZ.
        assert "<P_9AZ>900</P_9AZ>" in row
        assert "<P_11NettoZ>18000.00</P_11NettoZ>" in row


class TestLineScopedFieldsAreRejected:
    """Pola, których schemat nie ma na poziomie `FaWiersz`, nie mogą znikać cicho."""

    def test_line_period_is_reported_instead_of_dropped(self):
        from dataclasses import replace
        from datetime import date

        from ksef_client.documents.fa3 import BasicInvoiceBuilder, InvoiceParty

        builder = BasicInvoiceBuilder(invoice_number="FV/OKRES")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        invoice = builder.build()
        line = replace(
            invoice.lines[0], period_from=date(2026, 1, 1), period_to=date(2026, 1, 31)
        )
        broken = replace(invoice, lines=(line,))
        messages = [issue.message for issue in broken.validate().errors]
        assert any("OkresFa" in message for message in messages), messages

    def test_line_additional_description_is_reported_instead_of_dropped(self):
        from dataclasses import replace

        from ksef_client.documents.fa3 import BasicInvoiceBuilder, InvoiceParty

        builder = BasicInvoiceBuilder(invoice_number="FV/OPIS")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        invoice = builder.build()
        line = replace(invoice.lines[0], additional_description={"Klucz": "Wartosc"})
        broken = replace(invoice, lines=(line,))
        messages = [issue.message for issue in broken.validate().errors]
        assert any("DodatkowyOpis" in message for message in messages), messages


class TestLineIdentifiersUniqueId:
    """`LineIdentifiers.unique_id` musi trafiać do `UU_ID` tak jak pozostałe pola."""

    def test_identifiers_unique_id_is_emitted(self):
        from ksef_client.documents.fa3 import (
            BasicInvoiceBuilder,
            InvoiceParty,
            LineIdentifiers,
        )

        builder = BasicInvoiceBuilder(invoice_number="FV/UUID")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line(
            "Usługa",
            quantity="1",
            unit_net_price="100",
            identifiers=LineIdentifiers(unique_id="UU-1", gtin="1234567890123"),
        )
        xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
        assert "<UU_ID>UU-1</UU_ID>" in xml
        assert "<GTIN>1234567890123</GTIN>" in xml


class TestContactLimit:
    """`DaneKontaktowe` ma `maxOccurs="3"` — nadmiar nie może znikać bez słowa."""

    def test_more_than_three_contacts_are_reported(self):
        from dataclasses import replace

        from ksef_client.documents.fa3 import (
            BasicInvoiceBuilder,
            Contact,
            InvoiceParty,
        )

        builder = BasicInvoiceBuilder(invoice_number="FV/KONTAKTY")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        invoice = builder.build()
        contacts = tuple(Contact(email=f"osoba{i}@example.com") for i in range(1, 5))
        broken = replace(invoice, buyer=replace(invoice.buyer, contacts=contacts))
        messages = [issue.message for issue in broken.validate().errors]
        assert any("kontakt" in message for message in messages), messages


class TestAttachmentBlocksAccumulate:
    """`attachment_text()` + `attachment_table()` nie mogą się wzajemnie nadpisywać."""

    def test_text_and_table_blocks_are_both_kept(self):
        from ksef_client.documents.fa3 import BasicInvoiceBuilder, InvoiceParty

        builder = BasicInvoiceBuilder(invoice_number="FV/ZAL")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="S", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="B", address="ul. B 2")
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        builder.attachment_text("Naglowek", "akapit")
        builder.attachment_table(columns=("A",), rows=(("1",),))
        invoice = builder.build()
        assert invoice.attachment is not None
        assert len(invoice.attachment.blocks) == 2
        xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
        assert "akapit" in xml
        assert "<Tabela>" in xml


class TestVatCodePreservation:
    """Kod stawki nie może zniknąć w `from_vat_rate` ani w round-tripie JSON."""

    def test_from_vat_rate_keeps_zero_subtypes_and_non_percent_codes(self):
        from ksef_client.documents.fa3 import TaxCategory

        for value, expected_rate in (
            ("0 WDT", "0 WDT"),
            ("0 EX", "0 EX"),
            ("0 KR", "0 KR"),
            ("0", "0 KR"),
            ("oo", "oo"),
            ("np I", "np I"),
            ("np II", "np II"),
            ("zw", "zw"),
        ):
            assert TaxCategory.from_vat_rate(value).xml_rate == expected_rate, value

    def test_json_round_trip_keeps_non_percent_codes(self):
        from decimal import Decimal

        from ksef_client.documents.fa3 import FA3Line
        from ksef_client.documents.fa3.models import parse_vat_code, parse_vat_rate

        for code in ("oo", "np I", "np II", "0 WDT", "0 EX", "0 KR"):
            line = FA3Line(
                description="pozycja",
                quantity=Decimal("1"),
                unit="szt",
                unit_net_price=Decimal("100"),
                vat_rate=parse_vat_rate(code),
                vat_code=parse_vat_code(code),
            )
            restored = FA3Line.from_dict(line.to_dict())
            assert restored.vat_code == line.vat_code, code

    def test_plain_rate_is_written_as_a_number(self):
        """Pozycja bez kodu stawki zapisuje procent (a bez stawki — `zw`)."""
        from decimal import Decimal

        from ksef_client.documents.fa3 import FA3Line

        rated = FA3Line(
            description="pozycja",
            quantity=Decimal("1"),
            unit="szt",
            unit_net_price=Decimal("100"),
            vat_rate=Decimal("8.5"),
        )
        assert rated.to_dict()["vat"] == "8.5"

        exempt = FA3Line(
            description="pozycja",
            quantity=Decimal("1"),
            unit="szt",
            unit_net_price=Decimal("100"),
            vat_rate=None,
            exemption_basis="art. 43 ust. 1 pkt 1 ustawy",
        )
        assert exempt.to_dict()["vat"] == "zw"

    def test_from_vat_rate_without_a_code_falls_back_to_zero_domestic(self):
        """`0` bez kodu (np. `Decimal("0")`) to stawka krajowa `0 KR`."""
        from decimal import Decimal

        from ksef_client.documents.fa3 import TaxCategory

        assert TaxCategory.from_vat_rate(Decimal("0")).xml_rate == "0 KR"
        assert TaxCategory.from_vat_rate(0).xml_rate == "0 KR"
        # Wartość bez stawki i bez kodu (`None`) pozostaje zwolnieniem.
        assert TaxCategory.from_vat_rate(None).xml_rate == "zw"


class TestDraftRequiresAnAddress:
    """Draft nie może wstawiać literału "brak" ani wymyślonych danych kontaktowych."""

    def test_draft_without_address_is_reported(self):
        from datetime import date

        from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3Party

        builder = FA3InvoiceBuilder(
            invoice_number="FV/DRAFT",
            issue_date=date(2026, 9, 23),
            seller=FA3Party(name="Sprzedawca", tax_id="1234567890"),
            buyer=FA3Party(name="Nabywca", tax_id="1111111111"),
        )
        builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="23")
        # `build()` już odrzuca brak adresu (wcześniej wstawiał literał "brak").
        with pytest.raises(ValueError, match="adres jest wymagany"):
            builder.build()

    def test_draft_does_not_invent_buyer_contacts(self):
        from datetime import date

        from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3Party

        draft = (
            FA3InvoiceBuilder(
                invoice_number="FV/DRAFT2",
                issue_date=date(2026, 9, 23),
                seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. A 1"),
                buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. B 2"),
            )
            .add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="23")
            .build()
        )
        xml = draft.to_xml().decode("utf-8")
        assert "brak@example.com" not in xml
        assert "000000000" not in xml
        assert "<AdresL1>brak</AdresL1>" not in xml

    def test_draft_serializer_refuses_a_missing_address_even_without_validation(self):
        """Warstwa XML broni się niezależnie od walidacji domenowej."""
        from dataclasses import replace
        from datetime import date

        from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3Party
        from ksef_client.documents.fa3.xml import FA3XmlValidationError

        draft = (
            FA3InvoiceBuilder(
                invoice_number="FV/DRAFT3",
                issue_date=date(2026, 9, 23),
                seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. A 1"),
                buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. B 2"),
            )
            .add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="23")
            .build()
        )
        broken = replace(draft, seller=FA3Party(name="Sprzedawca", tax_id="1234567890"))
        with pytest.raises(FA3XmlValidationError, match="adres jest wymagany"):
            broken.to_xml(validate=False)


class TestCsrSubjectAttributes:
    """CSR musi nieść `givenName` (2.5.4.42) i `surname` (2.5.4.4) z wektora KSeF."""

    def test_csr_contains_given_name_and_surname(self):
        import base64

        from cryptography import x509

        from ksef_client.services.csr import generate_csr_ec, generate_csr_rsa

        info = {
            "commonName": "Jan Kowalski",
            "countryName": "PL",
            "givenName": "Jan",
            "surname": "Kowalski",
            "serialNumber": "TINPL-88102341294",
            "uniqueIdentifier": "UID-1",
        }
        for generator in (generate_csr_ec, generate_csr_rsa):
            csr = x509.load_der_x509_csr(base64.b64decode(generator(info).csr_base64))
            subject = csr.subject
            given = subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.42"))
            surname = subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.4"))
            assert [attribute.value for attribute in given] == ["Jan"]
            assert [attribute.value for attribute in surname] == ["Kowalski"]

    def test_csr_accepts_the_snake_case_field_names_from_the_sdk_model(self):
        """Nazwy pól z modelu SDK (`given_name`) też muszą trafić do DN.

        `CertificateEnrollmentDataResponse` używa snake_case, a `_build_subject`
        akceptował wyłącznie camelCase — wołający przekazujący pole z modelu
        dostawał CSR bez `givenName` i bez żadnego sygnału, a KSeF odrzuca taki
        wniosek (kod 25003).
        """
        import base64

        from cryptography import x509

        from ksef_client.services.csr import generate_csr_rsa

        info = {
            "common_name": "Jan Kowalski",
            "country_name": "PL",
            "given_name": "Jan",
            "last_name": "Kowalski",
            "serial_number": "TINPL-88102341294",
            "unique_identifier": "UID-1",
            "organization_name": "Firma",
            "organization_identifier": "VATPL-1111111111",
        }
        csr = x509.load_der_x509_csr(base64.b64decode(generate_csr_rsa(info).csr_base64))
        subject = csr.subject
        assert [
            attribute.value
            for attribute in subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.42"))
        ] == ["Jan"]
        assert [
            attribute.value
            for attribute in subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.4"))
        ] == ["Kowalski"]
        assert [
            attribute.value
            for attribute in subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.97"))
        ] == ["VATPL-1111111111"]


class TestSchemaConstraintsFromTheXsd:
    """Ograniczenia elementów, których tabela faset wcześniej nie miała.

    `BDO` to `xsd:restriction base="tns:TZnakowy"` (`minLength=1`), `StopkaFaktury`
    to `etd:TTekstowy` (`minLength=1`), a `NrWierszaFa`/`NrWierszaZam` to
    `tns:TNaturalny` z `totalDigits=14` — bez tych wpisów `validate()` i domyślne
    `to_xml()` przepuszczały dokument, który XSD odrzuca.
    """

    def test_empty_bdo_and_footer_are_reported(self):
        from xml.etree import ElementTree as ET

        from ksef_client.documents.fa3.validation import validate_xml_facets

        xml = (
            '<Faktura xmlns="http://crd.gov.pl/wzor/2025/06/25/13775/"><Podmiot1>'
            "<BDO></BDO></Podmiot1><Fa><StopkaFaktury></StopkaFaktury></Fa></Faktura>"
        )
        elements = {issue.element for issue in validate_xml_facets(ET.fromstring(xml))}
        assert "BDO" in elements
        assert "StopkaFaktury" in elements

    def test_row_number_over_fourteen_digits_is_reported(self):
        from xml.etree import ElementTree as ET

        from ksef_client.documents.fa3.validation import validate_xml_facets

        xml = (
            '<Faktura xmlns="http://crd.gov.pl/wzor/2025/06/25/13775/"><Fa><FaWiersz>'
            "<NrWierszaFa>123456789012345</NrWierszaFa></FaWiersz></Fa></Faktura>"
        )
        issues = validate_xml_facets(ET.fromstring(xml))
        assert any(issue.element == "NrWierszaFa" for issue in issues)


class TestTransportMeansValidation:
    """`NoweSrodkiTransportu` musi być spójne ze schematem.

    Znacznik bez wiersza dawał XML odrzucany przez XSD (`P_22N=1` bez
    `NowySrodekTransportu`), a literówka w `kind` (np. `sea`) cicho wybierała
    gałąź lądową — czyli dokument opisywał inny środek transportu.
    """

    def _invoice(self):
        from ksef_client.documents.fa3 import FA3Invoice, InvoiceParty, VatClass

        builder = FA3Invoice.basic("FV/NST/1")
        builder.seller(
            InvoiceParty.polish_company(
                nip="1111111111", name="Sprzedawca", address="ul. Testowa 1"
            )
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. Testowa 2")
        )
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        return builder.build()

    def _means(self, **overrides):
        from datetime import date

        from ksef_client.documents.fa3 import NewTransportMeans

        return NewTransportMeans(
            allowed_date=overrides.get("allowed_date", date(2026, 2, 20)),
            row_number=overrides.get("row_number", 1),
            kind=overrides.get("kind", "land"),
            mileage=overrides.get("mileage", "1000"),
            hours_used=overrides.get("hours_used"),
        )

    def test_flag_without_rows_is_reported(self):
        from dataclasses import replace

        invoice = self._invoice()
        broken = replace(invoice, annotations=replace(invoice.annotations, new_transport=True))
        messages = [issue.message for issue in broken.validate().errors]
        assert any("new_transport" in message and "wiersz" in message for message in messages)

    def test_rows_without_flag_are_reported(self):
        from dataclasses import replace

        invoice = self._invoice()
        broken = replace(
            invoice,
            annotations=replace(invoice.annotations, new_transport_means=(self._means(),)),
        )
        messages = [issue.message for issue in broken.validate().errors]
        assert any("new_transport_means" in message for message in messages)

    def test_unknown_kind_is_reported(self):
        issues = self._means(kind="sea").validate("means")
        assert any("kind" in issue.message for issue in issues)

    def test_water_and_air_require_working_hours(self):
        for kind in ("water", "air"):
            issues = self._means(kind=kind).validate("means")
            assert any("hours_used" in issue.message for issue in issues), kind

    def test_water_with_hours_is_accepted(self):
        assert self._means(kind="water", hours_used="12").validate("means") == []

    def test_non_positive_row_number_is_reported(self):
        issues = self._means(row_number=0).validate("means")
        assert any("row_number" in issue.message for issue in issues)


class TestPaymentDueDatesAreMerged:
    """`due_dates` nie może być po cichu pomijane, gdy `due_terms` jest niepuste."""

    def _invoice(self):
        from ksef_client.documents.fa3 import FA3Invoice, InvoiceParty, VatClass

        builder = FA3Invoice.basic("FV/PAY/1")
        builder.seller(
            InvoiceParty.polish_company(
                nip="1111111111", name="Sprzedawca", address="ul. Testowa 1"
            )
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. Testowa 2")
        )
        builder.add_service_line(
            "Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        return builder.build()

    def test_both_sources_land_in_the_xml(self):
        from dataclasses import replace
        from datetime import date

        from ksef_client.documents.fa3 import PaymentTerms
        from ksef_client.documents.fa3.sections import PaymentDue

        payment = PaymentTerms(
            due_dates=(date(2026, 3, 15),),
            due_terms=(PaymentDue.date(date(2026, 3, 1)),),
        )
        xml = (
            replace(self._invoice(), payment_terms=payment)
            .to_xml(validate=False)
            .decode("utf-8")
        )
        assert xml.count("<TerminPlatnosci>") == 2
        assert "<Termin>2026-03-01</Termin>" in xml
        assert "<Termin>2026-03-15</Termin>" in xml

    def test_paid_date_with_partial_payments_is_reported(self):
        """Schemat pozwala opisać albo pełną zapłatę, albo zapłaty częściowe."""
        from datetime import date
        from decimal import Decimal

        from ksef_client.documents.fa3.domain import PartialPayment, PaymentTerms

        payment = PaymentTerms(
            paid_date=date(2026, 3, 1),
            partial_payments=(
                PartialPayment(amount=Decimal("10.00"), payment_date=date(2026, 2, 1)),
            ),
        )
        issues = payment.validate("payment")
        assert any("paid_date" in issue.message for issue in issues)


class TestBatchPartCountLimit:
    """Kontrakt: „Maksymalna liczba części to 50" — SDK musi to egzekwować lokalnie."""

    def test_split_bytes_rejects_more_than_fifty_parts(self):
        from ksef_client.utils import MAX_BATCH_PARTS, split_bytes

        assert MAX_BATCH_PARTS == 50
        parts = split_bytes(b"x" * 5_000_000, max_part_size=100_000)
        assert len(parts) == 50

        with pytest.raises(ValueError, match="more than 50 parts"):
            split_bytes(b"x" * 5_000_001, max_part_size=100_000)

    def test_split_bytes_validates_arguments(self):
        from ksef_client.utils import split_bytes

        with pytest.raises(ValueError, match="max_part_size must be positive"):
            split_bytes(b"x", max_part_size=0)
        with pytest.raises(ValueError, match="max_parts must be positive"):
            split_bytes(b"x" * 10, max_part_size=1, max_parts=0)


class TestVerificationLinkSegments:
    """Segmenty linku nie mogą zmieniać jego struktury.

    Wartości trafiały do ścieżki dosłownie, więc `/` w `context_identifier_value`
    dokładał segment (i zmieniał napis podpisywany dla KOD II), a kod QR nadal
    powstawał — czyli prowadził do innego zasobu.
    """

    def _options(self):
        from ksef_client.config import KsefClientOptions

        return KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl/v2")

    def test_slash_in_identifier_is_percent_encoded(self):
        from ksef_client.services.verification_link import VerificationLinkService

        service = VerificationLinkService(self._options())
        url = service.build_invoice_verification_url("1111111111/evil", "01-02-2026", "YWJj")
        assert "/evil" not in url
        assert "1111111111%2Fevil" in url

    def test_blank_segment_is_rejected(self):
        from ksef_client.services.verification_link import VerificationLinkService

        service = VerificationLinkService(self._options())
        with pytest.raises(ValueError, match="nip"):
            service.build_invoice_verification_url("  ", "01-02-2026", "YWJj")
        with pytest.raises(ValueError, match="nip is required"):
            service.build_invoice_verification_url("", "01-02-2026", "YWJj")


class TestExportArchiveLimits:
    """Paczka eksportu może mieć 10 000 faktur + `_metadata.json` (nie liczy się)."""

    def test_archive_entry_limit_accounts_for_the_metadata_file(self):
        from ksef_client.utils.zip_utils import (
            EXPORT_MAX_ARCHIVE_ENTRIES,
            EXPORT_MAX_INVOICES,
        )

        assert EXPORT_MAX_INVOICES == 10_000
        assert EXPORT_MAX_ARCHIVE_ENTRIES == 10_001

    def test_full_export_package_unpacks(self):
        import io
        import zipfile

        from ksef_client.utils.zip_utils import EXPORT_MAX_ARCHIVE_ENTRIES, unzip_bytes_safe

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for index in range(EXPORT_MAX_ARCHIVE_ENTRIES - 1):
                archive.writestr(f"{index}.xml", b"<Faktura/>")
            archive.writestr("_metadata.json", b"{}")
        unpacked = unzip_bytes_safe(
            buffer.getvalue(), max_files=EXPORT_MAX_ARCHIVE_ENTRIES
        )
        assert len(unpacked) == EXPORT_MAX_ARCHIVE_ENTRIES
        assert "_metadata.json" in unpacked
